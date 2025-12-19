package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.Action;
import org.tsicoop.dpdpcms.framework.InputProcessor;
import org.tsicoop.dpdpcms.framework.OutputProcessor;
import org.tsicoop.dpdpcms.framework.PoolDB;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Map;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.time.format.DateTimeFormatter;
import java.sql.Timestamp;


/**
 * DashboardService class for retrieving aggregated metrics and recent activity
 * to populate the Admin Dashboard.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Tables: 'fiduciaries', 'apps', 'grievances', 'purge_requests', 'audit_logs'.
 */
public class AdminDash implements Action {

    /**
     * Handles all Dashboard operations (metrics retrieval, activity listing)
     * via a single POST endpoint.
     *
     * @param req The HttpServletRequest containing the JSON input.
     * @param res The HttpServletResponse for sending the JSON output.
     */
    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input;
        JSONObject output = new JSONObject();
        JSONArray outputArray = new JSONArray();

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "get_admin_metrics":
                    output = getAggregatedMetrics();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "get_dpo_metrics":
                    output = getDpoMetrics();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "list_recent_audit_logs":
                    // Get limit from input, default to 10 if not provided or invalid
                    Long limitLong = (input.get("limit") instanceof Long) ? (Long) input.get("limit") : 10L;
                    int limit = limitLong.intValue();
                    outputArray = listRecentAuditLogs(limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "list_pending_grievances":
                    Long listLimitLong = (input.get("limit") instanceof Long) ? (Long) input.get("limit") : 10L;
                    outputArray = listPendingGrievances(listLimitLong.intValue());
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred: " + e.getMessage(), req.getRequestURI());
        } catch (ParseException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid JSON input: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Validates the HTTP method and request content type.
     */
    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Dashboard operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    // --- Core Database Retrieval Logic ---

    /**
     * Retrieves DPO-specific metrics (SLA, Policy Review, Critical Failures).
     * @return JSONObject containing DPO metrics.
     * @throws SQLException
     */
    private JSONObject getDpoMetrics() throws SQLException {
        JSONObject metrics = new JSONObject();
        Connection conn = null;
        PoolDB pool = new PoolDB();
        int totalResolvedGrievances = 0;
        int resolvedOnTime = 0;

        try {
            conn = pool.getConnection();

            // --- 1. SLA Compliance Rate ---
            String sqlSlaTotal = "SELECT COUNT(*) AS total, " +
                    "COUNT(CASE WHEN g.resolution_timestamp IS NOT NULL AND g.resolution_timestamp <= g.due_date THEN 1 END) AS resolved_on_time " +
                    "FROM grievances g WHERE g.resolution_timestamp IS NOT NULL";
            try (PreparedStatement pstmt = conn.prepareStatement(sqlSlaTotal); ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    totalResolvedGrievances = rs.getInt("total");
                    resolvedOnTime = rs.getInt("resolved_on_time");
                }
            }

            double slaComplianceRate = (totalResolvedGrievances > 0) ?
                    ((double) resolvedOnTime / totalResolvedGrievances) * 100.0 :
                    100.0; // 100% if no grievances resolved yet, to show health

            // --- 2. Pending Requests (NEW or IN_PROGRESS) ---
            String sqlPending = "SELECT COUNT(*) FROM grievances WHERE status IN ('NEW', 'IN_PROGRESS') AND resolution_timestamp IS NULL";
            try (PreparedStatement pstmt = conn.prepareStatement(sqlPending); ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    metrics.put("pending_requests", rs.getInt(1));
                }
            }

            // --- 3. Policies Due for Review (Example: Policies due in the next 30 days or ACTIVE policies without recent update) ---
            // Simplified check: Policies that are ACTIVE but haven't been reviewed/updated in 180 days (6 months)
            // Or DRAFT policies with an upcoming effective date.
            String sqlPolicyReview = "SELECT COUNT(*) FROM consent_policies " +
                    "WHERE status = 'ACTIVE' AND last_updated_at < NOW() - INTERVAL '180 days'";
            try (PreparedStatement pstmt = conn.prepareStatement(sqlPolicyReview); ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    metrics.put("policies_due_for_review", rs.getInt(1));
                }
            }

            // --- 4. Critical Purge Failures ---
            String sqlPurgeFailures = "SELECT COUNT(*) FROM purge_requests WHERE status IN ('FAILED', 'UNDER_LEGAL_HOLD')";
            try (PreparedStatement pstmt = conn.prepareStatement(sqlPurgeFailures); ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    metrics.put("critical_purge_failures", rs.getInt(1));
                }
            }

            // Add SLA metric to output, formatted to one decimal place
            metrics.put("sla_compliance", Math.round(slaComplianceRate * 10.0) / 10.0);

        } finally {
            pool.cleanup(null, null, conn);
        }
        return new JSONObject() {{ put("success", true); put("metrics", metrics); }};
    }

    /**
     * Retrieves aggregated metrics for the admin dashboard widgets.
     * @return JSONObject containing key metrics.
     * @throws SQLException
     */
    private JSONObject getAggregatedMetrics() throws SQLException {
        JSONObject metrics = new JSONObject();
        Connection conn = null;
        PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();

            // SQL to count Active Fiduciaries (ACTIVE or PENDING status, not deleted)
            String sqlFiduciaries = "SELECT COUNT(*) FROM fiduciaries WHERE status IN ('ACTIVE', 'PENDING')";
            try (PreparedStatement pstmt = conn.prepareStatement(sqlFiduciaries); ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    metrics.put("active_fiduciaries", rs.getInt(1));
                }
            }

            // SQL to count Active Processors (ACTIVE status, not deleted)
            String sqlProcessors = "SELECT COUNT(*) FROM apps WHERE status = 'ACTIVE'";
            try (PreparedStatement pstmt = conn.prepareStatement(sqlProcessors); ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    metrics.put("active_processors", rs.getInt(1));
                }
            }

            // SQL to count Pending Grievances (status NEW or IN_PROGRESS)
            String sqlGrievances = "SELECT COUNT(*) FROM grievances WHERE status IN ('NEW', 'IN_PROGRESS') AND resolution_timestamp IS NULL";
            try (PreparedStatement pstmt = conn.prepareStatement(sqlGrievances); ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    metrics.put("pending_grievances", rs.getInt(1));
                }
            }

            // SQL to count Failed Purge Operations
            String sqlPurgeFailures = "SELECT COUNT(*) FROM purge_requests WHERE status = 'FAILED'";
            try (PreparedStatement pstmt = conn.prepareStatement(sqlPurgeFailures); ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    metrics.put("failed_purges", rs.getInt(1));
                }
            }

        } finally {
            pool.cleanup(null, null, conn); // Clean up connection
        }
        return new JSONObject() {{ put("success", true); put("metrics", metrics); }};
    }

    /**
     * Retrieves the most recent audit logs for display on the dashboard.
     * @param limit Maximum number of records to retrieve.
     * @return JSONArray of audit log objects.
     * @throws SQLException
     */
    private JSONArray listRecentAuditLogs(int limit) throws SQLException {
        JSONArray activities = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Note: Using entity_id AS VARCHAR for compatibility, though it's likely UUID in DB
        String sql = "SELECT timestamp, actor_user_id, actor_system_id, action_type, entity_type, CAST(entity_id AS VARCHAR) AS entity_id, status FROM audit_logs ORDER BY timestamp DESC LIMIT ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setInt(1, limit);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject activity = new JSONObject();

                // Assuming retrieval of UUIDs as Strings/Objects from JDBC
                String actorId = rs.getString("actor_user_id");
                String entityId = rs.getString("entity_id");

                activity.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                activity.put("actor_user_id", actorId);
                activity.put("actor_system_id", rs.getString("actor_system_id"));
                activity.put("action_type", rs.getString("action_type"));
                activity.put("entity_type", rs.getString("entity_type"));
                activity.put("entity_id", entityId);
                activity.put("status", rs.getString("status"));

                activities.add(activity);
            }

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return activities;
    }

    /**
     * Retrieves urgent pending grievances (NEW, IN_PROGRESS, sorted by nearest DUE DATE).
     * This method provides the list data for the DPO dashboard table.
     * @param limit Maximum number of records to retrieve.
     * @return JSONArray of grievance objects with calculated deadline display.
     * @throws SQLException
     */
    private JSONArray listPendingGrievances(int limit) throws SQLException {
        JSONArray grievancesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Select NEW/IN_PROGRESS grievances, order by due_date ascending (nearest deadline first)
        String sql = "SELECT id, user_id, type, subject, submission_timestamp, due_date, status, assigned_dpo_user_id FROM grievances " +
                "WHERE status IN ('NEW', 'IN_PROGRESS', 'ACKNOWLEDGED', 'PENDING_DPO_REVIEW') AND resolution_timestamp IS NULL " +
                "ORDER BY due_date ASC LIMIT ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setInt(1, limit);
            rs = pstmt.executeQuery();

            ZonedDateTime now = ZonedDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ISO_INSTANT;

            while (rs.next()) {
                JSONObject grievance = new JSONObject();
                Timestamp dueDateTimestamp = rs.getTimestamp("due_date");

                // Calculate days remaining/overdue
                long daysLeft = ChronoUnit.DAYS.between(now.toLocalDate(), dueDateTimestamp.toInstant().atZone(now.getZone()).toLocalDate());

                // Note: user_id and assigned_dpo_user_id should be joined with users table in production
                // to get names, but here we just pass the IDs/data stored in the table.

                grievance.put("grievance_id", rs.getString("id"));
                grievance.put("user_id", rs.getString("user_id"));
                grievance.put("type", rs.getString("type"));
                grievance.put("subject", rs.getString("subject"));
                grievance.put("submission_timestamp", rs.getTimestamp("submission_timestamp").toInstant().toString());
                grievance.put("due_date", dueDateTimestamp.toInstant().toString());
                grievance.put("status", rs.getString("status"));
                grievance.put("assigned_dpo_user_id", rs.getString("assigned_dpo_user_id"));
                grievance.put("days_left", daysLeft); // Days left/overdue

                grievancesArray.add(grievance);
            }

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return grievancesArray;
    }
}
