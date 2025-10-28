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

/**
 * DashboardService class for retrieving aggregated metrics and recent activity
 * to populate the Admin Dashboard.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Tables: 'fiduciaries', 'processors', 'grievances', 'purge_requests', 'audit_logs'.
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

                case "list_recent_audit_logs":
                    // Get limit from input, default to 10 if not provided or invalid
                    Long limitLong = (input.get("limit") instanceof Long) ? (Long) input.get("limit") : 10L;
                    int limit = limitLong.intValue();
                    outputArray = listRecentAuditLogs(limit);
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
            String sqlProcessors = "SELECT COUNT(*) FROM processors WHERE status = 'ACTIVE'";
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
}
