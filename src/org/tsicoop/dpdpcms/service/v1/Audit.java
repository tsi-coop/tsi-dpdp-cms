package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
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
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Audit Service class for managing immutable audit logs of DPDP compliance activities.
 * Modified to match the finalized schema: id, timestamp, user_id, service_type, service_id, audit_action, context_details.
 * Includes asynchronous logging support to reduce application latency.
 */
public class Audit implements Action {

    // Thread pool for asynchronous audit logging to prevent blocking the main request thread.
    private static final ExecutorService auditExecutor = Executors.newFixedThreadPool(10);

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;

        try {
            req.setCharacterEncoding("UTF-8");
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
               /* case "log_event":
                    String userId = (String) input.get("user_id");
                    String serviceType = (String) input.get("service_type"); // APP, SYSTEM, USER
                    String serviceId = (String) input.get("service_id");
                    String auditAction = (String) input.get("audit_action");
                    JSONObject contextDetails = (JSONObject) input.get("context_details");

                    if (userId == null || serviceType == null || auditAction == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (user_id, service_type, audit_action).", req.getRequestURI());
                        return;
                    }

                    // Perform the database insertion asynchronously
                    logEventAsync(userId, fiduciaryId, serviceType, serviceId, auditAction, contextDetails);

                    // Respond immediately to the caller
                    output = new JSONObject();
                    output.put("success", true);
                    output.put("message", "Audit event queued for processing.");
                    OutputProcessor.send(res, HttpServletResponse.SC_ACCEPTED, output);
                    break;*/

                case "list_audit_logs":
                    String search = (String) input.get("search");
                    String userIdFilter = (String) input.get("user_id_filter");
                    String serviceTypeFilter = (String) input.get("service_type_filter");
                    String actionFilter = (String) input.get("action_filter");
                    String startDateStr = (String) input.get("start_date");
                    String endDateStr = (String) input.get("end_date");

                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    Timestamp startDate = (startDateStr != null && !startDateStr.isEmpty()) ? Timestamp.from(Instant.parse(startDateStr)) : null;
                    Timestamp endDate = (endDateStr != null && !endDateStr.isEmpty()) ? Timestamp.from(Instant.parse(endDateStr)) : null;

                    outputArray = listAuditLogsFromDb(search, userIdFilter, serviceTypeFilter, actionFilter, startDate, endDate, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_audit_log":
                    String logIdStr = (String) input.get("id");
                    if (logIdStr == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "ID is required.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> logEntry = getAuditLogEntryFromDb(UUID.fromString(logIdStr));
                    if (logEntry.isPresent()) {
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, logEntry.get());
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Audit log not found.", req.getRequestURI());
                    }
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (ParseException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "JSON Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }

    /**
     * Submits a logging task to the internal thread pool.
     */
    protected void logEventAsync(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) {
        auditExecutor.submit(() -> {
            try {
                logEventToDb(userId, fiduciaryId, serviceType, serviceId, auditAction, contextDetails);
            } catch (SQLException e) {
                System.err.println("Asynchronous Audit Error for principal " + userId + ": " + e.getMessage());
            }
        });
    }

    private JSONObject logEventToDb(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) throws SQLException {
        String sql = "INSERT INTO audit_logs (id, fiduciary_id, timestamp, user_id, service_type, service_id, audit_action, context_details) " +
                "VALUES (uuid_generate_v4(), ?, NOW(), ?, ?, ?, ?, ?) RETURNING id";

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, userId);
            pstmt.setString(3, serviceType);
            pstmt.setObject(4, serviceId);
            pstmt.setString(5, auditAction);
            pstmt.setString(6, contextDetails);

            rs = pstmt.executeQuery();
            JSONObject result = new JSONObject();
            if (rs.next()) {
                result.put("success", true);
                result.put("id", rs.getObject("id").toString());
            }
            return result;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private JSONArray listAuditLogsFromDb(String search, String userId, String serviceType, String action, Timestamp start, Timestamp end, int page, int limit) throws SQLException {
        JSONArray logs = new JSONArray();
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_logs WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (userId != null) { sql.append(" AND user_id = ?"); params.add(userId); }
        if (serviceType != null) { sql.append(" AND service_type = ?"); params.add(serviceType); }
        if (action != null) { sql.append(" AND audit_action = ?"); params.add(action); }
        if (start != null) { sql.append(" AND timestamp >= ?"); params.add(start); }
        if (end != null) { sql.append(" AND timestamp <= ?"); params.add(end); }
        if (search != null) {
            sql.append(" AND (context_details::text ILIKE ? OR user_id ILIKE ?)");
            params.add("%" + search + "%"); params.add("%" + search + "%");
        }

        sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("id", rs.getObject("id").toString());
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("user_id", rs.getString("user_id"));
                log.put("service_type", rs.getString("service_type"));
                log.put("service_id", rs.getString("service_id"));
                log.put("audit_action", rs.getString("audit_action"));
                try {
                    log.put("context_details", new JSONParser().parse(rs.getString("context_details")));
                } catch (Exception e) { log.put("context_details", new JSONObject()); }
                logs.add(log);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return logs;
    }

    private Optional<JSONObject> getAuditLogEntryFromDb(UUID id) throws SQLException {
        String sql = "SELECT * FROM audit_logs WHERE id = ?";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("id", rs.getObject("id").toString());
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("user_id", rs.getString("user_id"));
                log.put("service_type", rs.getString("service_type"));
                log.put("service_id", rs.getString("service_id"));
                log.put("audit_action", rs.getString("audit_action"));
                try {
                    log.put("context_details", new JSONParser().parse(rs.getString("context_details")));
                } catch (Exception e) { log.put("context_details", new JSONObject()); }
                return Optional.of(log);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }
}