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
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Audit Service for managing immutable DPDP compliance logs.
 * Supports asynchronous logging and standardized search for the DPO Audit Explorer.
 * * Schema: id, fiduciary_id, timestamp, user_id, service_type, service_id, audit_action, context_details.
 */
public class Audit implements Action {

    // Thread pool for background logging to minimize latency on core business logic
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
                case "log_event":
                    // Extract fields matching the finalized schema
                    String userId = (String) input.get("user_id");
                    String fidStr = (String) input.get("fiduciary_id");
                    String serviceType = (String) input.get("service_type"); // APP, SYSTEM, USER
                    String sidStr = (String) input.get("service_id");
                    String action = (String) input.get("audit_action");

                    // context_details can be passed as an object or raw string
                    Object contextObj = input.get("context_details");
                    String details = (contextObj instanceof JSONObject) ? ((JSONObject)contextObj).toJSONString() : (String)contextObj;

                    if (userId == null || fidStr == null || serviceType == null || action == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required audit fields.", req.getRequestURI());
                        return;
                    }

                    UUID fiduciaryId = UUID.fromString(fidStr);
                    UUID serviceId = (sidStr != null && !sidStr.isEmpty()) ? UUID.fromString(sidStr) : null;

                    // Perform the database insertion asynchronously
                    logEventAsync(userId, fiduciaryId, serviceType, serviceId, action, details);

                    output = new JSONObject();
                    output.put("success", true);
                    output.put("message", "Audit event queued.");
                    OutputProcessor.send(res, HttpServletResponse.SC_ACCEPTED, output);
                    break;

                case "list_audit_logs":
                    String search = (String) input.get("search");
                    String fidFilter = (String) input.get("fiduciary_id");
                    String stypeFilter = (String) input.get("service_type_filter");
                    String actFilter = (String) input.get("action_filter");

                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 50;

                    if (fidFilter == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "fiduciary_id is required for listing logs.", req.getRequestURI());
                        return;
                    }

                    outputArray = listAuditLogsFromDb(search, UUID.fromString(fidFilter), stypeFilter, actFilter, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_audit_log":
                    String logIdStr = (String) input.get("id");
                    if (logIdStr == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Log ID is required.", req.getRequestURI());
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
     * Queues a log task for asynchronous execution.
     */
    public void logEventAsync(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) {
        auditExecutor.submit(() -> {
            try {
                logEventToDb(userId, fiduciaryId, serviceType, serviceId, auditAction, contextDetails);
            } catch (SQLException e) {
                System.err.println("CRITICAL: Async Audit Failure for Principal " + userId + ": " + e.getMessage());
            }
        });
    }

    private JSONObject logEventToDb(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) throws SQLException {
        String sql = "INSERT INTO audit_logs (id, fiduciary_id, timestamp, user_id, service_type, service_id, audit_action, context_details) " +
                "VALUES (uuid_generate_v4(), ?, NOW(), ?, ?, ?, ?, ?)";

        PoolDB pool = new PoolDB();
        try (Connection conn = pool.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, userId);
            pstmt.setString(3, serviceType);
            pstmt.setObject(4, serviceId);
            pstmt.setString(5, auditAction);
            pstmt.setString(6, contextDetails);

            pstmt.executeUpdate();
            return new JSONObject() {{ put("success", true); }};
        }
    }

    private JSONArray listAuditLogsFromDb(String search, UUID fiduciaryId, String serviceType, String action, int page, int limit) throws SQLException {
        JSONArray logs = new JSONArray();
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_logs WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (serviceType != null && !serviceType.isEmpty()) {
            sql.append(" AND service_type = ?"); params.add(serviceType);
        }
        if (action != null && !action.isEmpty()) {
            sql.append(" AND audit_action = ?"); params.add(action);
        }
        if (search != null && !search.isEmpty()) {
            sql.append(" AND (user_id ILIKE ? OR context_details ILIKE ?)");
            params.add("%" + search + "%"); params.add("%" + search + "%");
        }

        sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        PoolDB pool = new PoolDB();
        try (Connection conn = pool.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql.toString())) {

            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    JSONObject log = new JSONObject();
                    log.put("id", rs.getObject("id").toString());
                    log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                    log.put("user_id", rs.getString("user_id"));
                    log.put("service_type", rs.getString("service_type"));
                    log.put("service_id", rs.getString("service_id"));
                    log.put("audit_action", rs.getString("audit_action"));

                    // Parse details if they look like JSON, otherwise return as string
                    String details = rs.getString("context_details");
                    try {
                        log.put("context_details", new JSONParser().parse(details));
                    } catch (Exception e) {
                        log.put("context_details", details);
                    }
                    logs.add(log);
                }
            }
        }
        return logs;
    }

    private Optional<JSONObject> getAuditLogEntryFromDb(UUID id) throws SQLException {
        String sql = "SELECT * FROM audit_logs WHERE id = ?";
        PoolDB pool = new PoolDB();
        try (Connection conn = pool.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setObject(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    JSONObject log = new JSONObject();
                    log.put("id", rs.getObject("id").toString());
                    log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                    log.put("user_id", rs.getString("user_id"));
                    log.put("service_type", rs.getString("service_type"));
                    log.put("service_id", rs.getString("service_id"));
                    log.put("audit_action", rs.getString("audit_action"));

                    String details = rs.getString("context_details");
                    try {
                        log.put("context_details", new JSONParser().parse(details));
                    } catch (Exception e) {
                        log.put("context_details", details);
                    }
                    return Optional.of(log);
                }
            }
        }
        return Optional.empty();
    }
}