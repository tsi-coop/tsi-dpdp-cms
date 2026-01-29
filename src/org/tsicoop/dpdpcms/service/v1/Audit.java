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
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Audit Service for managing immutable DPDP compliance logs.
 * Refactored to use in-memory caching and batch writing via JobManager.
 */
public class Audit implements Action {

    // Thread-safe in-memory cache for incoming audit events
    private static final Queue<AuditEntry> auditCache = new ConcurrentLinkedQueue<>();

    /**
     * DTO to hold audit data in memory before batch writing.
     */
    private static class AuditEntry {
        String userId;
        UUID fiduciaryId;
        String serviceType;
        UUID serviceId;
        String auditAction;
        String contextDetails;

        Timestamp eventtime;

        AuditEntry(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails, Timestamp eventtime) {
            this.userId = userId;
            this.fiduciaryId = fiduciaryId;
            this.serviceType = serviceType;
            this.serviceId = serviceId;
            this.auditAction = auditAction;
            this.contextDetails = contextDetails;
            this.eventtime = eventtime;
        }
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            req.setCharacterEncoding("UTF-8");
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing _func.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "log_event":
                    handleLogRequest(input, res, req);
                    break;

                case "list_audit_logs":
                    handleListLogs(input, res, req);
                    break;

                case "get_audit_log":
                    handleGetLog(input, res, req);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function: " + func, req.getRequestURI());
                    break;
            }

        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    private void handleLogRequest(JSONObject input, HttpServletResponse res, HttpServletRequest req) {
        String userId = (String) input.get("user_id");
        String fidStr = (String) input.get("fiduciary_id");
        String serviceType = (String) input.get("service_type");
        String sidStr = (String) input.get("service_id");
        String action = (String) input.get("audit_action");

        Object contextObj = input.get("context_details");
        String details = (contextObj instanceof JSONObject) ? ((JSONObject)contextObj).toJSONString() : (String)contextObj;

        if (userId == null || fidStr == null || serviceType == null || action == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing parameters.", req.getRequestURI());
            return;
        }

        UUID fiduciaryId = UUID.fromString(fidStr);
        UUID serviceId = (sidStr != null && !sidStr.isEmpty()) ? UUID.fromString(sidStr) : null;

        // Push to memory cache instead of immediate DB write or ExecutorService
        logEventAsync(userId, fiduciaryId, serviceType, serviceId, action, details);

        JSONObject output = new JSONObject();
        output.put("success", true);
        output.put("message", "Audit event buffered in memory cache.");
        OutputProcessor.send(res, 202, output);
    }

    /**
     * Buffers a log event into the in-memory queue.
     */
    public void logEventAsync(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) {
        auditCache.add(new AuditEntry(userId, fiduciaryId, serviceType, serviceId, auditAction, contextDetails, Timestamp.from(Instant.now())));
    }

    /**
     * Batch writes all buffered logs from the memory cache to the database.
     * Intended to be called by JobManager periodically.
     */
    public void logEvents() {
        if (auditCache.isEmpty()) return;

        List<AuditEntry> batch = new ArrayList<>();
        AuditEntry entry;
        // Drain current queue into a local list for processing
        while ((entry = auditCache.poll()) != null) {
            batch.add(entry);
            if (batch.size() >= 500) break; // Limit batch size per transaction
        }

        if (batch.isEmpty()) return;

        String sql = "INSERT INTO audit_logs (id, fiduciary_id, timestamp, user_id, service_type, service_id, audit_action, context_details) " +
                "VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?)";

        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            conn.setAutoCommit(false);
            pstmt = conn.prepareStatement(sql);

            for (AuditEntry log : batch) {
                pstmt.setObject(1, log.fiduciaryId);
                pstmt.setTimestamp(2, log.eventtime);
                pstmt.setString(3, log.userId);
                pstmt.setString(4, log.serviceType);
                pstmt.setObject(5, log.serviceId);
                pstmt.setString(6, log.auditAction);
                pstmt.setString(7, log.contextDetails);
                pstmt.addBatch();
            }

            pstmt.executeBatch();
            conn.commit();
            System.out.println("[Audit] Successfully persisted " + batch.size() + " logs to database.");
        } catch (SQLException e) {
            System.err.println("CRITICAL: Failed to write audit batch: " + e.getMessage());
            // Fail-safe: Put failed entries back into the cache for retry in next run
            for (AuditEntry failed : batch) {
                auditCache.add(failed);
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private void handleListLogs(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String search = (String) input.get("search");
        String fidFilter = (String) input.get("fiduciary_id");
        String actFilter = (String) input.get("action_filter");

        if (fidFilter == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "fiduciary_id required.", req.getRequestURI());
            return;
        }

        int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
        int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 50;

        JSONArray outputArray = listAuditLogsFromDb(search, UUID.fromString(fidFilter), actFilter, page, limit);
        OutputProcessor.send(res, 200, outputArray);
    }

    protected JSONArray listAuditLogsFromDb(String search, UUID fiduciaryId, String action, int page, int limit) throws SQLException {
        JSONArray logs = new JSONArray();
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_logs WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        sql.append(" AND service_type IN ('APP','DPO_CONSOLE','SYSTEM')");

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
                log.put("service_id", rs.getString("service_id") != null ? rs.getString("service_id") : "");
                log.put("audit_action", rs.getString("audit_action"));
                log.put("context_details", rs.getString("context_details"));
                logs.add(log);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return logs;
    }

    private void handleGetLog(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String logIdStr = (String) input.get("id");
        if (logIdStr == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Log ID required.", req.getRequestURI());
            return;
        }

        Optional<JSONObject> logEntry = getAuditLogEntryFromDb(UUID.fromString(logIdStr));
        if (logEntry.isPresent()) {
            OutputProcessor.send(res, 200, logEntry.get());
        } else {
            OutputProcessor.errorResponse(res, 404, "Not Found", "Audit log not found.", req.getRequestURI());
        }
    }

    private Optional<JSONObject> getAuditLogEntryFromDb(UUID id) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM audit_logs WHERE id = ?");
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("id", rs.getObject("id").toString());
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("user_id", rs.getString("user_id"));
                log.put("service_type", rs.getString("service_type"));
                log.put("service_id", rs.getString("service_id") != null ? rs.getString("service_id") : "");
                log.put("audit_action", rs.getString("audit_action"));

                String details = rs.getString("context_details");
                try {
                    log.put("context_details", new JSONParser().parse(details));
                } catch (Exception e) {
                    log.put("context_details", details);
                }
                return Optional.of(log);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }
}