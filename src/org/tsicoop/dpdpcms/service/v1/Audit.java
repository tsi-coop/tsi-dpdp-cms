package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*; // Assuming these framework classes are available
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
import java.sql.Statement; // For Statement.RETURN_GENERATED_KEYS
import java.sql.Timestamp;
import java.net.InetAddress; // For INET type
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

/**
 * AuditLogService class for managing immutable audit logs of system activities.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Audit Log and Exceptions Review modules
 * of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'audit_logs'.
 * - Columns: id (UUID PK), timestamp (TIMESTAMPZ), actor_user_id (UUID),
 * actor_system_id (VARCHAR), action_type (VARCHAR), entity_type (VARCHAR),
 * entity_id (VARCHAR/UUID), context_details (JSONB), ip_address (INET),
 * status (VARCHAR), source_module (VARCHAR).
 * - Assumes 'users' table exists for FK references to actor_user_id.
 */
public class Audit implements REST {

    // All HTTP methods will now defer to the POST method
    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
    }

    /**
     * Handles all Audit Log Management operations via a single POST endpoint.
     * The specific operation is determined by the '_func' attribute in the JSON request body.
     *
     * @param req The HttpServletRequest containing the JSON input.
     * @param res The HttpServletResponse for sending the JSON output.
     */
    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;

        // Note: For audit logs, the actor_user_id should typically come from the
        // authenticated context of the microservice making the log request,
        // not directly from the input JSON for security/integrity.
        // For this template, we'll assume it's passed or derived.
        UUID actorUserId = null;
        String actorUserIdStr = (String) input.get("actor_user_id");
        if (actorUserIdStr != null && !actorUserIdStr.isEmpty()) {
            try {
                actorUserId = UUID.fromString(actorUserIdStr);
            } catch (IllegalArgumentException e) {
                // Log this as a warning, but don't fail the audit log request
                System.err.println("AuditLogService: Invalid actor_user_id format provided: " + actorUserIdStr);
            }
        }

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "log_event":
                    String actorSystemId = (String) input.get("actor_system_id");
                    String actionType = (String) input.get("action_type");
                    String entityType = (String) input.get("entity_type");
                    String entityId = (String) input.get("entity_id");
                    JSONObject contextDetails = (JSONObject) input.get("context_details");
                    String ipAddressStr = (String) input.get("ip_address"); // Should be captured by API Gateway/Servlet
                    String status = (String) input.get("status"); // SUCCESS, FAILURE
                    String sourceModule = (String) input.get("source_module");

                    // Basic validation for critical fields
                    if (actionType == null || actionType.isEmpty() || entityType == null || entityType.isEmpty() ||
                            entityId == null || entityId.isEmpty() || status == null || status.isEmpty() ||
                            sourceModule == null || sourceModule.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields for 'log_event'.", req.getRequestURI());
                        return;
                    }

                    InetAddress ipAddress = (ipAddressStr != null && !ipAddressStr.isEmpty()) ? InetAddress.getByName(ipAddressStr) : null;

                    output = logEventToDb(actorUserId, actorSystemId, actionType, entityType, entityId, contextDetails, ipAddress, status, sourceModule);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "list_audit_logs":
                    String search = (String) input.get("search");
                    String actionTypeFilter = (String) input.get("action_type_filter");
                    String entityTypeFilter = (String) input.get("entity_type_filter");
                    String entityIdFilter = (String) input.get("entity_id_filter");
                    String statusFilter = (String) input.get("status_filter");
                    String startDateStr = (String) input.get("start_date");
                    String endDateStr = (String) input.get("end_date");
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    Timestamp startDate = (startDateStr != null && !startDateStr.isEmpty()) ? Timestamp.from(Instant.parse(startDateStr)) : null;
                    Timestamp endDate = (endDateStr != null && !endDateStr.isEmpty()) ? Timestamp.from(Instant.parse(endDateStr)) : null;

                    outputArray = listAuditLogsFromDb(search, actionTypeFilter, entityTypeFilter, entityIdFilter, statusFilter, startDate, endDate, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_audit_log_entry":
                    UUID auditLogId = null;
                    String auditLogIdStr = (String) input.get("audit_log_id");
                    if (auditLogIdStr != null && !auditLogIdStr.isEmpty()) {
                        try {
                            auditLogId = UUID.fromString(auditLogIdStr);
                        } catch (IllegalArgumentException e) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'audit_log_id' format.", req.getRequestURI());
                            return;
                        }
                    }
                    if (auditLogId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'audit_log_id' is required for 'get_audit_log_entry'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> logEntryOptional = getAuditLogEntryFromDb(auditLogId);
                    if (logEntryOptional.isPresent()) {
                        output = logEntryOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Audit log entry with ID '" + auditLogId + "' not found.", req.getRequestURI());
                    }
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
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid UUID or date format in input: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) { // Catch broader exceptions like UnknownHostException from InetAddress
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Validates the HTTP method and request content type.
     * @param method The HTTP method of the request.
     * @param req The HttpServletRequest.
     * @param res The HttpServletResponse.
     * @return true if validation passes, false otherwise.
     */
    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Audit Log Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Audit Log Management ---

    /**
     * Logs an event to the audit_logs table.
     * This method is typically called internally by other services.
     * @return JSONObject containing the new log entry's ID.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject logEventToDb(UUID actorUserId, String actorSystemId, String actionType, String entityType, String entityId, JSONObject contextDetails, InetAddress ipAddress, String status, String sourceModule) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "INSERT INTO audit_logs (id, timestamp, actor_user_id, actor_system_id, action_type, entity_type, entity_id, context_details, ip_address, status, source_module) VALUES (uuid_generate_v4(), NOW(), ?, ?, ?, ?, ?, ?::jsonb, ?::inet, ?, ?) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setObject(1, actorUserId);
            pstmt.setString(2, actorSystemId);
            pstmt.setString(3, actionType);
            pstmt.setString(4, entityType);
            pstmt.setString(5, entityId);
            pstmt.setString(6, contextDetails != null ? contextDetails.toJSONString() : null);
            pstmt.setObject(7, ipAddress); // Use setObject for InetAddress
            pstmt.setString(8, status);
            pstmt.setString(9, sourceModule);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating audit log entry failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String logId = rs.getString(1);
                output.put("audit_log_id", logId);
                output.put("message", "Audit log entry created successfully.");
            } else {
                throw new SQLException("Creating audit log entry failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Retrieves a list of audit logs from the database with optional filtering and pagination.
     * @return JSONArray of audit log JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listAuditLogsFromDb(String search, String actionTypeFilter, String entityTypeFilter, String entityIdFilter, String statusFilter, Timestamp startDate, Timestamp endDate, int page, int limit) throws SQLException {
        JSONArray logsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, timestamp, actor_user_id, actor_system_id, action_type, entity_type, entity_id, context_details, ip_address, status, source_module FROM audit_logs WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (actionTypeFilter != null && !actionTypeFilter.isEmpty()) {
            sqlBuilder.append(" AND action_type = ?");
            params.add(actionTypeFilter);
        }
        if (entityTypeFilter != null && !entityTypeFilter.isEmpty()) {
            sqlBuilder.append(" AND entity_type = ?");
            params.add(entityTypeFilter);
        }
        if (entityIdFilter != null && !entityIdFilter.isEmpty()) {
            sqlBuilder.append(" AND entity_id = ?");
            params.add(entityIdFilter);
        }
        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            // Search within context_details JSONB as text or other string fields
            sqlBuilder.append(" AND (context_details::text ILIKE ? OR action_type ILIKE ? OR entity_type ILIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }
        if (startDate != null) {
            sqlBuilder.append(" AND timestamp >= ?");
            params.add(startDate);
        }
        if (endDate != null) {
            sqlBuilder.append(" AND timestamp <= ?");
            params.add(endDate);
        }

        sqlBuilder.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject logEntry = new JSONObject();
                logEntry.put("id", rs.getString("id"));
                logEntry.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                logEntry.put("actor_user_id", rs.getString("actor_user_id"));
                logEntry.put("actor_system_id", rs.getString("actor_system_id"));
                logEntry.put("action_type", rs.getString("action_type"));
                logEntry.put("entity_type", rs.getString("entity_type"));
                logEntry.put("entity_id", rs.getString("entity_id"));
                logEntry.put("context_details", new JSONParser().parse(rs.getString("context_details")));
                logEntry.put("ip_address", rs.getString("ip_address"));
                logEntry.put("status", rs.getString("status"));
                logEntry.put("source_module", rs.getString("source_module"));
                logsArray.add(logEntry);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse context_details JSON from DB for audit logs: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return logsArray;
    }

    /**
     * Retrieves a single audit log entry by ID from the database.
     * @return An Optional containing the audit log entry JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getAuditLogEntryFromDb(UUID auditLogId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, timestamp, actor_user_id, actor_system_id, action_type, entity_type, entity_id, context_details, ip_address, status, source_module FROM audit_logs WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, auditLogId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject logEntry = new JSONObject();
                logEntry.put("id", rs.getString("id"));
                logEntry.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                logEntry.put("actor_user_id", rs.getString("actor_user_id"));
                logEntry.put("actor_system_id", rs.getString("actor_system_id"));
                logEntry.put("action_type", rs.getString("action_type"));
                logEntry.put("entity_type", rs.getString("entity_type"));
                logEntry.put("entity_id", rs.getString("entity_id"));
                logEntry.put("context_details", new JSONParser().parse(rs.getString("context_details")));
                logEntry.put("ip_address", rs.getString("ip_address"));
                logEntry.put("status", rs.getString("status"));
                logEntry.put("source_module", rs.getString("source_module"));
                return Optional.of(logEntry);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse context_details JSON from DB for audit log entry: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }
}