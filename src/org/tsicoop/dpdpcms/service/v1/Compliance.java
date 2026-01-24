package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*; // Assuming these framework classes are available
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.tsicoop.dpdpcms.util.Constants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement; // For Statement.RETURN_GENERATED_KEYS
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

// Assuming calls to other services like ConsentRecordService and AuditLogService
// import org.tsicoop.dpdpcms.consent.ConsentRecordService; // Example
// import org.tsicoop.dpdpcms.audit.AuditLogService; // Example

/**
 * DataRetentionService class for managing data retention policies and purge operations.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Data Retention Policy Configuration
 * and Data Purge Reports modules of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'retention_policies'.
 * - Columns: id (UUID PK), fiduciary_id (UUID), name (VARCHAR), description (TEXT),
 * applicable_purposes (JSONB), applicable_data_categories (JSONB),
 * retention_duration_value (INTEGER), retention_duration_unit (VARCHAR),
 * retention_start_event (VARCHAR), action_at_expiry (VARCHAR), legal_reference (TEXT),
 * status (VARCHAR), created_at (TIMESTAMPZ), created_by_user_id (UUID),
 * last_updated_at (TIMESTAMPZ), last_updated_by_user_id (UUID).
 * - Table is named 'purge_requests'.
 * - Columns: id (UUID PK), user_id (VARCHAR), fiduciary_id (UUID), processor_id (UUID),
 * trigger_event (VARCHAR), data_categories_to_purge (JSONB), processing_purposes_affected (JSONB),
 * status (VARCHAR), initiated_at (TIMESTAMPZ), completed_at (TIMESTAMPZ),
 * records_affected_count (INTEGER), details (TEXT), legal_exception_applied_id (UUID),
 * error_message (TEXT), confirmed_by_entity_id (UUID), confirmed_at (TIMESTAMPZ),
 * created_by_user_id (UUID), last_updated_at (TIMESTAMPZ).
 * - Assumes 'fiduciaries', 'users', 'legal_retention_exceptions' tables exist for FKs and lookups.
 */
public class Compliance implements Action {

    /**
     * Handles all Data Retention and Purge Management operations via a single POST endpoint.
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
        UUID appId = null;
        UUID loginUserId = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            // For client APIs
            String apiKey = req.getHeader("X-API-Key");
            String apiSecret = req.getHeader("X-API-Secret");
            // For Admin APIs
            loginUserId = InputProcessor.getAuthenticatedUserId(req);
            // For apps
            appId = new ApiKey().getAppId(apiKey,apiSecret);

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = input.get("fiduciary_id") != null?(String) input.get("fiduciary_id"):new Fiduciary().getFiduciaryId(UUID.fromString(apiKey),apiSecret);
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                // --- Purge Request Management ---
               /* case "initiate_purge_request": // Called by other services (e.g., GrievanceService for Erasure)
                    String userId = (String) input.get("user_id");
                    String triggerEvent = (String) input.get("trigger_event");
                    JSONArray dataCategoriesToPurgeJson = (JSONArray) input.get("data_categories_to_purge");
                    JSONArray processingPurposesAffectedJson = (JSONArray) input.get("processing_purposes_affected");
                    UUID processorId = null; // Optional, if purge is specific to a processor
                    String processorIdStr = (String) input.get("processor_id");
                    if (processorIdStr != null && !processorIdStr.isEmpty()) {
                        try { processorId = UUID.fromString(processorIdStr); } catch (IllegalArgumentException e) { *//* handled below *//* }
                    }
                    if (processorIdStr != null && processorId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'processor_id' format for purge request.", req.getRequestURI());
                        return;
                    }

                    if (userId == null || userId.isEmpty() || fiduciaryId == null || triggerEvent == null || triggerEvent.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (user_id, fiduciary_id, trigger_event) for 'initiate_purge_request'.", req.getRequestURI());
                        return;
                    }

                    output = initiatePurgeRequest(userId, fiduciaryId, processorId, triggerEvent, dataCategoriesToPurgeJson, processingPurposesAffectedJson,"MANUAL_PURGE");
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;*/

                case "update_purge_status":
                    UUID purgeRequestId = null;
                    String purgeRequestIdStr = (String) input.get("id");
                    if (purgeRequestIdStr != null && !purgeRequestIdStr.isEmpty()) {
                        try { purgeRequestId = UUID.fromString(purgeRequestIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (purgeRequestId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'purge_request_id' is required for 'update_purge_status'.", req.getRequestURI());
                        return;
                    }
                    String status = (String) input.get("status"); // COMPLETED, FAILED, IN_PROGRESS
                    String details = (String) input.get("details");
                    updatePurgeStatus(purgeRequestId, status, details, loginUserId, appId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "Purge status confirmed."); }});
                    break;

                case "list_purge_requests":
                    String purgeStatusFilter = (String) input.get("status");
                    String purgeTriggerFilter = (String) input.get("trigger_event");
                    String purgeSearch = (String) input.get("search");
                    // fiduciaryId is required for listing purge requests
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'list_purge_requests'.", req.getRequestURI());
                        return;
                    }
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 20;

                    outputArray = listPurgeRequestsFromDb(fiduciaryId, appId, purgeStatusFilter, purgeTriggerFilter, purgeSearch, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_purge_request":
                    String id = (String) input.get("id");
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'list_purge_requests'.", req.getRequestURI());
                        return;
                    }
                    output = getPurgeRequestsFromDb(id);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
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
        } catch (Exception e) {
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Data Retention & Purge Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }



    /**
     * Initiates a purge request. This is typically called by other services
     * (e.g., GrievanceService for Erasure, or an internal scheduler for retention expiry).
     * @return JSONObject containing the new purge request's ID.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject initiatePurgeRequest(String userId, UUID fiduciaryId, UUID processorId, String triggerEvent,
                                            JSONArray dataCategoriesToPurge, JSONArray processingPurposesAffected,
                                            String status, String postedBy) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "INSERT INTO purge_requests (id, user_id, fiduciary_id, processor_id, trigger_event, data_categories_to_purge, processing_purposes_affected, status, initiated_at) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, NOW()) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setObject(3, processorId);
            pstmt.setString(4, triggerEvent);
            pstmt.setString(5, dataCategoriesToPurge != null ? dataCategoriesToPurge.toJSONString() : "[]");
            pstmt.setString(6, processingPurposesAffected != null ? processingPurposesAffected.toJSONString() : "[]");
            pstmt.setString(7, status);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Initiating purge request failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String purgeRequestId = rs.getString(1);
                output.put("purge_request_id", purgeRequestId);
                output.put("status", status);
                output.put("message", "Purge request initiated successfully.");
            } else {
                throw new SQLException("Initiating purge request failed, no ID obtained.");
            }

            // Audit Log: Log the purge request initiation
            // auditLogService.logEvent(initiatedByUserId, "PURGE_REQUEST_INITIATED", "PurgeRequest", UUID.fromString(output.get("purge_request_id").toString()), payloadData.toJSONString(), null, "SUCCESS", "DataRetentionService");

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Confirms the status of a purge request (called by DF/DP).
     * @throws SQLException if a database access error occurs.
     */
    private void updatePurgeStatus(UUID purgeRequestId, String confirmationStatus, String details, UUID loginUserId, UUID appId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String userId = null;
        UUID fiduciaryId = null;
        boolean updated = false;
        String serviceType = null;

        String sql = "UPDATE purge_requests SET status = ?, details = ?, last_updated_at = NOW() WHERE id = ?";
        String sql2 = "select user_id,fiduciary_id from  purge_requests WHERE id = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, confirmationStatus);
            pstmt.setString(2, details);
            pstmt.setObject(3, purgeRequestId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Confirming purge status failed, purge request not found or no changes made.");
            }

            // Audit Log: Log the purge confirmation event
            pstmt = conn.prepareStatement(sql2);
            pstmt.setObject(1, purgeRequestId);
            rs = pstmt.executeQuery();
            if(rs.next()) {
                userId = rs.getString("user_id");
                fiduciaryId = UUID.fromString(rs.getString("fiduciary_id"));
                updated = true;
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        if(updated) {
            if(appId != null){
                serviceType = Constants.SERVICE_TYPE_APP;
            }
            else{
                serviceType = Constants.SERVICE_TYPE_DPO;
            }
            JSONObject auditContext = new JSONObject();
            auditContext.put("details",details);
            new Audit().logEventAsync(userId, fiduciaryId, serviceType, loginUserId, confirmationStatus, details);
        }
    }

    /**
     * Retrieves a list of purge requests from the database with optional filtering and pagination.
     * @return JSONArray of purge request JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listPurgeRequestsFromDb(UUID fiduciaryId, UUID appId, String statusFilter, String triggerFilter, String search, int page, int limit) throws SQLException {
        JSONArray requestsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT pr.id, pr.user_id, pr.purpose_id, pr.fiduciary_id, pr.app_id, pr.trigger_event, pr.status, pr.initiated_at, pr.details, a.name FROM purge_requests pr, apps a WHERE pr.app_id=a.id and pr.fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND pr.status = ?");
            params.add(statusFilter);
        }
        if (appId != null) {
            sqlBuilder.append(" AND pr.app_id = ?");
            params.add(appId);
        }
        if (triggerFilter != null && !triggerFilter.isEmpty()) {
            sqlBuilder.append(" AND pr.trigger_event = ?");
            params.add(triggerFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (pr.user_id ILIKE ? OR pr.details ILIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY initiated_at DESC LIMIT ? OFFSET ?");
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
                JSONObject request = new JSONObject();
                request.put("id", rs.getString("id"));
                request.put("user_id", rs.getString("user_id"));
                request.put("purpose_id", rs.getString("purpose_id"));
                request.put("fiduciary_id", rs.getString("fiduciary_id"));
                request.put("app_id", rs.getString("app_id"));
                request.put("app_name", rs.getString("name"));
                request.put("trigger_event", rs.getString("trigger_event"));
                request.put("status", rs.getString("status"));
                request.put("initiated_at", rs.getTimestamp("initiated_at").toInstant().toString());
                request.put("details", rs.getString("details"));
                requestsArray.add(request);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return requestsArray;
    }

    /**
     * Retrieves a list of purge requests from the database with optional filtering and pagination.
     * @return JSONArray of purge request JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject getPurgeRequestsFromDb(String id) throws SQLException {
        JSONObject purgeob = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "SELECT pr.id, pr.user_id, pr.fiduciary_id, pr.purpose_id, pr.app_id, pr.trigger_event, pr.status, pr.initiated_at, pr.details, a.name FROM purge_requests pr, apps a WHERE pr.app_id=a.id and pr.id=?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(id));
            rs = pstmt.executeQuery();

            if (rs.next()) {
                purgeob = new JSONObject();
                purgeob.put("id", rs.getString("id"));
                purgeob.put("user_id", rs.getString("user_id"));
                purgeob.put("fiduciary_id", rs.getString("fiduciary_id"));
                purgeob.put("purpose_id", rs.getString("purpose_id"));
                purgeob.put("app_id", rs.getString("app_id"));
                purgeob.put("app_name", rs.getString("name"));
                purgeob.put("trigger_event", rs.getString("trigger_event"));
                purgeob.put("status", rs.getString("status"));
                purgeob.put("initiated_at", rs.getTimestamp("initiated_at").toInstant().toString());
                purgeob.put("details", rs.getString("details"));
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return purgeob;
    }
}