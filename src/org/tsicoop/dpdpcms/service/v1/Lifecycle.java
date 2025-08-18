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
public class Lifecycle implements Action {

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

        // Placeholder for current CMS user ID (from authentication context)
        UUID actionByCmsUserId = UUID.fromString("00000000-0000-0000-0000-000000000001"); // Example Admin User ID

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters for policies
            UUID policyId = null;
            String policyIdStr = (String) input.get("policy_id");
            if (policyIdStr != null && !policyIdStr.isEmpty()) {
                try {
                    policyId = UUID.fromString(policyIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'policy_id' format.", req.getRequestURI());
                    return;
                }
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = (String) input.get("fiduciary_id");
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                // --- Retention Policy Management ---
                case "create_retention_policy":
                    String name = (String) input.get("name");
                    String description = (String) input.get("description");
                    JSONArray applicablePurposesJson = (JSONArray) input.get("applicable_purposes");
                    JSONArray applicableDataCategoriesJson = (JSONArray) input.get("applicable_data_categories");
                    Long retentionDurationValueLong = (Long) input.get("retention_duration_value");
                    String retentionDurationUnit = (String) input.get("retention_duration_unit");
                    String retentionStartEvent = (String) input.get("retention_start_event");
                    String actionAtExpiry = (String) input.get("action_at_expiry");
                    String legalReference = (String) input.get("legal_reference");
                    String status = (String) input.get("status");

                    if (fiduciaryId == null || name == null || name.isEmpty() || retentionDurationValueLong == null ||
                            retentionDurationUnit == null || retentionDurationUnit.isEmpty() || retentionStartEvent == null || retentionStartEvent.isEmpty() ||
                            actionAtExpiry == null || actionAtExpiry.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields for 'create_retention_policy'.", req.getRequestURI());
                        return;
                    }
                    if (!fiduciaryExists(fiduciaryId)) { // Helper to check if fiduciary exists
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                        return;
                    }
                    if (retentionPolicyExistsByName(fiduciaryId, name, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Retention policy with name '" + name + "' already exists for this Fiduciary.", req.getRequestURI());
                        return;
                    }

                    int retentionDurationValue = retentionDurationValueLong.intValue();
                    output = saveRetentionPolicyToDb(fiduciaryId, name, description, applicablePurposesJson, applicableDataCategoriesJson,
                            retentionDurationValue, retentionDurationUnit, retentionStartEvent, actionAtExpiry,
                            legalReference, status, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_retention_policy":
                    if (policyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' is required for 'update_retention_policy'.", req.getRequestURI());
                        return;
                    }
                    if (getRetentionPolicyFromDb(policyId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Retention policy with ID '" + policyId + "' not found.", req.getRequestURI());
                        return;
                    }

                    name = (String) input.get("name");
                    description = (String) input.get("description");
                    applicablePurposesJson = (JSONArray) input.get("applicable_purposes");
                    applicableDataCategoriesJson = (JSONArray) input.get("applicable_data_categories");
                    retentionDurationValueLong = (Long) input.get("retention_duration_value");
                    retentionDurationUnit = (String) input.get("retention_duration_unit");
                    retentionStartEvent = (String) input.get("retention_start_event");
                    actionAtExpiry = (String) input.get("action_at_expiry");
                    legalReference = (String) input.get("legal_reference");
                    status = (String) input.get("status");

                    if (name == null && description == null && applicablePurposesJson == null && applicableDataCategoriesJson == null &&
                            retentionDurationValueLong == null && retentionDurationUnit == null && retentionStartEvent == null &&
                            actionAtExpiry == null && legalReference == null && status == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_retention_policy'.", req.getRequestURI());
                        return;
                    }
                    if (name != null && !name.isEmpty() && retentionPolicyExistsByName(fiduciaryId, name, policyId)) { // Need fiduciaryId for this check
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Retention policy with name '" + name + "' already exists for this Fiduciary.", req.getRequestURI());
                        return;
                    }

                    int retentionDurationValueUpdate = (retentionDurationValueLong != null) ? retentionDurationValueLong.intValue() : -1; // Use -1 to indicate no update
                    output = updateRetentionPolicyInDb(policyId, name, description, applicablePurposesJson, applicableDataCategoriesJson,
                            retentionDurationValueUpdate, retentionDurationUnit, retentionStartEvent, actionAtExpiry,
                            legalReference, status, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "get_retention_policy":
                    if (policyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' is required for 'get_retention_policy'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> policyOptional = getRetentionPolicyFromDb(policyId);
                    if (policyOptional.isPresent()) {
                        output = policyOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Retention policy with ID '" + policyId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "list_retention_policies":
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");
                    // fiduciaryId is required for listing policies
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'list_retention_policies'.", req.getRequestURI());
                        return;
                    }
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listRetentionPoliciesFromDb(fiduciaryId, statusFilter, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "delete_retention_policy": // Soft delete
                    if (policyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' is required for 'delete_retention_policy'.", req.getRequestURI());
                        return;
                    }
                    if (getRetentionPolicyFromDb(policyId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Retention policy with ID '" + policyId + "' not found.", req.getRequestURI());
                        return;
                    }
                    deleteRetentionPolicyFromDb(policyId, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;

                // --- Purge Request Management ---
                case "initiate_purge_request": // Called by other services (e.g., GrievanceService for Erasure)
                    String userId = (String) input.get("user_id");
                    String triggerEvent = (String) input.get("trigger_event");
                    JSONArray dataCategoriesToPurgeJson = (JSONArray) input.get("data_categories_to_purge");
                    JSONArray processingPurposesAffectedJson = (JSONArray) input.get("processing_purposes_affected");
                    UUID processorId = null; // Optional, if purge is specific to a processor
                    String processorIdStr = (String) input.get("processor_id");
                    if (processorIdStr != null && !processorIdStr.isEmpty()) {
                        try { processorId = UUID.fromString(processorIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (processorIdStr != null && processorId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'processor_id' format for purge request.", req.getRequestURI());
                        return;
                    }

                    if (userId == null || userId.isEmpty() || fiduciaryId == null || triggerEvent == null || triggerEvent.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (user_id, fiduciary_id, trigger_event) for 'initiate_purge_request'.", req.getRequestURI());
                        return;
                    }

                    output = initiatePurgeRequest(userId, fiduciaryId, processorId, triggerEvent, dataCategoriesToPurgeJson, processingPurposesAffectedJson, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "confirm_purge_status": // Called by Data Fiduciary/Processor via API
                    UUID purgeRequestId = null;
                    String purgeRequestIdStr = (String) input.get("purge_request_id");
                    if (purgeRequestIdStr != null && !purgeRequestIdStr.isEmpty()) {
                        try { purgeRequestId = UUID.fromString(purgeRequestIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (purgeRequestId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'purge_request_id' is required for 'confirm_purge_status'.", req.getRequestURI());
                        return;
                    }
                    String confirmationStatus = (String) input.get("status"); // COMPLETED, FAILED, IN_PROGRESS
                    Long recordsAffectedCountLong = (Long) input.get("records_affected_count");
                    String details = (String) input.get("details");
                    String errorMessage = (String) input.get("error_message");
                    UUID confirmedByEntityId = null; // ID of the DF/DP confirming
                    String confirmedByEntityIdStr = (String) input.get("confirmed_by_entity_id");
                    if (confirmedByEntityIdStr != null && !confirmedByEntityIdStr.isEmpty()) {
                        try { confirmedByEntityId = UUID.fromString(confirmedByEntityIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (confirmationStatus == null || confirmationStatus.isEmpty() || confirmedByEntityId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (status, confirmed_by_entity_id) for 'confirm_purge_status'.", req.getRequestURI());
                        return;
                    }
                    int recordsAffectedCount = (recordsAffectedCountLong != null) ? recordsAffectedCountLong.intValue() : 0;

                    confirmPurgeStatus(purgeRequestId, confirmationStatus, recordsAffectedCount, details, errorMessage, confirmedByEntityId, actionByCmsUserId);
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
                    page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listPurgeRequestsFromDb(fiduciaryId, purgeStatusFilter, purgeTriggerFilter, purgeSearch, page, limit);
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

    // --- Helper Methods for Data Retention & Purge Management ---

    /**
     * Checks if a fiduciary exists. (Ideally, this would be an API call to FiduciaryService)
     */
    private boolean fiduciaryExists(UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM fiduciaries WHERE id = ? AND deleted_at IS NULL";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Checks if a retention policy with the given name already exists for a specific fiduciary.
     */
    private boolean retentionPolicyExistsByName(UUID fiduciaryId, String name, UUID excludePolicyId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM retention_policies WHERE fiduciary_id = ? AND name = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);
        params.add(name);

        if (excludePolicyId != null) {
            sqlBuilder.append(" AND id != ?");
            params.add(excludePolicyId);
        }
        sqlBuilder.append(" AND deleted_at IS NULL"); // Only consider non-deleted policies

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Saves a new retention policy to the database.
     * @return JSONObject containing the new policy's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveRetentionPolicyToDb(UUID fiduciaryId, String name, String description, JSONArray applicablePurposes, JSONArray applicableDataCategories,
                                               int retentionDurationValue, String retentionDurationUnit, String retentionStartEvent, String actionAtExpiry,
                                               String legalReference, String status, UUID createdByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO retention_policies (id, fiduciary_id, name, description, applicable_purposes, applicable_data_categories, retention_duration_value, retention_duration_unit, retention_start_event, action_at_expiry, legal_reference, status, created_at, created_by_user_id, last_updated_at, last_updated_by_user_id) VALUES (uuid_generate_v4(), ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?, ?, NOW(), ?, NOW(), ?) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, name);
            pstmt.setString(3, description);
            pstmt.setString(4, applicablePurposes != null ? applicablePurposes.toJSONString() : "[]");
            pstmt.setString(5, applicableDataCategories != null ? applicableDataCategories.toJSONString() : "[]");
            pstmt.setInt(6, retentionDurationValue);
            pstmt.setString(7, retentionDurationUnit);
            pstmt.setString(8, retentionStartEvent);
            pstmt.setString(9, actionAtExpiry);
            pstmt.setString(10, legalReference);
            pstmt.setString(11, status);
            pstmt.setObject(12, createdByUserId);
            pstmt.setObject(13, createdByUserId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating retention policy failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String policyId = rs.getString(1);
                output.put("policy_id", policyId);
                output.put("name", name);
                output.put("fiduciary_id", fiduciaryId.toString());
                output.put("message", "Retention policy created successfully.");
            } else {
                throw new SQLException("Creating retention policy failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing retention policy in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateRetentionPolicyInDb(UUID policyId, String name, String description, JSONArray applicablePurposes, JSONArray applicableDataCategories,
                                                 int retentionDurationValue, String retentionDurationUnit, String retentionStartEvent, String actionAtExpiry,
                                                 String legalReference, String status, UUID updatedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE retention_policies SET last_updated_at = NOW(), last_updated_by_user_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(updatedByUserId);

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (description != null) { sqlBuilder.append(", description = ?"); params.add(description); }
        if (applicablePurposes != null) { sqlBuilder.append(", applicable_purposes = ?::jsonb"); params.add(applicablePurposes.toJSONString()); }
        if (applicableDataCategories != null) { sqlBuilder.append(", applicable_data_categories = ?::jsonb"); params.add(applicableDataCategories.toJSONString()); }
        if (retentionDurationValue != -1) { sqlBuilder.append(", retention_duration_value = ?"); params.add(retentionDurationValue); }
        if (retentionDurationUnit != null && !retentionDurationUnit.isEmpty()) { sqlBuilder.append(", retention_duration_unit = ?"); params.add(retentionDurationUnit); }
        if (retentionStartEvent != null && !retentionStartEvent.isEmpty()) { sqlBuilder.append(", retention_start_event = ?"); params.add(retentionStartEvent); }
        if (actionAtExpiry != null && !actionAtExpiry.isEmpty()) { sqlBuilder.append(", action_at_expiry = ?"); params.add(actionAtExpiry); }
        if (legalReference != null) { sqlBuilder.append(", legal_reference = ?"); params.add(legalReference); }
        if (status != null && !status.isEmpty()) { sqlBuilder.append(", status = ?"); params.add(status); }

        sqlBuilder.append(" WHERE id = ? AND deleted_at IS NULL");
        params.add(policyId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating retention policy failed, policy not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Retention policy updated successfully."); }};
    }

    /**
     * Retrieves a retention policy by ID from the database.
     * @return An Optional containing the policy JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getRetentionPolicyFromDb(UUID policyId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, fiduciary_id, name, description, applicable_purposes, applicable_data_categories, retention_duration_value, retention_duration_unit, retention_start_event, action_at_expiry, legal_reference, status, created_at, created_by_user_id, last_updated_at, last_updated_by_user_id FROM retention_policies WHERE id = ? AND deleted_at IS NULL";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, policyId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject policy = new JSONObject();
                policy.put("policy_id", rs.getString("id"));
                policy.put("fiduciary_id", rs.getString("fiduciary_id"));
                policy.put("name", rs.getString("name"));
                policy.put("description", rs.getString("description"));
                policy.put("applicable_purposes", new JSONParser().parse(rs.getString("applicable_purposes")));
                policy.put("applicable_data_categories", new JSONParser().parse(rs.getString("applicable_data_categories")));
                policy.put("retention_duration_value", rs.getInt("retention_duration_value"));
                policy.put("retention_duration_unit", rs.getString("retention_duration_unit"));
                policy.put("retention_start_event", rs.getString("retention_start_event"));
                policy.put("action_at_expiry", rs.getString("action_at_expiry"));
                policy.put("legal_reference", rs.getString("legal_reference"));
                policy.put("status", rs.getString("status"));
                policy.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                policy.put("created_by_user_id", rs.getString("created_by_user_id"));
                policy.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                policy.put("last_updated_by_user_id", rs.getString("last_updated_by_user_id"));
                return Optional.of(policy);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for retention policy: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Retrieves a list of retention policies from the database with optional filtering and pagination.
     * @return JSONArray of policy JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listRetentionPoliciesFromDb(UUID fiduciaryId, String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray policiesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, fiduciary_id, name, description, retention_duration_value, retention_duration_unit, retention_start_event, action_at_expiry, status, created_at, last_updated_at FROM retention_policies WHERE fiduciary_id = ? AND deleted_at IS NULL");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (name ILIKE ? OR description ILIKE ? OR legal_reference ILIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
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
                JSONObject policy = new JSONObject();
                policy.put("policy_id", rs.getString("id"));
                policy.put("fiduciary_id", rs.getString("fiduciary_id"));
                policy.put("name", rs.getString("name"));
                policy.put("description", rs.getString("description"));
                policy.put("retention_duration_value", rs.getInt("retention_duration_value"));
                policy.put("retention_duration_unit", rs.getString("retention_duration_unit"));
                policy.put("retention_start_event", rs.getString("retention_start_event"));
                policy.put("action_at_expiry", rs.getString("action_at_expiry"));
                policy.put("status", rs.getString("status"));
                policy.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                policy.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                policiesArray.add(policy);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return policiesArray;
    }

    /**
     * Deletes a retention policy from the database (soft delete).
     * @throws SQLException if a database access error occurs.
     */
    private void deleteRetentionPolicyFromDb(UUID policyId, UUID deletedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE retention_policies SET deleted_at = NOW(), deleted_by_user_id = ?, status = 'INACTIVE' WHERE id = ? AND deleted_at IS NULL";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, deletedByUserId);
            pstmt.setObject(2, policyId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting retention policy failed, policy not found or already deleted.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Initiates a purge request. This is typically called by other services
     * (e.g., GrievanceService for Erasure, or an internal scheduler for retention expiry).
     * @return JSONObject containing the new purge request's ID.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject initiatePurgeRequest(String userId, UUID fiduciaryId, UUID processorId, String triggerEvent,
                                            JSONArray dataCategoriesToPurge, JSONArray processingPurposesAffected,
                                            UUID initiatedByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Check for legal exceptions before initiating (simplified here)
        UUID legalExceptionId = checkLegalExceptions(userId, fiduciaryId, dataCategoriesToPurge, processingPurposesAffected);
        String status = (legalExceptionId != null) ? "UNDER_LEGAL_HOLD" : "PENDING";
        String errorMessage = (legalExceptionId != null) ? "Purge under legal hold due to exception." : null;

        String sql = "INSERT INTO purge_requests (id, user_id, fiduciary_id, processor_id, trigger_event, data_categories_to_purge, processing_purposes_affected, status, initiated_at, created_by_user_id, last_updated_at, legal_exception_applied_id, error_message) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, NOW(), ?, NOW(), ?, ?) RETURNING id";

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
            pstmt.setObject(8, initiatedByUserId);
            pstmt.setObject(9, legalExceptionId);
            pstmt.setString(10, errorMessage);

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
     * Mocks a check for legal exceptions. In a real system, this would involve
     * complex logic querying legal_retention_exceptions table and other data.
     * @return UUID of the legal exception if applicable, otherwise null.
     */
    private UUID checkLegalExceptions(String userId, UUID fiduciaryId, JSONArray dataCategories, JSONArray purposes) throws SQLException {
        // Mock logic: Always return a specific legal exception ID if user_id contains "legal_hold"
        // In a real system, this would:
        // 1. Query legal_retention_exceptions table based on fiduciary_id, data_categories, purposes.
        // 2. Check if the user's data (e.g., transaction history) meets criteria for a legal hold.
        // 3. Potentially call other services (e.g., FinancialService.hasActiveLiabilities(userId)).
        if (userId != null && userId.contains("legal_hold")) {
            // Mock a specific legal exception ID from your legal_retention_exceptions table
            return UUID.fromString("11111111-2222-3333-4444-555555555555"); // Example UUID for a legal exception
        }
        return null;
    }

    /**
     * Confirms the status of a purge request (called by DF/DP).
     * @throws SQLException if a database access error occurs.
     */
    private void confirmPurgeStatus(UUID purgeRequestId, String confirmationStatus, int recordsAffectedCount,
                                    String details, String errorMessage, UUID confirmedByEntityId, UUID updatedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        String sql = "UPDATE purge_requests SET status = ?, records_affected_count = ?, details = ?, error_message = ?, confirmed_by_entity_id = ?, confirmed_at = NOW(), last_updated_at = NOW(), last_updated_by_user_id = ? WHERE id = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, confirmationStatus);
            pstmt.setInt(2, recordsAffectedCount);
            pstmt.setString(3, details);
            pstmt.setString(4, errorMessage);
            pstmt.setObject(5, confirmedByEntityId);
            pstmt.setObject(6, updatedByUserId);
            pstmt.setObject(7, purgeRequestId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Confirming purge status failed, purge request not found or no changes made.");
            }

            // Audit Log: Log the purge confirmation event
            // auditLogService.logEvent(updatedByUserId, "PURGE_CONFIRMED", "PurgeRequest", purgeRequestId, details, null, "SUCCESS", "DataRetentionService");

            // Trigger Notification to DPO if purge failed
            if ("FAILED".equalsIgnoreCase(confirmationStatus)) {
                // notificationService.dispatchNotification(templateIdForPurgeFailure, "DPO_ADMIN", fiduciaryId, null, payloadData, updatedByUserId);
            }

        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Retrieves a list of purge requests from the database with optional filtering and pagination.
     * @return JSONArray of purge request JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listPurgeRequestsFromDb(UUID fiduciaryId, String statusFilter, String triggerFilter, String search, int page, int limit) throws SQLException {
        JSONArray requestsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, user_id, fiduciary_id, processor_id, trigger_event, status, initiated_at, completed_at, records_affected_count, details, legal_exception_applied_id, error_message FROM purge_requests WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (triggerFilter != null && !triggerFilter.isEmpty()) {
            sqlBuilder.append(" AND trigger_event = ?");
            params.add(triggerFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (user_id ILIKE ? OR details ILIKE ?)");
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
                request.put("purge_request_id", rs.getString("id"));
                request.put("user_id", rs.getString("user_id"));
                request.put("fiduciary_id", rs.getString("fiduciary_id"));
                request.put("processor_id", rs.getString("processor_id"));
                request.put("trigger_event", rs.getString("trigger_event"));
                request.put("status", rs.getString("status"));
                request.put("initiated_at", rs.getTimestamp("initiated_at").toInstant().toString());
                request.put("completed_at", rs.getTimestamp("completed_at") != null ? rs.getTimestamp("completed_at").toInstant().toString() : null);
                request.put("records_affected_count", rs.getInt("records_affected_count"));
                request.put("details", rs.getString("details"));
                request.put("legal_exception_applied_id", rs.getString("legal_exception_applied_id"));
                request.put("error_message", rs.getString("error_message"));
                requestsArray.add(request);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return requestsArray;
    }
}