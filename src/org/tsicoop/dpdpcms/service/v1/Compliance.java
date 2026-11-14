package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*; // Assuming these framework classes are available
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.util.LegalHoldRules;
import org.tsicoop.dpdpcms.util.PurgeRules;
import org.tsicoop.dpdpcms.ces.CESService;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement; // For Statement.RETURN_GENERATED_KEYS
import java.sql.Timestamp;
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
            String callerRole = InputProcessor.getVerifiedRole(req);
            // For apps
            appId = new ApiKey().getAppId(apiKey,apiSecret);

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = input.get("fiduciary_id") != null
                    ? (String) input.get("fiduciary_id")
                    : (apiKey != null ? new Fiduciary().getFiduciaryId(UUID.fromString(apiKey), apiSecret) : null);
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
                    JSONObject purgeToUpdate = getPurgeRequestsFromDb(purgeRequestIdStr);
                    if (purgeToUpdate == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Purge request not found.", req.getRequestURI());
                        return;
                    }
                    String callerKind = callerRole == null ? "API_KEY" : callerRole.toUpperCase();
                    if (callerRole == null) {
                        // Processor API key: the purge must belong to the key's own fiduciary AND be assigned to the key's own app.
                        Object purgeFid = purgeToUpdate.get("fiduciary_id");
                        if (!InputProcessor.callerOwns(req, purgeFid == null ? null : UUID.fromString(purgeFid.toString()))) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This purge request does not belong to your fiduciary.", req.getRequestURI());
                            return;
                        }
                        Object purgeApp = purgeToUpdate.get("app_id");
                        if (appId == null || purgeApp == null || !appId.toString().equals(purgeApp.toString())) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This purge request is not assigned to your app.", req.getRequestURI());
                            return;
                        }
                    }
                    String status = input.get("status") == null ? null : input.get("status").toString().trim().toUpperCase(); // PURGE_IN_PROGRESS, PURGE_COMPLETED, PURGE_FAILED, PURGE_CANCELLED, LEGAL_HOLD_APPLIED
                    String details = (String) input.get("details");
                    if (!PurgeRules.isKnownStatus(status)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown 'status'. Use PURGE_IN_PROGRESS, PURGE_COMPLETED, PURGE_FAILED, PURGE_CANCELLED or LEGAL_HOLD_APPLIED.", req.getRequestURI());
                        return;
                    }
                    if (PurgeRules.isProcessorObligationReport(callerKind, status)) {
                        // A processor that must keep the data says so. Recorded for the DPO; the purge is not suspended.
                        String obligationProblem = PurgeRules.obligationNoteProblem(details);
                        if (obligationProblem != null) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", obligationProblem + ".", req.getRequestURI());
                            return;
                        }
                        String reporter = callerRole == null ? (appId == null ? "API_KEY" : appId.toString()) : (loginUserId == null ? callerKind : loginUserId.toString());
                        if (!reportProcessorObligation(purgeRequestId, details.trim(), reporter)) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "A purge request that is " + purgeToUpdate.get("status") + " cannot be changed.", req.getRequestURI());
                            return;
                        }
                        String obligationFid = String.valueOf(purgeToUpdate.get("fiduciary_id"));
                        new Audit().logEventAsync(String.valueOf(purgeToUpdate.get("user_id")), UUID.fromString(obligationFid), Constants.SERVICE_TYPE_APP, null,
                                "PURGE_PROCESSOR_LEGAL_OBLIGATION", "purge=" + purgeRequestId + " purpose=" + purgeToUpdate.get("purpose_id") + " reported_by=" + reporter);
                        try {
                            PoolDB dpoPool = new PoolDB(); Connection dpoConn = null;
                            try {
                                dpoConn = dpoPool.getConnection();
                                try (PreparedStatement d = dpoConn.prepareStatement("SELECT id FROM operators WHERE fiduciary_id = ? AND role = 'DPO' AND status = 'ACTIVE' ORDER BY created_at, id LIMIT 1")) {
                                    d.setObject(1, UUID.fromString(obligationFid));
                                    try (ResultSet dr = d.executeQuery()) {
                                        if (dr.next()) new CESService().insertNotification("OPERATOR", dr.getString(1), obligationFid, Constants.NOTIF_PURGE_OBLIGATION);
                                    }
                                }
                            } finally { dpoPool.cleanup(null, null, dpoConn); }
                        } catch (Exception e) { e.printStackTrace(); }
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true);
                            put("message", "Recorded for the DPO. The purge request is still open; only the DPO can place a legal hold."); }});
                        break;
                    }
                    if (!PurgeRules.mayChooseTarget(callerKind, status)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Only the DPO can cancel a purge or place it on legal hold.", req.getRequestURI());
                        return;
                    }
                    if (!PurgeRules.canMove((String) purgeToUpdate.get("status"), status)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "A purge request that is " + purgeToUpdate.get("status") + " cannot become " + status + ".", req.getRequestURI());
                        return;
                    }
                    String claimedProblem = PurgeRules.claimedCountProblem(input.get("records_affected"));
                    if (claimedProblem != null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", claimedProblem + ".", req.getRequestURI());
                        return;
                    }
                    Long claimedCount = (Long) input.get("records_affected");
                    if (!updatePurgeStatus(purgeRequestId, status, details, loginUserId, appId, callerRole, claimedCount)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This purge request is not assigned to you.", req.getRequestURI());
                        return;
                    }
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
                    if (rejectIfNotOwnFiduciary(fiduciaryId, loginUserId, callerRole, req, res)) return;
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 20;

                    // Operators only see their own assigned queue; DPO/ADMIN see the full fiduciary list.
                    UUID scopeOperatorId = "OPERATOR".equalsIgnoreCase(callerRole) ? loginUserId : null;
                    outputArray = listPurgeRequestsFromDb(fiduciaryId, appId, purgeStatusFilter, purgeTriggerFilter, purgeSearch, page, limit, scopeOperatorId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_purge_request":
                    String id = (String) input.get("id");
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'list_purge_requests'.", req.getRequestURI());
                        return;
                    }
                    output = getPurgeRequestsFromDb(id);
                    if (output != null && "OPERATOR".equalsIgnoreCase(callerRole)) {
                        Object assignedOperatorId = output.get("assigned_operator_id");
                        if (assignedOperatorId == null || !assignedOperatorId.equals(loginUserId.toString())) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This purge request is not assigned to you.", req.getRequestURI());
                            return;
                        }
                    } else if (output != null && output.get("fiduciary_id") != null) {
                        if (rejectIfNotOwnFiduciary(UUID.fromString((String) output.get("fiduciary_id")), loginUserId, callerRole, req, res)) return;
                    }
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "assign_purge_request":
                    if (InputProcessor.rejectIfOperator(req, res)) return; // Only DPO/ADMIN may delegate
                    UUID assignPurgeId = null;
                    String assignPurgeIdStr = (String) input.get("id");
                    String assignOperatorIdStr = (String) input.get("operator_id");
                    if (assignPurgeIdStr != null && !assignPurgeIdStr.isEmpty()) {
                        try { assignPurgeId = UUID.fromString(assignPurgeIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    UUID assignOperatorId = null;
                    if (assignOperatorIdStr != null && !assignOperatorIdStr.isEmpty()) {
                        try { assignOperatorId = UUID.fromString(assignOperatorIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (assignPurgeId == null || assignOperatorId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'id' and 'operator_id' are required for 'assign_purge_request'.", req.getRequestURI());
                        return;
                    }
                    JSONObject targetPurgeRequest = getPurgeRequestsFromDb(assignPurgeIdStr);
                    if (targetPurgeRequest == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Purge request not found.", req.getRequestURI());
                        return;
                    }
                    if (targetPurgeRequest.get("fiduciary_id") != null
                            && rejectIfNotOwnFiduciary(UUID.fromString((String) targetPurgeRequest.get("fiduciary_id")), loginUserId, callerRole, req, res)) return;
                    // The assignee must be an active operator of the purge request's fiduciary.
                    if (!InputProcessor.isActiveOperatorOf(assignOperatorId, UUID.fromString((String) targetPurgeRequest.get("fiduciary_id")))) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'operator_id' must be an active operator of this fiduciary.", req.getRequestURI());
                        return;
                    }
                    assignPurgeRequest(assignPurgeId, assignOperatorId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); }});
                    break;

                case "place_legal_hold":
                case "list_legal_holds":
                case "release_legal_hold": {
                    if (callerRole == null) { OutputProcessor.errorResponse(res, 403, "Forbidden", "Staff only.", req.getRequestURI()); return; }
                    if (InputProcessor.rejectIfOperator(req, res)) return; // a legal decision: DPO / ADMIN
                    UUID holdFid = "ADMIN".equalsIgnoreCase(callerRole) ? fiduciaryId : InputProcessor.getCallerFiduciaryId(req);
                    if (holdFid == null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'fiduciary_id' is required.", req.getRequestURI()); return; }
                    String actor = InputProcessor.getEmail(req);
                    if (func.equalsIgnoreCase("place_legal_hold")) placeLegalHold(input, holdFid, actor, loginUserId, res, req);
                    else if (func.equalsIgnoreCase("list_legal_holds")) listLegalHolds(input, holdFid, res);
                    else releaseLegalHold(input, holdFid, actor, loginUserId, res, req);
                    break;
                }

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

    // ---------------------------------------------------------------------------------------
    // Legal holds: a time-bound reason to keep a principal's data (court order, investigation)
    // ---------------------------------------------------------------------------------------
    private void placeLegalHold(JSONObject input, UUID fid, String actor, UUID actorId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String userId = (String) input.get("user_id");
        String purposeId = input.get("purpose_id") == null || input.get("purpose_id").toString().isBlank() ? null : input.get("purpose_id").toString().trim();
        String reason = (String) input.get("reason");
        String reference = input.get("reference") == null ? null : input.get("reference").toString().trim();
        if (userId == null || userId.isEmpty()) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'user_id' is required.", req.getRequestURI()); return; }
        java.time.Instant until = org.tsicoop.dpdpcms.util.ExpiryDates.parse(input.get("valid_until") == null ? null : input.get("valid_until").toString());
        String problem = LegalHoldRules.problem(reason, until, java.time.Instant.now());
        if (problem == null) problem = LegalHoldRules.referenceProblem(reference);
        if (problem != null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid legal hold: " + problem + ".", req.getRequestURI()); return; }

        PoolDB pool = new PoolDB(); Connection conn = null;
        UUID holdId; JSONArray held = new JSONArray();
        try {
            conn = pool.getConnection();
            try (PreparedStatement e = conn.prepareStatement("SELECT 1 FROM data_principal WHERE fiduciary_id = ? AND user_id = ?")) {
                e.setObject(1, fid); e.setString(2, userId);
                try (ResultSet er = e.executeQuery()) {
                    if (!er.next()) { OutputProcessor.errorResponse(res, 404, "Not Found", "No such data principal at this fiduciary.", req.getRequestURI()); return; }
                }
            }
            try (PreparedStatement ins = conn.prepareStatement("INSERT INTO legal_holds (fiduciary_id, user_id, purpose_id, reason, reference, placed_by, valid_until) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id")) {
                ins.setObject(1, fid); ins.setString(2, userId); ins.setString(3, purposeId); ins.setString(4, reason.trim());
                ins.setString(5, reference == null || reference.isEmpty() ? null : reference); ins.setString(6, actor == null ? "UNKNOWN" : actor);
                ins.setTimestamp(7, Timestamp.from(until));
                try (ResultSet ir = ins.executeQuery()) { ir.next(); holdId = (UUID) ir.getObject(1); }
            }
            // Purges already under way for this principal (and purpose) are put on hold now
            try (PreparedStatement u = conn.prepareStatement(
                    "UPDATE purge_requests SET status = 'LEGAL_HOLD_APPLIED', legal_hold_id = ?, details = 'On legal hold: purge deferred until the hold ends.', last_updated_at = NOW() " +
                    "WHERE fiduciary_id = ? AND user_id = ? AND (?::text IS NULL OR purpose_id = ?) AND status IN ('PURGE_INITIATED', 'PURGE_IN_PROGRESS', 'PURGE_FAILED') RETURNING id, purpose_id")) {
                u.setObject(1, holdId); u.setObject(2, fid); u.setString(3, userId); u.setString(4, purposeId); u.setString(5, purposeId);
                try (ResultSet ur = u.executeQuery()) {
                    while (ur.next()) {
                        JSONObject h = new JSONObject(); h.put("id", ur.getString(1)); h.put("status", "LEGAL_HOLD_APPLIED"); h.put("user_id", userId);
                        h.put("details", "On legal hold: purge deferred until the hold ends."); held.add(h);
                        org.tsicoop.dpdpcms.framework.WebhookDispatcher.dispatch(fid.toString(), "PURGE", "purge_request_status_updated", h);
                    }
                }
            }
        } finally { pool.cleanup(null, null, conn); }

        if (!held.isEmpty()) {
            try { new CESService().insertNotification("PRINCIPAL", userId, fid.toString(), Constants.NOTIF_LEGAL_ONHOLD); } catch (SQLException e) { e.printStackTrace(); }
        }
        JSONObject out = new JSONObject();
        out.put("success", true); out.put("hold_id", holdId.toString()); out.put("purges_held", (long) held.size());
        OutputProcessor.send(res, 201, out);
        JSONObject ctx = new JSONObject();
        ctx.put("hold_id", holdId.toString()); ctx.put("purpose_id", purposeId); ctx.put("valid_until", until.toString()); ctx.put("reference", reference); ctx.put("reason", reason.trim());
        new Audit().logEventAsync(actor == null ? "UNKNOWN" : actor, fid, Constants.SERVICE_TYPE_DPO_CONSOLE, actorId, "LEGAL_HOLD_PLACED", ctx.toJSONString());
    }

    private void listLegalHolds(JSONObject input, UUID fid, HttpServletResponse res) throws SQLException {
        StringBuilder sql = new StringBuilder("SELECT id, user_id, purpose_id, reason, reference, placed_by, placed_at, valid_until, released_at, released_by, release_reason FROM legal_holds WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>(); params.add(fid);
        String user = (String) input.get("user_id");
        if (user != null && !user.isEmpty()) { sql.append(" AND user_id = ?"); params.add(user); }
        if (Boolean.TRUE.equals(input.get("active_only"))) sql.append(" AND released_at IS NULL AND valid_until > NOW()");
        sql.append(" ORDER BY placed_at DESC LIMIT 200");
        PoolDB pool = new PoolDB(); Connection conn = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) ps.setObject(i + 1, params.get(i));
            rs = ps.executeQuery();
            JSONArray arr = new JSONArray();
            while (rs.next()) {
                JSONObject h = new JSONObject();
                h.put("hold_id", rs.getString("id")); h.put("user_id", rs.getString("user_id")); h.put("purpose_id", rs.getString("purpose_id"));
                h.put("reason", rs.getString("reason")); h.put("reference", rs.getString("reference")); h.put("placed_by", rs.getString("placed_by"));
                h.put("placed_at", rs.getTimestamp("placed_at").toInstant().toString()); h.put("valid_until", rs.getTimestamp("valid_until").toInstant().toString());
                boolean released = rs.getTimestamp("released_at") != null;
                h.put("released_at", released ? rs.getTimestamp("released_at").toInstant().toString() : null);
                h.put("released_by", rs.getString("released_by")); h.put("release_reason", rs.getString("release_reason"));
                h.put("status", released ? "RELEASED" : (rs.getTimestamp("valid_until").toInstant().isAfter(java.time.Instant.now()) ? "ACTIVE" : "ENDED"));
                arr.add(h);
            }
            OutputProcessor.send(res, 200, arr);
        } finally { pool.cleanup(rs, ps, conn); }
    }

    private void releaseLegalHold(JSONObject input, UUID fid, String actor, UUID actorId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String holdIdStr = (String) input.get("hold_id");
        String reason = (String) input.get("reason");
        UUID holdId;
        try { holdId = UUID.fromString(holdIdStr); } catch (Exception e) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'hold_id' is required.", req.getRequestURI()); return; }
        if (reason == null || reason.trim().length() < LegalHoldRules.MIN_REASON) { OutputProcessor.errorResponse(res, 400, "Bad Request", "A reason of at least " + LegalHoldRules.MIN_REASON + " characters is required.", req.getRequestURI()); return; }
        PoolDB pool = new PoolDB(); Connection conn = null; String userId = null; int resumed;
        try {
            conn = pool.getConnection();
            try (PreparedStatement u = conn.prepareStatement("UPDATE legal_holds SET released_at = NOW(), released_by = ?, release_reason = ? WHERE id = ? AND fiduciary_id = ? AND released_at IS NULL RETURNING user_id")) {
                u.setString(1, actor == null ? "UNKNOWN" : actor); u.setString(2, reason.trim()); u.setObject(3, holdId); u.setObject(4, fid);
                try (ResultSet r = u.executeQuery()) { if (r.next()) userId = r.getString(1); }
            }
            if (userId == null) { OutputProcessor.errorResponse(res, 404, "Not Found", "No active legal hold with that id.", req.getRequestURI()); return; }
            resumed = resumeHeldPurges(conn);
        } finally { pool.cleanup(null, null, conn); }
        JSONObject out = new JSONObject(); out.put("success", true); out.put("purges_resumed", (long) resumed);
        OutputProcessor.send(res, 200, out);
        new Audit().logEventAsync(actor == null ? "UNKNOWN" : actor, fid, Constants.SERVICE_TYPE_DPO_CONSOLE, actorId, "LEGAL_HOLD_RELEASED", "hold_id=" + holdId + " reason=" + reason.trim());
    }

    /**
     * Resumes purges that a legal hold deferred, once no active hold covers them any more: they become PURGE_INITIATED
     * again, the processor is told, and the event is audited. Safe to call repeatedly and from several instances: the
     * UPDATE only matches purges still on hold.
     */
    private static int resumeHeldPurges(Connection conn) throws SQLException {
        List<String[]> resumed = new ArrayList<>();
        try (PreparedStatement u = conn.prepareStatement(
                "UPDATE purge_requests pr SET status = 'PURGE_INITIATED', legal_hold_id = NULL, details = 'Legal hold ended: purge resumed.', last_updated_at = NOW() " +
                "WHERE pr.status = 'LEGAL_HOLD_APPLIED' AND pr.legal_hold_id IS NOT NULL " +
                "AND EXISTS (SELECT 1 FROM legal_holds h WHERE h.id = pr.legal_hold_id AND h.released_at IS NOT NULL) " +
                "AND NOT EXISTS (SELECT 1 FROM legal_holds h2 WHERE h2.fiduciary_id = pr.fiduciary_id AND h2.user_id = pr.user_id AND h2.released_at IS NULL AND h2.valid_until > NOW() " +
                "AND (h2.purpose_id IS NULL OR h2.purpose_id = pr.purpose_id)) " +
                "RETURNING pr.id, pr.fiduciary_id, pr.user_id, pr.app_id")) {
            try (ResultSet r = u.executeQuery()) {
                while (r.next()) resumed.add(new String[]{r.getString(1), r.getString(2), r.getString(3), r.getString(4)});
            }
        }
        for (String[] p : resumed) {
            try {
                if (p[3] != null) new CESService().insertNotification("APP", p[3], p[1], Constants.NOTIF_PURGE_INIT);
                JSONObject payload = new JSONObject();
                payload.put("id", p[0]); payload.put("status", "PURGE_INITIATED"); payload.put("details", "Legal hold ended: purge resumed."); payload.put("user_id", p[2]);
                org.tsicoop.dpdpcms.framework.WebhookDispatcher.dispatch(p[1], "PURGE", "purge_request_status_updated", payload);
                new Audit().logEventAsync(p[2], UUID.fromString(p[1]), "SYSTEM", null, "PURGE_RESUMED_AFTER_HOLD", "purge=" + p[0]);
            } catch (Exception e) { e.printStackTrace(); }
        }
        return resumed.size();
    }

    /** Daily/frequent sweep: ends holds whose period has run out and resumes the purges they deferred. Returns {holds ended, purges resumed}. */
    public static int[] sweepLegalHolds() throws SQLException {
        PoolDB pool = new PoolDB(); Connection conn = null;
        try {
            conn = pool.getConnection();
            List<String[]> ended = new ArrayList<>();
            try (PreparedStatement u = conn.prepareStatement(
                    "UPDATE legal_holds SET released_at = NOW(), released_by = 'SYSTEM_SWEEP', release_reason = 'Hold period ended' WHERE released_at IS NULL AND valid_until <= NOW() RETURNING id, fiduciary_id, user_id")) {
                try (ResultSet r = u.executeQuery()) { while (r.next()) ended.add(new String[]{r.getString(1), r.getString(2), r.getString(3)}); }
            }
            for (String[] h : ended) new Audit().logEventAsync(h[2], UUID.fromString(h[1]), "SYSTEM", null, "LEGAL_HOLD_ENDED", "hold_id=" + h[0]);
            return new int[]{ended.size(), resumeHeldPurges(conn)};
        } finally { pool.cleanup(null, null, conn); }
    }

    /**
     * Flags purges that are still unconfirmed after PURGE_COMPLETION_SLA_DAYS (only when that is configured) and tells the
     * fiduciary's DPO once per sweep. A purge under legal hold is not late. Returns the number newly flagged.
     */
    public static int sweepPurgeSla() throws SQLException {
        return sweepPurgeSla(PurgeRules.slaDays(System.getenv("PURGE_COMPLETION_SLA_DAYS")));
    }

    /** As above with the limit given explicitly (null = no SLA configured, nothing is flagged). */
    public static int sweepPurgeSla(Integer days) throws SQLException {
        if (days == null) return 0;
        PoolDB pool = new PoolDB(); Connection conn = null;
        List<String[]> flagged = new ArrayList<>();
        try {
            conn = pool.getConnection();
            try (PreparedStatement u = conn.prepareStatement(
                    "UPDATE purge_requests SET sla_flagged_at = NOW() WHERE sla_flagged_at IS NULL AND status NOT IN ('PURGE_COMPLETED', 'PURGE_CANCELLED', 'LEGAL_HOLD_APPLIED') " +
                    "AND initiated_at < NOW() - make_interval(days => ?) RETURNING id, fiduciary_id, user_id, purpose_id")) {
                u.setInt(1, days);
                try (ResultSet r = u.executeQuery()) { while (r.next()) flagged.add(new String[]{r.getString(1), r.getString(2), r.getString(3), r.getString(4)}); }
            }
            java.util.Set<String> notified = new java.util.HashSet<>();
            for (String[] f : flagged) {
                new Audit().logEventAsync(f[2], UUID.fromString(f[1]), "SYSTEM", null, "PURGE_SLA_BREACHED", "purge=" + f[0] + " purpose=" + f[3] + " limit_days=" + days);
                if (notified.add(f[1])) {
                    try (PreparedStatement d = conn.prepareStatement("SELECT id FROM operators WHERE fiduciary_id = ? AND role = 'DPO' AND status = 'ACTIVE' ORDER BY created_at, id LIMIT 1")) {
                        d.setObject(1, UUID.fromString(f[1]));
                        try (ResultSet dr = d.executeQuery()) {
                            if (dr.next()) new CESService().insertNotification("OPERATOR", dr.getString(1), f[1], Constants.NOTIF_PURGE_SLA);
                        }
                    }
                }
            }
        } finally { pool.cleanup(null, null, conn); }
        return flagged.size();
    }

    /** Evidence and SLA fields shared by the list and get outputs. */
    private static void putPurgeEvidence(JSONObject o, ResultSet rs) throws SQLException {
        Object claimed = rs.getObject("claimed_record_count");
        o.put("claimed_record_count", claimed == null ? null : ((Number) claimed).longValue()); // the processor's claim, not verified by the CMS
        o.put("confirmed_by", rs.getString("confirmed_by"));
        o.put("confirmed_by_type", rs.getString("confirmed_by_type"));
        o.put("confirmed_at", rs.getTimestamp("confirmed_at") == null ? null : rs.getTimestamp("confirmed_at").toInstant().toString());
        o.put("sla_overdue", rs.getTimestamp("sla_flagged_at") != null);
        Object hold = rs.getObject("legal_hold_id");
        o.put("legal_hold_id", hold == null ? null : hold.toString());
        Timestamp obligationAt = rs.getTimestamp("processor_obligation_at");
        o.put("processor_obligation_at", obligationAt == null ? null : obligationAt.toInstant().toString());
        o.put("processor_obligation_note", rs.getString("processor_obligation_note")); // what the processor said; not verified by the CMS
    }

    /**
     * A processor reports that it must keep the data because of a legal obligation. Recorded for the DPO; the purge's status
     * is NOT changed and the purge is not suspended (only the DPO's time-bound legal hold does that).
     * @return false if the purge is already final
     */
    private boolean reportProcessorObligation(UUID purgeRequestId, String note, String reportedBy) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE purge_requests SET processor_obligation_at = NOW(), processor_obligation_note = ?, processor_obligation_by = ?, " +
                    "last_updated_at = NOW() WHERE id = ? AND status NOT IN ('PURGE_COMPLETED', 'PURGE_CANCELLED')");
            pstmt.setString(1, note);
            pstmt.setString(2, reportedBy);
            pstmt.setObject(3, purgeRequestId);
            return pstmt.executeUpdate() > 0;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Confirms the status of a purge request (called by DF/DP).
     * @throws SQLException if a database access error occurs.
     */
    private boolean updatePurgeStatus(UUID purgeRequestId, String confirmationStatus, String details, UUID loginUserId, UUID appId, String callerRole, Long claimedCount) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String userId = null;
        UUID fiduciaryId = null;
        boolean updated = false;
        String serviceType = null;

        // Who confirmed it comes from the credential (the API key's app, or the operator), never from the body. The
        // processor's own count is stored as CLAIMED: the CMS cannot verify records held in the processor's systems.
        // A final state (completed, cancelled) is never overwritten.
        String sql = "UPDATE purge_requests SET status = ?, details = ?, claimed_record_count = COALESCE(?, claimed_record_count), " +
                "confirmed_by = COALESCE(?, confirmed_by), confirmed_by_type = COALESCE(?, confirmed_by_type), confirmed_at = COALESCE(?, confirmed_at), " +
                "last_updated_at = NOW() WHERE id = ? AND status NOT IN ('PURGE_COMPLETED', 'PURGE_CANCELLED')";
        String sql2 = "select user_id, fiduciary_id, assigned_operator_id from purge_requests WHERE id = ?";

        try {
            conn = pool.getConnection();

            // Operators may only close purge requests explicitly assigned to them.
            if ("OPERATOR".equalsIgnoreCase(callerRole)) {
                UUID assignedOperatorId = null;
                try (PreparedStatement p = conn.prepareStatement("SELECT assigned_operator_id FROM purge_requests WHERE id = ?")) {
                    p.setObject(1, purgeRequestId);
                    try (ResultSet r = p.executeQuery()) {
                        if (r.next()) assignedOperatorId = (UUID) r.getObject("assigned_operator_id");
                    }
                }
                if (assignedOperatorId == null || !assignedOperatorId.equals(loginUserId)) {
                    return false;
                }
            }

            // DPOs may only update purge requests belonging to their own fiduciary.
            if (callerRole != null && !"ADMIN".equalsIgnoreCase(callerRole) && !"OPERATOR".equalsIgnoreCase(callerRole)) {
                UUID targetFid = null;
                try (PreparedStatement p = conn.prepareStatement("SELECT fiduciary_id FROM purge_requests WHERE id = ?")) {
                    p.setObject(1, purgeRequestId);
                    try (ResultSet r = p.executeQuery()) {
                        if (r.next()) targetFid = (UUID) r.getObject("fiduciary_id");
                    }
                }
                UUID callerFid = loginUserId != null ? getCallerFiduciaryId(conn, loginUserId) : null;
                if (callerFid == null || !callerFid.equals(targetFid)) {
                    return false;
                }
            }

            pstmt = conn.prepareStatement(sql);
            boolean confirming = Constants.EVENT_PURGE_COMPLETED.equals(confirmationStatus);
            pstmt.setString(1, confirmationStatus);
            pstmt.setString(2, details);
            if (claimedCount == null) pstmt.setNull(3, java.sql.Types.BIGINT); else pstmt.setLong(3, claimedCount);
            String confirmedBy = callerRole != null ? (loginUserId != null ? loginUserId.toString() : null) : (appId != null ? appId.toString() : null);
            if (confirming && confirmedBy != null) {
                pstmt.setString(4, confirmedBy);
                pstmt.setString(5, callerRole != null ? "OPERATOR" : "API_KEY");
                pstmt.setTimestamp(6, new Timestamp(System.currentTimeMillis()));
            } else {
                pstmt.setNull(4, java.sql.Types.VARCHAR);
                pstmt.setNull(5, java.sql.Types.VARCHAR);
                pstmt.setNull(6, java.sql.Types.TIMESTAMP);
            }
            pstmt.setObject(7, purgeRequestId);

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
                serviceType = Constants.SERVICE_TYPE_DPO_CONSOLE;
            }
            JSONObject auditContext = new JSONObject();
            auditContext.put("details",details);
            try {
                // Security event: the status row is already updated, so make the record durable now.
                new Audit().logEventSync(userId, fiduciaryId, serviceType, loginUserId, confirmationStatus, details);
            } catch (SQLException e) {
                System.err.println("[ERROR] Purge confirmation audit write failed (event stays queued): " + e.getMessage());
            }

            // Give the Data Principal full lifecycle visibility: notify them once the purge
            // they triggered (erasure/retention expiry) actually completes, or if it's put on
            // legal hold instead. Fire-and-forget — a notification failure must not fail the
            // status update itself.
            try {
                if (Constants.EVENT_PURGE_COMPLETED.equals(confirmationStatus)) {
                    new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), Constants.NOTIF_PURGE_CONFIRM);
                } else if (Constants.EVENT_LEGAL_HOLD_APPLIED.equals(confirmationStatus)) {
                    new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), Constants.NOTIF_LEGAL_ONHOLD);
                }
            } catch (SQLException e) {
                e.printStackTrace(); // Notification failure must not fail the purge status update
            }

            JSONObject webhookPayload = new JSONObject();
            webhookPayload.put("id", purgeRequestId.toString());
            webhookPayload.put("status", confirmationStatus);
            webhookPayload.put("details", details);
            webhookPayload.put("user_id", userId);
            WebhookDispatcher.dispatch(fiduciaryId.toString(), "PURGE", "purge_request_status_updated", webhookPayload);
        }
        return updated;
    }

    /**
     * Assigns a purge request to a specific Operator for delegated closure.
     * @throws SQLException if a database access error occurs.
     */
    private void assignPurgeRequest(UUID purgeRequestId, UUID operatorId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE purge_requests SET assigned_operator_id = ?, last_updated_at = NOW() WHERE id = ?");
            pstmt.setObject(1, operatorId);
            pstmt.setObject(2, purgeRequestId);
            if (pstmt.executeUpdate() == 0) {
                throw new SQLException("Assigning purge request failed, purge request not found.");
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
    private JSONArray listPurgeRequestsFromDb(UUID fiduciaryId, UUID appId, String statusFilter, String triggerFilter, String search, int page, int limit, UUID scopeOperatorId) throws SQLException {
        JSONArray requestsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT pr.id, pr.user_id, pr.purpose_id, pr.fiduciary_id, pr.app_id, pr.trigger_event, pr.status, pr.initiated_at, pr.details, pr.assigned_operator_id, pr.action, pr.claimed_record_count, pr.confirmed_by, pr.confirmed_by_type, pr.confirmed_at, pr.sla_flagged_at, pr.legal_hold_id, pr.processor_obligation_at, pr.processor_obligation_note, a.name FROM purge_requests pr LEFT JOIN apps a ON pr.app_id = a.id WHERE pr.fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        // Operators only see their own assigned queue; DPO/ADMIN see the full fiduciary list.
        if (scopeOperatorId != null) {
            sqlBuilder.append(" AND pr.assigned_operator_id = ?");
            params.add(scopeOperatorId);
        }

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND pr.status = ?");
            params.add(statusFilter);
        }
        if (appId != null) {
            // Include orphaned purge requests (no linked processor -- see
            // CESService.recordOrphanComplianceEvent) alongside this App's own, so an
            // App-scoped poller (e.g. PurgeHandler) can still see and acknowledge them
            // instead of them being invisible to every App's API key.
            sqlBuilder.append(" AND (pr.app_id = ? OR pr.app_id IS NULL)");
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
                request.put("app_name", rs.getString("name") != null ? rs.getString("name") : "No Linked Processor");
                request.put("trigger_event", rs.getString("trigger_event"));
                request.put("status", rs.getString("status"));
                request.put("initiated_at", rs.getTimestamp("initiated_at").toInstant().toString());
                request.put("details", rs.getString("details"));
                Object assignedOperatorId = rs.getObject("assigned_operator_id");
                request.put("assigned_operator_id", assignedOperatorId != null ? assignedOperatorId.toString() : null);
                request.put("action", rs.getString("action")); // ERASE or DE_IDENTIFY
                putPurgeEvidence(request, rs);
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

        String sql = "SELECT pr.id, pr.user_id, pr.fiduciary_id, pr.purpose_id, pr.app_id, pr.trigger_event, pr.status, pr.initiated_at, pr.details, pr.assigned_operator_id, pr.action, pr.claimed_record_count, pr.confirmed_by, pr.confirmed_by_type, pr.confirmed_at, pr.sla_flagged_at, pr.legal_hold_id, pr.processor_obligation_at, pr.processor_obligation_note, a.name FROM purge_requests pr LEFT JOIN apps a ON pr.app_id = a.id WHERE pr.id=?";

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
                purgeob.put("app_name", rs.getString("name") != null ? rs.getString("name") : "No Linked Processor");
                purgeob.put("trigger_event", rs.getString("trigger_event"));
                purgeob.put("status", rs.getString("status"));
                purgeob.put("initiated_at", rs.getTimestamp("initiated_at").toInstant().toString());
                purgeob.put("details", rs.getString("details"));
                Object assignedOperatorId = rs.getObject("assigned_operator_id");
                purgeob.put("assigned_operator_id", assignedOperatorId != null ? assignedOperatorId.toString() : null);
                purgeob.put("action", rs.getString("action")); // ERASE or DE_IDENTIFY
                putPurgeEvidence(purgeob, rs);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return purgeob;
    }

    /**
     * Blocks a non-ADMIN DPO/Operator from accessing purge requests for a fiduciary
     * other than their own. No-op for ADMIN or callers not authenticated as an
     * operator at all. Returns true (and sends a 403) if blocked; caller must
     * return immediately.
     */
    private boolean rejectIfNotOwnFiduciary(UUID targetFiduciaryId, UUID loginUserId, String callerRole, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        // Operators, processor API keys and principal tokens are all held to their own fiduciary
        // (an API-key caller has no role, which used to bypass this check).
        if (InputProcessor.callerOwns(req, targetFiduciaryId)) {
            return false;
        }
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You may only access purge requests for your own fiduciary.", req.getRequestURI());
        return true;
    }

    /** Looks up the fiduciary_id an operator account is bound to (null for ADMIN accounts). */
    private UUID getCallerFiduciaryId(UUID operatorId) throws SQLException {
        Connection conn = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            return getCallerFiduciaryId(conn, operatorId);
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    /** Same as above, but reuses an already-open connection. */
    private UUID getCallerFiduciaryId(Connection conn, UUID operatorId) throws SQLException {
        try (PreparedStatement pstmt = conn.prepareStatement("SELECT fiduciary_id FROM operators WHERE id = ?")) {
            pstmt.setObject(1, operatorId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return (UUID) rs.getObject("fiduciary_id");
                }
            }
        }
        return null;
    }
}