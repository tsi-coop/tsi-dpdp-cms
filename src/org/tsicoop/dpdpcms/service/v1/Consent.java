package org.tsicoop.dpdpcms.service.v1; // Package changed as requested

import org.tsicoop.dpdpcms.ces.CESUtil;
import org.tsicoop.dpdpcms.ces.CESService;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.framework.*; // Assuming these framework classes are available
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement; // For Statement.RETURN_GENERATED_KEYS
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

/**
 * ConsentRecordService class for managing Data Principal consent records.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Consent Collection, Storage,
 * Validation, and Linking modules of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'consent_records'.
 * - Columns: id (UUID PK), user_id (VARCHAR), fiduciary_id (UUID), policy_id (VARCHAR),
 * policy_version (VARCHAR), timestamp (TIMESTAMPZ), jurisdiction (VARCHAR),
 * language_selected (VARCHAR), consent_status_general (VARCHAR),
 * consent_mechanism (VARCHAR), ip_address (INET), user_agent (TEXT),
 * data_point_consents (JSONB), is_active_consent (BOOLEAN), created_at (TIMESTAMPZ),
 * last_updated_at (TIMESTAMPZ).
 * - Assumes 'fiduciaries' and 'consent_policies' tables exist for FK references.
 * - Assumes 'users' table exists for created_by_user_id etc. in audit logs.
 */
public class Consent implements Action {

    /**
     * Handles all Consent Record Management operations via a single POST endpoint.
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
        String reason = null;
        UUID appId = null;
        UUID loginUserId = null;
        String serviceType = null;
        UUID serviceId = null;


        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            String apiKey = req.getHeader("X-API-Key");
            String apiSecret = req.getHeader("X-API-Secret");
            // For Admin APIs
            loginUserId = InputProcessor.getAuthenticatedUserId(req);
            // For apps
            appId = new ApiKey().getAppId(apiKey,apiSecret);
            if(appId != null){
                serviceType = Constants.SERVICE_TYPE_APP;
                serviceId = appId;
            }
            else{
                serviceType = Constants.SERVICE_TYPE_DPO_CONSOLE;
                serviceId = loginUserId;
            }

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters for consent record operations
            String userId = (String) input.get("user_id"); // Data Principal's ID
            UUID fiduciaryId = null;
            String fiduciaryIdStr = input.get("fiduciary_id") != null ? (String) input.get("fiduciary_id") : null;
            // When called via PRINCIPAL JWT, fiduciary_id is stamped on request attributes by InterceptingFilter
            if (fiduciaryIdStr == null) {
                Object fidAttr = req.getAttribute("fiduciary_id");
                if (fidAttr != null) fiduciaryIdStr = fidAttr.toString();
            }
            // Fall back to API key lookup when fiduciary_id is still unresolved
            if (fiduciaryIdStr == null) {
                fiduciaryIdStr = new Fiduciary().getFiduciaryId(UUID.fromString(apiKey != null ? apiKey : "00000000-0000-0000-0000-000000000000"), apiSecret);
            }
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            // Security guard: when authenticated via PRINCIPAL JWT, enforce that user_id matches the token subject
            Boolean viaPrincipalJwt = (Boolean) req.getAttribute("auth_via_principal_jwt");
            if (Boolean.TRUE.equals(viaPrincipalJwt) && userId != null) {
                String principalUserId = (String) req.getAttribute("principal_user_id");
                if (!userId.equals(principalUserId)) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "User ID mismatch: token does not authorize access to the requested principal.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                case "record_consent": // Used for initial grant, update, or withdrawal
                    String policyId = (String) input.get("policy_id");
                    String policyVersion = "";
                    String timestampStr = (String) input.get("timestamp");
                    String jurisdiction = "IN";
                    String languageSelected = input.get("language_selected")!=null?(String) input.get("language_selected"):"en";
                    String consentStatusGeneral = "CONSENT_GIVEN";
                    String consentMechanism = "CONSENT_GIVEN";
                    String ipAddressStr = (String) req.getRemoteAddr();
                    String userAgent = (String) input.get("user_agent");
                    JSONArray dataPointConsents = (JSONArray) input.get("data_point_consents");
                    String verificationLogIdStr = (String) input.get("verification_log_id");
                    UUID verificationLogId = (verificationLogIdStr != null && !verificationLogIdStr.isEmpty()) ? UUID.fromString(verificationLogIdStr) : null;


                    // Basic validation
                    if (userId == null || userId.isEmpty()
                            || fiduciaryId == null
                            || policyId == null || policyId.isEmpty()
                            || dataPointConsents == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields for 'record_consent'.", req.getRequestURI());
                        return;
                    }

                    Timestamp timestamp = Timestamp.from(Instant.now());

                    // Check if policy exists (important for provenance)
                    JSONObject policy = getPolicy(policyId, policyVersion, fiduciaryId);
                    if (policy == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Referenced policy (ID: " + policyId + ", Version: " + policyVersion + ") not found or does not belong to fiduciary.", req.getRequestURI());
                        return;
                    }else{
                        // Determine consent expiry
                        JSONArray revisedDataPoints =  CESUtil.appendConsentExpiry( policy,
                                                                                    dataPointConsents,
                                                                                    Constants.ACTION_CONSENT_GIVEN);

                        output = recordConsentToDb(userId, fiduciaryId, policyId, policyVersion, timestamp, jurisdiction, languageSelected,
                                consentStatusGeneral, consentMechanism, ipAddressStr, userAgent, revisedDataPoints, appId, verificationLogId);
                        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    }
                    break;
                case "record_parent_consent":
                    handleRecordParentalVerification(input, fiduciaryId, appId, res);
                    break;
                case "get_active_consent":
                    if (userId == null || userId.isEmpty() || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' and 'fiduciary_id' are required for 'get_active_consent'.", req.getRequestURI());
                        return;
                    }
                    String activeConsentPolicyId = (String) input.get("policy_id"); // optional — scope to a specific policy
                    Optional<JSONObject> activeConsentOptional = getActiveConsentFromDb(userId, fiduciaryId, activeConsentPolicyId);
                    if (activeConsentOptional.isPresent()) {
                        output = activeConsentOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No active consent found for User ID '" + userId + "' and Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                    }
                    break;
                case "get_consent_record_details":
                    String recordId = (String) input.get("record_id");
                    Optional<JSONObject> consentOptional = getConsentFromDb(UUID.fromString(recordId));
                    if (consentOptional.isPresent()) {
                        output = consentOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No active consent found for User ID '" + userId + "' and Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                    }
                    break;

                case "list_consent_history":
                    if (userId == null || userId.isEmpty() || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' and 'fiduciary_id' are required for 'list_consent_history'.", req.getRequestURI());
                        return;
                    }
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;
                    outputArray = listConsentHistoryFromDb(userId, fiduciaryId, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "list_principals": // Recent Data Principals, shown by default on the Principals screen
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'list_principals'.", req.getRequestURI());
                        return;
                    }
                    int principalsLimit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 20;
                    outputArray = listPrincipalsFromDb(fiduciaryId, principalsLimit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "link_user": // Used to link anonymous ID to authenticated ID
                    String anonymousUserId = (String) input.get("anonymous_user_id");
                    String authenticatedUserId = (String) input.get("authenticated_user_id");
                    String ageCategory = (String) input.get("age_category");
                    String guardianId = (String) input.get("guardian_id");
                    String vStatus = (String) input.get("verification_status");

                    if (anonymousUserId == null || anonymousUserId.isEmpty() || authenticatedUserId == null || authenticatedUserId.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Both 'anonymous_user_id' and 'authenticated_user_id' are required for 'link_user'.", req.getRequestURI());
                        return;
                    }
                    if (anonymousUserId.equals(authenticatedUserId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Anonymous ID and Authenticated ID cannot be the same.", req.getRequestURI());
                        return;
                    }

                    linkUserConsentRecords(anonymousUserId, authenticatedUserId, fiduciaryId, appId, ageCategory, guardianId, vStatus);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "User consent records linked successfully."); }});
                    break;

                case "validate_consent":
                    // --- Extract Validation Parameters from Body ---
                    userId = (String) input.get("user_id");
                    String requiredPurposeId = (String) input.get("required_purpose_id");

                    if (userId == null || fiduciaryId == null || requiredPurposeId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required parameters (user_id, fiduciary_id, required_purpose_id).", req.getRequestURI());
                        break;
                    }

                    // --- Execute Validation ---
                    JSONObject result = validateConsent(userId, fiduciaryIdStr, appId, requiredPurposeId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, result);
                    break;

                case "withdraw_consent":
                    userId = (String) input.get("user_id");
                    reason = (String) input.get("reason");
                    String withdrawPolicyId = (String) input.get("policy_id"); // optional — scope to a specific policy
                    JSONArray withdrawPurposeIds = (JSONArray) input.get("purpose_ids"); // optional — scope to specific purposes

                    if (userId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required parameters (user_id, fiduciary_id) for withdrawal.", req.getRequestURI());
                        return;
                    }

                    result = withdrawConsent(userId, fiduciaryId, withdrawPolicyId, serviceType, serviceId, false, withdrawPurposeIds);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, result);
                    break;

                case "erasure_request":
                    userId = (String) input.get("user_id");
                    reason = (String) input.get("reason");
                    String erasurePolicyId = (String) input.get("policy_id"); // optional — scope to a specific policy

                    if (userId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required parameters (user_id, fiduciary_id) for withdrawal.", req.getRequestURI());
                        return;
                    }

                    result = withdrawConsent(userId, fiduciaryId, erasurePolicyId, serviceType, serviceId, true, null);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, result);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Consent.service (SQL): " + e);
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred.", req.getRequestURI());
        } catch (ParseException e) {
            System.err.println("[ERROR] Consent.service (parse): " + e);
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid request format.", req.getRequestURI());
        } catch (IllegalArgumentException e) {
            System.err.println("[ERROR] Consent.service (arg): " + e);
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid input.", req.getRequestURI());
        } catch (UnknownHostException e) {
            System.err.println("[ERROR] Consent.service (host): " + e);
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid input.", req.getRequestURI());
        } catch (Exception e) {
            System.err.println("[ERROR] Consent.service: " + e);
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An internal error occurred.", req.getRequestURI());
        }
    }

    private void handleRecordParentalVerification(JSONObject input, UUID fiduciaryId, UUID appId, HttpServletResponse res) throws SQLException {
        String childId = (String) input.get("child_principal_id");
        String guardianId = (String) input.get("guardian_principal_id");
        String mechanism = (String) input.get("verification_mechanism");
        String provider = (String) input.get("provider_name");
        String refId = (String) input.get("verification_ref_id");
        Object proofObj = input.get("proof_metadata");
        String proofMetadata = (proofObj instanceof JSONObject) ? ((JSONObject) proofObj).toJSONString() : (String) proofObj;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        UUID logId = null;

        String sql = "INSERT INTO parental_verification_logs (id, child_principal_id, guardian_principal_id, verification_mechanism, provider_name, verification_ref_id, proof_metadata, fiduciary_id) " +
                "VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?::jsonb, ?) RETURNING id";

        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, childId);
            pstmt.setString(2, guardianId);
            pstmt.setString(3, mechanism);
            pstmt.setString(4, provider);
            pstmt.setString(5, refId);
            pstmt.setString(6, proofMetadata != null ? proofMetadata : "{}");
            pstmt.setObject(7, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                logId = (UUID) rs.getObject(1);
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Consent.logEvent: " + e);
        } finally {
            pool.cleanup(rs,pstmt,conn);
        }

        if (logId != null){
            JSONObject auditContext = new JSONObject();
            auditContext.put("action", Constants.ACTION_PARENTAL_CONSENT);
            auditContext.put("principal", childId);
            auditContext.put("guardian", guardianId);
            auditContext.put("proof_metadata", proofMetadata);
            new Audit().logEventAsync(childId, fiduciaryId, Constants.SERVICE_TYPE_APP, appId , Constants.ACTION_PARENTAL_CONSENT, auditContext.toJSONString());

            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("verification_log_id", logId.toString());
            OutputProcessor.send(res, HttpServletResponse.SC_CREATED, out);
        }else{
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Parental Consent Failed","");
        }
    }

    /**
     * Implements the core consent validation logic, checking credentials, status, and granular permissions.
     * * @param userId The Data Principal's ID.
     * @param fiduciaryId The Data Fiduciary ID owning the record.
     * @param requiredPurposeId The specific purpose ID being checked.
     * @return JSONObject containing the validation result (success: boolean, consent_granted: boolean).
     * @throws SQLException
     */
    private JSONObject validateConsent(String userId, String fiduciaryId, UUID appId, String requiredPurposeId) throws Exception {

        JSONObject result = new JSONObject();
        result.put("success", false);
        result.put("consent_granted", false);
        Connection conn = null;
        PoolDB pool = new PoolDB();
        Boolean granted = null;

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // --- STEP 3: RETRIEVE ACTIVE CONSENT RECORD ---
                String capturedPolicyId = null;
                String capturedPolicyVersion = null;
                String sqlConsent = "SELECT data_point_consents, is_active_consent, created_at, policy_id, policy_version FROM consent_records " +
                    "WHERE user_id = ? AND fiduciary_id = ? " +
                    "ORDER BY created_at DESC LIMIT 1";

                try (PreparedStatement pstmt = conn.prepareStatement(sqlConsent)) {
                    pstmt.setString(1, userId);
                    pstmt.setObject(2, UUID.fromString(fiduciaryId)); // Cast string to UUID for DB

                    try (ResultSet rs = pstmt.executeQuery()) {
                        if (!rs.next()) {
                            result.put("message", "No active consent record found for this principal.");
                            return result;
                        }

                        // --- STEP 4: CHECK GRANULAR CONSENT ---

                        boolean active= rs.getBoolean("is_active_consent");
                        String consentsJson = rs.getString("data_point_consents");
                        capturedPolicyId = rs.getString("policy_id");
                        capturedPolicyVersion = rs.getString("policy_version");

                        if (!active) {
                            result.put("message", "Consent record exists but is INACTIVE/REVOKED.");
                            return result;
                        }

                        // Parse the JSONB data point consents
                        JSONParser parser = new JSONParser();
                        JSONArray granularConsents = (JSONArray) parser.parse(consentsJson);
                        Iterator<JSONObject> it = granularConsents.iterator();
                        JSONObject consent = null;
                        String purposeId = null;
                        String expiryStr = null;
                        Instant expiryinstant = null;
                        Timestamp expiry = null;
                        Timestamp now = null;

                        while(it.hasNext()) {
                            consent = (JSONObject) it.next();
                            // Check if the specific required purpose ID is present and set to TRUE
                            purposeId = (String)consent.get("data_point_id");
                            expiryStr = (String)consent.get("consent_expiry");
                            if(expiryStr!=null) {
                                expiryinstant = Instant.parse(expiryStr);
                                expiry = Timestamp.from(expiryinstant);
                            }
                            now = Timestamp.from(Instant.now());
                            if(purposeId.equalsIgnoreCase(requiredPurposeId)) {
                                granted = (Boolean) consent.get("consent_granted");
                                if(expiry!=null && now.after(expiry)){
                                    //System.out.println("Consent Expired");
                                    granted = false;
                                }
                                if (granted != null && granted) break;
                            }
                        }

                        if (Boolean.TRUE.equals(granted)) {
                            result.put("success", true);
                            result.put("consent_granted", true);
                            result.put("message", "Consent granted for purpose: " + requiredPurposeId);

                            logConsentValidations(conn, UUID.fromString(fiduciaryId), appId, userId, requiredPurposeId, "VALID");
                            flagCES(conn, UUID.fromString(fiduciaryId), userId); // do a sanity run
                        }
                    }
                conn.commit();
            }
        } catch (Exception e) {
            // Log detailed SQL error internally
            System.err.println("SQL Error in validateConsent: " + e.getMessage());
            result.put("message", "Internal error during database lookup.");
            throw e;
        } finally {
            pool.cleanup(null,null,conn);
        }

        JSONObject auditContext = new JSONObject();
        auditContext.put("action", Constants.ACTION_CONSENT_VALIDATION);
        auditContext.put("principal", userId);
        auditContext.put("purpose", requiredPurposeId);
        if (granted != null && granted) {
            auditContext.put("status", Constants.VALIDATION_SUCCESS);
            new Audit().logEventAsync(userId, UUID.fromString(fiduciaryId), Constants.SERVICE_TYPE_APP, appId , "CONSENT_VALIDATED", auditContext.toJSONString());
        } else {
            auditContext.put("status", Constants.VALIDATION_FAILED);
            new Audit().logEventAsync(userId, UUID.fromString(fiduciaryId), Constants.SERVICE_TYPE_APP, appId , "CONSENT_DENIED", auditContext.toJSONString());
        }
        return result;
    }

    /**
     * Registers/refreshes the data_principal record for a user so the CES batch job
     * (which enumerates principals from this table) picks them up on its next run.
     * Resetting last_ces_run to NULL forces a fresh evaluation of the latest consent action.
     */
    private void upsertDataPrincipal(Connection conn, UUID fiduciaryId, String userId, String lastConsentMechanism) throws SQLException {
        String sql = "INSERT INTO data_principal (user_id, fiduciary_id, last_consent_mechanism, last_ces_run) " +
                "VALUES (?, ?, ?, NULL) " +
                "ON CONFLICT (user_id, fiduciary_id) DO UPDATE SET " +
                "last_consent_mechanism = EXCLUDED.last_consent_mechanism, last_ces_run = NULL";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, userId);
            stmt.setObject(2, fiduciaryId);
            stmt.setString(3, lastConsentMechanism);
            stmt.executeUpdate();
        }
    }

    private void logConsentValidations(Connection conn, UUID fiduciaryId, UUID appId, String userId, String purpose_id, String status) throws SQLException{
        // Upsert Data Principal Record
        String upsertDataPrincipalSql = "INSERT INTO consent_validations (fiduciary_id,app_id,user_id,purpose_id,status) VALUES (?,?,?,?,?)";
        PreparedStatement stmt = conn.prepareStatement(upsertDataPrincipalSql);
        stmt.setObject(1, fiduciaryId);
        stmt.setObject(2, appId);
        stmt.setString(3, userId);
        stmt.setObject(4, purpose_id);
        stmt.setObject(5, status);
        stmt.executeUpdate();
    }

    private void flagCES(Connection conn, UUID fiduciaryId, String userId) throws SQLException{
        // Upsert Data Principal Record
        String upsertDataPrincipalSql = "update data_principal set last_ces_run=null where fiduciary_id=? and user_id=?";
        PreparedStatement stmt = conn.prepareStatement(upsertDataPrincipalSql);
        stmt.setObject(1, fiduciaryId);
        stmt.setString(2, userId);
        stmt.executeUpdate();
    }

    /**
     * Implements the core logic for Data Principal withdrawal of consent.
     * 1. Deactivates the currently active consent record.
     * 2. Creates a new record with all non-mandatory purposes set to DENIED (false).
     * 3. Triggers downstream purge instructions.
     *
     * @param userId The Data Principal's ID.
     * @param fiduciaryId The Data Fiduciary ID.
     * @return JSONObject indicating success.
     * @throws SQLException
     */
    private JSONObject withdrawConsent(String userId, UUID fiduciaryId, String scopedPolicyId,
                                       String serviceType, UUID serviceId, boolean erasure, JSONArray purposeIds) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String action = Constants.ACTION_CONSENT_WITHDRAWN;
        JSONObject result = null;

        if(erasure)
            action = Constants.ACTION_ERASURE_REQUEST;

        // --- 1. Find the most-recent consent record, optionally scoped to a specific policy ---
        String sqlSelectActive;
        if (scopedPolicyId != null && !scopedPolicyId.isEmpty()) {
            sqlSelectActive = "SELECT id, policy_id, policy_version, data_point_consents FROM consent_records " +
                    "WHERE user_id = ? AND fiduciary_id = ? AND policy_id = ? ORDER BY timestamp DESC LIMIT 1";
        } else {
            sqlSelectActive = "SELECT id, policy_id, policy_version, data_point_consents FROM consent_records " +
                    "WHERE user_id = ? AND fiduciary_id = ? ORDER BY timestamp DESC LIMIT 1";
        }

        UUID oldRecordId = null;
        JSONArray currentConsents = null;
        String policyId = null;
        String policyVersion = null;

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // A. Select current active record details
            pstmt = conn.prepareStatement(sqlSelectActive);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            if (scopedPolicyId != null && !scopedPolicyId.isEmpty()) {
                pstmt.setString(3, scopedPolicyId);
            }
            rs = pstmt.executeQuery();

            if (!rs.next()) {
                conn.rollback();
                return new JSONObject() {{ put("success", false); put("message", "No consent record found for withdrawal."); }};
            }

            oldRecordId = UUID.fromString(rs.getString("id"));
            policyId = rs.getString("policy_id");
            policyVersion = rs.getString("policy_version");
            // Cast JSONB string back to JSONObject
            currentConsents = (JSONArray) new JSONParser().parse(rs.getString("data_point_consents"));

            // --- 2. Deactivate Old Record ---
            String sqlDeactivate = "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE id = ?";
            pstmt.close();
            pstmt = conn.prepareStatement(sqlDeactivate);
            pstmt.setObject(1, oldRecordId);
            pstmt.executeUpdate();

            // --- 3. Determine New (Denied) Consents ---

            boolean partialWithdrawal = !erasure && purposeIds != null && !purposeIds.isEmpty();
            boolean newIsActive;

            JSONObject policy = getPolicy(policyId, policyVersion, fiduciaryId);

            if (partialWithdrawal) {
                // Partial withdrawal: only withdraw the specified purposes.
                // appendConsentExpiry forces consent_granted=false on every entry when called with
                // ACTION_CONSENT_WITHDRAWN, so we must split the array, process each half with the
                // correct action, then merge — otherwise all purposes get wiped.
                java.util.Set<String> toWithdraw = new java.util.HashSet<>();
                for (Object pid : purposeIds) toWithdraw.add(pid.toString());

                JSONArray withdrawGroup = new JSONArray();
                JSONArray keepGroup    = new JSONArray();
                for (Object obj : currentConsents) {
                    JSONObject dp = (JSONObject) obj;
                    if (toWithdraw.contains((String) dp.get("data_point_id"))) {
                        withdrawGroup.add(dp);
                    } else {
                        keepGroup.add(dp);
                    }
                }

                if (policy != null) {
                    withdrawGroup = CESUtil.appendConsentExpiry(policy, withdrawGroup, action);
                    keepGroup     = CESUtil.appendConsentExpiry(policy, keepGroup, Constants.ACTION_CONSENT_GIVEN);
                }

                currentConsents = new JSONArray();
                currentConsents.addAll(withdrawGroup);
                currentConsents.addAll(keepGroup);
                newIsActive = true;
            } else {
                // Full withdrawal / erasure: all purposes denied, record becomes inactive.
                if (policy != null) {
                    currentConsents = CESUtil.appendConsentExpiry(policy, currentConsents, action);
                }
                newIsActive = false;
            }

            // --- 4. Insert New WITHDRAWN Record (Immutability/Provenance) ---
            UUID ropaEntryId = resolveRopaEntryId(conn, fiduciaryId, policyId);
            String sqlInsertNew = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, consent_status_general, consent_mechanism, data_point_consents, is_active_consent, created_at,language_selected,ip_address,ropa_entry_id) " +
                    "VALUES (uuid_generate_v4(), ?, ?, ?, ?, NOW(), 'IN', ?, ?, ?::jsonb, ?, NOW(), 'en', '[0:0:0:0:0:0:0:1]', ?) RETURNING id";

            pstmt.close();
            pstmt = conn.prepareStatement(sqlInsertNew, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setString(3, policyId);
            pstmt.setString(4, policyVersion);
            pstmt.setString(5, action);
            pstmt.setString(6, action);
            pstmt.setString(7, currentConsents.toJSONString());
            pstmt.setBoolean(8, newIsActive);
            pstmt.setObject(9, ropaEntryId);

            if (pstmt.executeUpdate() == 0) {
                throw new SQLException("Creating withdrawal record failed.");
            }

            // Register/refresh the data_principal record so the CES batch job picks this principal up
            // (resets last_ces_run to NULL, ensuring the new WITHDRAWN/ERASURE_REQUEST record is evaluated)
            upsertDataPrincipal(conn, fiduciaryId, userId, action);

            UUID newRecordId = null;
            try (ResultSet newRs = pstmt.getGeneratedKeys()) {
                if (newRs.next()) {
                    newRecordId = (UUID) newRs.getObject(1);
                }
            }

            // --- 5. Commit Transaction ---
            conn.commit();

            UUID finalNewRecordId = newRecordId;
            result =  new JSONObject();
            result.put("success", true);
            if(erasure)
                result.put("message", "Erasure initiated successfully.");
            else
                result.put("message", "Consent successfully withdrawn and recorded.");
            result.put("record_id", finalNewRecordId.toString());
            result.put("action", action);

            try {
                String notifType = erasure ? Constants.NOTIF_ERASURE_REQUESTED : Constants.NOTIF_WITHDRAWAL_ACK;
                new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), notifType);
            } catch (SQLException e) {
                e.printStackTrace(); // Notification failure must not fail the withdrawal/erasure operation
            }
        } catch (Exception e) {
            if (conn != null) conn.rollback();
            System.err.println("SQL Error during withdrawal: " + e.getMessage());
            return new JSONObject() {{
                put("success", false);
                put("message", e.getMessage());
            }};
        } finally {
            if (conn != null) conn.setAutoCommit(true);
            pool.cleanup(null, null, conn);
        }

        // --- log audit event
        if(erasure){
            new Audit().logEventAsync(userId, fiduciaryId, serviceType, serviceId , Constants.ACTION_ERASURE_REQUEST, currentConsents.toJSONString());
        }else{
            new Audit().logEventAsync(userId, fiduciaryId, serviceType, serviceId , Constants.ACTION_CONSENT_WITHDRAWN, currentConsents.toJSONString());
        }
        return result;
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Consent Record Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Consent Record Management ---

    /**
     * Checks if a specific policy version exists for a fiduciary.
     * (Ideally, this would be an API call to PolicyService in a microservices 5)
     */
    private JSONObject  getPolicy(String policyId, String version, UUID fiduciaryId) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        JSONObject retval = null;
        String sql = "SELECT policy_content FROM consent_policies WHERE id = ? AND version = ? AND fiduciary_id = ? AND status = 'ACTIVE'";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            pstmt.setObject(3, fiduciaryId);
            rs = pstmt.executeQuery();
            if(rs.next()){
                retval = (JSONObject) new JSONParser().parse(rs.getString("policy_content"));
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return retval;
    }

    /**
     * Records a new consent decision or updates an existing one by deactivating old and inserting new.
     * This ensures consent provenance.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject recordConsentToDb(String userId, UUID fiduciaryId, String policyId, String policyVersion,
                                         Timestamp timestamp, String jurisdiction, String languageSelected,
                                         String consentStatusGeneral, String consentMechanism,
                                         String ipAddress, String userAgent, JSONArray dataPointConsents,
                                         UUID appId, UUID verificationLogId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmtDeactivate = null;
        PreparedStatement pstmtInsert = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        boolean recorded = false;

        String deactivateSql = "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE user_id = ? AND fiduciary_id = ? AND is_active_consent = TRUE";
        String insertSql = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, user_agent, data_point_consents, is_active_consent, created_at, last_updated_at, verification_log_id, ropa_entry_id) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, TRUE, NOW(), NOW(), ?, ?) RETURNING id";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // 1. Deactivate previous active consent for this user and fiduciary
            pstmtDeactivate = conn.prepareStatement(deactivateSql);
            pstmtDeactivate.setString(1, userId);
            pstmtDeactivate.setObject(2, fiduciaryId);
            pstmtDeactivate.executeUpdate();

            // 2. Insert the NEW consent record — hash IP before storage
            String storedIp = ipAddress;
            try {
                storedIp = new LookupHasher().hashData(ipAddress != null ? ipAddress : "0.0.0.0");
            } catch (Exception ignored) {
                // TSI_LOOKUP_SALT not set or SHA-256 unavailable — store original
            }

            UUID ropaEntryId = resolveRopaEntryId(conn, fiduciaryId, policyId);
            pstmtInsert = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS);
            pstmtInsert.setString(1, userId);
            pstmtInsert.setObject(2, fiduciaryId);
            pstmtInsert.setString(3, policyId);
            pstmtInsert.setString(4, policyVersion);
            pstmtInsert.setTimestamp(5, timestamp);
            pstmtInsert.setString(6, jurisdiction);
            pstmtInsert.setString(7, languageSelected);
            pstmtInsert.setString(8, consentStatusGeneral);
            pstmtInsert.setString(9, consentMechanism);
            pstmtInsert.setString(10, storedIp);
            pstmtInsert.setString(11, userAgent);
            pstmtInsert.setString(12, dataPointConsents.toJSONString());
            pstmtInsert.setObject(13, verificationLogId);
            pstmtInsert.setObject(14, ropaEntryId);

            int affectedRows = pstmtInsert.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Recording consent failed, no rows affected.");
            }

            // Register/refresh the data_principal record so the CES batch job picks this principal up
            upsertDataPrincipal(conn, fiduciaryId, userId, consentMechanism);

            rs = pstmtInsert.getGeneratedKeys();
            UUID newConsentId;
            if (rs.next()) {
                newConsentId = UUID.fromString(rs.getString(1));
                output.put("consent_record_id", newConsentId.toString());
                output.put("user_id", userId);
                output.put("sync_token", JWTUtil.generateSyncToken(userId, fiduciaryId.toString()));
                output.put("message", "Consent recorded successfully.");
            } else {
                throw new SQLException("Recording consent failed, no ID obtained.");
            }

            conn.commit(); // Commit transaction

            recorded = true;
        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            throw e;
        } finally {
            pool.cleanup(rs, pstmtInsert, null); // Cleanup rs and pstmtInsert
            pool.cleanup(null, pstmtDeactivate, conn); // Cleanup pstmtDeactivate and conn
        }

        if(recorded){
            // Audit Log: Log the consent record event
            JSONObject auditContext = new JSONObject();
            auditContext.put("policy_id", policyId);
            auditContext.put("policy_version", policyVersion);
            auditContext.put("data_point_consents", dataPointConsents);
            new Audit().logEventAsync(userId, fiduciaryId, "APP", appId , "CONSENT_GIVEN", auditContext.toJSONString());
            try {
                new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), Constants.NOTIF_CONSENT_GIVEN);
            } catch (SQLException e) {
                e.printStackTrace(); // Notification failure must not fail the consent operation
            }
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Retrieves the active consent record for a given user and fiduciary.
     * @return An Optional containing the consent record JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private UUID resolveRopaEntryId(Connection conn, UUID fiduciaryId, String policyId) {
        String sql = "SELECT id FROM ropa_entries WHERE fiduciary_id = ? AND linked_policy_ids @> ?::jsonb AND status = 'active' LIMIT 1";
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, "[\"" + policyId + "\"]");
            rs = pstmt.executeQuery();
            return rs.next() ? (UUID) rs.getObject(1) : null;
        } catch (Exception e) {
            return null;
        } finally {
            try { if (rs != null) rs.close(); } catch (Exception ignored) {}
            try { if (pstmt != null) pstmt.close(); } catch (Exception ignored) {}
        }
    }

    private Optional<JSONObject> getActiveConsentFromDb(String userId, UUID fiduciaryId, String policyId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, user_agent, data_point_consents, is_active_consent FROM consent_records WHERE user_id = ? AND fiduciary_id = ? AND is_active_consent = TRUE";
        if (policyId != null && !policyId.isEmpty()) {
            sql += " AND policy_id = ?";
        }
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            if (policyId != null && !policyId.isEmpty()) {
                pstmt.setString(3, policyId);
            }
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject consent = new JSONObject();
                consent.put("id", rs.getString("id"));
                consent.put("user_id", rs.getString("user_id"));
                consent.put("fiduciary_id", rs.getString("fiduciary_id"));
                consent.put("policy_id", rs.getString("policy_id"));
                consent.put("policy_version", rs.getString("policy_version"));
                consent.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                consent.put("jurisdiction", rs.getString("jurisdiction"));
                consent.put("language_selected", rs.getString("language_selected"));
                consent.put("consent_status_general", rs.getString("consent_status_general"));
                consent.put("consent_mechanism", rs.getString("consent_mechanism"));
                consent.put("ip_address", rs.getString("ip_address")); // INET is read as String
                consent.put("user_agent", rs.getString("user_agent"));
                consent.put("data_point_consents", new JSONParser().parse(rs.getString("data_point_consents"))); // Parse JSONB
                consent.put("is_active_consent", rs.getBoolean("is_active_consent"));
                return Optional.of(consent);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse data_point_consents JSON from DB: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Retrieves the active consent record for a given user and fiduciary.
     * @return An Optional containing the consent record JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getConsentFromDb(UUID recordId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT cr.id, cr.user_id, cr.fiduciary_id, cr.policy_id, cr.policy_version, cr.timestamp, " +
                "cr.jurisdiction, cr.language_selected, cr.consent_status_general, cr.consent_mechanism, " +
                "cr.ip_address, cr.user_agent, cr.data_point_consents, cr.is_active_consent, " +
                "cr.ropa_entry_id, re.activity_name AS ropa_activity_name " +
                "FROM consent_records cr " +
                "LEFT JOIN ropa_entries re ON re.id = cr.ropa_entry_id " +
                "WHERE cr.id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, recordId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject consent = new JSONObject();
                consent.put("id", rs.getString("id"));
                consent.put("user_id", rs.getString("user_id"));
                consent.put("fiduciary_id", rs.getString("fiduciary_id"));
                consent.put("policy_id", rs.getString("policy_id"));
                consent.put("policy_version", rs.getString("policy_version"));
                consent.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                consent.put("jurisdiction", rs.getString("jurisdiction"));
                consent.put("language_selected", rs.getString("language_selected"));
                consent.put("consent_status_general", rs.getString("consent_status_general"));
                consent.put("consent_mechanism", rs.getString("consent_mechanism"));
                consent.put("ip_address", rs.getString("ip_address")); // INET is read as String
                consent.put("user_agent", rs.getString("user_agent"));
                consent.put("data_point_consents", new JSONParser().parse(rs.getString("data_point_consents"))); // Parse JSONB
                consent.put("is_active_consent", rs.getBoolean("is_active_consent"));
                Object ropaId = rs.getObject("ropa_entry_id");
                consent.put("ropa_entry_id", ropaId != null ? ropaId.toString() : null);
                consent.put("ropa_activity_name", rs.getString("ropa_activity_name"));
                return Optional.of(consent);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse data_point_consents JSON from DB: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }


    /**
     * Retrieves a list of consent records for a given user and fiduciary (history).
     * @return JSONArray of consent record JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listConsentHistoryFromDb(String userId, UUID fiduciaryId, int page, int limit) throws SQLException {
        JSONArray historyArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, user_agent, data_point_consents, is_active_consent FROM consent_records WHERE user_id = ? AND fiduciary_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        List<Object> params = new ArrayList<>();
        params.add(userId);
        params.add(fiduciaryId);
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
                JSONObject consent = new JSONObject();
                consent.put("id", rs.getString("id"));
                consent.put("user_id", rs.getString("user_id"));
                consent.put("fiduciary_id", rs.getString("fiduciary_id"));
                consent.put("policy_id", rs.getString("policy_id"));
                consent.put("policy_version", rs.getString("policy_version"));
                consent.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                consent.put("jurisdiction", rs.getString("jurisdiction"));
                consent.put("language_selected", rs.getString("language_selected"));
                consent.put("consent_status_general", rs.getString("consent_status_general"));
                consent.put("consent_mechanism", rs.getString("consent_mechanism"));
                consent.put("ip_address", rs.getString("ip_address"));
                consent.put("user_agent", rs.getString("user_agent"));
                consent.put("data_point_consents", new JSONParser().parse(rs.getString("data_point_consents")));
                consent.put("is_active_consent", rs.getBoolean("is_active_consent"));
                consent.put("sync_token", JWTUtil.generateSyncToken(rs.getString("user_id"), rs.getString("fiduciary_id")));
                historyArray.add(consent);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse data_point_consents JSON from DB: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return historyArray;
    }

    /**
     * Retrieves the most recently onboarded Data Principals for a fiduciary, shown by
     * default on the Principals screen before a DPO searches for a specific one.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listPrincipalsFromDb(UUID fiduciaryId, int limit) throws SQLException {
        JSONArray principalsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "SELECT user_id, last_consent_mechanism, age_category, verification_status, created_at, last_ces_run " +
                "FROM data_principal WHERE fiduciary_id = ? ORDER BY created_at DESC LIMIT ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setInt(2, limit);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject principal = new JSONObject();
                principal.put("user_id", rs.getString("user_id"));
                principal.put("last_consent_mechanism", rs.getString("last_consent_mechanism"));
                principal.put("age_category", rs.getString("age_category"));
                principal.put("verification_status", rs.getString("verification_status"));
                principal.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                principal.put("last_ces_run", rs.getTimestamp("last_ces_run") != null ? rs.getTimestamp("last_ces_run").toInstant().toString() : null);
                principalsArray.add(principal);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return principalsArray;
    }

    /**
     * Links anonymous user consent records to an authenticated Data Principal ID.
     * This operation is transactional.
     * @throws SQLException if a database access error occurs.
     */
    private void linkUserConsentRecords(String anonymousUserId, String authenticatedUserId, UUID fiduciaryId, UUID appId,
                                        String ageCategory, String guardianId, String verificationStatus) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtUpdateConsent = null;
        PreparedStatement pstmtDeactivate = null;
        PoolDB pool = new PoolDB();
        String deactivateSql = "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE user_id = ? AND fiduciary_id = ? AND is_active_consent = TRUE";
        String effectiveAge = (ageCategory != null) ? ageCategory : "ADULT";
        String effectiveVStatus = (verificationStatus != null) ? verificationStatus : "NOT_VERIFIED";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // Deactivate previous active consent for this authenticated user and fiduciary (if any)
            pstmtDeactivate = conn.prepareStatement(deactivateSql);
            pstmtDeactivate.setString(1, authenticatedUserId);
            pstmtDeactivate.setObject(2, fiduciaryId);
            pstmtDeactivate.executeUpdate();

            // Update Consent Record
            String updateConsentSql = "UPDATE consent_records SET user_id = ?, last_updated_at = NOW() WHERE user_id = ?";
            pstmtUpdateConsent = conn.prepareStatement(updateConsentSql);
            pstmtUpdateConsent.setString(1, authenticatedUserId);
            pstmtUpdateConsent.setString(2, anonymousUserId);
            pstmtUpdateConsent.executeUpdate();

            // 3. Upsert Data Principal with Minor Metadata
            String upsertSql = "INSERT INTO data_principal (user_id, fiduciary_id, age_category, guardian_id, verification_status) " +
                    "VALUES (?, ?, ?, ?, ?) " +
                    "ON CONFLICT (user_id, fiduciary_id) DO UPDATE SET " +
                    "age_category = EXCLUDED.age_category, guardian_id = EXCLUDED.guardian_id, verification_status = EXCLUDED.verification_status";

            try (PreparedStatement pstmt = conn.prepareStatement(upsertSql)) {
                pstmt.setString(1, authenticatedUserId);
                pstmt.setObject(2, fiduciaryId);
                pstmt.setString(3, effectiveAge);
                pstmt.setString(4, guardianId);
                pstmt.setString(5, effectiveVStatus);
                pstmt.executeUpdate();
            }

            conn.commit(); // Commit transaction
        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            throw e;
        } finally {
            pool.cleanup(null, pstmtUpdateConsent, conn);
        }

        // Audit Log: Log the link user event
        JSONObject auditContext = new JSONObject();
        auditContext.put("action", Constants.ACTION_LINK_USER);
        auditContext.put("anonymous_id", anonymousUserId);
        auditContext.put("principal", authenticatedUserId);
        new Audit().logEventAsync(authenticatedUserId, fiduciaryId, Constants.SERVICE_TYPE_APP, appId , Constants.ACTION_LINK_USER, auditContext.toJSONString());
    }

    // --- Processor authorization helpers ---

    private String getAppNameForAuth(UUID appId) {
        if (appId == null) return null;
        String sql = "SELECT name FROM apps WHERE id = ?";
        PoolDB pool = null;
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getString("name") : null;
        } catch (Exception e) {
            return null; // fail-open
        } finally {
            if (pool != null) try { pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    private JSONObject getPolicyContentByVersion(String policyId, String version, UUID fiduciaryId) {
        if (policyId == null || version == null) return null;
        String sql = "SELECT policy_content FROM consent_policies WHERE id = ? AND version = ? AND fiduciary_id = ?";
        PoolDB pool = null;
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            pstmt.setObject(3, fiduciaryId);
            rs = pstmt.executeQuery();
            if (!rs.next()) return null;
            return (JSONObject) new JSONParser().parse(rs.getString("policy_content"));
        } catch (Exception e) {
            return null; // fail-open
        } finally {
            if (pool != null) try { pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    @SuppressWarnings("unchecked")
    private boolean isProcessorAuthorized(String appName, String purposeId, JSONObject policyContent) {
        try {
            String lang = (String) policyContent.keySet().iterator().next();
            JSONObject block = (JSONObject) policyContent.get(lang);
            if (block == null) return true;
            JSONArray purposes = (JSONArray) block.get("data_processing_purposes");
            if (purposes == null) return true;
            for (Object o : purposes) {
                JSONObject p = (JSONObject) o;
                if (!purposeId.equalsIgnoreCase((String) p.get("id"))) continue;
                Object rtp = p.get("recipients_or_third_parties");
                if (!(rtp instanceof JSONArray) || ((JSONArray) rtp).isEmpty()) return true;
                for (Object r : (JSONArray) rtp) {
                    if (r != null && appName.equalsIgnoreCase(r.toString())) return true;
                }
                return false; // rtp is non-empty and appName not found
            }
        } catch (Exception ignored) {}
        return true; // purpose not found or parse error — fail-open
    }
}
