package org.tsicoop.dpdpcms.service.v1; // Package changed as requested

import org.tsicoop.dpdpcms.ces.CESUtil;
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
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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

        // Placeholder for current user ID (in a real system, this would come from authentication context)
        // For consent records, the 'actor' is often the Data Principal or the system acting on their behalf.
        // For audit logs, it would be the CMS user who initiated an action.
        UUID currentCmsUserId = null; // Assume null for Data Principal initiated actions, or get from session if CMS user
        // Example: If a DPO manually updates consent, currentCmsUserId would be DPO's ID.

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            String apiKey = req.getHeader("X-API-Key");
            String apiSecret = req.getHeader("X-API-Secret");
            appId = new ApiKey().getAppId(apiKey,apiSecret);

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters for consent record operations
            String userId = (String) input.get("user_id"); // Data Principal's ID
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
                    Optional<JSONObject> activeConsentOptional = getActiveConsentFromDb(userId, fiduciaryId);
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
                    // --- Extract Withdrawal Parameters ---
                    userId = (String) input.get("user_id");
                    reason = (String) input.get("reason");

                    if (userId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required parameters (user_id, fiduciary_id) for withdrawal.", req.getRequestURI());
                        return;
                    }

                    result = withdrawConsent(userId, fiduciaryId, appId, reason, false);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, result);

                    break;
                case "erasure_request":
                    // --- Extract Withdrawal Parameters ---
                    userId = (String) input.get("user_id");
                    reason = (String) input.get("reason");

                    if (userId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required parameters (user_id, fiduciary_id) for withdrawal.", req.getRequestURI());
                        return;
                    }

                    result = withdrawConsent(userId, fiduciaryId, appId, reason, true);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, result);
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
        } catch (UnknownHostException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid IP address format: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
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
        } catch(Exception e){
            e.printStackTrace();
        }
        finally {
            pool.cleanup(rs,pstmt,conn);
        }

        if (logId != null){
            JSONObject auditContext = new JSONObject();
            auditContext.put("action", Constants.ACTION_PARENTAL_CONSENT);
            auditContext.put("principal", childId);
            auditContext.put("guardian", guardianId);
            auditContext.put("proof_metadata", proofMetadata);
            new Audit().logEventAsync(childId, fiduciaryId, "APP", appId , Constants.ACTION_PARENTAL_CONSENT, auditContext.toJSONString());

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
                String sqlConsent = "SELECT data_point_consents, is_active_consent, created_at FROM consent_records " +
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

                        if (granted != null && granted) {
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
            new Audit().logEventAsync(userId, UUID.fromString(fiduciaryId), "APP", appId , "CONSENT_VALIDATED", auditContext.toJSONString());
        } else {
            auditContext.put("status", Constants.VALIDATION_FAILED);
            new Audit().logEventAsync(userId, UUID.fromString(fiduciaryId), "APP", appId , "CONSENT_DENIED", auditContext.toJSONString());
        }
        return result;
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
     * @param reason The reason for withdrawal (optional).
     * @return JSONObject indicating success.
     * @throws SQLException
     */
    private JSONObject withdrawConsent(String userId, UUID fiduciaryId, UUID appId, String reason, boolean erasure) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String action = Constants.ACTION_CONSENT_WITHDRAWN;
        JSONObject result = null;

        if(erasure)
            action = Constants.ACTION_ERASURE_REQUEST;

        // --- 1. Find the current ACTIVE record and Policy context ---
        // This query also ensures the user exists and has a record.
        String sqlSelectActive = "SELECT id, policy_id, policy_version, data_point_consents FROM consent_records " +
                "WHERE user_id = ? AND fiduciary_id = ? ORDER BY timestamp DESC LIMIT 1";

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

            // Check if policy exists (important for provenance)
            JSONObject policy = getPolicy(policyId, policyVersion, fiduciaryId);
            if (policy != null) {
                // Determine consent expiry
                currentConsents = CESUtil.appendConsentExpiry(          policy,
                                                                        currentConsents,
                                                                        action);
            }

            // --- 4. Insert New WITHDRAWN Record (Immutability/Provenance) ---
            String sqlInsertNew = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, consent_status_general, consent_mechanism, data_point_consents, is_active_consent, created_at,language_selected,ip_address) " +
                    "VALUES (uuid_generate_v4(), ?, ?, ?, ?, NOW(), 'IN', ?, ?, ?::jsonb, FALSE, NOW(), 'en', '[0:0:0:0:0:0:0:1]') RETURNING id";

            pstmt.close();
            pstmt = conn.prepareStatement(sqlInsertNew, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setString(3, policyId);
            pstmt.setString(4, policyVersion);
            pstmt.setString(5, action);
            pstmt.setString(6, action);
            pstmt.setString(7, currentConsents.toJSONString());

            if (pstmt.executeUpdate() == 0) {
                throw new SQLException("Creating withdrawal record failed.");
            }

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
            new Audit().logEventAsync(userId, fiduciaryId, "APP", appId , Constants.ACTION_ERASURE_REQUEST, currentConsents.toJSONString());
        }else{
            new Audit().logEventAsync(userId, fiduciaryId, "APP", appId , Constants.ACTION_CONSENT_WITHDRAWN, currentConsents.toJSONString());
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
        String sql = "SELECT policy_content FROM consent_policies WHERE id = ? AND version = ? AND fiduciary_id = ?";
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
        String insertSql = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, user_agent, data_point_consents, is_active_consent, created_at, last_updated_at, verification_log_id) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, TRUE, NOW(), NOW(),?) RETURNING id";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // 1. Deactivate previous active consent for this user and fiduciary
            pstmtDeactivate = conn.prepareStatement(deactivateSql);
            pstmtDeactivate.setString(1, userId);
            pstmtDeactivate.setObject(2, fiduciaryId);
            pstmtDeactivate.executeUpdate();

            // 2. Insert the NEW consent record
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
            pstmtInsert.setString(10, ipAddress);
            pstmtInsert.setString(11, userAgent);
            pstmtInsert.setString(12, dataPointConsents.toJSONString());
            pstmtInsert.setObject(13, verificationLogId);

            int affectedRows = pstmtInsert.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Recording consent failed, no rows affected.");
            }

            rs = pstmtInsert.getGeneratedKeys();
            UUID newConsentId;
            if (rs.next()) {
                newConsentId = UUID.fromString(rs.getString(1));
                output.put("consent_record_id", newConsentId.toString());
                output.put("user_id", userId);
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
            new Audit().logEventAsync(userId, fiduciaryId, "APP", appId , "CONSENT_GIVEN", dataPointConsents.toJSONString());
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Retrieves the active consent record for a given user and fiduciary.
     * @return An Optional containing the consent record JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getActiveConsentFromDb(String userId, UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, user_agent, data_point_consents, is_active_consent FROM consent_records WHERE user_id = ? AND fiduciary_id = ? AND is_active_consent = TRUE";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
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
        String sql = "SELECT id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, user_agent, data_point_consents, is_active_consent FROM consent_records WHERE id = ?";
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
                    "ON CONFLICT (user_id) DO UPDATE SET " +
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
        new Audit().logEventAsync(authenticatedUserId, fiduciaryId, "APP", appId , Constants.ACTION_LINK_USER, auditContext.toJSONString());
    }
}
