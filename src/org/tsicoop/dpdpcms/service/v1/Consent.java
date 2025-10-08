package org.tsicoop.dpdpcms.service.v1; // Package changed as requested

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
import java.net.InetAddress; // For INET type
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

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

        // Placeholder for current user ID (in a real system, this would come from authentication context)
        // For consent records, the 'actor' is often the Data Principal or the system acting on their behalf.
        // For audit logs, it would be the CMS user who initiated an action.
        UUID currentCmsUserId = null; // Assume null for Data Principal initiated actions, or get from session if CMS user
        // Example: If a DPO manually updates consent, currentCmsUserId would be DPO's ID.

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters for consent record operations
            String userId = (String) input.get("user_id"); // Data Principal's ID
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
                case "record_consent": // Used for initial grant, update, or withdrawal
                    String policyId = (String) input.get("policy_id");
                    String policyVersion = (String) input.get("policy_version");
                    String timestampStr = (String) input.get("timestamp");
                    String jurisdiction = (String) input.get("jurisdiction");
                    String languageSelected = (String) input.get("language_selected");
                    String consentStatusGeneral = (String) input.get("consent_status_general");
                    String consentMechanism = (String) input.get("consent_mechanism");
                    String ipAddressStr = (String) req.getRemoteAddr();
                    String userAgent = (String) input.get("user_agent");
                    JSONArray dataPointConsents = (JSONArray) input.get("data_point_consents");

                    // Basic validation
                    if (userId == null || userId.isEmpty() || fiduciaryId == null || policyId == null || policyId.isEmpty() ||
                            policyVersion == null || policyVersion.isEmpty() || timestampStr == null || timestampStr.isEmpty() ||
                            jurisdiction == null || jurisdiction.isEmpty() || languageSelected == null || languageSelected.isEmpty() ||
                            consentStatusGeneral == null || consentStatusGeneral.isEmpty() || consentMechanism == null || consentMechanism.isEmpty() ||
                            dataPointConsents == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields for 'record_consent'.", req.getRequestURI());
                        return;
                    }

                    Timestamp timestamp = Timestamp.from(Instant.parse(timestampStr));

                    // Check if policy exists (important for provenance)
                    if (!policyExists(policyId, policyVersion, fiduciaryId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Referenced policy (ID: " + policyId + ", Version: " + policyVersion + ") not found or does not belong to fiduciary.", req.getRequestURI());
                        return;
                    }

                    output = recordConsentToDb(userId, fiduciaryId, policyId, policyVersion, timestamp, jurisdiction, languageSelected,
                            consentStatusGeneral, consentMechanism, ipAddressStr, userAgent, dataPointConsents, currentCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
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

                    if (anonymousUserId == null || anonymousUserId.isEmpty() || authenticatedUserId == null || authenticatedUserId.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Both 'anonymous_user_id' and 'authenticated_user_id' are required for 'link_user'.", req.getRequestURI());
                        return;
                    }
                    if (anonymousUserId.equals(authenticatedUserId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Anonymous ID and Authenticated ID cannot be the same.", req.getRequestURI());
                        return;
                    }

                    linkUserConsentRecords(anonymousUserId, authenticatedUserId, currentCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "User consent records linked successfully."); }});
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
     * (Ideally, this would be an API call to PolicyService in a microservices setup)
     */
    private boolean policyExists(String policyId, String version, UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM consent_policies WHERE id = ? AND version = ? AND fiduciary_id = ? AND status = 'ACTIVE' AND deleted_at IS NULL";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            pstmt.setObject(3, fiduciaryId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
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
                                         UUID actionByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmtDeactivate = null;
        PreparedStatement pstmtInsert = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String deactivateSql = "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE user_id = ? AND fiduciary_id = ? AND is_active_consent = TRUE";
        String insertSql = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, user_agent, data_point_consents, is_active_consent, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, TRUE, NOW(), NOW()) RETURNING id";

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

            // Audit Log: Log the consent record event
            // This would typically be an async call to an Audit Log Service
            // auditLogService.logEvent(actionByUserId, "CONSENT_RECORDED", "ConsentRecord", newConsentId, dataPointConsents.toJSONString(), ipAddress.getHostAddress(), "SUCCESS", "ConsentRecordService");

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
    private void linkUserConsentRecords(String anonymousUserId, String authenticatedUserId, UUID actionByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtUpdateConsent = null;
        PoolDB pool = new PoolDB();

        String updateConsentSql = "UPDATE consent_records SET user_id = ?, last_updated_at = NOW() WHERE user_id = ?";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            pstmtUpdateConsent = conn.prepareStatement(updateConsentSql);
            pstmtUpdateConsent.setString(1, authenticatedUserId);
            pstmtUpdateConsent.setString(2, anonymousUserId);
            int affectedRows = pstmtUpdateConsent.executeUpdate();

            if (affectedRows > 0) {
                // Audit Log: Log the linking event
                // This would typically be an async call to an Audit Log Service
                // auditLogService.logEvent(actionByUserId, "USER_LINKED", "User", authenticatedUserId, "Linked from anonymous ID: " + anonymousUserId, null, "SUCCESS", "ConsentRecordService");
            } else {
                // No records to link, might be an issue or already linked/no anonymous activity
                // Log this as an info or warning
                System.out.println("No consent records found for anonymous ID: " + anonymousUserId + " to link.");
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
    }
}
