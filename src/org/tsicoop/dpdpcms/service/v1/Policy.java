package org.tsicoop.dpdpcms.service.v1; // Package changed as requested

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
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;
import java.util.regex.Pattern; // Not strictly needed for PolicyService, but kept for consistency with template

/**
 * PolicyService class for managing Consent Policies.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Policy Definition and Retrieval modules
 * of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'consent_policies'.
 * - Primary Key is composite: (id, version).
 * - Columns: id (VARCHAR), version (VARCHAR), fiduciary_id (UUID), effective_date (TIMESTAMPZ),
 * status (VARCHAR), jurisdiction (VARCHAR), policy_content (JSONB), created_at (TIMESTAMPZ),
 * created_by_user_id (UUID), last_updated_at (TIMESTAMPZ), last_updated_by_user_id (UUID),
 * deleted_at (TIMESTAMPZ), deleted_by_user_id (UUID).
 * - Assumes 'users' table exists for FK references to created_by_user_id etc.
 */
public class Policy implements Action {

    // Regex for basic validation (not exhaustive for all fields, but for consistency)
    private static final Pattern POLICY_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,255}$");
    private static final Pattern VERSION_PATTERN = Pattern.compile("^[0-9]+\\.[0-9]+(\\.[0-9]+)?$"); // e.g., 1.0, 1.0.1

    /**
     * Handles all Policy Management operations via a single POST endpoint.
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
        UUID currentUserId = UUID.fromString("00000000-0000-0000-0000-000000000001"); // Example Admin User ID

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters
            String policyIdStr = (String) input.get("policy_id");
            String versionStr = (String) input.get("version");
            String jurisdiction = (String) input.get("jurisdiction");
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
                case "list_policies":
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");
                    String fidIdFilter = (String) input.get("fiduciary_id_filter"); // For listing policies of a specific fiduciary
                    UUID listFidId = null;
                    if (fidIdFilter != null && !fidIdFilter.isEmpty()) {
                        try { listFidId = UUID.fromString(fidIdFilter); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (fidIdFilter != null && listFidId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id_filter' format.", req.getRequestURI());
                        return;
                    }
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listPoliciesFromDb(statusFilter, search, listFidId, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_policy":
                    if (policyIdStr == null || policyIdStr.isEmpty() || versionStr == null || versionStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' and 'version' are required for 'get_policy'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> policyOptional = getPolicyFromDb(policyIdStr, versionStr);
                    if (policyOptional.isPresent()) {
                        output = policyOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Policy with ID '" + policyIdStr + "' and version '" + versionStr + "' not found.", req.getRequestURI());
                    }
                    break;

                case "get_active_policy":
                    if (fiduciaryId == null || jurisdiction == null || jurisdiction.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' and 'jurisdiction' are required for 'get_active_policy'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> activePolicyOptional = getActivePolicyFromDb(fiduciaryId, jurisdiction);
                    if (activePolicyOptional.isPresent()) {
                        output = activePolicyOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No active policy found for Fiduciary ID '" + fiduciaryId + "' and jurisdiction '" + jurisdiction + "'.", req.getRequestURI());
                    }
                    break;

                case "create_policy":
                    JSONObject policyContent = (JSONObject) input.get("policy_content");
                    String effectiveDateStr = (String) input.get("effective_date");

                    if (policyIdStr == null || policyIdStr.isEmpty() || versionStr == null || versionStr.isEmpty() || fiduciaryId == null || jurisdiction == null || jurisdiction.isEmpty() || policyContent == null || effectiveDateStr == null || effectiveDateStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (policy_id, version, fiduciary_id, jurisdiction, policy_content, effective_date) for 'create_policy'.", req.getRequestURI());
                        return;
                    }
                    if (!POLICY_ID_PATTERN.matcher(policyIdStr).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid policy_id format.", req.getRequestURI());
                        return;
                    }
                    if (!VERSION_PATTERN.matcher(versionStr).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid version format (e.g., 1.0, 1.0.1).", req.getRequestURI());
                        return;
                    }
                    Timestamp effectiveDate = Timestamp.from(Instant.now());

                    if (policyExists(policyIdStr, versionStr)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Policy with ID '" + policyIdStr + "' and version '" + versionStr + "' already exists.", req.getRequestURI());
                        return;
                    }
                    if (!fiduciaryExists(fiduciaryId)) { // Helper to check if fiduciary exists
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                        return;
                    }

                    output = savePolicyToDb(policyIdStr, versionStr, fiduciaryId, effectiveDate, jurisdiction, policyContent, "DRAFT", currentUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_policy":
                    if (policyIdStr == null || policyIdStr.isEmpty() || versionStr == null || versionStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' and 'version' are required for 'update_policy'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> existingPolicy = getPolicyFromDb(policyIdStr, versionStr);
                    if (existingPolicy.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Policy with ID '" + policyIdStr + "' and version '" + versionStr + "' not found.", req.getRequestURI());
                        return;
                    }
                    String currentStatus = (String) existingPolicy.get().get("status");
                    if (!"DRAFT".equalsIgnoreCase(currentStatus)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Only DRAFT policies can be updated. Current status: " + currentStatus, req.getRequestURI());
                        return;
                    }

                    policyContent = (JSONObject) input.get("policy_content");
                    effectiveDateStr = (String) input.get("effective_date");
                    jurisdiction = (String) input.get("jurisdiction"); // Jurisdiction can also be updated for draft
                    fiduciaryIdStr = (String) input.get("fiduciary_id"); // Fiduciary can also be updated for draft

                    if (policyContent == null && effectiveDateStr == null && jurisdiction == null && fiduciaryIdStr == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_policy'.", req.getRequestURI());
                        return;
                    }

                    if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                        try { fiduciaryId = UUID.fromString(fiduciaryIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                        if (fiduciaryId == null || !fiduciaryExists(fiduciaryId)) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Fiduciary with ID '" + fiduciaryIdStr + "' not found for update.", req.getRequestURI());
                            return;
                        }
                    }

                    Timestamp updatedEffectiveDate = (effectiveDateStr != null && !effectiveDateStr.isEmpty()) ? Timestamp.from(Instant.parse(effectiveDateStr)) : null;

                    output = updatePolicyInDb(policyIdStr, versionStr, fiduciaryId, updatedEffectiveDate, jurisdiction, policyContent, currentUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "publish_policy":
                    if (policyIdStr == null || policyIdStr.isEmpty() || versionStr == null || versionStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' and 'version' are required for 'publish_policy'.", req.getRequestURI());
                        return;
                    }
                    existingPolicy = getPolicyFromDb(policyIdStr, versionStr);
                    if (existingPolicy.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Policy with ID '" + policyIdStr + "' and version '" + versionStr + "' not found.", req.getRequestURI());
                        return;
                    }
                    currentStatus = (String) existingPolicy.get().get("status");
                    if ("ACTIVE".equalsIgnoreCase(currentStatus)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Policy is already ACTIVE.", req.getRequestURI());
                        return;
                    }
                    if ("ARCHIVED".equalsIgnoreCase(currentStatus) || "EXPIRED".equalsIgnoreCase(currentStatus)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot publish an ARCHIVED or EXPIRED policy.", req.getRequestURI());
                        return;
                    }

                    // Get fiduciary_id and jurisdiction from the policy itself for deactivation logic
                    UUID policyFidId = UUID.fromString((String)existingPolicy.get().get("fiduciary_id"));
                    String policyJurisdiction = (String)existingPolicy.get().get("jurisdiction");

                    publishPolicyInDb(policyIdStr, versionStr, policyFidId, policyJurisdiction, currentUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "Policy published successfully."); }});
                    break;

                case "delete_policy": // Soft delete
                    if (policyIdStr == null || policyIdStr.isEmpty() || versionStr == null || versionStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' and 'version' are required for 'delete_policy'.", req.getRequestURI());
                        return;
                    }
                    existingPolicy = getPolicyFromDb(policyIdStr, versionStr);
                    if (existingPolicy.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Policy with ID '" + policyIdStr + "' and version '" + versionStr + "' not found.", req.getRequestURI());
                        return;
                    }
                    currentStatus = (String) existingPolicy.get().get("status");
                    if ("ACTIVE".equalsIgnoreCase(currentStatus)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot delete an ACTIVE policy. Please archive it first.", req.getRequestURI());
                        return;
                    }

                    deletePolicyFromDb(policyIdStr, versionStr, currentUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Policy Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Policy Management ---

    /**
     * Checks if a policy version already exists.
     */
    private boolean policyExists(String policyId, String version) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM consent_policies WHERE id = ? AND version = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Checks if a fiduciary exists. (Placeholder - ideally call FiduciaryService)
     */
    private boolean fiduciaryExists(UUID fiduciaryId) throws SQLException {
        // In a microservices architecture, this would typically involve an API call
        // to the FiduciaryService to check if the fiduciaryId is valid.
        // For this example, we'll do a direct DB check.
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM fiduciaries WHERE id = ?";
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
     * Retrieves a list of policies from the database with optional filtering and pagination.
     * @return JSONArray of policy JSONObjects (summary, not full content).
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listPoliciesFromDb(String statusFilter, String search, UUID fiduciaryIdFilter, int page, int limit) throws SQLException {
        JSONArray policiesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, version, fiduciary_id, effective_date, status, jurisdiction, created_at, last_updated_at FROM consent_policies WHERE status is not null");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (fiduciaryIdFilter != null) {
            sqlBuilder.append(" AND fiduciary_id = ?");
            params.add(fiduciaryIdFilter);
        }
        if (search != null && !search.isEmpty()) {
            // Search within policy_content JSONB for name/description (example, can be complex)
            sqlBuilder.append(" AND policy_content::text ILIKE ?"); // Simple text search for demo
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY effective_date DESC LIMIT ? OFFSET ?");
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
                policy.put("id", rs.getString("id"));
                policy.put("version", rs.getString("version"));
                policy.put("fiduciary_id", rs.getString("fiduciary_id"));
                policy.put("effective_date", rs.getTimestamp("effective_date").toInstant().toString());
                policy.put("status", rs.getString("status"));
                policy.put("jurisdiction", rs.getString("jurisdiction"));
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
     * Retrieves a single policy by ID and version from the database.
     * @return An Optional containing the policy JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getPolicyFromDb(String policyId, String version) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at FROM consent_policies WHERE id = ? AND version = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject policy = new JSONObject();
                policy.put("policy_id", rs.getString("id"));
                policy.put("version", rs.getString("version"));
                policy.put("fiduciary_id", rs.getString("fiduciary_id"));
                policy.put("effective_date", rs.getTimestamp("effective_date").toInstant().toString());
                policy.put("status", rs.getString("status"));
                policy.put("jurisdiction", rs.getString("jurisdiction"));
                policy.put("policy_content", new JSONParser().parse(rs.getString("policy_content"))); // Parse JSONB to JSONObject
                policy.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                policy.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                return Optional.of(policy);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse policy_content JSON from DB: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Retrieves the active policy for a given fiduciary and jurisdiction.
     * @return An Optional containing the policy JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getActivePolicyFromDb(UUID fiduciaryId, String jurisdiction) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at FROM consent_policies WHERE fiduciary_id = ? AND jurisdiction = ? AND status = 'ACTIVE' AND effective_date <= NOW() ORDER BY effective_date DESC LIMIT 1";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, jurisdiction);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject policy = new JSONObject();
                policy.put("policy_id", rs.getString("id"));
                policy.put("version", rs.getString("version"));
                policy.put("fiduciary_id", rs.getString("fiduciary_id"));
                policy.put("effective_date", rs.getTimestamp("effective_date").toInstant().toString());
                policy.put("status", rs.getString("status"));
                policy.put("jurisdiction", rs.getString("jurisdiction"));
                policy.put("policy_content", new JSONParser().parse(rs.getString("policy_content")));
                policy.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                policy.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                return Optional.of(policy);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse policy_content JSON from DB: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new policy to the database (status DRAFT).
     * @return JSONObject containing the new policy's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject savePolicyToDb(String policyId, String version, UUID fiduciaryId, Timestamp effectiveDate, String jurisdiction, JSONObject policyContent, String status, UUID createdByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, NOW(),NOW())";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            pstmt.setObject(3, fiduciaryId);
            pstmt.setTimestamp(4, effectiveDate);
            pstmt.setString(5, status);
            pstmt.setString(6, jurisdiction);
            pstmt.setString(7, policyContent.toJSONString()); // Pass JSON as String, cast to JSONB

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating policy failed, no rows affected.");
            }

            output.put("policy_id", policyId);
            output.put("version", version);
            output.put("message", "Policy created successfully.");
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing policy in the database (only DRAFT policies can be updated).
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updatePolicyInDb(String policyId, String version, UUID fiduciaryId, Timestamp effectiveDate, String jurisdiction, JSONObject policyContent, UUID updatedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE consent_policies SET last_updated_at = NOW()");
        List<Object> params = new ArrayList<>();
        if (fiduciaryId != null) { sqlBuilder.append(", fiduciary_id = ?"); params.add(fiduciaryId); }
        if (effectiveDate != null) { sqlBuilder.append(", effective_date = ?"); params.add(effectiveDate); }
        if (jurisdiction != null && !jurisdiction.isEmpty()) { sqlBuilder.append(", jurisdiction = ?"); params.add(jurisdiction); }
        if (policyContent != null) { sqlBuilder.append(", policy_content = ?::jsonb"); params.add(policyContent.toJSONString()); }

        sqlBuilder.append(" WHERE id = ? AND version = ? AND status = 'DRAFT'");
        params.add(policyId);
        params.add(version);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating policy failed, policy not found or not in DRAFT status, or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Policy updated successfully."); }};
    }

    /**
     * Publishes a policy, setting its status to ACTIVE and deactivating previous active versions.
     * This operation is transactional.
     * @throws SQLException if a database access error occurs.
     */
    private void publishPolicyInDb(String policyId, String version, UUID fiduciaryId, String jurisdiction, UUID publishedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtDeactivate = null;
        PreparedStatement pstmtActivate = null;
        PoolDB pool = new PoolDB();

        String deactivateSql = "UPDATE consent_policies SET status = 'ARCHIVED', last_updated_at = NOW() WHERE fiduciary_id = ? AND jurisdiction = ? AND status = 'ACTIVE'";
        String activateSql = "UPDATE consent_policies SET status = 'ACTIVE', last_updated_at = NOW() WHERE id = ? AND version = ?";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // 1. Deactivate any currently ACTIVE policy for this fiduciary and jurisdiction
            pstmtDeactivate = conn.prepareStatement(deactivateSql);
            pstmtDeactivate.setObject(1, fiduciaryId);
            pstmtDeactivate.setString(2, jurisdiction);
            pstmtDeactivate.executeUpdate();

            // 2. Activate the specified policy version
            pstmtActivate = conn.prepareStatement(activateSql);
            pstmtActivate.setString(1, policyId);
            pstmtActivate.setString(2, version);
            int affectedRows = pstmtActivate.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Publishing policy failed, target policy not found or not in DRAFT/INACTIVE status.");
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
            pool.cleanup(null, pstmtDeactivate, null);
            pool.cleanup(null, pstmtActivate, conn);
        }
    }

    /**
     * Deletes a policy version from the database (soft delete).
     * @throws SQLException if a database access error occurs.
     */
    private void deletePolicyFromDb(String policyId, String version, UUID deletedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE consent_policies SET status = 'DELETED' WHERE id = ? AND version = ? AND status != 'ACTIVE'"; // Cannot delete active
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting policy failed, policy not found or is ACTIVE.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}