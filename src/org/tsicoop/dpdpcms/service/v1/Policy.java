package org.tsicoop.dpdpcms.service.v1; // Package changed as requested

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
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern; // Not strictly needed for PolicyService, but kept for consistency with template

/**
 * PolicyService class for managing Consent Policies.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 */
public class Policy implements Action {

    // Regex for basic validation (not exhaustive for all fields, but for consistency)
    private static final Pattern POLICY_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,255}$");
    private static final Pattern VERSION_PATTERN = Pattern.compile("^[0-9]+\\.[0-9]+(\\.[0-9]+)?$"); // e.g., 1.0, 1.0.1
    private static final UUID ADMIN_FID_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");
    // Thread-safe in-memory cache for Policy lookups to minimize database round-trips
    private static final Map<String, JSONObject> policyCache = new ConcurrentHashMap<>();

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

        try {
            req.setCharacterEncoding("UTF-8");
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            res.setCharacterEncoding("UTF-8");
            res.setContentType("application/json; charset=UTF-8");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters
            String policyIdStr = (String) input.get("policy_id");
            String versionStr = (String) input.get("version");
            if(versionStr == null) versionStr = "";
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
                    if (policyIdStr == null || policyIdStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' is required for 'get_policy'.", req.getRequestURI());
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

                    if (policyIdStr == null || policyIdStr.isEmpty() || fiduciaryId == null || jurisdiction == null || jurisdiction.isEmpty() || policyContent == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (policy_id, fiduciary_id, jurisdiction, policy_content) for 'create_policy'.", req.getRequestURI());
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

                    output = savePolicyToDb(policyIdStr, versionStr, fiduciaryId, effectiveDate, jurisdiction, policyContent, "DRAFT");
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_policy":
                    if (policyIdStr == null || policyIdStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' is required for 'update_policy'.", req.getRequestURI());
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
                    jurisdiction = (String) input.get("jurisdiction"); // Jurisdiction can also be updated for draft
                    fiduciaryIdStr = (String) input.get("fiduciary_id"); // Fiduciary can also be updated for draft

                    if (policyContent == null && fiduciaryIdStr == null) {
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

                    output = updatePolicyInDb(policyIdStr, fiduciaryId, policyContent);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "publish_policy":
                    if (policyIdStr == null || policyIdStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' is required for 'publish_policy'.", req.getRequestURI());
                        return;
                    }
                    existingPolicy = getPolicyFromDb(policyIdStr, versionStr);
                    if (existingPolicy.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Policy with ID '" + policyIdStr + "' not found.", req.getRequestURI());
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

                    publishPolicyInDb(policyIdStr, versionStr, policyFidId, policyJurisdiction);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "Policy published successfully."); }});
                    break;

                case "delete_policy": // Soft delete
                    if (policyIdStr == null || policyIdStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'policy_id' is required for 'delete_policy'.", req.getRequestURI());
                        return;
                    }
                    existingPolicy = getPolicyFromDb(policyIdStr, versionStr);
                    if (existingPolicy.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Policy with ID '" + policyIdStr + "' not found.", req.getRequestURI());
                        return;
                    }
                    deletePolicyFromDb(fiduciaryId, policyIdStr, versionStr);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "System Error: " + e.getMessage(), req.getRequestURI());
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
        boolean valid = false;

        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Policy Management operations.", req.getRequestURI());
            return false;
        }
        boolean validbasics = InputProcessor.validate(req, res); // This validates content-type and basic body parsing
        if(validbasics){
            valid = validateFinerPolicyDetails(req, res);
        }
        return valid;
    }

    /**
     * Validates the policy logic using the request and response objects.
     * Collates business rule violations and sends a 400 response if invalid.
     */
    public boolean validateFinerPolicyDetails(HttpServletRequest req, HttpServletResponse res) {

        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            if(!func.equalsIgnoreCase("create_policy") && !func.equalsIgnoreCase("update_policy")) {
                return true;
            }
            else {
                JSONObject policyContent = (JSONObject) input.get("policy_content");

                if (policyContent == null || policyContent.isEmpty()) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Validation Error", "The 'policy_content' object is required.", req.getRequestURI());
                    return false;
                }

                // Call the internal validator which returns a JSONObject
                JSONObject result = validatePolicyContent(policyContent);

                if (!(Boolean) result.get("isValid")) {
                    JSONArray errors = (JSONArray) result.get("errors");
                    // Collate all errors into a formatted string similar to JSON Schema validation output
                    String collatedErrors = "Policy Logic Violations: [" + String.join(" | ", errors) + "]";
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", collatedErrors, req.getRequestURI());
                    return false;
                }
            }
        }catch(Exception e){
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid JSON input: " + e.getMessage(), req.getRequestURI());
        }
        return true;
    }

    /**
     * Internal logic to validate policy structure and referential integrity.
     * @param policyContent The 'policy_content' object from the request.
     * @return JSONObject containing {"isValid": boolean, "errors": JSONArray}
     */
    public static JSONObject validatePolicyContent(JSONObject policyContent) {
        JSONObject result = new JSONObject();
        JSONArray errors = new JSONArray();
        result.put("isValid", true);
        result.put("errors", errors);

        Set<String> languages = policyContent.keySet();
        Map<String, Set<String>> languageToPurposeIds = new HashMap<>();

        for (String lang : languages) {
            JSONObject langData = (JSONObject) policyContent.get(lang);

            // 1. Gather defined categories for referential integrity check
            JSONArray categories = (JSONArray) langData.get("data_categories_details");
            Set<String> definedCategoryIds = new HashSet<>();
            if (categories != null) {
                for (Object obj : categories) {
                    JSONObject cat = (JSONObject) obj;
                    definedCategoryIds.add((String) cat.get("id"));
                }
            }

            // 2. Validate Purposes within this language
            JSONArray purposes = (JSONArray) langData.get("data_processing_purposes");
            Set<String> currentLangPurposeIds = new HashSet<>();

            if (purposes != null) {
                for (int i = 0; i < purposes.size(); i++) {
                    JSONObject purpose = (JSONObject) purposes.get(i);
                    String pid = (String) purpose.get("id");

                    // Rule: ID Uniqueness within language
                    if (!currentLangPurposeIds.add(pid)) {
                        errors.add(String.format("[%s] Duplicate purpose ID: %s", lang, pid));
                        result.put("isValid", false);
                    }

                    // Rule: Retention Start Event Domain
                    String startEvent = (String) purpose.get("retention_start_event");
                    if (startEvent != null && !startEvent.equals("COLLECTION") && !startEvent.equals("CESSATION")) {
                        errors.add(String.format("[%s] Purpose '%s' has invalid start event: %s. Must be COLLECTION or CESSATION.", lang, pid, startEvent));
                        result.put("isValid", false);
                    }
                }
            } else {
                errors.add(String.format("[%s] Missing 'data_processing_purposes' array.", lang));
                result.put("isValid", false);
            }
            languageToPurposeIds.put(lang, currentLangPurposeIds);
        }

        // 3. Rule: Cross-Language Parity (All languages must have identical purpose IDs)
        if (languages.size() > 1) {
            Iterator<Map.Entry<String, Set<String>>> it = languageToPurposeIds.entrySet().iterator();
            Map.Entry<String, Set<String>> first = it.next();
            while (it.hasNext()) {
                Map.Entry<String, Set<String>> current = it.next();
                if (!first.getValue().equals(current.getValue())) {
                    errors.add(String.format("Language Parity Failure: Purpose IDs in '%s' do not match '%s'.", current.getKey(), first.getKey()));
                    result.put("isValid", false);
                }
            }
        }

        return result;
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
     * Checks if a fiduciary exists.
     */
    private boolean fiduciaryExists(UUID fiduciaryId) throws SQLException {
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
     * Retrieves a list of policies from the database.
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
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND id LIKE ?");
            params.add("%" + search + "%");
        }
        if (fiduciaryIdFilter != null) {
            sqlBuilder.append(" AND fiduciary_id = ?");
            params.add(fiduciaryIdFilter);
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
     * Retrieves a policy from the database.
     * Uses a ConcurrentHashMap to cache results and minimize latency.
     */
    protected Optional<JSONObject> getPolicyFromDb(String policyId, String version) throws SQLException {
        String cacheKey = policyId;

        // 1. Return from cache if present
        if (policyCache.containsKey(cacheKey)) {
            return Optional.of(policyCache.get(cacheKey));
        }

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
                policy.put("policy_content", rs.getString("policy_content"));
                policy.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                policy.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());

                // 2. Populate cache on successful lookup
                policyCache.put(cacheKey, policy);
                return Optional.of(policy);
            }
        } catch (Exception e) {
            throw new SQLException("Failed to parse policy_content: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    protected Optional<JSONObject> getActivePolicyFromDb(UUID fiduciaryId, String jurisdiction) throws SQLException {
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
            throw new SQLException("Failed to parse policy_content: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    private JSONObject savePolicyToDb(String policyId, String version, UUID fiduciaryId, Timestamp effectiveDate, String jurisdiction, JSONObject policyContent, String status) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, NOW(),NOW())";
        boolean success = false;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            pstmt.setObject(3, fiduciaryId);
            pstmt.setTimestamp(4, effectiveDate);
            pstmt.setString(5, status);
            pstmt.setString(6, jurisdiction);
            pstmt.setString(7, policyContent.toJSONString());

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating policy failed, no rows affected.");
            }

            output.put("policy_id", policyId);
            output.put("version", version);
            output.put("message", "Policy created successfully.");
            success = true;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        // Instrument audit log only after connection is returned to pool
        if (success) {
            new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, fiduciaryId, "POLICY_CREATED", "ID: " + policyId);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    private JSONObject updatePolicyInDb(String policyId, UUID fiduciaryId, JSONObject policyContent) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        boolean success = false;

        StringBuilder sqlBuilder = new StringBuilder("UPDATE consent_policies SET last_updated_at = NOW()");
        List<Object> params = new ArrayList<>();
        if (fiduciaryId != null) { sqlBuilder.append(", fiduciary_id = ?"); params.add(fiduciaryId); }
        if (policyContent != null) { sqlBuilder.append(", policy_content = ?::jsonb"); params.add(policyContent.toJSONString()); }

        sqlBuilder.append(" WHERE id = ? AND version = ? AND status = 'DRAFT'");
        params.add(policyId);
        params.add("");

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating policy failed, not found or not in DRAFT status.");
            }
            success = true;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        // Instrument audit log only after connection is returned to pool
        if (success) {
            new Audit().logEventAsync("DPO", (fiduciaryId != null ? fiduciaryId : ADMIN_FID_UUID), Constants.SERVICE_TYPE_DPO_CONSOLE, (fiduciaryId != null ? fiduciaryId : ADMIN_FID_UUID), "POLICY_UPDATED", "ID: " + policyId);
        }
        return new JSONObject() {{ put("success", true); put("message", "Policy updated successfully."); }};
    }

    private void publishPolicyInDb(String policyId, String version, UUID fiduciaryId, String jurisdiction) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtCheck = null;
        PreparedStatement pstmtActivate = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        boolean success = false;

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // 1. Extract Purpose IDs from the target policy
            Set<String> targetPurposes = new HashSet<>();
            String fetchSql = "SELECT policy_content FROM consent_policies WHERE id = ? AND version = ?";
            try (PreparedStatement pFetch = conn.prepareStatement(fetchSql)) {
                pFetch.setString(1, policyId);
                pFetch.setString(2, version);
                try (ResultSet rsFetch = pFetch.executeQuery()) {
                    if (rsFetch.next()) {
                        targetPurposes = extractPurposeIdsFromContent(rsFetch.getString("policy_content"));
                    }
                }
            }

            // 2. Scan all currently ACTIVE policies for the fiduciary for potential collisions
            Set<String> activePurposes = new HashSet<>();
            String scanSql = "SELECT policy_content FROM consent_policies WHERE fiduciary_id = ? AND status = 'ACTIVE' AND (id != ? OR version != ?)";
            pstmtCheck = conn.prepareStatement(scanSql);
            pstmtCheck.setObject(1, fiduciaryId);
            pstmtCheck.setString(2, policyId);
            pstmtCheck.setString(3, version);
            rs = pstmtCheck.executeQuery();
            while (rs.next()) {
                activePurposes.addAll(extractPurposeIdsFromContent(rs.getString("policy_content")));
            }

            // 3. Collision Logic: Ensure no duplicate Purpose IDs exist in the active set
            Set<String> collisions = new HashSet<>(targetPurposes);
            collisions.retainAll(activePurposes);
            if (!collisions.isEmpty()) {
                throw new SQLException("Publication Conflict: The following Purpose IDs are already defined in other active policies for this fiduciary: " + collisions + ". Please archive conflicting policies first.");
            }

            // 4. Update target to ACTIVE
            String activateSql = "UPDATE consent_policies SET status = 'ACTIVE', last_updated_at = NOW() WHERE id = ? AND version = ?";
            pstmtActivate = conn.prepareStatement(activateSql);
            pstmtActivate.setString(1, policyId);
            pstmtActivate.setString(2, version);

            if (pstmtActivate.executeUpdate() == 0) {
                throw new SQLException("Publishing failed: policy not found.");
            }

            conn.commit();
            success = true;
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(rs, pstmtCheck, null);
            pool.cleanup(null, pstmtActivate, conn);
        }

        if (success) {
            new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, fiduciaryId, "POLICY_PUBLISHED", "ID: " + policyId);
        }
    }

    /**
     * Internal logic to extract Purpose IDs from the JSONB policy content.
     */
    private Set<String> extractPurposeIdsFromContent(String policyContentStr) {
        Set<String> ids = new HashSet<>();
        try {
            if (policyContentStr == null || policyContentStr.isEmpty()) return ids;
            JSONObject content = (JSONObject) new JSONParser().parse(policyContentStr);
            if (content.isEmpty()) return ids;

            // Reference the first available language (integrity checks ensure parity)
            String lang = (String) content.keySet().iterator().next();
            JSONObject langObj = (JSONObject) content.get(lang);
            JSONArray purposes = (JSONArray) langObj.get("data_processing_purposes");

            if (purposes != null) {
                for (Object obj : purposes) {
                    JSONObject p = (JSONObject) obj;
                    String pid = (String) p.get("id");
                    if (pid != null) ids.add(pid);
                }
            }
        } catch (Exception e) { /* Content structure invalid or unparseable */ }
        return ids;
    }



    private void deletePolicyFromDb(UUID fiduciaryId, String policyId, String version) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE consent_policies SET status = 'ARCHIVED' WHERE id = ?";
        boolean success = false;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.executeUpdate();
            success = true;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        // Instrument audit log only after connection is returned to pool
        if (success) {
            new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, fiduciaryId, "POLICY_DELETED", "ID: " + policyId);
        }
    }
}