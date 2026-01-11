package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.Action;
import org.tsicoop.dpdpcms.framework.PoolDB;
import org.tsicoop.dpdpcms.framework.InputProcessor;
import org.tsicoop.dpdpcms.framework.OutputProcessor;
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
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * API Key Management Service (ApiKey).
 * This service manages the secure generation, storage, usage tracking, and lifecycle
 * of API keys for Apps.
 */
public class ApiKey implements Action {

    /**
     * Handles all API Key Management operations via a single POST endpoint.
     */
    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // --- Extract common parameters ---
            UUID keyId = null;
            String keyIdStr = (String) input.get("key_id");
            if (keyIdStr != null && !keyIdStr.isEmpty()) {
                try {
                    keyId = UUID.fromString(keyIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'key_id' format.", req.getRequestURI());
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
                case "generate_api_key":
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required to generate a key.", req.getRequestURI());
                        return;
                    }
                    String description = (String) input.get("description");
                    JSONArray permissionsJson = (JSONArray) input.get("permissions");
                    String appIdStr = (String) input.get("app_id");

                    UUID appId = null;
                    if (appIdStr != null && !appIdStr.isEmpty()) {
                        try {
                            appId = UUID.fromString(appIdStr);
                        } catch (IllegalArgumentException e) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'processor_id' format.", req.getRequestURI());
                            return;
                        }
                    }

                    if (permissionsJson == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (permissions) for key generation.", req.getRequestURI());
                        return;
                    }

                    // NOTE: Fiduciary existence check is recommended here but omitted for brevity.

                    output = generateAndSaveApiKey(fiduciaryId, appId, description, permissionsJson);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "get_api_key_details":
                    if (keyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'key_id' is required.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> keyOptional = getApiKeyDetailsFromDb(keyId);
                    if (keyOptional.isPresent()) {
                        output = keyOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "API Key with ID '" + keyId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "list_api_keys":
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");

                    outputArray = listApiKeysFromDb("", statusFilter, search);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "revoke_api_key": // Deactivates key instantly
                    if (keyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'key_id' is required for revocation.", req.getRequestURI());
                        return;
                    }
                    revokeApiKeyInDb(keyId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "API Key revoked successfully."); }});
                    break;

                case "update_api_key_status":
                    if (keyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'key_id' is required.", req.getRequestURI());
                        return;
                    }
                    statusFilter = (String) input.get("status"); // Expected status: ACTIVE, INACTIVE, EXPIRED
                    if (statusFilter == null || statusFilter.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'status' is required for updating key status.", req.getRequestURI());
                        return;
                    }
                    // Revoke is handled by a separate function (case "revoke_api_key")
                    if (statusFilter.equalsIgnoreCase("REVOKED")) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Use 'revoke_api_key' function to permanently revoke keys.", req.getRequestURI());
                        return;
                    }
                    updateApiKeyStatusInDb(keyId, statusFilter);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "API Key status updated successfully."); }});
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

    // --- Validation and Helper Methods ---

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for API Key Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    /**
     * MOCK: Generates a cryptographically strong API key string.
     */
    private String generateRawApiKey() {
        return UUID.randomUUID().toString() + UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * MOCK: Hashes the raw API key for secure database storage.
     */
    private String hashApiKey(String rawKey) {
        // In a real system, use BCrypt or Argon2 for secure hashing.
        // For this example, we just return a simple hash for demonstration.
        return "HASHED_" + rawKey;
    }

    /**
     * Generates a new API key, saves the hashed value, and returns the raw key.
     */
    private JSONObject generateAndSaveApiKey(UUID fiduciaryId, UUID appId, String description,
                                             JSONArray permissionsJson) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // 1. Generate Raw Key and Hash
        String rawKey = generateRawApiKey();
        String hashedKey = hashApiKey(rawKey);
        String permissionsString = permissionsJson != null ? permissionsJson.toJSONString() : "[]";

        JSONObject output = new JSONObject();

        String sql = "INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, description, permissions, created_at, status) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?::jsonb, NOW(), 'ACTIVE') RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);

            // NOTE: Storing the HASHED key in the key_value column.
            pstmt.setString(1, hashedKey);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setObject(3, appId);
            pstmt.setString(4, description);
            pstmt.setString(5, permissionsString);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Key generation failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                output.put("key_id", rs.getString(1));
                output.put("raw_api_key", rawKey); // RETURN RAW KEY ONLY ONCE!
                output.put("permissions", permissionsJson);
                output.put("fiduciary_id", fiduciaryId.toString());
                output.put("app_id", appId.toString());

                // NOTE: Audit log service call would go here to log key creation.
            } else {
                throw new SQLException("Key generation failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); put("message", "API Key created successfully. STORE THIS KEY SAFELY, IT WILL NOT BE SHOWN AGAIN."); }};
    }

    /**
     * Retrieves API key details from the database by its ID. (Does NOT retrieve raw key).
     */
    private Optional<JSONObject> getApiKeyDetailsFromDb(UUID keyId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Exclude the sensitive key_value hash from being pulled into general objects
        String sql = "SELECT id, fiduciary_id, app_id, description, status, permissions, created_at, expires_at, last_used_at FROM api_keys WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, keyId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject key = new JSONObject();
                key.put("key_id", rs.getString("id"));
                key.put("fiduciary_id", rs.getString("fiduciary_id"));
                key.put("app_id", rs.getString("app_id"));
                key.put("description", rs.getString("description"));
                key.put("status", rs.getString("status"));
                key.put("permissions", new JSONParser().parse(rs.getString("permissions")));
                key.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                key.put("expires_at", rs.getTimestamp("expires_at") != null ? rs.getTimestamp("expires_at").toInstant().toString() : null);
                key.put("last_used_at", rs.getTimestamp("last_used_at") != null ? rs.getTimestamp("last_used_at").toInstant().toString() : null);
                return Optional.of(key);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for API key: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    public UUID getAppId(String apiKey, String apiSecret) throws SQLException {
        if(apiKey == null || apiSecret == null) return null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        UUID appId = null;
        String sql = "SELECT app_id FROM api_keys WHERE id = ? AND key_value=?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(apiKey));
            pstmt.setString(2, "HASHED_"+apiSecret);
            rs = pstmt.executeQuery();
            if(rs.next())
                appId = UUID.fromString(rs.getString("app_id"));
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return appId;
    }


    /**
     * Revokes an API key by setting its status to REVOKED and recording revocation details.
     */
    private void revokeApiKeyInDb(UUID keyId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        // Soft delete/Revoke by updating status and recording metadata
        String sql = "UPDATE api_keys SET status = 'REVOKED', revoked_at = NOW(), last_used_at = NOW() WHERE id = ? AND status != 'REVOKED'";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, keyId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                // Check if it exists at all (optional)
                if (getApiKeyDetailsFromDb(keyId).isEmpty()) {
                    throw new SQLException("API Key not found.");
                }
                // Already revoked/expired
                // Log a warning: Key revocation attempted on already revoked key.
            }
            // NOTE: Audit log service call would go here to log key revocation.
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Updates the ACTIVE/INACTIVE/EXPIRED status of an existing key.
     */
    private void updateApiKeyStatusInDb(UUID keyId, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        String sql = "UPDATE api_keys SET status = ?, last_updated_at = NOW() WHERE id = ? AND status != 'REVOKED'";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, status.toUpperCase());
            pstmt.setObject(2, keyId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                // Check if it exists at all and if it was already permanently revoked.
                Optional<JSONObject> keyDetails = getApiKeyDetailsFromDb(keyId);
                if (keyDetails.isEmpty()) {
                    throw new SQLException("API Key not found.");
                }
                if (keyDetails.get().get("status").equals("REVOKED")) {
                    throw new SQLException("Cannot update status of a permanently REVOKED key.");
                }
            }
            // NOTE: Audit log service call would go here to log key status update.
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Retrieves a list of API keys for a specific Fiduciary, with filtering.
     */
    private JSONArray listApiKeysFromDb(String fiduciaryId, String statusFilter, String search) throws SQLException {
        JSONArray keysArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Select metadata columns (excluding the hash)
        StringBuilder sqlBuilder = new StringBuilder("SELECT ak.id, ak.fiduciary_id, ak.app_id, ak.description, ak.status, ak.permissions, ak.created_at, ak.expires_at, ak.last_used_at, ap.name FROM api_keys ak, apps ap WHERE ak.app_id=ap.id");
        List<Object> params = new ArrayList<>();

        if (fiduciaryId != null && !fiduciaryId.isEmpty()) {
            sqlBuilder.append(" AND fiduciary_id = ?");
            params.add(fiduciaryId);
        }
        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter.toUpperCase());
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND description LIKE ?");
            params.add("%" + search + "%");
        }
        sqlBuilder.append(" ORDER BY created_at DESC");

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject key = new JSONObject();
                key.put("key_id", rs.getString("id"));
                key.put("fiduciary_id", rs.getString("fiduciary_id"));
                key.put("app_id", rs.getString("app_id"));
                key.put("app_name", rs.getString("name"));
                key.put("description", rs.getString("description"));
                key.put("status", rs.getString("status"));
                key.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                key.put("expires_at", rs.getTimestamp("expires_at") != null ? rs.getTimestamp("expires_at").toInstant().toString() : null);
                key.put("last_used_at", rs.getTimestamp("last_used_at") != null ? rs.getTimestamp("last_used_at").toInstant().toString() : null);

                keysArray.add(key);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return keysArray;
    }
}
