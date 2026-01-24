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
import java.util.regex.Pattern; // For domain validation, if needed

/**
 * App class for managing interfacing with Consent Manager.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the App Management module
 * of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'apps'.
 * - Columns: id (UUID PK), fiduciary_id (UUID), name (VARCHAR), contact_person (VARCHAR),
 * email (VARCHAR), phone (VARCHAR), address (TEXT), jurisdiction (VARCHAR),
 * dpa_reference (VARCHAR), dpa_effective_date (DATE), dpa_expiry_date (DATE),
 * processing_purposes (JSONB), data_categories_processed (JSONB),
 * security_measures_description (TEXT), status (VARCHAR), created_at (TIMESTAMPZ),
 * created_by_user_id (UUID), last_updated_at (TIMESTAMPZ), last_updated_by_user_id (UUID),
 * deleted_at (TIMESTAMPZ), deleted_by_user_id (UUID).
 * - Assumes 'fiduciaries' and 'users' tables exist for FK references.
 */
public class App implements Action {

    // Regex for basic domain validation (simplified, if app has a domain to validate)
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    /**
     * Handles all App Management operations via a single POST endpoint.
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
        String processingPurposes = null;

        // Placeholder for current CMS user ID (from authentication context)
        UUID currentCmsUserId = UUID.fromString("00000000-0000-0000-0000-000000000001"); // Example Admin User ID

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters
            UUID appId = null;
            String appIdStr = (String) input.get("app_id");
            if (appIdStr != null && !appIdStr.isEmpty()) {
                try {
                    appId = UUID.fromString(appIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'app_id' format.", req.getRequestURI());
                    return;
                }
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = (String) input.get("fiduciary_id"); // Required for create and often for list/get
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                case "list_apps":
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");

                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listAppsFromDb(fiduciaryId, statusFilter, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_app":
                    if (appId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'app_id' and 'fiduciary_id' are required for 'get_app'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> appOptional = getAppFromDb(appId, fiduciaryId);
                    if (appOptional.isPresent()) {
                        output = appOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "App with ID '" + appId + "' not found for Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                    }
                    break;

                case "create_app":
                    String name = (String) input.get("name");
                    String email = (String) input.get("email");
                    String phone = (String) input.get("phone");
                    String dpaReference = (String) input.get("dpa_reference");
                    processingPurposes = (String) input.get("processing_purposes");

                    if (fiduciaryId == null || name == null || name.isEmpty() || processingPurposes == null || processingPurposes.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (fiduciary_id, name, processing_purposes, data_categories_processed) for 'create_app'.", req.getRequestURI());
                        return;
                    }
                    if (!fiduciaryExists(fiduciaryId)) { // Helper to check if fiduciary exists
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                        return;
                    }
                    if (appExistsByNameForFiduciary(fiduciaryId, name)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "App with name '" + name + "' already exists for this Fiduciary.", req.getRequestURI());
                        return;
                    }

                    output = saveAppToDb(fiduciaryId, name, email, phone, dpaReference, processingPurposes);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_app":
                    if (appId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'app_id' and 'fiduciary_id' are required for 'update_app'.", req.getRequestURI());
                        return;
                    }
                    if (getAppFromDb(appId, fiduciaryId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "App with ID '" + appId + "' not found for Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                        return;
                    }

                    name = (String) input.get("name");
                    email = (String) input.get("email");
                    phone = (String) input.get("phone");
                    dpaReference = (String) input.get("dpa_reference");
                    processingPurposes = (String) input.get("processing_purposes");

                    if (name == null && email == null && phone == null && dpaReference == null &&
                            processingPurposes == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_app'.", req.getRequestURI());
                        return;
                    }

                   /* if (name != null && !name.isEmpty() && appExistsByNameForFiduciary(fiduciaryId, name)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Updated App name '" + name + "' conflicts with an existing app for this Fiduciary.", req.getRequestURI());
                        return;
                    }*/

                    output = updateAppInDb(appId, fiduciaryId, name, email, phone, dpaReference, processingPurposes);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_app": // Soft delete
                    if (appId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'app_id' and 'fiduciary_id' are required for 'delete_app'.", req.getRequestURI());
                        return;
                    }
                    if (getAppFromDb(appId, fiduciaryId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "App with ID '" + appId + "' not found for Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                        return;
                    }
                    deleteAppFromDb(appId, currentCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, null);
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for App Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for App Management ---

    /**
     * Checks if a fiduciary exists. (Ideally, this would be an API call to FiduciaryService in a microservices 5)
     */
    private boolean fiduciaryExists(UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM fiduciaries WHERE id = ? AND status = 'ACTIVE'";
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
     * Checks if a app with the given name already exists for a specific fiduciary.
     * @param fiduciaryId The ID of the fiduciary.
     * @param appName The name of the app to check.
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean appExistsByNameForFiduciary(UUID fiduciaryId, String appName) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM apps WHERE fiduciary_id = ? AND name = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);
        params.add(appName);

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
     * Retrieves a list of apps from the database with optional filtering and pagination.
     * @return JSONArray of app JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listAppsFromDb(UUID fiduciaryId, String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray appsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, fiduciary_id, name, email, phone, dpa_reference, processing_purposes, status, created_at, last_updated_at FROM apps WHERE status IS NOT NULL");
        List<Object> params = new ArrayList<>();

        if (fiduciaryId != null && !fiduciaryId.toString().isEmpty()) {
            sqlBuilder.append(" AND fiduciary_id = ?");
            params.add(fiduciaryId);
        }
        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (name LIKE ? OR email LIKE ? OR dpa_reference LIKE ?)");
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
                JSONObject app = new JSONObject();
                app.put("app_id", rs.getString("id"));
                app.put("fiduciary_id", rs.getString("fiduciary_id"));
                app.put("name", rs.getString("name"));
                app.put("email", rs.getString("email"));
                app.put("phone", rs.getString("phone"));
                app.put("dpa_reference", rs.getString("dpa_reference"));
                app.put("processing_purposes", rs.getString("processing_purposes"));
                app.put("status", rs.getString("status"));
                app.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                app.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                appsArray.add(app);
            }
        } catch (Exception e) {
            throw new SQLException("Failed to retrieve content from DB for app list: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return appsArray;
    }

    /**
     * Retrieves a single app by ID and fiduciary ID from the database.
     * @return An Optional containing the app JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getAppFromDb(UUID appId, UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, fiduciary_id, name, email, phone, dpa_reference, processing_purposes, status, created_at, last_updated_at FROM apps WHERE id = ? AND fiduciary_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject app = new JSONObject();
                app.put("app_id", rs.getString("id"));
                app.put("fiduciary_id", rs.getString("fiduciary_id"));
                app.put("name", rs.getString("name"));
                app.put("email", rs.getString("email"));
                app.put("phone", rs.getString("phone"));
                app.put("dpa_reference", rs.getString("dpa_reference"));
                app.put("processing_purposes", rs.getString("processing_purposes"));
                app.put("status", rs.getString("status"));
                app.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                app.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                return Optional.of(app);
            }
        } catch (Exception e) {
            throw new SQLException("Failed to retrieve content from DB for app: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Retrieves a single app by ID and fiduciary ID from the database.
     * @return An Optional containing the app JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    public String getAppName(UUID appId, UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT name FROM apps WHERE id = ? AND fiduciary_id = ?";
        String name = "";

        // To do: Cache Check
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                name =  rs.getString("name");
            }
        } catch (Exception e) {
            throw new SQLException("Failed to retrieve content from DB for app: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return name;
    }


    /**
     * Saves a new app to the database.
     * @return JSONObject containing the new app's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveAppToDb(UUID fiduciaryId, String name, String email, String phone, String dpaReference,
                                         String processingPurposes) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO apps (id, fiduciary_id, name, email, phone, dpa_reference, processing_purposes, status, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?,?,NOW(),NOW()) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, name);
            pstmt.setString(3, email);
            pstmt.setString(4, phone);
            pstmt.setString(5, dpaReference);
            pstmt.setString(6, processingPurposes);
            pstmt.setString(7, "ACTIVE");

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating app failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String appId = rs.getString(1);
                output.put("app_id", appId);
                output.put("name", name);
                output.put("fiduciary_id", fiduciaryId.toString());
                output.put("message", "App created successfully.");
            } else {
                throw new SQLException("Creating app failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing app in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateAppInDb(UUID appId, UUID fiduciaryId, String name, String email, String phone,String dpaReference, String processingPurposes) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE apps SET last_updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (email != null && !email.isEmpty()) { sqlBuilder.append(", email = ?"); params.add(email); }
        if (phone != null) { sqlBuilder.append(", phone = ?"); params.add(phone); }
        if (dpaReference != null) { sqlBuilder.append(", dpa_reference = ?"); params.add(dpaReference); }
        if (processingPurposes != null) { sqlBuilder.append(", processing_purposes = ?"); params.add(processingPurposes); }
        sqlBuilder.append(" WHERE id = ? AND fiduciary_id = ?");
        params.add(appId);
        params.add(fiduciaryId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating app failed, app not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "App updated successfully."); }};
    }

    /**
     * Deletes an app from the database (soft delete).
     * @throws SQLException if a database access error occurs.
     */
    private void deleteAppFromDb(UUID appId, UUID deletedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE apps SET status = 'INACTIVE' WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting app failed, app not found or already deleted.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}