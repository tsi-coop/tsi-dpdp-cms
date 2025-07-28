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
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

// Assuming external HTTP client for DPB API calls
// import org.tsicoop.dpdpcms.external.DpbApiClient; // Placeholder for DPB API client

/**
 * RegulatoryService class for managing communication and reporting with the Data Protection Board (DPB).
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Register Data Fiduciary with Data Protection Board
 * module of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'dpb_registrations' (not directly in init.sql, but implied by functional design).
 * - Columns: id (UUID PK), fiduciary_id (UUID), dpb_registration_id (VARCHAR),
 * dpb_endpoint_url (TEXT), client_certificate (TEXT), private_key (TEXT),
 * status (VARCHAR), last_successful_communication_at (TIMESTAMPZ),
 * created_at (TIMESTAMPZ), created_by_user_id (UUID), last_updated_at (TIMESTAMPZ), last_updated_by_user_id (UUID).
 * - Table is named 'dpb_report_submissions' (not directly in init.sql, but implied).
 * - Columns: id (UUID PK), registration_id (UUID), report_type (VARCHAR),
 * submission_timestamp (TIMESTAMPZ), status (VARCHAR), confirmation_receipt (TEXT),
 * error_details (TEXT), submitted_by_user_id (UUID).
 * - Assumes 'fiduciaries' and 'users' tables exist for FK references and lookups.
 * - Assumes external DpbApiClient for actual DPB API calls (including Mutual TLS).
 */
public class DPB implements REST {

    // All HTTP methods will now defer to the POST method
    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
    }

    /**
     * Handles all Regulatory Management operations via a single POST endpoint.
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

            // Extract common parameters
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

            UUID registrationId = null;
            String registrationIdStr = (String) input.get("registration_id");
            if (registrationIdStr != null && !registrationIdStr.isEmpty()) {
                try {
                    registrationId = UUID.fromString(registrationIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'registration_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                // --- DPB Registration Management ---
                case "create_dpb_registration":
                    String dpbRegId = (String) input.get("dpb_registration_id"); // DPB-provided ID
                    String dpbEndpointUrl = (String) input.get("dpb_endpoint_url");
                    String clientCert = (String) input.get("client_certificate"); // PEM format
                    String privateKey = (String) input.get("private_key"); // PEM format

                    if (fiduciaryId == null || dpbRegId == null || dpbRegId.isEmpty() || dpbEndpointUrl == null || dpbEndpointUrl.isEmpty() || clientCert == null || clientCert.isEmpty() || privateKey == null || privateKey.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields for 'create_dpb_registration'.", req.getRequestURI());
                        return;
                    }
                    if (!fiduciaryExists(fiduciaryId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                        return;
                    }
                    if (dpbRegistrationExists(fiduciaryId, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "DPB registration already exists for Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                        return;
                    }

                    output = saveDpbRegistrationToDb(fiduciaryId, dpbRegId, dpbEndpointUrl, clientCert, privateKey, "PENDING", actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_dpb_registration":
                    if (registrationId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'registration_id' is required for 'update_dpb_registration'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> existingReg = getDpbRegistrationFromDb(registrationId);
                    if (existingReg.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "DPB registration with ID '" + registrationId + "' not found.", req.getRequestURI());
                        return;
                    }

                    dpbRegId = (String) input.get("dpb_registration_id");
                    dpbEndpointUrl = (String) input.get("dpb_endpoint_url");
                    clientCert = (String) input.get("client_certificate");
                    privateKey = (String) input.get("private_key");
                    String status = (String) input.get("status");

                    if (dpbRegId == null && dpbEndpointUrl == null && clientCert == null && privateKey == null && status == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_dpb_registration'.", req.getRequestURI());
                        return;
                    }

                    output = updateDpbRegistrationInDb(registrationId, dpbRegId, dpbEndpointUrl, clientCert, privateKey, status, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "get_dpb_registration":
                    if (registrationId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'registration_id' is required for 'get_dpb_registration'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> regOptional = getDpbRegistrationFromDb(registrationId);
                    if (regOptional.isPresent()) {
                        output = regOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "DPB registration with ID '" + registrationId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "list_dpb_registrations":
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listDpbRegistrationsFromDb(statusFilter, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "test_dpb_connection":
                    if (registrationId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'registration_id' is required for 'test_dpb_connection'.", req.getRequestURI());
                        return;
                    }
                    existingReg = getDpbRegistrationFromDb(registrationId);
                    if (existingReg.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "DPB registration with ID '" + registrationId + "' not found.", req.getRequestURI());
                        return;
                    }
                    JSONObject regDetails = existingReg.get();
                    String endpoint = (String) regDetails.get("dpb_endpoint_url");
                    String cert = (String) regDetails.get("client_certificate");
                    String key = (String) regDetails.get("private_key");

                    // --- Placeholder for actual DPB API client test ---
                    // DpbApiClient dpbClient = new DpbApiClient(endpoint, cert, key);
                    boolean connectionTestSuccess = false;
                    String testMessage = "Connection test initiated.";
                    try {
                        // connectionTestSuccess = dpbClient.testConnection(); // Actual test
                        connectionTestSuccess = true; // Mock success
                        testMessage = "DPB connection test successful.";
                    } catch (Exception e) {
                        testMessage = "DPB connection test failed: " + e.getMessage();
                        System.err.println(testMessage);
                    }
                    // --- End Placeholder ---

                    updateDpbRegistrationStatus(registrationId, connectionTestSuccess ? "REGISTERED" : "FAILED", actionByCmsUserId); // Update status based on test
                    output = new JSONObject();
                    output.put("registration_id", registrationId.toString());
                    output.put("connection_status", connectionTestSuccess ? "SUCCESS" : "FAILED");
                    output.put("message", testMessage);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                // --- DPB Report Submission ---
                case "submit_dpb_report":
                    if (registrationId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'registration_id' is required for 'submit_dpb_report'.", req.getRequestURI());
                        return;
                    }
                    existingReg = getDpbRegistrationFromDb(registrationId);
                    if (existingReg.isEmpty() || !"REGISTERED".equalsIgnoreCase((String)existingReg.get().get("status"))) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "DPB registration not found or not in 'REGISTERED' status for submission.", req.getRequestURI());
                        return;
                    }

                    String reportType = (String) input.get("report_type"); // e.g., "BREACH_NOTIFICATION", "COMPLIANCE_REPORT"
                    JSONObject reportData = (JSONObject) input.get("report_data"); // The actual report payload

                    if (reportType == null || reportType.isEmpty() || reportData == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (report_type, report_data) for 'submit_dpb_report'.", req.getRequestURI());
                        return;
                    }

                    // --- Placeholder for actual DPB API client submission ---
                    // DpbApiClient dpbClient = new DpbApiClient(endpoint, cert, key); // Use client from existingReg
                    String submissionStatus = "FAILED";
                    String confirmationReceipt = null;
                    String errorDetails = null;
                    try {
                        // confirmationReceipt = dpbClient.submitReport(reportType, reportData); // Actual submission
                        confirmationReceipt = "DPB_CONF_" + UUID.randomUUID().toString().substring(0, 8); // Mock receipt
                        submissionStatus = "SUBMITTED";
                    } catch (Exception e) {
                        errorDetails = e.getMessage();
                        System.err.println("DnsVerifier: Failed to submit report: " + errorDetails);
                    }
                    // --- End Placeholder ---

                    output = saveDpbReportSubmissionToDb(registrationId, reportType, submissionStatus, confirmationReceipt, errorDetails, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "list_dpb_submissions":
                    String submissionReportTypeFilter = (String) input.get("report_type_filter");
                    String submissionStatusFilter = (String) input.get("status_filter");
                    page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listDpbSubmissionsFromDb(registrationId, submissionReportTypeFilter, submissionStatusFilter, page, limit);
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Regulatory Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Regulatory Management ---

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
     * Checks if a DPB registration already exists for a fiduciary.
     */
    private boolean dpbRegistrationExists(UUID fiduciaryId, UUID excludeRegistrationId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM dpb_registrations WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (excludeRegistrationId != null) {
            sqlBuilder.append(" AND id != ?");
            params.add(excludeRegistrationId);
        }

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
     * Saves a new DPB registration to the database.
     * @return JSONObject containing the new registration's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveDpbRegistrationToDb(UUID fiduciaryId, String dpbRegistrationId, String dpbEndpointUrl, String clientCert, String privateKey, String status, UUID createdByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO dpb_registrations (id, fiduciary_id, dpb_registration_id, dpb_endpoint_url, client_certificate, private_key, status, created_at, created_by_user_id, last_updated_at, last_updated_by_user_id) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, NOW(), ?, NOW(), ?) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, dpbRegistrationId);
            pstmt.setString(3, dpbEndpointUrl);
            pstmt.setString(4, clientCert); // Store securely (encrypted) in real system
            pstmt.setString(5, privateKey); // Store securely (encrypted) in real system
            pstmt.setString(6, status);
            pstmt.setObject(7, createdByUserId);
            pstmt.setObject(8, createdByUserId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating DPB registration failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String regId = rs.getString(1);
                output.put("registration_id", regId);
                output.put("fiduciary_id", fiduciaryId.toString());
                output.put("dpb_registration_id", dpbRegistrationId);
                output.put("message", "DPB registration created successfully.");
            } else {
                throw new SQLException("Creating DPB registration failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing DPB registration in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateDpbRegistrationInDb(UUID registrationId, String dpbRegistrationId, String dpbEndpointUrl, String clientCert, String privateKey, String status, UUID updatedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE dpb_registrations SET last_updated_at = NOW(), last_updated_by_user_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(updatedByUserId);

        if (dpbRegistrationId != null && !dpbRegistrationId.isEmpty()) { sqlBuilder.append(", dpb_registration_id = ?"); params.add(dpbRegistrationId); }
        if (dpbEndpointUrl != null && !dpbEndpointUrl.isEmpty()) { sqlBuilder.append(", dpb_endpoint_url = ?"); params.add(dpbEndpointUrl); }
        if (clientCert != null && !clientCert.isEmpty()) { sqlBuilder.append(", client_certificate = ?"); params.add(clientCert); }
        if (privateKey != null && !privateKey.isEmpty()) { sqlBuilder.append(", private_key = ?"); params.add(privateKey); }
        if (status != null && !status.isEmpty()) { sqlBuilder.append(", status = ?"); params.add(status); }

        sqlBuilder.append(" WHERE id = ?");
        params.add(registrationId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating DPB registration failed, registration not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "DPB registration updated successfully."); }};
    }

    /**
     * Updates the status of a DPB registration.
     * @throws SQLException if a database access error occurs.
     */
    private void updateDpbRegistrationStatus(UUID registrationId, String newStatus, UUID updatedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE dpb_registrations SET status = ?, last_updated_at = NOW(), last_updated_by_user_id = ?, last_successful_communication_at = NOW() WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, newStatus);
            pstmt.setObject(2, updatedByUserId);
            pstmt.setObject(3, registrationId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating DPB registration status failed, registration not found.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Retrieves a DPB registration by ID from the database.
     * @return An Optional containing the registration JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getDpbRegistrationFromDb(UUID registrationId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, fiduciary_id, dpb_registration_id, dpb_endpoint_url, client_certificate, private_key, status, last_successful_communication_at, created_at, created_by_user_id, last_updated_at, last_updated_by_user_id FROM dpb_registrations WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, registrationId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject registration = new JSONObject();
                registration.put("registration_id", rs.getString("id"));
                registration.put("fiduciary_id", rs.getString("fiduciary_id"));
                registration.put("dpb_registration_id", rs.getString("dpb_registration_id"));
                registration.put("dpb_endpoint_url", rs.getString("dpb_endpoint_url"));
                // WARNING: Do NOT expose client_certificate and private_key directly via API in real system
                registration.put("client_certificate", rs.getString("client_certificate"));
                registration.put("private_key", rs.getString("private_key"));
                registration.put("status", rs.getString("status"));
                registration.put("last_successful_communication_at", rs.getTimestamp("last_successful_communication_at") != null ? rs.getTimestamp("last_successful_communication_at").toInstant().toString() : null);
                registration.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                registration.put("created_by_user_id", rs.getString("created_by_user_id"));
                registration.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                registration.put("last_updated_by_user_id", rs.getString("last_updated_by_user_id"));
                return Optional.of(registration);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Retrieves a list of DPB registrations from the database with optional filtering and pagination.
     * @return JSONArray of registration JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listDpbRegistrationsFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray registrationsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, fiduciary_id, dpb_registration_id, dpb_endpoint_url, status, last_successful_communication_at, created_at, last_updated_at FROM dpb_registrations WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (dpb_registration_id ILIKE ? OR dpb_endpoint_url ILIKE ?)");
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
                JSONObject registration = new JSONObject();
                registration.put("registration_id", rs.getString("id"));
                registration.put("fiduciary_id", rs.getString("fiduciary_id"));
                registration.put("dpb_registration_id", rs.getString("dpb_registration_id"));
                registration.put("dpb_endpoint_url", rs.getString("dpb_endpoint_url"));
                registration.put("status", rs.getString("status"));
                registration.put("last_successful_communication_at", rs.getTimestamp("last_successful_communication_at") != null ? rs.getTimestamp("last_successful_communication_at").toInstant().toString() : null);
                registration.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                registration.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                registrationsArray.add(registration);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return registrationsArray;
    }

    /**
     * Saves a new DPB report submission record to the database.
     * @return JSONObject containing the new submission's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveDpbReportSubmissionToDb(UUID registrationId, String reportType, String status, String confirmationReceipt, String errorDetails, UUID submittedByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO dpb_report_submissions (id, registration_id, report_type, submission_timestamp, status, confirmation_receipt, error_details, submitted_by_user_id) VALUES (uuid_generate_v4(), ?, ?, NOW(), ?, ?, ?, ?) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setObject(1, registrationId);
            pstmt.setString(2, reportType);
            pstmt.setString(3, status);
            pstmt.setString(4, confirmationReceipt);
            pstmt.setString(5, errorDetails);
            pstmt.setObject(6, submittedByUserId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Saving DPB report submission failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String submissionId = rs.getString(1);
                output.put("submission_id", submissionId);
                output.put("message", "DPB report submission record saved successfully.");
            } else {
                throw new SQLException("Saving DPB report submission failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Retrieves a list of DPB report submissions from the database with optional filtering and pagination.
     * @return JSONArray of submission JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listDpbSubmissionsFromDb(UUID registrationId, String reportTypeFilter, String statusFilter, int page, int limit) throws SQLException {
        JSONArray submissionsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, registration_id, report_type, submission_timestamp, status, confirmation_receipt, error_details, submitted_by_user_id FROM dpb_report_submissions WHERE registration_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(registrationId);

        if (reportTypeFilter != null && !reportTypeFilter.isEmpty()) {
            sqlBuilder.append(" AND report_type = ?");
            params.add(reportTypeFilter);
        }
        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }

        sqlBuilder.append(" ORDER BY submission_timestamp DESC LIMIT ? OFFSET ?");
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
                JSONObject submission = new JSONObject();
                submission.put("submission_id", rs.getString("id"));
                submission.put("registration_id", rs.getString("registration_id"));
                submission.put("report_type", rs.getString("report_type"));
                submission.put("submission_timestamp", rs.getTimestamp("submission_timestamp").toInstant().toString());
                submission.put("status", rs.getString("status"));
                submission.put("confirmation_receipt", rs.getString("confirmation_receipt"));
                submission.put("error_details", rs.getString("error_details"));
                submission.put("submitted_by_user_id", rs.getString("submitted_by_user_id"));
                submissionsArray.add(submission);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return submissionsArray;
    }
}