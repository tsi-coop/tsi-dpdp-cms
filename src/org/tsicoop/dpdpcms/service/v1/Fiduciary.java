package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
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
import java.util.regex.Pattern; // For domain validation, if needed


/**
 * FiduciaryService class for managing Data Fiduciary profiles.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Fiduciary Management module
 * of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'fiduciaries'.
 * - Columns: id (UUID PK), name (VARCHAR), contact_person (VARCHAR), email (VARCHAR),
 * phone (VARCHAR), address (TEXT), primary_domain (VARCHAR), cms_cname (VARCHAR),
 * dns_txt_record_token (VARCHAR), domain_validation_status (VARCHAR),
 * is_significant_data_fiduciary (BOOLEAN), dpo_user_id (UUID), dpb_registration_id (VARCHAR),
 * status (VARCHAR), created_at (TIMESTAMPZ), created_by_user_id (UUID),
 * last_updated_at (TIMESTAMPZ), last_updated_by_user_id (UUID),
 * deleted_at (TIMESTAMPZ), deleted_by_user_id (UUID).
 * - Assumes 'users' table exists for FK references to created_by_user_id etc.
 */
public class Fiduciary implements Action {

    // Regex for basic domain validation (simplified)
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");
    private static final Pattern CNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    /**
     * Handles all Data Fiduciary Management operations via a single POST endpoint.
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

            switch (func.toLowerCase()) {
                case "list_fiduciaries":
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listFiduciariesFromDb(statusFilter, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_fiduciary":
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'get_fiduciary' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> fiduciaryOptional = getFiduciaryFromDb(fiduciaryId);
                    if (fiduciaryOptional.isPresent()) {
                        output = fiduciaryOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Data Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "create_fiduciary":
                    String name = (String) input.get("name");
                    String contactPerson = (String) input.get("contact_person");
                    String email = (String) input.get("email");
                    String phone = (String) input.get("phone");
                    String address = (String) input.get("address");
                    String primaryDomain = (String) input.get("primary_domain");
                    String cmsCname = (String) input.get("cms_cname");
                    Boolean isSignificant = (Boolean) input.get("is_significant_data_fiduciary");
                    String dpoUserIdStr = (String) input.get("dpo_user_id"); // Optional
                    String dpbRegId = (String) input.get("dpb_registration_id"); // Optional

                    if (name == null || name.isEmpty() || email == null || email.isEmpty() || primaryDomain == null || primaryDomain.isEmpty() || cmsCname == null || cmsCname.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (name, email, primary_domain, cms_cname) for 'create_fiduciary'.", req.getRequestURI());
                        return;
                    }
                    if (!DOMAIN_PATTERN.matcher(primaryDomain).matches() || !CNAME_PATTERN.matcher(cmsCname).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid domain or CNAME format.", req.getRequestURI());
                        return;
                    }
                    if (fiduciaryExistsByNameOrDomain(name, primaryDomain, email, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Fiduciary with this name, domain or email already exists.", req.getRequestURI());
                        return;
                    }

                    UUID dpoUserId = (dpoUserIdStr != null && !dpoUserIdStr.isEmpty()) ? UUID.fromString(dpoUserIdStr) : null;
                    if (dpoUserId != null && !userExists(dpoUserId)) { // Helper to check if user exists
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Provided DPO User ID not found.", req.getRequestURI());
                        return;
                    }

                    // Generate a unique DNS TXT record token
                    String dnsTxtToken = "dpdp-verify-" + UUID.randomUUID().toString().substring(0, 8);

                    output = saveFiduciaryToDb(name, contactPerson, email, phone, address, primaryDomain, cmsCname, dnsTxtToken,
                            isSignificant != null ? isSignificant : false, dpoUserId, dpbRegId, "PENDING");
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_fiduciary":
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'update_fiduciary'.", req.getRequestURI());
                        return;
                    }
                    if (getFiduciaryFromDb(fiduciaryId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Data Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                        return;
                    }
                    name = (String) input.get("name");
                    contactPerson = (String) input.get("contact_person");
                    email = (String) input.get("email");
                    phone = (String) input.get("phone");
                    address = (String) input.get("address");
                    primaryDomain = (String) input.get("primary_domain");
                    cmsCname = (String) input.get("cms_cname");
                    isSignificant = (Boolean) input.get("is_significant_data_fiduciary");
                    dpoUserIdStr = (String) input.get("dpo_user_id");
                    dpbRegId = (String) input.get("dpb_registration_id");
                    statusFilter = (String) input.get("status"); // 'status' is the field name in JSON
                    if (name == null && contactPerson == null && email == null && phone == null && address == null &&
                            primaryDomain == null && cmsCname == null && isSignificant == null && dpoUserIdStr == null &&
                            dpbRegId == null && statusFilter == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_fiduciary'.", req.getRequestURI());
                        return;
                    }

                    if ((name != null && !name.isEmpty()) || (primaryDomain != null && !primaryDomain.isEmpty()) || (email != null && !email.isEmpty())) {
                        if (fiduciaryExistsByNameOrDomain(name, primaryDomain, email, fiduciaryId)) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Updated Fiduciary name, domain or email conflicts with an existing fiduciary.", req.getRequestURI());
                            return;
                        }
                    }
                    if (primaryDomain != null && !primaryDomain.isEmpty() && !DOMAIN_PATTERN.matcher(primaryDomain).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid primary_domain format for update.", req.getRequestURI());
                        return;
                    }
                    if (cmsCname != null && !cmsCname.isEmpty() && !CNAME_PATTERN.matcher(cmsCname).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid cms_cname format for update.", req.getRequestURI());
                        return;
                    }

                    dpoUserId = (dpoUserIdStr != null && !dpoUserIdStr.isEmpty()) ? UUID.fromString(dpoUserIdStr) : null;

                    if (dpoUserId != null && !userExists(dpoUserId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Provided DPO User ID not found for update.", req.getRequestURI());
                        return;
                    }
                    output = updateFiduciaryInDb(fiduciaryId, name, contactPerson, email, phone, address, primaryDomain, cmsCname,
                            isSignificant, dpoUserId, dpbRegId, statusFilter);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_fiduciary":
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'delete_fiduciary'.", req.getRequestURI());
                        return;
                    }
                    if (getFiduciaryFromDb(fiduciaryId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Data Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                        return;
                    }
                    deleteFiduciaryFromDb(fiduciaryId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, null);
                    break;

                case "validate_fiduciary_domain":
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'validate_domain'.", req.getRequestURI());
                        return;
                    }
                    if(System.getenv("TSI_DPDP_CMS_ENV").contains("local")){
                        String validationStatus = "VALIDATED";
                        updateFiduciaryDomainValidationStatus(fiduciaryId, validationStatus);
                        output = new JSONObject();
                        output.put("fiduciary_id", fiduciaryId.toString());
                        output.put("domain_validation_status", validationStatus);
                        output.put("message","Domain validation successful.");
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                        break;

                    }else {
                        Optional<JSONObject> fidToValidate = getFiduciaryFromDb(fiduciaryId);
                        if (fidToValidate.isEmpty()) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Data Fiduciary with ID '" + fiduciaryId + "' not found for domain validation.", req.getRequestURI());
                            return;
                        }
                        String cmsCnameToValidate = (String) fidToValidate.get().get("cms_cname");
                        dnsTxtToken = (String) fidToValidate.get().get("dns_txt_record_token");

                        if (cmsCnameToValidate == null || cmsCnameToValidate.isEmpty() || dnsTxtToken == null || dnsTxtToken.isEmpty()) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "CMS CNAME or DNS TXT token not set for this Fiduciary. Please update Fiduciary profile first.", req.getRequestURI());
                            return;
                        }

                        // --- Call DNS verification utility ---
                        // This is a placeholder for actual DNS lookup logic
                        boolean isDnsTxtVerified = DnsVerifier.verifyDnsTxtRecord(cmsCnameToValidate, "dpdp-verify=" + dnsTxtToken);
                        // --- End DNS verification call ---

                        String validationStatus = isDnsTxtVerified ? "VALIDATED" : "FAILED";
                        updateFiduciaryDomainValidationStatus(fiduciaryId, validationStatus);
                        output = new JSONObject();
                        output.put("fiduciary_id", fiduciaryId.toString());
                        output.put("domain_validation_status", validationStatus);
                        output.put("message", isDnsTxtVerified ? "Domain validation successful." : "Domain validation failed. Please check your DNS TXT record.");
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid UUID format in input: " + e.getMessage(), req.getRequestURI());
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Fiduciary Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Fiduciary Management ---

    /**
     * Checks if a fiduciary exists by name, primary domain, or email (for uniqueness).
     * @param name The fiduciary name to check.
     * @param primaryDomain The primary domain to check.
     * @param email The email to check.
     * @param excludeFiduciaryId Optional UUID to exclude from the check (for update operations).
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean fiduciaryExistsByNameOrDomain(String name, String primaryDomain, String email, UUID excludeFiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM fiduciaries WHERE (1=0"); // Start with 1=0 to easily append OR clauses
        List<Object> params = new ArrayList<>();

        if (name != null && !name.isEmpty()) {
            sqlBuilder.append(" OR name = ?");
            params.add(name);
        }
        if (primaryDomain != null && !primaryDomain.isEmpty()) {
            sqlBuilder.append(" OR primary_domain = ?");
            params.add(primaryDomain);
        }
        if (email != null && !email.isEmpty()) {
            sqlBuilder.append(" OR email = ?");
            params.add(email);
        }
        sqlBuilder.append(")"); // Close the OR group

        if (excludeFiduciaryId != null) {
            sqlBuilder.append(" AND id != ?");
            params.add(excludeFiduciaryId);
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
     * Helper to check if a user (DPO) exists by ID.
     * (Ideally, this would be an API call to UserService in a microservices 5)
     */
    private boolean userExists(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM users WHERE id = ? AND deleted_at IS NULL";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, userId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Retrieves a list of fiduciaries from the database with optional filtering and pagination.
     * @return JSONArray of fiduciary JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listFiduciariesFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray fiduciariesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, name, contact_person, email, primary_domain, cms_cname, domain_validation_status, is_significant_data_fiduciary, status, created_at, last_updated_at FROM fiduciaries WHERE status is not null");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }

        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (name LIKE ? OR primary_domain LIKE ? OR email LIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        //System.out.println(sqlBuilder.toString());

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject fiduciary = new JSONObject();
                fiduciary.put("fiduciary_id", rs.getString("id"));
                fiduciary.put("name", rs.getString("name"));
                fiduciary.put("contact_person", rs.getString("contact_person"));
                fiduciary.put("email", rs.getString("email"));
                fiduciary.put("primary_domain", rs.getString("primary_domain"));
                fiduciary.put("cms_cname", rs.getString("cms_cname"));
                fiduciary.put("domain_validation_status", rs.getString("domain_validation_status"));
                fiduciary.put("is_significant_data_fiduciary", rs.getBoolean("is_significant_data_fiduciary"));
                fiduciary.put("status", rs.getString("status"));
                fiduciary.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                fiduciary.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                fiduciariesArray.add(fiduciary);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return fiduciariesArray;
    }

    /**
     * Retrieves a single fiduciary by ID from the database.
     * @return An Optional containing the fiduciary JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getFiduciaryFromDb(UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, name, contact_person, email, phone, address, primary_domain, cms_cname, dns_txt_record_token, domain_validation_status, is_significant_data_fiduciary, status, created_at, last_updated_at FROM fiduciaries WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject fiduciary = new JSONObject();
                fiduciary.put("fiduciary_id", rs.getString("id"));
                fiduciary.put("name", rs.getString("name"));
                fiduciary.put("contact_person", rs.getString("contact_person"));
                fiduciary.put("email", rs.getString("email"));
                fiduciary.put("phone", rs.getString("phone"));
                fiduciary.put("address", rs.getString("address"));
                fiduciary.put("primary_domain", rs.getString("primary_domain"));
                fiduciary.put("cms_cname", rs.getString("cms_cname"));
                fiduciary.put("dns_txt_record_token", rs.getString("dns_txt_record_token"));
                fiduciary.put("domain_validation_status", rs.getString("domain_validation_status"));
                fiduciary.put("is_significant_data_fiduciary", rs.getBoolean("is_significant_data_fiduciary"));
                fiduciary.put("status", rs.getString("status"));
                fiduciary.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                fiduciary.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                return Optional.of(fiduciary);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new fiduciary to the database.
     * @return JSONObject containing the new fiduciary's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveFiduciaryToDb(String name, String contactPerson, String email, String phone, String address,
                                         String primaryDomain, String cmsCname, String dnsTxtToken,
                                         boolean isSignificant, UUID dpoUserId, String dpbRegId, String status) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO fiduciaries (id, name, contact_person, email, phone, address, primary_domain, cms_cname, dns_txt_record_token, domain_validation_status, is_significant_data_fiduciary, status, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW()) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, name);
            pstmt.setString(2, contactPerson);
            pstmt.setString(3, email);
            pstmt.setString(4, phone);
            pstmt.setString(5, address);
            pstmt.setString(6, primaryDomain);
            pstmt.setString(7, cmsCname);
            pstmt.setString(8, dnsTxtToken);
            pstmt.setString(9, "PENDING"); // Initial validation status
            pstmt.setBoolean(10, isSignificant);
            pstmt.setString(11, status);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating fiduciary failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String fiduciaryId = rs.getString(1);
                output.put("fiduciary_id", fiduciaryId);
                output.put("name", name);
                output.put("primary_domain", primaryDomain);
                output.put("cms_cname", cmsCname);
                output.put("dns_txt_record_token", dnsTxtToken); // Return token for admin to provide to fiduciary
                output.put("domain_validation_status", "PENDING");
                output.put("message", "Fiduciary created successfully. Please add the DNS TXT record for validation.");
            } else {
                throw new SQLException("Creating fiduciary failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing fiduciary in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateFiduciaryInDb(UUID fiduciaryId, String name, String contactPerson, String email, String phone, String address,
                                           String primaryDomain, String cmsCname, Boolean isSignificant, UUID dpoUserId, String dpbRegId, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE fiduciaries SET last_updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (contactPerson != null) { sqlBuilder.append(", contact_person = ?"); params.add(contactPerson); }
        if (email != null && !email.isEmpty()) { sqlBuilder.append(", email = ?"); params.add(email); }
        if (phone != null) { sqlBuilder.append(", phone = ?"); params.add(phone); }
        if (address != null) { sqlBuilder.append(", address = ?"); params.add(address); }
        if (primaryDomain != null && !primaryDomain.isEmpty()) { sqlBuilder.append(", primary_domain = ?"); params.add(primaryDomain); }
        if (cmsCname != null && !cmsCname.isEmpty()) { sqlBuilder.append(", cms_cname = ?"); params.add(cmsCname); }
        if (isSignificant != null) { sqlBuilder.append(", is_significant_data_fiduciary = ?"); params.add(isSignificant); }
        if (dpoUserId != null) { sqlBuilder.append(", dpo_user_id = ?"); params.add(dpoUserId); }
        if (dpbRegId != null) { sqlBuilder.append(", dpb_registration_id = ?"); params.add(dpbRegId); }
        if (status != null && !status.isEmpty()) { sqlBuilder.append(", status = ?"); params.add(status); }

        sqlBuilder.append(" WHERE id = ?");
        params.add(fiduciaryId);
        //System.out.println(sqlBuilder.toString());

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating fiduciary failed, fiduciary not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Fiduciary updated successfully."); }};
    }

    /**
     * Updates the domain validation status of a fiduciary.
     * @throws SQLException if a database access error occurs.
     */
    private void updateFiduciaryDomainValidationStatus(UUID fiduciaryId, String validationStatus) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE fiduciaries SET domain_validation_status = ?, last_updated_at = NOW() WHERE id = ? AND deleted_at IS NULL";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, validationStatus);
            pstmt.setObject(2, fiduciaryId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating fiduciary domain validation status failed, fiduciary not found.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Deletes a fiduciary from the database (soft delete).
     * @throws SQLException if a database access error occurs.
     */
    private void deleteFiduciaryFromDb(UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE fiduciaries SET status = 'INACTIVE' WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting fiduciary failed, fiduciary not found or already deleted.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}