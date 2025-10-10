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
import java.util.regex.Pattern; // For domain validation, if needed

/**
 * ProcessorService class for managing Data Processor profiles.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Data Processor Management module
 * of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'processors'.
 * - Columns: id (UUID PK), fiduciary_id (UUID), name (VARCHAR), contact_person (VARCHAR),
 * email (VARCHAR), phone (VARCHAR), address (TEXT), jurisdiction (VARCHAR),
 * dpa_reference (VARCHAR), dpa_effective_date (DATE), dpa_expiry_date (DATE),
 * processing_purposes (JSONB), data_categories_processed (JSONB),
 * security_measures_description (TEXT), status (VARCHAR), created_at (TIMESTAMPZ),
 * created_by_user_id (UUID), last_updated_at (TIMESTAMPZ), last_updated_by_user_id (UUID),
 * deleted_at (TIMESTAMPZ), deleted_by_user_id (UUID).
 * - Assumes 'fiduciaries' and 'users' tables exist for FK references.
 */
public class Processor implements Action {

    // Regex for basic domain validation (simplified, if processor has a domain to validate)
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    /**
     * Handles all Data Processor Management operations via a single POST endpoint.
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
        UUID currentCmsUserId = UUID.fromString("00000000-0000-0000-0000-000000000001"); // Example Admin User ID

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters
            UUID processorId = null;
            String processorIdStr = (String) input.get("processor_id");
            if (processorIdStr != null && !processorIdStr.isEmpty()) {
                try {
                    processorId = UUID.fromString(processorIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'processor_id' format.", req.getRequestURI());
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
                case "list_processors":
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");
                    // fiduciaryId is required for listing processors
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'list_processors'.", req.getRequestURI());
                        return;
                    }
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listProcessorsFromDb(fiduciaryId, statusFilter, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_processor":
                    if (processorId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'processor_id' and 'fiduciary_id' are required for 'get_processor'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> processorOptional = getProcessorFromDb(processorId, fiduciaryId);
                    if (processorOptional.isPresent()) {
                        output = processorOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Data Processor with ID '" + processorId + "' not found for Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                    }
                    break;

                case "create_processor":
                    String name = (String) input.get("name");
                    String contactPerson = (String) input.get("contact_person");
                    String email = (String) input.get("email");
                    String phone = (String) input.get("phone");
                    String address = (String) input.get("address");
                    String jurisdiction = (String) input.get("jurisdiction");
                    String dpaReference = (String) input.get("dpa_reference");
                    String dpaEffectiveDateStr = (String) input.get("dpa_effective_date");
                    String dpaExpiryDateStr = (String) input.get("dpa_expiry_date");
                    JSONArray processingPurposesJson = (JSONArray) input.get("processing_purposes");
                    JSONArray dataCategoriesProcessedJson = (JSONArray) input.get("data_categories_processed");
                    String securityMeasures = (String) input.get("security_measures_description");

                    if (fiduciaryId == null || name == null || name.isEmpty() || processingPurposesJson == null || processingPurposesJson.isEmpty() || dataCategoriesProcessedJson == null || dataCategoriesProcessedJson.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (fiduciary_id, name, processing_purposes, data_categories_processed) for 'create_processor'.", req.getRequestURI());
                        return;
                    }
                    if (!fiduciaryExists(fiduciaryId)) { // Helper to check if fiduciary exists
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                        return;
                    }
                    if (processorExistsByNameForFiduciary(fiduciaryId, name, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Processor with name '" + name + "' already exists for this Fiduciary.", req.getRequestURI());
                        return;
                    }

                    Timestamp dpaEffectiveDate = (dpaEffectiveDateStr != null && !dpaEffectiveDateStr.isEmpty()) ? Timestamp.from(Instant.parse(dpaEffectiveDateStr)) : null;
                    Timestamp dpaExpiryDate = (dpaExpiryDateStr != null && !dpaExpiryDateStr.isEmpty()) ? Timestamp.from(Instant.parse(dpaExpiryDateStr)) : null;

                    output = saveProcessorToDb(fiduciaryId, name, contactPerson, email, phone, address, jurisdiction, dpaReference,
                            dpaEffectiveDate, dpaExpiryDate, processingPurposesJson, dataCategoriesProcessedJson,
                            securityMeasures, "ACTIVE", currentCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_processor":
                    if (processorId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'processor_id' and 'fiduciary_id' are required for 'update_processor'.", req.getRequestURI());
                        return;
                    }
                    if (getProcessorFromDb(processorId, fiduciaryId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Data Processor with ID '" + processorId + "' not found for Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                        return;
                    }

                    name = (String) input.get("name");
                    contactPerson = (String) input.get("contact_person");
                    email = (String) input.get("email");
                    phone = (String) input.get("phone");
                    address = (String) input.get("address");
                    jurisdiction = (String) input.get("jurisdiction");
                    dpaReference = (String) input.get("dpa_reference");
                    dpaEffectiveDateStr = (String) input.get("dpa_effective_date");
                    dpaExpiryDateStr = (String) input.get("dpa_expiry_date");
                    processingPurposesJson = (JSONArray) input.get("processing_purposes");
                    dataCategoriesProcessedJson = (JSONArray) input.get("data_categories_processed");
                    securityMeasures = (String) input.get("security_measures_description");
                    statusFilter = (String) input.get("status");

                    if (name == null && contactPerson == null && email == null && phone == null && address == null &&
                            jurisdiction == null && dpaReference == null && dpaEffectiveDateStr == null && dpaExpiryDateStr == null &&
                            processingPurposesJson == null && dataCategoriesProcessedJson == null && securityMeasures == null && statusFilter == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_processor'.", req.getRequestURI());
                        return;
                    }

                    if (name != null && !name.isEmpty() && processorExistsByNameForFiduciary(fiduciaryId, name, processorId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Updated Processor name '" + name + "' conflicts with an existing processor for this Fiduciary.", req.getRequestURI());
                        return;
                    }

                    dpaEffectiveDate = (dpaEffectiveDateStr != null && !dpaEffectiveDateStr.isEmpty()) ? Timestamp.from(Instant.parse(dpaEffectiveDateStr)) : null;
                    dpaExpiryDate = (dpaExpiryDateStr != null && !dpaExpiryDateStr.isEmpty()) ? Timestamp.from(Instant.parse(dpaExpiryDateStr)) : null;

                    output = updateProcessorInDb(processorId, fiduciaryId, name, contactPerson, email, phone, address, jurisdiction, dpaReference,
                            dpaEffectiveDate, dpaExpiryDate, processingPurposesJson, dataCategoriesProcessedJson,
                            securityMeasures, statusFilter, currentCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_processor": // Soft delete
                    if (processorId == null || fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'processor_id' and 'fiduciary_id' are required for 'delete_processor'.", req.getRequestURI());
                        return;
                    }
                    if (getProcessorFromDb(processorId, fiduciaryId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Data Processor with ID '" + processorId + "' not found for Fiduciary ID '" + fiduciaryId + "'.", req.getRequestURI());
                        return;
                    }
                    deleteProcessorFromDb(processorId, currentCmsUserId);
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Processor Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Processor Management ---

    /**
     * Checks if a fiduciary exists. (Ideally, this would be an API call to FiduciaryService in a microservices setup)
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
     * Checks if a processor with the given name already exists for a specific fiduciary.
     * @param fiduciaryId The ID of the fiduciary.
     * @param processorName The name of the processor to check.
     * @param excludeProcessorId Optional UUID to exclude from the check (for update operations).
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean processorExistsByNameForFiduciary(UUID fiduciaryId, String processorName, UUID excludeProcessorId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM processors WHERE fiduciary_id = ? AND name = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);
        params.add(processorName);

        if (excludeProcessorId != null) {
            sqlBuilder.append(" AND id != ?");
            params.add(excludeProcessorId);
        }
        sqlBuilder.append(" AND deleted_at IS NULL"); // Only consider non-deleted processors

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
     * Retrieves a list of processors from the database with optional filtering and pagination.
     * @return JSONArray of processor JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listProcessorsFromDb(UUID fiduciaryId, String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray processorsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, fiduciary_id, name, contact_person, email, phone, address, jurisdiction, dpa_reference, dpa_effective_date, dpa_expiry_date, processing_purposes, data_categories_processed, security_measures_description, status, created_at, last_updated_at FROM processors WHERE fiduciary_id = ? AND deleted_at IS NULL");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (name ILIKE ? OR email ILIKE ? OR dpa_reference ILIKE ?)");
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
                JSONObject processor = new JSONObject();
                processor.put("processor_id", rs.getString("id"));
                processor.put("fiduciary_id", rs.getString("fiduciary_id"));
                processor.put("name", rs.getString("name"));
                processor.put("contact_person", rs.getString("contact_person"));
                processor.put("email", rs.getString("email"));
                processor.put("phone", rs.getString("phone"));
                processor.put("address", rs.getString("address"));
                processor.put("jurisdiction", rs.getString("jurisdiction"));
                processor.put("dpa_reference", rs.getString("dpa_reference"));
                processor.put("dpa_effective_date", rs.getDate("dpa_effective_date") != null ? rs.getDate("dpa_effective_date").toLocalDate().toString() : null);
                processor.put("dpa_expiry_date", rs.getDate("dpa_expiry_date") != null ? rs.getDate("dpa_expiry_date").toLocalDate().toString() : null);
                processor.put("processing_purposes", new JSONParser().parse(rs.getString("processing_purposes")));
                processor.put("data_categories_processed", new JSONParser().parse(rs.getString("data_categories_processed")));
                processor.put("security_measures_description", rs.getString("security_measures_description"));
                processor.put("status", rs.getString("status"));
                processor.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                processor.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                processorsArray.add(processor);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for processor list: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return processorsArray;
    }

    /**
     * Retrieves a single processor by ID and fiduciary ID from the database.
     * @return An Optional containing the processor JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getProcessorFromDb(UUID processorId, UUID fiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, fiduciary_id, name, contact_person, email, phone, address, jurisdiction, dpa_reference, dpa_effective_date, dpa_expiry_date, processing_purposes, data_categories_processed, security_measures_description, status, created_at, last_updated_at FROM processors WHERE id = ? AND fiduciary_id = ? AND deleted_at IS NULL";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, processorId);
            pstmt.setObject(2, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject processor = new JSONObject();
                processor.put("processor_id", rs.getString("id"));
                processor.put("fiduciary_id", rs.getString("fiduciary_id"));
                processor.put("name", rs.getString("name"));
                processor.put("contact_person", rs.getString("contact_person"));
                processor.put("email", rs.getString("email"));
                processor.put("phone", rs.getString("phone"));
                processor.put("address", rs.getString("address"));
                processor.put("jurisdiction", rs.getString("jurisdiction"));
                processor.put("dpa_reference", rs.getString("dpa_reference"));
                processor.put("dpa_effective_date", rs.getDate("dpa_effective_date") != null ? rs.getDate("dpa_effective_date").toLocalDate().toString() : null);
                processor.put("dpa_expiry_date", rs.getDate("dpa_expiry_date") != null ? rs.getDate("dpa_expiry_date").toLocalDate().toString() : null);
                processor.put("processing_purposes", new JSONParser().parse(rs.getString("processing_purposes")));
                processor.put("data_categories_processed", new JSONParser().parse(rs.getString("data_categories_processed")));
                processor.put("security_measures_description", rs.getString("security_measures_description"));
                processor.put("status", rs.getString("status"));
                processor.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                processor.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                return Optional.of(processor);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for processor: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new processor to the database.
     * @return JSONObject containing the new processor's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveProcessorToDb(UUID fiduciaryId, String name, String contactPerson, String email, String phone, String address,
                                         String jurisdiction, String dpaReference, Timestamp dpaEffectiveDate, Timestamp dpaExpiryDate,
                                         JSONArray processingPurposes, JSONArray dataCategoriesProcessed, String securityMeasures,
                                         String status, UUID createdByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO processors (id, fiduciary_id, name, contact_person, email, phone, address, jurisdiction, dpa_reference, dpa_effective_date, dpa_expiry_date, processing_purposes, data_categories_processed, security_measures_description, status, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, NOW(), NOW()) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, name);
            pstmt.setString(3, contactPerson);
            pstmt.setString(4, email);
            pstmt.setString(5, phone);
            pstmt.setString(6, address);
            pstmt.setString(7, jurisdiction);
            pstmt.setString(8, dpaReference);
            pstmt.setTimestamp(9, dpaEffectiveDate);
            pstmt.setTimestamp(10, dpaExpiryDate);
            pstmt.setString(11, processingPurposes.toJSONString());
            pstmt.setString(12, dataCategoriesProcessed.toJSONString());
            pstmt.setString(13, securityMeasures);
            pstmt.setString(14, status);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating processor failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String processorId = rs.getString(1);
                output.put("processor_id", processorId);
                output.put("name", name);
                output.put("fiduciary_id", fiduciaryId.toString());
                output.put("message", "Processor created successfully.");
            } else {
                throw new SQLException("Creating processor failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing processor in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateProcessorInDb(UUID processorId, UUID fiduciaryId, String name, String contactPerson, String email, String phone, String address,
                                           String jurisdiction, String dpaReference, Timestamp dpaEffectiveDate, Timestamp dpaExpiryDate,
                                           JSONArray processingPurposes, JSONArray dataCategoriesProcessed, String securityMeasures,
                                           String status, UUID updatedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE processors SET last_updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (contactPerson != null) { sqlBuilder.append(", contact_person = ?"); params.add(contactPerson); }
        if (email != null && !email.isEmpty()) { sqlBuilder.append(", email = ?"); params.add(email); }
        if (phone != null) { sqlBuilder.append(", phone = ?"); params.add(phone); }
        if (address != null) { sqlBuilder.append(", address = ?"); params.add(address); }
        if (jurisdiction != null && !jurisdiction.isEmpty()) { sqlBuilder.append(", jurisdiction = ?"); params.add(jurisdiction); }
        if (dpaReference != null) { sqlBuilder.append(", dpa_reference = ?"); params.add(dpaReference); }
        if (dpaEffectiveDate != null) { sqlBuilder.append(", dpa_effective_date = ?"); params.add(dpaEffectiveDate); }
        if (dpaExpiryDate != null) { sqlBuilder.append(", dpa_expiry_date = ?"); params.add(dpaExpiryDate); }
        if (processingPurposes != null) { sqlBuilder.append(", processing_purposes = ?::jsonb"); params.add(processingPurposes.toJSONString()); }
        if (dataCategoriesProcessed != null) { sqlBuilder.append(", data_categories_processed = ?::jsonb"); params.add(dataCategoriesProcessed.toJSONString()); }
        if (securityMeasures != null) { sqlBuilder.append(", security_measures_description = ?"); params.add(securityMeasures); }
        if (status != null && !status.isEmpty()) { sqlBuilder.append(", status = ?"); params.add(status); }

        sqlBuilder.append(" WHERE id = ? AND fiduciary_id = ? AND deleted_at IS NULL");
        params.add(processorId);
        params.add(fiduciaryId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating processor failed, processor not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Processor updated successfully."); }};
    }

    /**
     * Deletes a processor from the database (soft delete).
     * @throws SQLException if a database access error occurs.
     */
    private void deleteProcessorFromDb(UUID processorId, UUID deletedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE processors SET deleted_at = NOW(), deleted_by_user_id = ?, status = 'INACTIVE' WHERE id = ? AND deleted_at IS NULL";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, deletedByUserId);
            pstmt.setObject(2, processorId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting processor failed, processor not found or already deleted.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}