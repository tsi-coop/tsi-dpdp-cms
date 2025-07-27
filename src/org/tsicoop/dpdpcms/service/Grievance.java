package org.tsicoop.dpdpcms.service;

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

/**
 * GrievanceService class for managing Data Principal grievances and requests.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Grievance Management module
 * of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'grievances'.
 * - Columns: id (UUID PK), user_id (VARCHAR), fiduciary_id (UUID), subject (VARCHAR),
 * description (TEXT), submission_timestamp (TIMESTAMPZ), status (VARCHAR),
 * assigned_dpo_user_id (UUID), resolution_details (TEXT), resolution_timestamp (TIMESTAMPZ),
 * communication_log (JSONB), attachments (JSONB), last_updated_at (TIMESTAMPZ),
 * last_updated_by_user_id (UUID), due_date (TIMESTAMPZ).
 * - Assumes 'fiduciaries' and 'users' tables exist for FK references.
 */
public class Grievance implements REST {

    // Define standard SLA for different grievance types (e.g., in days)
    private static final int DEFAULT_SLA_DAYS = 30; // DPDP Act typically gives 30 days
    private static final int ERASURE_SLA_DAYS = 7; // Example: Erasure might have shorter SLA

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
     * Handles all Grievance Management operations via a single POST endpoint.
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

        // Placeholder for current CMS user ID (from authentication context, if DPO/Admin)
        // This is the user performing the action on the grievance (e.g., assigning, resolving)
        UUID actionByCmsUserId = UUID.fromString("00000000-0000-0000-0000-000000000001"); // Example Admin User ID

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters
            UUID grievanceId = null;
            String grievanceIdStr = (String) input.get("grievance_id");
            if (grievanceIdStr != null && !grievanceIdStr.isEmpty()) {
                try {
                    grievanceId = UUID.fromString(grievanceIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'grievance_id' format.", req.getRequestURI());
                    return;
                }
            }

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
                case "submit_grievance":
                    String type = (String) input.get("type");
                    String subject = (String) input.get("subject");
                    String description = (String) input.get("description");
                    JSONArray attachmentsJson = (JSONArray) input.get("attachments"); // Array of file references
                    String language = (String) input.get("language"); // Language of submission

                    if (userId == null || userId.isEmpty() || fiduciaryId == null || type == null || type.isEmpty() || subject == null || subject.isEmpty() || description == null || description.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (user_id, fiduciary_id, type, subject, description) for 'submit_grievance'.", req.getRequestURI());
                        return;
                    }
                    if (!fiduciaryExists(fiduciaryId)) { // Helper to check if fiduciary exists
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Fiduciary with ID '" + fiduciaryId + "' not found.", req.getRequestURI());
                        return;
                    }

                    output = saveGrievanceToDb(userId, fiduciaryId, type, subject, description, attachmentsJson, language, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "get_grievance":
                    if (grievanceId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'grievance_id' is required for 'get_grievance'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> grievanceOptional = getGrievanceFromDb(grievanceId);
                    if (grievanceOptional.isPresent()) {
                        output = grievanceOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Grievance with ID '" + grievanceId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "list_grievances":
                    String statusFilter = (String) input.get("status");
                    String typeFilter = (String) input.get("type");
                    String assignedDpoIdStr = (String) input.get("assigned_dpo_user_id"); // For DPO dashboard
                    UUID assignedDpoId = null;
                    if (assignedDpoIdStr != null && !assignedDpoIdStr.isEmpty()) {
                        try { assignedDpoId = UUID.fromString(assignedDpoIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (assignedDpoIdStr != null && assignedDpoId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'assigned_dpo_user_id' format.", req.getRequestURI());
                        return;
                    }
                    String search = (String) input.get("search");
                    // fiduciaryId is required for listing grievances
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'list_grievances'.", req.getRequestURI());
                        return;
                    }
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listGrievancesFromDb(fiduciaryId, statusFilter, typeFilter, assignedDpoId, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "update_grievance_status":
                    if (grievanceId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'grievance_id' is required for 'update_grievance_status'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> existingGrievance = getGrievanceFromDb(grievanceId);
                    if (existingGrievance.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Grievance with ID '" + grievanceId + "' not found.", req.getRequestURI());
                        return;
                    }

                    String newStatus = (String) input.get("status");
                    String resolutionDetails = (String) input.get("resolution_details");
                    String assignedDpoIdForUpdateStr = (String) input.get("assigned_dpo_user_id");
                    UUID assignedDpoIdForUpdate = null;
                    if (assignedDpoIdForUpdateStr != null && !assignedDpoIdForUpdateStr.isEmpty()) {
                        try { assignedDpoIdForUpdate = UUID.fromString(assignedDpoIdForUpdateStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (assignedDpoIdForUpdateStr != null && assignedDpoIdForUpdate == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'assigned_dpo_user_id' format for update.", req.getRequestURI());
                        return;
                    }

                    if (newStatus == null || newStatus.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "New 'status' is required for 'update_grievance_status'.", req.getRequestURI());
                        return;
                    }
                    // Basic status transition validation (can be more complex with a state machine)
                    String currentGrievanceStatus = (String) existingGrievance.get().get("status");
                    if (("RESOLVED".equalsIgnoreCase(currentGrievanceStatus) || "CLOSED".equalsIgnoreCase(currentGrievanceStatus)) &&
                            !("RESOLVED".equalsIgnoreCase(newStatus) || "CLOSED".equalsIgnoreCase(newStatus))) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Cannot change status from RESOLVED/CLOSED to a prior state.", req.getRequestURI());
                        return;
                    }

                    output = updateGrievanceStatusInDb(grievanceId, newStatus, resolutionDetails, assignedDpoIdForUpdate, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);

                    // --- Trigger Downstream Actions based on status update ---
                    if ("RESOLVED".equalsIgnoreCase(newStatus) && "ERASURE_REQUEST".equalsIgnoreCase((String)existingGrievance.get().get("type"))) {
                        // This would typically call the Data Retention/Purge Service via API or Message Queue
                        System.out.println("GrievanceService: Triggering purge for erasure request " + grievanceId);
                        // Example: purgeService.initiatePurge(userId, fiduciaryId, "ERASURE_REQUEST", grievanceId);
                    }
                    // --- End Downstream Actions ---
                    break;

                case "add_grievance_communication":
                    if (grievanceId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'grievance_id' is required for 'add_grievance_communication'.", req.getRequestURI());
                        return;
                    }
                    if (getGrievanceFromDb(grievanceId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Grievance with ID '" + grievanceId + "' not found.", req.getRequestURI());
                        return;
                    }
                    String message = (String) input.get("message");
                    String sender = (String) input.get("sender"); // e.g., "DP", "DPO"
                    String channel = (String) input.get("channel"); // e.g., "PORTAL", "EMAIL"

                    if (message == null || message.isEmpty() || sender == null || sender.isEmpty() || channel == null || channel.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (message, sender, channel) for 'add_grievance_communication'.", req.getRequestURI());
                        return;
                    }
                    addCommunicationToGrievance(grievanceId, message, sender, channel, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "Communication added successfully."); }});
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Grievance Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Grievance Management ---

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
     * Calculates the due date for a grievance based on its type and predefined SLAs.
     */
    private Timestamp calculateDueDate(String grievanceType) {
        int slaDays = DEFAULT_SLA_DAYS;
        if ("ERASURE_REQUEST".equalsIgnoreCase(grievanceType)) {
            slaDays = ERASURE_SLA_DAYS;
        }
        return Timestamp.from(Instant.now().plusSeconds(slaDays * 24 * 60 * 60)); // Add SLA days in seconds
    }

    /**
     * Saves a new grievance to the database.
     * @return JSONObject containing the new grievance's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveGrievanceToDb(String userId, UUID fiduciaryId, String type, String subject, String description,
                                         JSONArray attachments, String language, UUID submittedByCmsUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        Timestamp submissionTime = Timestamp.from(Instant.now());
        Timestamp dueDate = calculateDueDate(type);
        JSONArray communicationLog = new JSONArray();
        JSONObject initialCommunication = new JSONObject();
        initialCommunication.put("timestamp", submissionTime.toInstant().toString());
        initialCommunication.put("sender", "Data Principal");
        initialCommunication.put("message", "Grievance submitted: " + subject);
        initialCommunication.put("channel", "PORTAL");
        communicationLog.add(initialCommunication);

        String sql = "INSERT INTO grievances (id, user_id, fiduciary_id, type, subject, description, submission_timestamp, status, communication_log, attachments, due_date, last_updated_at, last_updated_by_user_id) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, NOW(), ?) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setString(3, type);
            pstmt.setString(4, subject);
            pstmt.setString(5, description);
            pstmt.setTimestamp(6, submissionTime);
            pstmt.setString(7, "NEW"); // Initial status
            pstmt.setString(8, communicationLog.toJSONString());
            pstmt.setString(9, attachments != null ? attachments.toJSONString() : "[]");
            pstmt.setTimestamp(10, dueDate);
            pstmt.setObject(11, submittedByCmsUserId); // User who submitted (if CMS user) or null

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Submitting grievance failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String grievanceId = rs.getString(1);
                output.put("grievance_id", grievanceId);
                output.put("user_id", userId);
                output.put("message", "Grievance submitted successfully.");
            } else {
                throw new SQLException("Submitting grievance failed, no ID obtained.");
            }

            // Audit Log: Log the grievance submission event
            // auditLogService.logEvent(submittedByCmsUserId, "GRIEVANCE_SUBMITTED", "Grievance", UUID.fromString(output.get("grievance_id").toString()), subject, null, "SUCCESS", "GrievanceService");

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Retrieves a single grievance by ID from the database.
     * @return An Optional containing the grievance JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getGrievanceFromDb(UUID grievanceId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, user_id, fiduciary_id, type, subject, description, submission_timestamp, status, assigned_dpo_user_id, resolution_details, resolution_timestamp, communication_log, attachments, due_date, last_updated_at, last_updated_by_user_id FROM grievances WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, grievanceId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject grievance = new JSONObject();
                grievance.put("grievance_id", rs.getString("id"));
                grievance.put("user_id", rs.getString("user_id"));
                grievance.put("fiduciary_id", rs.getString("fiduciary_id"));
                grievance.put("type", rs.getString("type"));
                grievance.put("subject", rs.getString("subject"));
                grievance.put("description", rs.getString("description"));
                grievance.put("submission_timestamp", rs.getTimestamp("submission_timestamp").toInstant().toString());
                grievance.put("status", rs.getString("status"));
                grievance.put("assigned_dpo_user_id", rs.getString("assigned_dpo_user_id"));
                grievance.put("resolution_details", rs.getString("resolution_details"));
                grievance.put("resolution_timestamp", rs.getTimestamp("resolution_timestamp") != null ? rs.getTimestamp("resolution_timestamp").toInstant().toString() : null);
                grievance.put("communication_log", new JSONParser().parse(rs.getString("communication_log")));
                grievance.put("attachments", new JSONParser().parse(rs.getString("attachments")));
                grievance.put("due_date", rs.getTimestamp("due_date").toInstant().toString());
                grievance.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                grievance.put("last_updated_by_user_id", rs.getString("last_updated_by_user_id"));
                return Optional.of(grievance);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for grievance: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Retrieves a list of grievances from the database with optional filtering and pagination.
     * @return JSONArray of grievance JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listGrievancesFromDb(UUID fiduciaryId, String statusFilter, String typeFilter, UUID assignedDpoId, String search, int page, int limit) throws SQLException {
        JSONArray grievancesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, user_id, fiduciary_id, type, subject, submission_timestamp, status, assigned_dpo_user_id, due_date FROM grievances WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (typeFilter != null && !typeFilter.isEmpty()) {
            sqlBuilder.append(" AND type = ?");
            params.add(typeFilter);
        }
        if (assignedDpoId != null) {
            sqlBuilder.append(" AND assigned_dpo_user_id = ?");
            params.add(assignedDpoId);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (subject ILIKE ? OR description ILIKE ? OR user_id ILIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
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
                JSONObject grievance = new JSONObject();
                grievance.put("grievance_id", rs.getString("id"));
                grievance.put("user_id", rs.getString("user_id"));
                grievance.put("fiduciary_id", rs.getString("fiduciary_id"));
                grievance.put("type", rs.getString("type"));
                grievance.put("subject", rs.getString("subject"));
                grievance.put("submission_timestamp", rs.getTimestamp("submission_timestamp").toInstant().toString());
                grievance.put("status", rs.getString("status"));
                grievance.put("assigned_dpo_user_id", rs.getString("assigned_dpo_user_id"));
                grievance.put("due_date", rs.getTimestamp("due_date").toInstant().toString());
                grievancesArray.add(grievance);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return grievancesArray;
    }

    /**
     * Updates the status and resolution details of a grievance.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateGrievanceStatusInDb(UUID grievanceId, String newStatus, String resolutionDetails, UUID assignedDpoId, UUID updatedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE grievances SET status = ?, last_updated_at = NOW(), last_updated_by_user_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(newStatus);
        params.add(updatedByUserId);

        if (resolutionDetails != null && !resolutionDetails.isEmpty()) {
            sqlBuilder.append(", resolution_details = ?");
            params.add(resolutionDetails);
            sqlBuilder.append(", resolution_timestamp = NOW()"); // Set resolution timestamp if details provided
        }
        if (assignedDpoId != null) {
            sqlBuilder.append(", assigned_dpo_user_id = ?");
            params.add(assignedDpoId);
        }

        sqlBuilder.append(" WHERE id = ?");
        params.add(grievanceId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating grievance status failed, grievance not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Grievance status updated successfully."); }};
    }

    /**
     * Adds a communication entry to a grievance's communication_log.
     * @throws SQLException if a database access error occurs.
     */
    private void addCommunicationToGrievance(UUID grievanceId, String message, String sender, String channel, UUID addedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        // Append new communication to the existing JSONB array
        String sql = "UPDATE grievances SET communication_log = communication_log || ?::jsonb, last_updated_at = NOW(), last_updated_by_user_id = ? WHERE id = ?";

        JSONObject newCommunication = new JSONObject();
        newCommunication.put("timestamp", Instant.now().toString());
        newCommunication.put("sender", sender);
        newCommunication.put("message", message);
        newCommunication.put("channel", channel);

        JSONArray communicationArray = new JSONArray();
        communicationArray.add(newCommunication); // Create a new array with just the new message to append

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, communicationArray.toJSONString()); // Append the new JSON object
            pstmt.setObject(2, addedByUserId);
            pstmt.setObject(3, grievanceId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Adding communication to grievance failed, grievance not found.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}