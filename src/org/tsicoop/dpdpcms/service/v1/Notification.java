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
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

// Assuming external Email and SMS gateway clients exist
// import org.tsicoop.dpdpcms.external.EmailGatewayClient; // Placeholder
// import org.tsicoop.dpdpcms.external.SmsGatewayClient;   // Placeholder

/**
 * NotificationService class for generating, delivering, and managing notifications.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Notification System module
 * of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'notification_templates'.
 * - Columns: id (UUID PK), name (VARCHAR), category (VARCHAR), severity (VARCHAR),
 * channels_enabled (JSONB), content_template (JSONB), action_link_template (TEXT),
 * created_at (TIMESTAMPZ), created_by_user_id (UUID), last_updated_at (TIMESTAMPZ), last_updated_by_user_id (UUID).
 * - Table is named 'notification_instances'.
 * - Columns: id (UUID PK), template_id (UUID), recipient_type (VARCHAR), recipient_id (VARCHAR/UUID),
 * fiduciary_id (UUID), status (VARCHAR), channel_used (VARCHAR), sent_at (TIMESTAMPZ),
 * payload_data (JSONB), error_details (TEXT), read_at (TIMESTAMPZ).
 * - Assumes 'users' and 'fiduciaries' tables exist for FK references and recipient lookups.
 * - Assumes external EmailGatewayClient and SmsGatewayClient are available.
 */
public class Notification implements REST {

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
     * Handles all Notification System operations via a single POST endpoint.
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

        // Placeholder for current CMS user ID (from authentication context, if Admin)
        UUID actionByCmsUserId = UUID.fromString("00000000-0000-0000-0000-000000000001"); // Example Admin User ID

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract common parameters for templates
            UUID templateId = null;
            String templateIdStr = (String) input.get("template_id");
            if (templateIdStr != null && !templateIdStr.isEmpty()) {
                try {
                    templateId = UUID.fromString(templateIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'template_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                // --- Notification Template Management ---
                case "create_template":
                    String name = (String) input.get("name");
                    String category = (String) input.get("category");
                    String severity = (String) input.get("severity");
                    JSONArray channelsEnabledJson = (JSONArray) input.get("channels_enabled");
                    JSONObject contentTemplate = (JSONObject) input.get("content_template"); // Multilingual content
                    String actionLinkTemplate = (String) input.get("action_link_template");

                    if (name == null || name.isEmpty() || category == null || category.isEmpty() || severity == null || severity.isEmpty() ||
                            channelsEnabledJson == null || channelsEnabledJson.isEmpty() || contentTemplate == null || contentTemplate.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields for 'create_template'.", req.getRequestURI());
                        return;
                    }
                    if (templateExistsByName(name, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Notification template with name '" + name + "' already exists.", req.getRequestURI());
                        return;
                    }

                    output = saveNotificationTemplateToDb(name, category, severity, channelsEnabledJson, contentTemplate, actionLinkTemplate, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_template":
                    if (templateId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'template_id' is required for 'update_template'.", req.getRequestURI());
                        return;
                    }
                    if (getNotificationTemplateFromDb(templateId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Notification template with ID '" + templateId + "' not found.", req.getRequestURI());
                        return;
                    }

                    name = (String) input.get("name");
                    category = (String) input.get("category");
                    severity = (String) input.get("severity");
                    channelsEnabledJson = (JSONArray) input.get("channels_enabled");
                    contentTemplate = (JSONObject) input.get("content_template");
                    actionLinkTemplate = (String) input.get("action_link_template");

                    if (name == null && category == null && severity == null && channelsEnabledJson == null && contentTemplate == null && actionLinkTemplate == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_template'.", req.getRequestURI());
                        return;
                    }
                    if (name != null && !name.isEmpty() && templateExistsByName(name, templateId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Notification template with name '" + name + "' already exists.", req.getRequestURI());
                        return;
                    }

                    output = updateNotificationTemplateInDb(templateId, name, category, severity, channelsEnabledJson, contentTemplate, actionLinkTemplate, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "get_template":
                    if (templateId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'template_id' is required for 'get_template'.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> templateOptional = getNotificationTemplateFromDb(templateId);
                    if (templateOptional.isPresent()) {
                        output = templateOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Notification template with ID '" + templateId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "list_templates":
                    String templateCategoryFilter = (String) input.get("category");
                    String templateSeverityFilter = (String) input.get("severity");
                    String templateSearch = (String) input.get("search");
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listNotificationTemplatesFromDb(templateCategoryFilter, templateSeverityFilter, templateSearch, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                // --- Notification Dispatch ---
                case "dispatch_notification":
                    // This is the primary method called by other microservices to send notifications
                    UUID triggerTemplateId = null;
                    String triggerTemplateIdStr = (String) input.get("template_id");
                    if (triggerTemplateIdStr != null && !triggerTemplateIdStr.isEmpty()) {
                        try { triggerTemplateId = UUID.fromString(triggerTemplateIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (triggerTemplateId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'template_id' is required for 'dispatch_notification'.", req.getRequestURI());
                        return;
                    }

                    String recipientType = (String) input.get("recipient_type"); // DATA_PRINCIPAL, DPO_ADMIN, DATA_PROCESSOR
                    String recipientId = (String) input.get("recipient_id"); // User ID, Fiduciary ID, Processor ID
                    String fiduciaryIdStr = (String) input.get("fiduciary_id"); // Contextual Fiduciary ID
                    JSONObject payloadData = (JSONObject) input.get("payload_data"); // Data to populate template

                    if (recipientType == null || recipientType.isEmpty() || recipientId == null || recipientId.isEmpty() || payloadData == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (recipient_type, recipient_id, payload_data) for 'dispatch_notification'.", req.getRequestURI());
                        return;
                    }
                    UUID dispatchFiduciaryId = null;
                    if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                        try { dispatchFiduciaryId = UUID.fromString(fiduciaryIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (fiduciaryIdStr != null && dispatchFiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format for dispatch.", req.getRequestURI());
                        return;
                    }

                    // Asynchronous dispatch is ideal for notifications
                    // For simplicity, this example will do it synchronously
                    dispatchNotification(triggerTemplateId, recipientType, recipientId, dispatchFiduciaryId, payloadData, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "Notification dispatch initiated."); }});
                    break;

                case "list_notification_instances":
                    String instanceRecipientType = (String) input.get("recipient_type");
                    String instanceRecipientId = (String) input.get("recipient_id");
                    String instanceFidIdStr = (String) input.get("fiduciary_id");
                    UUID instanceFidId = null;
                    if (instanceFidIdStr != null && !instanceFidIdStr.isEmpty()) {
                        try { instanceFidId = UUID.fromString(instanceFidIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (instanceFidIdStr != null && instanceFidId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format for instance list.", req.getRequestURI());
                        return;
                    }
                    String instanceStatus = (String) input.get("status");
                    page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listNotificationInstancesFromDb(instanceRecipientType, instanceRecipientId, instanceFidId, instanceStatus, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "mark_notification_read":
                    UUID instanceId = null;
                    String instanceIdStr = (String) input.get("instance_id");
                    if (instanceIdStr != null && !instanceIdStr.isEmpty()) {
                        try { instanceId = UUID.fromString(instanceIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (instanceId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'instance_id' is required for 'mark_notification_read'.", req.getRequestURI());
                        return;
                    }
                    markNotificationReadInDb(instanceId, actionByCmsUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "Notification marked as read."); }});
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
        } catch (Exception e) { // Catch broader exceptions like UnknownHostException from InetAddress
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Notification Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Notification Management ---

    /**
     * Checks if a template name already exists.
     */
    private boolean templateExistsByName(String name, UUID excludeTemplateId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM notification_templates WHERE name = ?");
        List<Object> params = new ArrayList<>();
        params.add(name);
        if (excludeTemplateId != null) {
            sqlBuilder.append(" AND id != ?");
            params.add(excludeTemplateId);
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
     * Retrieves a notification template by ID.
     */
    private Optional<JSONObject> getNotificationTemplateFromDb(UUID templateId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, name, category, severity, channels_enabled, content_template, action_link_template, created_at, created_by_user_id, last_updated_at, last_updated_by_user_id FROM notification_templates WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, templateId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject template = new JSONObject();
                template.put("template_id", rs.getString("id"));
                template.put("name", rs.getString("name"));
                template.put("category", rs.getString("category"));
                template.put("severity", rs.getString("severity"));
                template.put("channels_enabled", new JSONParser().parse(rs.getString("channels_enabled")));
                template.put("content_template", new JSONParser().parse(rs.getString("content_template")));
                template.put("action_link_template", rs.getString("action_link_template"));
                template.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                template.put("created_by_user_id", rs.getString("created_by_user_id"));
                template.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                template.put("last_updated_by_user_id", rs.getString("last_updated_by_user_id"));
                return Optional.of(template);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for template: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new notification template to the database.
     */
    private JSONObject saveNotificationTemplateToDb(String name, String category, String severity, JSONArray channelsEnabled, JSONObject contentTemplate, String actionLinkTemplate, UUID createdByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO notification_templates (id, name, category, severity, channels_enabled, content_template, action_link_template, created_at, created_by_user_id, last_updated_at, last_updated_by_user_id) VALUES (uuid_generate_v4(), ?, ?, ?, ?::jsonb, ?::jsonb, ?, NOW(), ?, NOW(), ?) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, name);
            pstmt.setString(2, category);
            pstmt.setString(3, severity);
            pstmt.setString(4, channelsEnabled.toJSONString());
            pstmt.setString(5, contentTemplate.toJSONString());
            pstmt.setString(6, actionLinkTemplate);
            pstmt.setObject(7, createdByUserId);
            pstmt.setObject(8, createdByUserId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating notification template failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String templateId = rs.getString(1);
                output.put("template_id", templateId);
                output.put("name", name);
                output.put("message", "Notification template created successfully.");
            } else {
                throw new SQLException("Creating notification template failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing notification template in the database.
     */
    private JSONObject updateNotificationTemplateInDb(UUID templateId, String name, String category, String severity, JSONArray channelsEnabled, JSONObject contentTemplate, String actionLinkTemplate, UUID updatedByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE notification_templates SET last_updated_at = NOW(), last_updated_by_user_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(updatedByUserId);

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (category != null && !category.isEmpty()) { sqlBuilder.append(", category = ?"); params.add(category); }
        if (severity != null && !severity.isEmpty()) { sqlBuilder.append(", severity = ?"); params.add(severity); }
        if (channelsEnabled != null) { sqlBuilder.append(", channels_enabled = ?::jsonb"); params.add(channelsEnabled.toJSONString()); }
        if (contentTemplate != null) { sqlBuilder.append(", content_template = ?::jsonb"); params.add(contentTemplate.toJSONString()); }
        if (actionLinkTemplate != null) { sqlBuilder.append(", action_link_template = ?"); params.add(actionLinkTemplate); }

        sqlBuilder.append(" WHERE id = ?");
        params.add(templateId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating notification template failed, template not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Notification template updated successfully."); }};
    }

    /**
     * Retrieves a list of notification templates from the database with optional filtering and pagination.
     */
    private JSONArray listNotificationTemplatesFromDb(String categoryFilter, String severityFilter, String search, int page, int limit) throws SQLException {
        JSONArray templatesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, name, category, severity, channels_enabled, created_at, last_updated_at FROM notification_templates WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (categoryFilter != null && !categoryFilter.isEmpty()) {
            sqlBuilder.append(" AND category = ?");
            params.add(categoryFilter);
        }
        if (severityFilter != null && !severityFilter.isEmpty()) {
            sqlBuilder.append(" AND severity = ?");
            params.add(severityFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (name ILIKE ? OR description ILIKE ?)"); // Assuming description exists or search applies to name
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
                JSONObject template = new JSONObject();
                template.put("template_id", rs.getString("id"));
                template.put("name", rs.getString("name"));
                template.put("category", rs.getString("category"));
                template.put("severity", rs.getString("severity"));
                template.put("channels_enabled", new JSONParser().parse(rs.getString("channels_enabled")));
                template.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                template.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString());
                templatesArray.add(template);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for template list: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return templatesArray;
    }

    /**
     * Dispatches a notification based on a template and payload.
     * This method logs the instance and attempts delivery.
     * In a real system, actual delivery would be async (e.g., via message queue).
     */
    private void dispatchNotification(UUID templateId, String recipientType, String recipientId, UUID fiduciaryId, JSONObject payloadData, UUID dispatchedByUserId) throws SQLException {
        Optional<JSONObject> templateOpt = getNotificationTemplateFromDb(templateId);
        if (templateOpt.isEmpty()) {
            throw new SQLException("Notification template with ID '" + templateId + "' not found for dispatch.");
        }
        JSONObject template = templateOpt.get();
        JSONArray channelsEnabled = (JSONArray) template.get("channels_enabled");
        JSONObject contentTemplate = (JSONObject) template.get("content_template");
        String actionLinkTemplate = (String) template.get("action_link_template");
        String severity = (String) template.get("severity");

        // Resolve recipient contact details (email, phone, etc.)
        // This is a complex step and would involve calls to User Service, Fiduciary Service, Processor Service
        // For demo, we'll mock recipient contact details.
        String recipientEmail = null;
        String recipientPhone = null;
        String recipientLang = "en"; // Assume English for simplicity or get from user profile

        // Mock recipient resolution based on type (replace with actual service calls)
        if ("DATA_PRINCIPAL".equalsIgnoreCase(recipientType)) {
            // In real system, query User Service for email/phone by recipientId (Data Principal ID)
            recipientEmail = "data.principal@example.com";
            recipientPhone = "+919876543210";
            // recipientLang = userService.getUserLanguage(recipientId); // Get language from user profile
        } else if ("DPO_ADMIN".equalsIgnoreCase(recipientType)) {
            // In real system, query User Service for email/phone by recipientId (CMS User ID)
            recipientEmail = "dpo.admin@tsicoop.com";
            recipientPhone = "+919988776655";
            // recipientLang = userService.getUserLanguage(recipientId);
        } else if ("DATA_PROCESSOR".equalsIgnoreCase(recipientType)) {
            // In real system, query Processor Service for email/phone by recipientId (Processor ID)
            recipientEmail = "processor.contact@example.com";
            recipientPhone = "+919123456789";
            // recipientLang = processorService.getProcessorLanguage(recipientId);
        }

        // Personalize content
        String subject = (String) contentTemplate.get("subject"); // Assuming subject is part of template JSON
        String body = (String) contentTemplate.get(recipientLang); // Get localized content based on recipient's language
        String actionLink = actionLinkTemplate; // Simple for now, real links need payload data

        // Replace placeholders in subject, body, and actionLink
        for (Object keyObj : payloadData.keySet()) {
            String key = (String) keyObj;
            String value = String.valueOf(payloadData.get(key));
            if (subject != null) subject = subject.replace("{" + key + "}", value);
            if (body != null) body = body.replace("{" + key + "}", value);
            if (actionLink != null) actionLink = actionLink.replace("{" + key + "}", value);
        }

        // --- Dispatch to channels ---
        // Email Dispatch
        if (channelsEnabled.contains("EMAIL") && recipientEmail != null && !recipientEmail.isEmpty()) {
            String status = "FAILED";
            String error = null;
            try {
                // EmailGatewayClient.sendEmail(recipientEmail, subject, body, actionLink); // Actual call
                System.out.println(String.format("NotificationService: [MOCK EMAIL] To: %s, Subject: %s, Body: %s (Link: %s)", recipientEmail, subject, body, actionLink));
                status = "SENT"; // Or "DELIVERED" if gateway provides callback
            } catch (Exception e) {
                error = e.getMessage();
                System.err.println("NotificationService: Failed to send email: " + error);
            }
            saveNotificationInstanceToDb(templateId, recipientType, recipientId, fiduciaryId, "EMAIL", status, payloadData, error, dispatchedByUserId);
        }

        // SMS Dispatch
        if (channelsEnabled.contains("SMS") && recipientPhone != null && !recipientPhone.isEmpty()) {
            String status = "FAILED";
            String error = null;
            try {
                // SmsGatewayClient.sendSms(recipientPhone, body); // Actual call
                System.out.println(String.format("NotificationService: [MOCK SMS] To: %s, Body: %s", recipientPhone, body));
                status = "SENT"; // Or "DELIVERED" if gateway provides callback
            } catch (Exception e) {
                error = e.getMessage();
                System.err.println("NotificationService: Failed to send SMS: " + error);
            }
            saveNotificationInstanceToDb(templateId, recipientType, recipientId, fiduciaryId, "SMS", status, payloadData, error, dispatchedByUserId);
        }

        // In-App Notification (always "sent" if recorded in DB for dashboard display)
        if (channelsEnabled.contains("IN_APP")) {
            saveNotificationInstanceToDb(templateId, recipientType, recipientId, fiduciaryId, "IN_APP", "SENT", payloadData, null, dispatchedByUserId);
        }
    }

    /**
     * Saves a new notification instance to the database.
     */
    private JSONObject saveNotificationInstanceToDb(UUID templateId, String recipientType, String recipientId, UUID fiduciaryId, String channelUsed, String status, JSONObject payloadData, String errorDetails, UUID createdByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO notification_instances (id, template_id, recipient_type, recipient_id, fiduciary_id, status, channel_used, sent_at, payload_data, error_details, created_at, created_by_user_id) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, NOW(), ?::jsonb, ?, NOW(), ?) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setObject(1, templateId);
            pstmt.setString(2, recipientType);
            pstmt.setString(3, recipientId);
            pstmt.setObject(4, fiduciaryId);
            pstmt.setString(5, status);
            pstmt.setString(6, channelUsed);
            pstmt.setString(7, payloadData.toJSONString());
            pstmt.setString(8, errorDetails);
            pstmt.setObject(9, createdByUserId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating notification instance failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String instanceId = rs.getString(1);
                output.put("instance_id", instanceId);
                output.put("message", "Notification instance saved.");
            } else {
                throw new SQLException("Creating notification instance failed, no ID obtained.");
            }

            // Audit Log: Log the notification instance creation
            // auditLogService.logEvent(createdByUserId, "NOTIFICATION_SENT_INSTANCE_CREATED", "NotificationInstance", UUID.fromString(output.get("instance_id").toString()), payloadData.toJSONString(), null, status, "NotificationService");

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Retrieves a list of notification instances from the database with optional filtering and pagination.
     */
    private JSONArray listNotificationInstancesFromDb(String recipientType, String recipientId, UUID fiduciaryId, String statusFilter, int page, int limit) throws SQLException {
        JSONArray instancesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, template_id, recipient_type, recipient_id, fiduciary_id, status, channel_used, sent_at, payload_data, error_details, read_at FROM notification_instances WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (recipientType != null && !recipientType.isEmpty()) {
            sqlBuilder.append(" AND recipient_type = ?");
            params.add(recipientType);
        }
        if (recipientId != null && !recipientId.isEmpty()) {
            sqlBuilder.append(" AND recipient_id = ?");
            params.add(recipientId);
        }
        if (fiduciaryId != null) {
            sqlBuilder.append(" AND fiduciary_id = ?");
            params.add(fiduciaryId);
        }
        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }

        sqlBuilder.append(" ORDER BY sent_at DESC LIMIT ? OFFSET ?");
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
                JSONObject instance = new JSONObject();
                instance.put("instance_id", rs.getString("id"));
                instance.put("template_id", rs.getString("template_id"));
                instance.put("recipient_type", rs.getString("recipient_type"));
                instance.put("recipient_id", rs.getString("recipient_id"));
                instance.put("fiduciary_id", rs.getString("fiduciary_id"));
                instance.put("status", rs.getString("status"));
                instance.put("channel_used", rs.getString("channel_used"));
                instance.put("sent_at", rs.getTimestamp("sent_at").toInstant().toString());
                instance.put("payload_data", new JSONParser().parse(rs.getString("payload_data")));
                instance.put("error_details", rs.getString("error_details"));
                instance.put("read_at", rs.getTimestamp("read_at") != null ? rs.getTimestamp("read_at").toInstant().toString() : null);
                instancesArray.add(instance);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for notification instance list: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return instancesArray;
    }

    /**
     * Marks a notification instance as read.
     */
    private void markNotificationReadInDb(UUID instanceId, UUID readByUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE notification_instances SET status = 'READ', read_at = NOW() WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, instanceId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Marking notification as read failed, instance not found.");
            }
            // Audit Log: Log the notification read event
            // auditLogService.logEvent(readByUserId, "NOTIFICATION_READ", "NotificationInstance", instanceId, null, null, "SUCCESS", "NotificationService");
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}