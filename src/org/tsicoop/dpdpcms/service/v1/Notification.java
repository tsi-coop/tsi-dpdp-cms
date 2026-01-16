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
public class Notification implements Action {

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
        UUID appId = null;
        UUID loginUserId = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            // For client APIs
            String apiKey = req.getHeader("X-API-Key");
            String apiSecret = req.getHeader("X-API-Secret");
            // For Admin APIs
            loginUserId = InputProcessor.getAuthenticatedUserId(req);
            // For apps
            appId = new ApiKey().getAppId(apiKey,apiSecret);

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = input.get("fiduciary_id") != null?(String) input.get("fiduciary_id"):new Fiduciary().getFiduciaryId(UUID.fromString(apiKey),apiSecret);
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                case "list_notifications":

                    String recipientType = (String) input.get("recipient_type");
                    String recipientId = (String) input.get("recipient_id");

                    if(recipientType != null && recipientType.equalsIgnoreCase("APP") && recipientId == null){
                        recipientId = appId.toString();
                    }

                    String instanceStatus = (String) input.get("status");
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;

                    outputArray = listNotificationsFromDb(recipientType, recipientId, fiduciaryId, instanceStatus, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "mark_notification_read":
                    UUID notifId = null;
                    String id = (String) input.get("id");
                    if (id != null && !id.isEmpty()) {
                        try { notifId = UUID.fromString(id); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (notifId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'instance_id' is required for 'mark_notification_read'.", req.getRequestURI());
                        return;
                    }
                    markNotificationReadInDb(notifId);
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
     * Retrieves a list of notification instances from the database with optional filtering and pagination.
     */
    private JSONArray listNotificationsFromDb(String recipientType, String recipientId, UUID fiduciaryId, String statusFilter, int page, int limit) throws SQLException {
        JSONArray instancesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, recipient_type, recipient_id, fiduciary_id, notification_type, created_at, read_at FROM notifications WHERE 1=1");
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
                JSONObject instance = new JSONObject();
                instance.put("id", rs.getString("id"));
                instance.put("recipient_type", rs.getString("recipient_type"));
                instance.put("recipient_id", rs.getString("recipient_id"));
                instance.put("fiduciary_id", rs.getString("fiduciary_id"));
                instance.put("notification_type", rs.getString("notification_type"));
                instance.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                instance.put("read_at", rs.getTimestamp("read_at") != null ? rs.getTimestamp("read_at").toInstant().toString() : null);
                instancesArray.add(instance);
            }
        } catch (Exception e) {
            throw new SQLException("Failed to parse JSONB content from DB for notification instance list: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return instancesArray;
    }

    /**
     * Marks a notification instance as read.
     */
    private void markNotificationReadInDb(UUID instanceId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE notifications SET read_at = NOW() WHERE id = ?";
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