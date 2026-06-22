package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

/**
 * Grievance class for managing Data Principal grievances and requests.
 * Refactored to determine service context (APP/DPO) and log audit events after pool cleanup.
 */
public class Grievance implements Action {

    private static final int DEFAULT_SLA_DAYS = 30;
    private static final int ERASURE_SLA_DAYS = 7;
    private static final UUID ADMIN_FID_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            String apiKey = req.getHeader("X-API-Key");
            String apiSecret = req.getHeader("X-API-Secret");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            // Determine Service Context for Audit
            UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);
            String callerRole = InputProcessor.getVerifiedRole(req);
            UUID appId = new ApiKey().getAppId(apiKey, apiSecret);

            String serviceType = "SYSTEM";
            UUID actorServiceId = ADMIN_FID_UUID;

            if (appId != null) {
                serviceType = Constants.SERVICE_TYPE_APP;
                actorServiceId = appId;
            } else if (loginUserId != null) {
                serviceType = Constants.SERVICE_TYPE_DPO_CONSOLE;
                actorServiceId = loginUserId;
            }

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

            String userId = (String) input.get("user_id");
            UUID fiduciaryId = null;
            String fiduciaryIdStr = input.get("fiduciary_id") != null ? (String) input.get("fiduciary_id") : null;
            // When called via PRINCIPAL JWT, fiduciary_id is stamped on request attributes by InterceptingFilter
            if (fiduciaryIdStr == null) {
                Object fidAttr = req.getAttribute("fiduciary_id");
                if (fidAttr != null) fiduciaryIdStr = fidAttr.toString();
            }
            // Fall back to API key lookup when fiduciary_id is still unresolved
            if (fiduciaryIdStr == null) {
                fiduciaryIdStr = new Fiduciary().getFiduciaryId(UUID.fromString(apiKey != null ? apiKey : "00000000-0000-0000-0000-000000000000"), apiSecret);
            }
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                fiduciaryId = UUID.fromString(fiduciaryIdStr);
            }

            // Security guard: when authenticated via PRINCIPAL JWT, enforce that user_id matches the token subject
            Boolean viaPrincipalJwt = (Boolean) req.getAttribute("auth_via_principal_jwt");
            if (Boolean.TRUE.equals(viaPrincipalJwt) && userId != null) {
                String principalUserId = (String) req.getAttribute("principal_user_id");
                if (!userId.equals(principalUserId)) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "User ID mismatch: token does not authorize access to the requested principal.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                case "submit_grievance":
                    handleSubmitGrievance(input, userId, fiduciaryId, serviceType, actorServiceId, res, req);
                    break;

                case "get_grievance":
                    handleGetGrievance(grievanceId, loginUserId, callerRole, res, req);
                    break;

                case "list_grievances":
                    handleListGrievances(fiduciaryId, loginUserId, callerRole, input, res, req);
                    break;

                case "list_user_grievances":
                    handleListUserGrievances(fiduciaryId, userId, res, req);
                    break;

                case "update_grievance_status":
                    handleUpdateGrievanceStatus(input, grievanceId, loginUserId, callerRole, serviceType, actorServiceId, res, req);
                    break;

                case "assign_grievance":
                    handleAssignGrievance(input, grievanceId, callerRole, serviceType, actorServiceId, res, req);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown '_func': " + func, req.getRequestURI());
                    break;
            }

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    private void handleSubmitGrievance(JSONObject input, String userId, UUID fiduciaryId, String serviceType, UUID serviceId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String type = (String) input.get("type");
        String subject = (String) input.get("subject");
        String description = (String) input.get("description");
        JSONArray attachments = (JSONArray) input.get("attachments");

        if (userId == null || fiduciaryId == null || type == null || subject == null || description == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing mandatory fields.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        boolean success = false;
        String newGrievanceId = null;
        Timestamp submissionTime = Timestamp.from(Instant.now());
        Timestamp dueDate = calculateDueDate(type);

        try {
            conn = pool.getConnection();
            String sql = "INSERT INTO grievances (id, user_id, fiduciary_id, type, subject, description, submission_timestamp, status, communication_log, attachments, due_date, last_updated_at) " +
                    "VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, 'NEW', '[]'::jsonb, ?::jsonb, ?, NOW()) RETURNING id";

            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setString(3, type);
            pstmt.setString(4, subject);
            pstmt.setString(5, description);
            pstmt.setTimestamp(6, submissionTime);
            pstmt.setString(7, attachments != null ? attachments.toJSONString() : "[]");
            pstmt.setTimestamp(8, dueDate);

            rs = pstmt.executeQuery();
            if (rs.next()) {
                newGrievanceId = rs.getString(1);
                JSONObject out = new JSONObject();
                out.put("success", true);
                out.put("grievance_id", newGrievanceId);
                OutputProcessor.send(res, 201, out);
                success = true;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        // Audit Log: Instrument after cleanup. Audit user is the principal (userId).
        if (success) {
            new Audit().logEventAsync(userId, fiduciaryId, serviceType, serviceId, "GRIEVANCE_SUBMITTED", "Subject: " + subject);
        }
    }

    private void handleUpdateGrievanceStatus(JSONObject input, UUID grievanceId, UUID loginUserId, String callerRole, String serviceType, UUID serviceId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String newStatus = (String) input.get("status");
        String resolutionDetails = (String) input.get("resolution_details");

        if (grievanceId == null || newStatus == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "ID and Status required.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        boolean success = false;
        String principalId = "N/A";
        UUID fiduciaryId = ADMIN_FID_UUID;

        try {
            conn = pool.getConnection();
            // Fetch metadata for audit context, and the current assignee for Operator scoping
            UUID assignedDpoUserId = null;
            try (PreparedStatement p = conn.prepareStatement("SELECT user_id, fiduciary_id, assigned_dpo_user_id FROM grievances WHERE id = ?")) {
                p.setObject(1, grievanceId);
                try (ResultSet r = p.executeQuery()) {
                    if (r.next()) {
                        principalId = r.getString("user_id");
                        fiduciaryId = (UUID) r.getObject("fiduciary_id");
                        assignedDpoUserId = (UUID) r.getObject("assigned_dpo_user_id");
                    }
                }
            }

            // Operators may only close grievances explicitly assigned to them.
            if ("OPERATOR".equalsIgnoreCase(callerRole) && (assignedDpoUserId == null || !assignedDpoUserId.equals(loginUserId))) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This grievance is not assigned to you.", req.getRequestURI());
                return;
            }

            StringBuilder sql = new StringBuilder("UPDATE grievances SET status = ?, last_updated_at = NOW()");
            if (resolutionDetails != null) {
                sql.append(", resolution_details = ?, resolution_timestamp = NOW()");
            }
            sql.append(" WHERE id = ?");

            pstmt = conn.prepareStatement(sql.toString());
            pstmt.setString(1, newStatus);
            if (resolutionDetails != null) {
                pstmt.setString(2, resolutionDetails);
                pstmt.setObject(3, grievanceId);
            } else {
                pstmt.setObject(2, grievanceId);
            }

            if (pstmt.executeUpdate() > 0) {
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                success = true;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        // Audit Log: Instrument after cleanup. Audit user is the principal (principalId).
        // Added resolution details
        if (success) {
            new Audit().logEventAsync(principalId, fiduciaryId, serviceType, serviceId, "GRIEVANCE_STATUS_UPDATED", "New Status: " + newStatus+" Details: "+resolutionDetails);
        }
    }

    private void handleGetGrievance(UUID id, UUID loginUserId, String callerRole, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM grievances WHERE id = ?");
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                UUID assignedDpoUserId = (UUID) rs.getObject("assigned_dpo_user_id");
                // Operators may only view grievances explicitly assigned to them.
                if ("OPERATOR".equalsIgnoreCase(callerRole) && (assignedDpoUserId == null || !assignedDpoUserId.equals(loginUserId))) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This grievance is not assigned to you.", req.getRequestURI());
                    return;
                }
                JSONObject g = new JSONObject();
                g.put("grievance_id", rs.getString("id"));
                g.put("user_id", rs.getString("user_id"));
                g.put("status", rs.getString("status"));
                g.put("subject", rs.getString("subject"));
                g.put("description", rs.getString("description"));
                g.put("submission_timestamp", rs.getTimestamp("submission_timestamp").toString());
                g.put("due_date", rs.getTimestamp("due_date").toString());
                g.put("assigned_dpo_user_id", assignedDpoUserId != null ? assignedDpoUserId.toString() : null);
                try {
                    g.put("communication_log", new JSONParser().parse(rs.getString("communication_log")));
                    g.put("attachments", new JSONParser().parse(rs.getString("attachments")));
                } catch (Exception e) { }
                OutputProcessor.send(res, 200, g);
            } else {
                OutputProcessor.errorResponse(res, 404, "Not Found", "Grievance not found.", req.getRequestURI());
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleListGrievances(UUID fiduciaryId, UUID loginUserId, String callerRole, JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        JSONArray arr = new JSONArray();

        // Operators only see their own assigned queue; DPO/ADMIN see the full fiduciary list.
        boolean scopeToCaller = "OPERATOR".equalsIgnoreCase(callerRole);

        try {
            String sql = "SELECT id, user_id, type, subject, submission_timestamp, status, due_date, assigned_dpo_user_id FROM grievances WHERE fiduciary_id = ?"
                    + (scopeToCaller ? " AND assigned_dpo_user_id = ?" : "")
                    + " ORDER BY submission_timestamp DESC";
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            if (scopeToCaller) {
                pstmt.setObject(2, loginUserId);
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject g = new JSONObject();
                g.put("grievance_id", rs.getString("id"));
                g.put("user_id", rs.getString("user_id"));
                g.put("type", rs.getString("type"));
                g.put("subject", rs.getString("subject"));
                g.put("status", rs.getString("status"));
                g.put("submission_timestamp", rs.getTimestamp("submission_timestamp").toString());
                g.put("due_date", rs.getTimestamp("due_date").toString());
                Object assignedId = rs.getObject("assigned_dpo_user_id");
                g.put("assigned_dpo_user_id", assignedId != null ? assignedId.toString() : null);
                arr.add(g);
            }
            OutputProcessor.send(res, 200, arr);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleAssignGrievance(JSONObject input, UUID grievanceId, String callerRole, String serviceType, UUID serviceId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        if (InputProcessor.rejectIfOperator(req, res)) return; // Only DPO/ADMIN may delegate

        String operatorIdStr = (String) input.get("operator_id");
        if (grievanceId == null || operatorIdStr == null || operatorIdStr.isEmpty()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "'grievance_id' and 'operator_id' are required.", req.getRequestURI());
            return;
        }
        UUID operatorId;
        try {
            operatorId = UUID.fromString(operatorIdStr);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid 'operator_id' format.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        boolean success = false;
        String principalId = "N/A";
        UUID fiduciaryId = ADMIN_FID_UUID;

        try {
            conn = pool.getConnection();
            try (PreparedStatement p = conn.prepareStatement("SELECT user_id, fiduciary_id FROM grievances WHERE id = ?")) {
                p.setObject(1, grievanceId);
                try (ResultSet r = p.executeQuery()) {
                    if (r.next()) {
                        principalId = r.getString("user_id");
                        fiduciaryId = (UUID) r.getObject("fiduciary_id");
                    }
                }
            }

            pstmt = conn.prepareStatement("UPDATE grievances SET assigned_dpo_user_id = ?, last_updated_at = NOW() WHERE id = ?");
            pstmt.setObject(1, operatorId);
            pstmt.setObject(2, grievanceId);

            if (pstmt.executeUpdate() > 0) {
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                success = true;
            } else {
                OutputProcessor.errorResponse(res, 404, "Not Found", "Grievance not found.", req.getRequestURI());
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(principalId, fiduciaryId, serviceType, serviceId, "GRIEVANCE_ASSIGNED", "Assigned to operator: " + operatorId);
        }
    }

    private void handleListUserGrievances(UUID fiduciaryId, String userId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        JSONArray arr = new JSONArray();

        try {
            String sql = "SELECT id, type, subject, status, submission_timestamp, due_date FROM grievances WHERE fiduciary_id = ? AND user_id = ? ORDER BY submission_timestamp DESC";
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, userId);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject g = new JSONObject();
                g.put("grievance_id", rs.getString("id"));
                g.put("type", rs.getString("type"));
                g.put("subject", rs.getString("subject"));
                g.put("status", rs.getString("status"));
                g.put("due_date", rs.getTimestamp("due_date").toString());
                arr.add(g);
            }
            OutputProcessor.send(res, 200, arr);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private Timestamp calculateDueDate(String type) {
        int days = "ERASURE_REQUEST".equalsIgnoreCase(type) ? ERASURE_SLA_DAYS : DEFAULT_SLA_DAYS;
        return Timestamp.from(Instant.now().plusSeconds(days * 24L * 60 * 60));
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}