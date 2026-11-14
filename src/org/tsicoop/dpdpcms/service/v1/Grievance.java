package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.AttachmentRules;
import org.tsicoop.dpdpcms.util.GrievanceRules;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.ces.CESService;

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
                    if (rejectIfNotOwnFiduciary(fiduciaryId, loginUserId, callerRole, res, req)) return;
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

                case "upload_grievance_attachment":
                    handleUploadAttachment(input, grievanceId, userId, loginUserId, callerRole, serviceType, actorServiceId, res, req);
                    break;

                case "get_grievance_attachment":
                    handleGetAttachment(input, userId, loginUserId, callerRole, res, req);
                    break;

                case "submit_grievance_feedback":
                    handleFeedback(input, grievanceId, userId, loginUserId, callerRole, serviceType, actorServiceId, res, req);
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
        // A grievance is filed against the caller's own fiduciary, never one named in the body.
        if (!InputProcessor.callerOwns(req, fiduciaryId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You may only submit grievances for your own fiduciary.", req.getRequestURI());
            return;
        }

        // Channel: a principal token means the portal; otherwise the caller may relay a supported channel.
        boolean viaPrincipal = Boolean.TRUE.equals(req.getAttribute("auth_via_principal_jwt"));
        String defaultChannel = InputProcessor.getAuthenticatedUserId(req) != null ? "OPERATOR_CONSOLE" : "API_INTEGRATION";
        String channel = GrievanceRules.channel(viaPrincipal, (String) input.get("channel"), defaultChannel);
        if (channel == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Unsupported 'channel'.", req.getRequestURI());
            return;
        }

        UUID consentRecordId = null;
        String consentRecordStr = (String) input.get("consent_record_id");
        if (consentRecordStr != null && !consentRecordStr.isEmpty()) {
            try { consentRecordId = UUID.fromString(consentRecordStr); } catch (IllegalArgumentException e) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid 'consent_record_id'.", req.getRequestURI());
                return;
            }
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        boolean success = false;
        String newGrievanceId = null;
        String referenceNumber = null;
        UUID autoAssignedDpo = null;
        Timestamp submissionTime = Timestamp.from(Instant.now());
        Timestamp dueDate = calculateDueDate(type);

        try {
            conn = pool.getConnection();

            if (consentRecordId != null) {
                // The consent record must be this principal's, at this fiduciary.
                try (PreparedStatement c = conn.prepareStatement("SELECT 1 FROM consent_records WHERE id = ? AND fiduciary_id = ? AND user_id = ?")) {
                    c.setObject(1, consentRecordId); c.setObject(2, fiduciaryId); c.setString(3, userId);
                    try (ResultSet cr = c.executeQuery()) {
                        if (!cr.next()) {
                            OutputProcessor.errorResponse(res, 400, "Bad Request", "'consent_record_id' does not belong to this principal.", req.getRequestURI());
                            return;
                        }
                    }
                }
            }

            try (PreparedStatement seq = conn.prepareStatement("SELECT nextval('grievance_reference_seq')");
                 ResultSet sr = seq.executeQuery()) {
                sr.next();
                referenceNumber = GrievanceRules.referenceNumber(java.time.LocalDate.now().getYear(), sr.getLong(1));
            }

            // Route it to the fiduciary's DPO straight away (oldest active DPO account).
            try (PreparedStatement d = conn.prepareStatement("SELECT id FROM operators WHERE fiduciary_id = ? AND role = 'DPO' AND status = 'ACTIVE' ORDER BY created_at, id LIMIT 1")) {
                d.setObject(1, fiduciaryId);
                try (ResultSet dr = d.executeQuery()) { if (dr.next()) autoAssignedDpo = (UUID) dr.getObject(1); }
            }

            String sql = "INSERT INTO grievances (id, user_id, fiduciary_id, type, subject, description, submission_timestamp, status, communication_log, attachments, due_date, last_updated_at, channel, reference_number, consent_record_id, assigned_dpo_user_id) " +
                    "VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, 'NEW', '[]'::jsonb, ?::jsonb, ?, NOW(), ?, ?, ?, ?) RETURNING id";

            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setString(3, type);
            pstmt.setString(4, subject);
            pstmt.setString(5, description);
            pstmt.setTimestamp(6, submissionTime);
            pstmt.setString(7, attachments != null ? attachments.toJSONString() : "[]");
            pstmt.setTimestamp(8, dueDate);
            pstmt.setString(9, channel);
            pstmt.setString(10, referenceNumber);
            pstmt.setObject(11, consentRecordId);
            pstmt.setObject(12, autoAssignedDpo);

            rs = pstmt.executeQuery();
            if (rs.next()) {
                newGrievanceId = rs.getString(1);
                JSONObject out = new JSONObject();
                out.put("success", true);
                out.put("grievance_id", newGrievanceId);
                out.put("reference_number", referenceNumber);
                out.put("channel", channel);
                out.put("due_date", dueDate.toInstant().toString());
                OutputProcessor.send(res, 201, out);
                success = true;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        // Audit Log: Instrument after cleanup. Audit user is the principal (userId).
        if (success) {
            new Audit().logEventAsync(userId, fiduciaryId, serviceType, serviceId, "GRIEVANCE_SUBMITTED", "Ref: " + referenceNumber + " Channel: " + channel + " Subject: " + subject);
            try {
                new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), Constants.NOTIF_GRIEVANCE_SUBMITTED);
                if (autoAssignedDpo != null) {
                    new CESService().insertNotification("OPERATOR", autoAssignedDpo.toString(), fiduciaryId.toString(), Constants.NOTIF_GRIEVANCE_ASSIGNED);
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    private void handleUpdateGrievanceStatus(JSONObject input, UUID grievanceId, UUID loginUserId, String callerRole, String serviceType, UUID serviceId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String newStatus = (String) input.get("status");
        String resolutionDetails = (String) input.get("resolution_details");

        if (grievanceId == null || newStatus == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "ID and Status required.", req.getRequestURI());
            return;
        }
        if (!GrievanceRules.isKnownStatus(newStatus)) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown status. Use NEW, IN_PROGRESS, RESOLVED, CLOSED or ESCALATED.", req.getRequestURI());
            return;
        }
        newStatus = newStatus.trim().toUpperCase();
        String resolutionProblem = GrievanceRules.resolutionProblem(newStatus, resolutionDetails);
        if (resolutionProblem != null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Cannot update: " + resolutionProblem + ".", req.getRequestURI());
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
            // DPOs may only update grievances belonging to their own fiduciary.
            if (rejectIfNotOwnFiduciary(fiduciaryId, loginUserId, callerRole, res, req)) return;

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
            String notifType = Constants.GRIEVANCE_ESCALATED.equalsIgnoreCase(newStatus)
                    ? Constants.NOTIF_GRIEVANCE_ESCALATED
                    : Constants.GRIEVANCE_RESOLVED.equalsIgnoreCase(newStatus) ? Constants.NOTIF_GRIEVANCE_RESOLVED : null;
            if (notifType != null && principalId != null && !"N/A".equals(principalId)) {
                try {
                    new CESService().insertNotification("PRINCIPAL", principalId, fiduciaryId.toString(), notifType);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
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
                UUID grievanceFiduciaryId = (UUID) rs.getObject("fiduciary_id");
                // Operators may only view grievances explicitly assigned to them.
                if ("OPERATOR".equalsIgnoreCase(callerRole) && (assignedDpoUserId == null || !assignedDpoUserId.equals(loginUserId))) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This grievance is not assigned to you.", req.getRequestURI());
                    return;
                }
                // DPOs may only view grievances belonging to their own fiduciary.
                if (rejectIfNotOwnFiduciary(grievanceFiduciaryId, loginUserId, callerRole, res, req)) return;
                // A data principal may only read their own grievance.
                String principalSubject = InputProcessor.getPrincipalSubject(req);
                if (principalSubject != null && !principalSubject.equals(rs.getString("user_id"))) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This grievance belongs to another data principal.", req.getRequestURI());
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
                g.put("reference_number", rs.getString("reference_number"));
                g.put("channel", rs.getString("channel"));
                g.put("type", rs.getString("type"));
                Object crid = rs.getObject("consent_record_id");
                g.put("consent_record_id", crid != null ? crid.toString() : null);
                g.put("resolution_details", rs.getString("resolution_details"));
                Object fr = rs.getObject("feedback_rating");
                if (fr != null) {
                    g.put("feedback_rating", ((Number) fr).longValue());
                    g.put("feedback_comment", rs.getString("feedback_comment"));
                    g.put("feedback_at", rs.getTimestamp("feedback_at").toInstant().toString());
                }
                g.put("files", listAttachmentMetadata(conn, id));
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
            String sql = "SELECT id, user_id, type, subject, submission_timestamp, status, due_date, assigned_dpo_user_id, reference_number, channel FROM grievances WHERE fiduciary_id = ?"
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
                g.put("reference_number", rs.getString("reference_number"));
                g.put("channel", rs.getString("channel"));
                arr.add(g);
            }
            OutputProcessor.send(res, 200, arr);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Attachments and feedback
    // ------------------------------------------------------------------------------------------
    private static final class GrievanceRef {
        UUID id, fiduciaryId, assignedTo;
        String userId, status;
    }

    private GrievanceRef loadGrievanceRef(Connection conn, UUID id) throws SQLException {
        try (PreparedStatement p = conn.prepareStatement("SELECT id, user_id, fiduciary_id, assigned_dpo_user_id, status FROM grievances WHERE id = ?")) {
            p.setObject(1, id);
            try (ResultSet r = p.executeQuery()) {
                if (!r.next()) return null;
                GrievanceRef g = new GrievanceRef();
                g.id = (UUID) r.getObject("id");
                g.userId = r.getString("user_id");
                g.fiduciaryId = (UUID) r.getObject("fiduciary_id");
                g.assignedTo = (UUID) r.getObject("assigned_dpo_user_id");
                g.status = r.getString("status");
                return g;
            }
        }
    }

    /**
     * May this caller act on this grievance? Same fiduciary as the grievance (operators, API keys, principal tokens);
     * a principal only their own; an OPERATOR only one assigned to them; an API key must name the principal
     * (user_id) the grievance belongs to. Sends the refusal and returns false when not allowed.
     */
    private boolean mayActOn(GrievanceRef g, String bodyUserId, UUID loginUserId, String callerRole, HttpServletResponse res, HttpServletRequest req) {
        if (g == null) {
            OutputProcessor.errorResponse(res, 404, "Not Found", "Grievance not found.", req.getRequestURI());
            return false;
        }
        if (!InputProcessor.callerOwns(req, g.fiduciaryId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You may only access grievances for your own fiduciary.", req.getRequestURI());
            return false;
        }
        String principal = InputProcessor.getPrincipalSubject(req);
        if (principal != null && !principal.equals(g.userId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This grievance belongs to another data principal.", req.getRequestURI());
            return false;
        }
        if ("OPERATOR".equalsIgnoreCase(callerRole) && (g.assignedTo == null || !g.assignedTo.equals(loginUserId))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "This grievance is not assigned to you.", req.getRequestURI());
            return false;
        }
        boolean isApiKeyCaller = principal == null && callerRole == null;
        if (isApiKeyCaller && (bodyUserId == null || !bodyUserId.equals(g.userId))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "'user_id' must be the data principal this grievance belongs to.", req.getRequestURI());
            return false;
        }
        return true;
    }

    private JSONArray listAttachmentMetadata(Connection conn, UUID grievanceId) throws SQLException {
        JSONArray files = new JSONArray();
        try (PreparedStatement p = conn.prepareStatement("SELECT id, file_name, content_type, size_bytes, created_at FROM grievance_attachments WHERE grievance_id = ? ORDER BY created_at")) {
            p.setObject(1, grievanceId);
            try (ResultSet r = p.executeQuery()) {
                while (r.next()) {
                    JSONObject f = new JSONObject();
                    f.put("attachment_id", r.getString("id"));
                    f.put("file_name", r.getString("file_name"));
                    f.put("content_type", r.getString("content_type"));
                    f.put("size_bytes", r.getLong("size_bytes"));
                    f.put("uploaded_at", r.getTimestamp("created_at").toInstant().toString());
                    files.add(f);
                }
            }
        }
        return files;
    }

    private void handleUploadAttachment(JSONObject input, UUID grievanceId, String bodyUserId, UUID loginUserId, String callerRole,
                                        String serviceType, UUID serviceId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String fileName = (String) input.get("file_name");
        String contentType = (String) input.get("content_type");
        String b64 = (String) input.get("content_base64");
        if (grievanceId == null || contentType == null || b64 == null || b64.isEmpty()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "'grievance_id', 'content_type' and 'content_base64' are required.", req.getRequestURI());
            return;
        }
        if (AttachmentRules.encodedTooLarge(b64.length())) {
            OutputProcessor.errorResponse(res, 413, "Payload Too Large", "The file is larger than " + (AttachmentRules.MAX_BYTES / (1024 * 1024)) + " MB.", req.getRequestURI());
            return;
        }
        byte[] data;
        try { data = java.util.Base64.getDecoder().decode(b64); } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "'content_base64' is not valid base64.", req.getRequestURI());
            return;
        }
        String problem = AttachmentRules.problem(fileName, contentType, data);
        if (problem != null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Attachment refused: " + problem + ".", req.getRequestURI());
            return;
        }
        String safeName = AttachmentRules.safeFileName(fileName);
        String sha;
        try {
            StringBuilder hex = new StringBuilder();
            for (byte b : java.security.MessageDigest.getInstance("SHA-256").digest(data)) hex.append(String.format("%02x", b));
            sha = hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) { throw new SQLException(e); }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        String attachmentId = null;
        GrievanceRef g;
        try {
            conn = pool.getConnection();
            g = loadGrievanceRef(conn, grievanceId);
            if (!mayActOn(g, bodyUserId, loginUserId, callerRole, res, req)) return;
            if ("CLOSED".equalsIgnoreCase(g.status)) {
                OutputProcessor.errorResponse(res, 409, "Conflict", "A closed grievance accepts no new attachments.", req.getRequestURI());
                return;
            }
            try (PreparedStatement c = conn.prepareStatement("SELECT COUNT(*) FROM grievance_attachments WHERE grievance_id = ?")) {
                c.setObject(1, grievanceId);
                try (ResultSet cr = c.executeQuery()) {
                    cr.next();
                    if (cr.getInt(1) >= AttachmentRules.MAX_PER_GRIEVANCE) {
                        OutputProcessor.errorResponse(res, 409, "Conflict", "At most " + AttachmentRules.MAX_PER_GRIEVANCE + " attachments per grievance.", req.getRequestURI());
                        return;
                    }
                }
            }
            String by; String byType;
            String principal = InputProcessor.getPrincipalSubject(req);
            if (principal != null) { by = principal; byType = "PRINCIPAL"; }
            else if (loginUserId != null) { by = loginUserId.toString(); byType = "OPERATOR"; }
            else { by = String.valueOf(req.getHeader("X-API-Key")); byType = "API_KEY"; }
            try (PreparedStatement ins = conn.prepareStatement(
                    "INSERT INTO grievance_attachments (grievance_id, fiduciary_id, file_name, content_type, size_bytes, sha256, content, uploaded_by, uploaded_by_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id")) {
                ins.setObject(1, grievanceId);
                ins.setObject(2, g.fiduciaryId);
                ins.setString(3, safeName);
                ins.setString(4, contentType.trim().toLowerCase());
                ins.setInt(5, data.length);
                ins.setString(6, sha);
                ins.setBytes(7, data);
                ins.setString(8, by);
                ins.setString(9, byType);
                try (ResultSet ir = ins.executeQuery()) { ir.next(); attachmentId = ir.getString(1); }
            }
        } finally {
            pool.cleanup(null, null, conn);
        }
        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("attachment_id", attachmentId);
        out.put("file_name", safeName);
        out.put("size_bytes", (long) data.length);
        OutputProcessor.send(res, 201, out);
        new Audit().logEventAsync(g.userId, g.fiduciaryId, serviceType, serviceId, "GRIEVANCE_ATTACHMENT_ADDED", "File: " + safeName + " Size: " + data.length + " SHA256: " + sha);
    }

    private void handleGetAttachment(JSONObject input, String bodyUserId, UUID loginUserId, String callerRole, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String idStr = (String) input.get("attachment_id");
        UUID attachmentId;
        try { attachmentId = UUID.fromString(idStr); } catch (Exception e) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "'attachment_id' is required.", req.getRequestURI());
            return;
        }
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT grievance_id, file_name, content_type, size_bytes, sha256, content FROM grievance_attachments WHERE id = ?");
            ps.setObject(1, attachmentId);
            rs = ps.executeQuery();
            if (!rs.next()) {
                OutputProcessor.errorResponse(res, 404, "Not Found", "Attachment not found.", req.getRequestURI());
                return;
            }
            GrievanceRef g = loadGrievanceRef(conn, (UUID) rs.getObject("grievance_id"));
            if (!mayActOn(g, bodyUserId, loginUserId, callerRole, res, req)) return;
            JSONObject out = new JSONObject();
            out.put("attachment_id", attachmentId.toString());
            out.put("grievance_id", g.id.toString());
            out.put("file_name", rs.getString("file_name"));
            out.put("content_type", rs.getString("content_type"));
            out.put("size_bytes", rs.getLong("size_bytes"));
            out.put("sha256", rs.getString("sha256"));
            out.put("content_base64", java.util.Base64.getEncoder().encodeToString(rs.getBytes("content")));
            OutputProcessor.send(res, 200, out);
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    private void handleFeedback(JSONObject input, UUID grievanceId, String bodyUserId, UUID loginUserId, String callerRole,
                                String serviceType, UUID serviceId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        Object rating = input.get("rating");
        String comment = (String) input.get("comment");
        if (grievanceId == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "'grievance_id' is required.", req.getRequestURI());
            return;
        }
        String problem = GrievanceRules.feedbackProblem(rating, comment);
        if (problem != null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid feedback: " + problem + ".", req.getRequestURI());
            return;
        }
        // Feedback is the data principal's own: operators do not give it on their behalf.
        if (callerRole != null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Only the data principal can give feedback on a grievance.", req.getRequestURI());
            return;
        }
        PoolDB pool = new PoolDB();
        Connection conn = null;
        GrievanceRef g;
        try {
            conn = pool.getConnection();
            g = loadGrievanceRef(conn, grievanceId);
            if (!mayActOn(g, bodyUserId, loginUserId, callerRole, res, req)) return;
            if (!"RESOLVED".equalsIgnoreCase(g.status) && !"CLOSED".equalsIgnoreCase(g.status)) {
                OutputProcessor.errorResponse(res, 409, "Conflict", "Feedback can be given once the grievance is resolved or closed.", req.getRequestURI());
                return;
            }
            try (PreparedStatement u = conn.prepareStatement("UPDATE grievances SET feedback_rating = ?, feedback_comment = ?, feedback_at = NOW(), last_updated_at = NOW() WHERE id = ? AND feedback_at IS NULL")) {
                u.setInt(1, ((Long) rating).intValue());
                u.setString(2, comment);
                u.setObject(3, grievanceId);
                if (u.executeUpdate() == 0) {
                    OutputProcessor.errorResponse(res, 409, "Conflict", "Feedback was already given for this grievance.", req.getRequestURI());
                    return;
                }
            }
        } finally {
            pool.cleanup(null, null, conn);
        }
        OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
        new Audit().logEventAsync(g.userId, g.fiduciaryId, serviceType, serviceId, "GRIEVANCE_FEEDBACK_GIVEN", "Rating: " + rating);
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
            // DPOs may only assign grievances belonging to their own fiduciary.
            UUID assignerLoginUserId = InputProcessor.getAuthenticatedUserId(req);
            if (rejectIfNotOwnFiduciary(fiduciaryId, assignerLoginUserId, callerRole, res, req)) return;
            // The assignee must be an active operator of the same fiduciary, never an account of another tenant.
            if (!InputProcessor.isActiveOperatorOf(operatorId, fiduciaryId)) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "'operator_id' must be an active operator of this fiduciary.", req.getRequestURI());
                return;
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
            try {
                new CESService().insertNotification("OPERATOR", operatorId.toString(), fiduciaryId.toString(), Constants.NOTIF_GRIEVANCE_ASSIGNED);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    private void handleListUserGrievances(UUID fiduciaryId, String userId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        JSONArray arr = new JSONArray();

        try {
            String sql = "SELECT id, type, subject, status, submission_timestamp, due_date, reference_number, channel, feedback_rating FROM grievances WHERE fiduciary_id = ? AND user_id = ? ORDER BY submission_timestamp DESC";
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
                g.put("reference_number", rs.getString("reference_number"));
                g.put("channel", rs.getString("channel"));
                Object rating = rs.getObject("feedback_rating");
                g.put("feedback_given", rating != null);
                arr.add(g);
            }
            OutputProcessor.send(res, 200, arr);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private Timestamp calculateDueDate(String type) {
        // Every complaint gets the default period. (There used to be a 7-day branch for a grievance of type
        // ERASURE_REQUEST, but a grievance does not erase anything: erasure has its own flow, and an erasure
        // COMPLAINT is a complaint like any other.)
        return Timestamp.from(Instant.now().plusSeconds(DEFAULT_SLA_DAYS * 24L * 60 * 60));
    }

    /**
     * Blocks a non-ADMIN DPO/Operator from accessing a grievance belonging to a
     * fiduciary other than their own. No-op for ADMIN or callers not authenticated
     * as an operator at all (client/API-key calls have their own separate scoping).
     * Returns true (and sends a 403) if blocked; caller must return immediately.
     */
    private boolean rejectIfNotOwnFiduciary(UUID targetFiduciaryId, UUID loginUserId, String callerRole, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        // Operators, API keys and principal tokens are all held to their own fiduciary
        // (an API-key or principal caller has no role, which used to bypass this check).
        if (InputProcessor.callerOwns(req, targetFiduciaryId)) {
            return false;
        }
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You may only access grievances for your own fiduciary.", req.getRequestURI());
        return true;
    }

    /** Looks up the fiduciary_id an operator account is bound to (null for ADMIN accounts). */
    private UUID getCallerFiduciaryId(UUID operatorId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fiduciary_id FROM operators WHERE id = ?");
            pstmt.setObject(1, operatorId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                return (UUID) rs.getObject("fiduciary_id");
            }
            return null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}