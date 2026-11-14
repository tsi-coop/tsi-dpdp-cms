package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.ces.CESService;
import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.util.GrievanceRules;
import org.tsicoop.dpdpcms.util.NominationRules;
import org.tsicoop.dpdpcms.util.RightsRules;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Data principal rights requests: access (s.11) and correction (s.12).
 *
 * These are rights to be FULFILLED (unlike a grievance, which is a complaint to be resolved). The CMS tracks the
 * request, its deadline, who handled it and the outcome. It never holds personal data values: an access copy is
 * delivered by the DPO outside the CMS, and a correction is described in words. To help the DPO cover every system,
 * the DPO's view of a request carries a read-only "data map" of the apps, purposes and ROPA entries for that principal.
 */
public class Rights implements Action {

    private static final UUID SYSTEM_FID = new UUID(0L, 0L);

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }
            UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);
            String callerRole = InputProcessor.getVerifiedRole(req);

            // The fiduciary comes from the caller's credential, never from the body. Only ADMIN names one.
            UUID fiduciaryId;
            if ("ADMIN".equalsIgnoreCase(callerRole)) {
                fiduciaryId = parseUuid((String) input.get("fiduciary_id"));
            } else {
                fiduciaryId = InputProcessor.getCallerFiduciaryId(req);
                if (fiduciaryId == null || SYSTEM_FID.equals(fiduciaryId)) {
                    OutputProcessor.errorResponse(res, 403, "Forbidden", "No fiduciary is bound to this credential.", req.getRequestURI());
                    return;
                }
            }

            Caller caller = new Caller(req, loginUserId, callerRole, (String) input.get("user_id"));

            switch (func.toLowerCase()) {
                case "submit_rights_request": submit(input, fiduciaryId, caller, res, req); break;
                case "get_rights_request": get(input, caller, res, req); break;
                case "list_user_rights_requests": listForUser(fiduciaryId, caller, res, req); break;
                case "list_rights_requests": listForFiduciary(input, fiduciaryId, caller, res, req); break;
                case "assign_rights_request": assign(input, caller, res, req); break;
                case "update_rights_request_status": updateStatus(input, caller, res, req); break;
                case "create_nomination": createNomination(input, fiduciaryId, caller, res, req); break;
                case "list_nominations": listNominations(fiduciaryId, caller, res, req); break;
                case "revoke_nomination": revokeNomination(input, fiduciaryId, caller, res, req); break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown '_func': " + func, req.getRequestURI());
            }
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid input.", req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", "An internal error occurred.", req.getRequestURI());
        }
    }

    // ---------------------------------------------------------------------------------------
    // Who is calling
    // ---------------------------------------------------------------------------------------
    private static final class Caller {
        final UUID loginUserId; final String role; final String principalSubject; final String bodyUserId; final boolean viaApiKey;
        Caller(HttpServletRequest req, UUID loginUserId, String role, String bodyUserId) {
            this.loginUserId = loginUserId; this.role = role; this.bodyUserId = bodyUserId;
            this.principalSubject = InputProcessor.getPrincipalSubject(req);
            this.viaApiKey = principalSubject == null && role == null;
        }
        boolean isStaff() { return role != null; }
        boolean isAdmin() { return "ADMIN".equalsIgnoreCase(role); }
        boolean isOperatorRole() { return "OPERATOR".equalsIgnoreCase(role); }
        /** The principal this call is about: the token's subject, else the named user_id. */
        String principalId() { return principalSubject != null ? principalSubject : bodyUserId; }
    }

    private static final class RequestRow {
        UUID id, fiduciaryId, assignedTo; String userId, type, status, reference;
    }

    private RequestRow loadRow(Connection conn, UUID id) throws SQLException {
        try (PreparedStatement p = conn.prepareStatement("SELECT id, user_id, fiduciary_id, assigned_dpo_user_id, type, status, reference_number FROM rights_requests WHERE id = ?")) {
            p.setObject(1, id);
            try (ResultSet r = p.executeQuery()) {
                if (!r.next()) return null;
                RequestRow row = new RequestRow();
                row.id = (UUID) r.getObject("id"); row.userId = r.getString("user_id");
                row.fiduciaryId = (UUID) r.getObject("fiduciary_id"); row.assignedTo = (UUID) r.getObject("assigned_dpo_user_id");
                row.type = r.getString("type"); row.status = r.getString("status"); row.reference = r.getString("reference_number");
                return row;
            }
        }
    }

    /** Same rules as grievances: own fiduciary; a principal only their own; an OPERATOR only what is assigned; an API key names the principal. */
    private boolean mayAccess(RequestRow row, Caller c, HttpServletResponse res, HttpServletRequest req) {
        if (row == null) { OutputProcessor.errorResponse(res, 404, "Not Found", "Rights request not found.", req.getRequestURI()); return false; }
        if (!InputProcessor.callerOwns(req, row.fiduciaryId)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "You may only access requests of your own fiduciary.", req.getRequestURI()); return false;
        }
        if (c.principalSubject != null && !c.principalSubject.equals(row.userId)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "This request belongs to another data principal.", req.getRequestURI()); return false;
        }
        if (c.isOperatorRole() && (row.assignedTo == null || !row.assignedTo.equals(c.loginUserId))) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "This request is not assigned to you.", req.getRequestURI()); return false;
        }
        if (c.viaApiKey && (c.bodyUserId == null || !c.bodyUserId.equals(row.userId))) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "'user_id' must be the data principal this request belongs to.", req.getRequestURI()); return false;
        }
        return true;
    }

    // ---------------------------------------------------------------------------------------
    // submit
    // ---------------------------------------------------------------------------------------
    private void submit(JSONObject input, UUID fiduciaryId, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        if (fiduciaryId == null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'fiduciary_id' is required.", req.getRequestURI()); return; }
        String type = input.get("type") == null ? null : input.get("type").toString().trim().toUpperCase();
        String description = (String) input.get("description");
        String userId = c.principalId();
        if (userId == null || userId.isEmpty()) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'user_id' is required.", req.getRequestURI()); return; }
        if (c.principalSubject != null && c.bodyUserId != null && !c.bodyUserId.equals(c.principalSubject)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "A principal can only submit requests for themselves.", req.getRequestURI()); return;
        }
        if (!RightsRules.isKnownType(type)) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'type' must be ACCESS or CORRECTION.", req.getRequestURI()); return; }
        String problem = RightsRules.descriptionProblem(description);
        if (problem != null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid description: " + problem + ".", req.getRequestURI()); return; }
        if (c.isOperatorRole() ) { OutputProcessor.errorResponse(res, 403, "Forbidden", "Operators do not file requests on behalf of principals.", req.getRequestURI()); return; }

        boolean viaPrincipal = c.principalSubject != null;
        String channel = GrievanceRules.channel(viaPrincipal, (String) input.get("channel"), c.isStaff() ? "OPERATOR_CONSOLE" : "API_INTEGRATION");
        if (channel == null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Unsupported 'channel'.", req.getRequestURI()); return; }

        Integer days = RightsRules.slaDays(System.getenv("ACCESS".equals(type) ? "ACCESS_SLA_DAYS" : "CORRECTION_SLA_DAYS"));
        Timestamp due = days == null ? null : Timestamp.from(Instant.now().plusSeconds(days * 24L * 3600L));

        PoolDB pool = new PoolDB(); Connection conn = null;
        String id, reference; UUID dpo = null;
        try {
            conn = pool.getConnection();
            try (PreparedStatement s = conn.prepareStatement("SELECT nextval('rights_request_reference_seq')"); ResultSet r = s.executeQuery()) {
                r.next(); reference = RightsRules.referenceNumber(java.time.LocalDate.now().getYear(), r.getLong(1));
            }
            try (PreparedStatement d = conn.prepareStatement("SELECT id FROM operators WHERE fiduciary_id = ? AND role = 'DPO' AND status = 'ACTIVE' ORDER BY created_at, id LIMIT 1")) {
                d.setObject(1, fiduciaryId);
                try (ResultSet dr = d.executeQuery()) { if (dr.next()) dpo = (UUID) dr.getObject(1); }
            }
            try (PreparedStatement ins = conn.prepareStatement(
                    "INSERT INTO rights_requests (id, reference_number, user_id, fiduciary_id, type, description, status, due_date, assigned_dpo_user_id, channel) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, 'NEW', ?, ?, ?) RETURNING id")) {
                ins.setString(1, reference); ins.setString(2, userId); ins.setObject(3, fiduciaryId); ins.setString(4, type);
                ins.setString(5, description.trim()); ins.setTimestamp(6, due); ins.setObject(7, dpo); ins.setString(8, channel);
                try (ResultSet ir = ins.executeQuery()) { ir.next(); id = ir.getString(1); }
            }
        } finally { pool.cleanup(null, null, conn); }

        JSONObject out = new JSONObject();
        out.put("success", true); out.put("request_id", id); out.put("reference_number", reference);
        out.put("type", type); out.put("status", "NEW"); out.put("due_date", due == null ? null : due.toInstant().toString());
        OutputProcessor.send(res, 201, out);

        new Audit().logEventAsync(userId, fiduciaryId, c.isStaff() ? Constants.SERVICE_TYPE_DPO_CONSOLE : Constants.SERVICE_TYPE_APP, null,
                "RIGHTS_REQUEST_SUBMITTED", "Ref: " + reference + " Type: " + type + " Channel: " + channel);
        try {
            new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), Constants.NOTIF_RIGHTS_SUBMITTED);
            if (dpo != null) new CESService().insertNotification("OPERATOR", dpo.toString(), fiduciaryId.toString(), Constants.NOTIF_RIGHTS_ASSIGNED);
        } catch (SQLException e) { e.printStackTrace(); }
    }

    // ---------------------------------------------------------------------------------------
    // read
    // ---------------------------------------------------------------------------------------
    private JSONObject toJson(ResultSet r) throws SQLException {
        JSONObject o = new JSONObject();
        o.put("request_id", r.getString("id"));
        o.put("reference_number", r.getString("reference_number"));
        o.put("user_id", r.getString("user_id"));
        o.put("type", r.getString("type"));
        o.put("description", r.getString("description"));
        o.put("status", r.getString("status"));
        Timestamp due = r.getTimestamp("due_date");
        o.put("due_date", due == null ? null : due.toInstant().toString());
        o.put("overdue", RightsRules.isOverdue(r.getString("status"), due == null ? null : due.getTime(), System.currentTimeMillis()));
        Object assigned = r.getObject("assigned_dpo_user_id");
        o.put("assigned_dpo_user_id", assigned == null ? null : assigned.toString());
        o.put("outcome_note", r.getString("outcome_note"));
        o.put("channel", r.getString("channel"));
        o.put("submission_timestamp", r.getTimestamp("submission_timestamp").toInstant().toString());
        Timestamp resolved = r.getTimestamp("resolution_timestamp");
        o.put("resolution_timestamp", resolved == null ? null : resolved.toInstant().toString());
        return o;
    }

    private static final String COLUMNS = "id, reference_number, user_id, fiduciary_id, type, description, status, due_date, assigned_dpo_user_id, outcome_note, channel, submission_timestamp, resolution_timestamp";

    private void get(JSONObject input, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID id = parseUuid((String) input.get("request_id"));
        if (id == null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'request_id' is required.", req.getRequestURI()); return; }
        PoolDB pool = new PoolDB(); Connection conn = null;
        try {
            conn = pool.getConnection();
            RequestRow row = loadRow(conn, id);
            if (!mayAccess(row, c, res, req)) return;
            JSONObject out;
            try (PreparedStatement p = conn.prepareStatement("SELECT " + COLUMNS + " FROM rights_requests WHERE id = ?")) {
                p.setObject(1, id);
                try (ResultSet r = p.executeQuery()) { r.next(); out = toJson(r); }
            }
            // The DPO's view carries the data map; the principal's does not.
            if (c.isStaff()) out.put("data_map", buildDataMap(conn, row.fiduciaryId, row.userId));
            OutputProcessor.send(res, 200, out);
        } finally { pool.cleanup(null, null, conn); }
    }

    private void listForUser(UUID fiduciaryId, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String userId = c.principalId();
        if (userId == null || userId.isEmpty() || fiduciaryId == null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'user_id' is required.", req.getRequestURI()); return; }
        if (c.principalSubject != null && c.bodyUserId != null && !c.bodyUserId.equals(c.principalSubject)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "A principal can only list their own requests.", req.getRequestURI()); return;
        }
        PoolDB pool = new PoolDB(); Connection conn = null;
        try {
            conn = pool.getConnection();
            JSONArray arr = new JSONArray();
            try (PreparedStatement p = conn.prepareStatement("SELECT " + COLUMNS + " FROM rights_requests WHERE fiduciary_id = ? AND user_id = ?" + (c.isOperatorRole() ? " AND assigned_dpo_user_id = ?" : "") + " ORDER BY submission_timestamp DESC LIMIT 200")) {
                p.setObject(1, fiduciaryId); p.setString(2, userId);
                if (c.isOperatorRole()) p.setObject(3, c.loginUserId);
                try (ResultSet r = p.executeQuery()) { while (r.next()) arr.add(toJson(r)); }
            }
            OutputProcessor.send(res, 200, arr);
        } finally { pool.cleanup(null, null, conn); }
    }

    private void listForFiduciary(JSONObject input, UUID fiduciaryId, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        if (!c.isStaff()) { OutputProcessor.errorResponse(res, 403, "Forbidden", "Staff only.", req.getRequestURI()); return; }
        if (fiduciaryId == null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'fiduciary_id' is required.", req.getRequestURI()); return; }
        StringBuilder sql = new StringBuilder("SELECT " + COLUMNS + " FROM rights_requests WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>(); params.add(fiduciaryId);
        String type = (String) input.get("type"), status = (String) input.get("status");
        if (type != null && !type.isEmpty()) { if (!RightsRules.isKnownType(type)) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown type.", req.getRequestURI()); return; } sql.append(" AND type = ?"); params.add(type.toUpperCase()); }
        if (status != null && !status.isEmpty()) { if (!RightsRules.isKnownStatus(status)) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown status.", req.getRequestURI()); return; } sql.append(" AND status = ?"); params.add(status.toUpperCase()); }
        if (Boolean.TRUE.equals(input.get("overdue"))) sql.append(" AND status IN ('NEW','IN_PROGRESS') AND due_date IS NOT NULL AND due_date < NOW()");
        if (c.isOperatorRole()) { sql.append(" AND assigned_dpo_user_id = ?"); params.add(c.loginUserId); }
        sql.append(" ORDER BY submission_timestamp DESC LIMIT 200");
        PoolDB pool = new PoolDB(); Connection conn = null;
        try {
            conn = pool.getConnection();
            JSONArray arr = new JSONArray();
            try (PreparedStatement p = conn.prepareStatement(sql.toString())) {
                for (int i = 0; i < params.size(); i++) p.setObject(i + 1, params.get(i));
                try (ResultSet r = p.executeQuery()) { while (r.next()) arr.add(toJson(r)); }
            }
            OutputProcessor.send(res, 200, arr);
        } finally { pool.cleanup(null, null, conn); }
    }

    // ---------------------------------------------------------------------------------------
    // assign / status
    // ---------------------------------------------------------------------------------------
    private void assign(JSONObject input, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        if (InputProcessor.rejectIfOperator(req, res)) return; // only DPO / ADMIN delegate
        if (!c.isStaff()) { OutputProcessor.errorResponse(res, 403, "Forbidden", "Staff only.", req.getRequestURI()); return; }
        UUID id = parseUuid((String) input.get("request_id"));
        UUID operatorId = parseUuid((String) input.get("operator_id"));
        if (id == null || operatorId == null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'request_id' and 'operator_id' are required.", req.getRequestURI()); return; }
        PoolDB pool = new PoolDB(); Connection conn = null; RequestRow row;
        try {
            conn = pool.getConnection();
            row = loadRow(conn, id);
            if (!mayAccess(row, c, res, req)) return;
            if (!InputProcessor.isActiveOperatorOf(operatorId, row.fiduciaryId)) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "'operator_id' must be an active operator of this fiduciary.", req.getRequestURI()); return;
            }
            try (PreparedStatement u = conn.prepareStatement("UPDATE rights_requests SET assigned_dpo_user_id = ?, last_updated_at = NOW() WHERE id = ?")) {
                u.setObject(1, operatorId); u.setObject(2, id); u.executeUpdate();
            }
        } finally { pool.cleanup(null, null, conn); }
        OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
        new Audit().logEventAsync(row.userId, row.fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, c.loginUserId, "RIGHTS_REQUEST_ASSIGNED", "Ref: " + row.reference + " Assigned to operator: " + operatorId);
        try { new CESService().insertNotification("OPERATOR", operatorId.toString(), row.fiduciaryId.toString(), Constants.NOTIF_RIGHTS_ASSIGNED); } catch (SQLException e) { e.printStackTrace(); }
    }

    private void updateStatus(JSONObject input, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        if (!c.isStaff()) { OutputProcessor.errorResponse(res, 403, "Forbidden", "Staff only.", req.getRequestURI()); return; }
        UUID id = parseUuid((String) input.get("request_id"));
        String newStatus = input.get("status") == null ? null : input.get("status").toString().trim().toUpperCase();
        String note = (String) input.get("outcome_note");
        if (id == null || newStatus == null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'request_id' and 'status' are required.", req.getRequestURI()); return; }
        if (!RightsRules.isKnownStatus(newStatus)) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown status. Use IN_PROGRESS, FULFILLED or REJECTED.", req.getRequestURI()); return; }
        String problem = RightsRules.outcomeProblem(newStatus, note);
        if (problem != null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Cannot update: " + problem + ".", req.getRequestURI()); return; }

        PoolDB pool = new PoolDB(); Connection conn = null; RequestRow row;
        try {
            conn = pool.getConnection();
            row = loadRow(conn, id);
            if (!mayAccess(row, c, res, req)) return;
            if (!RightsRules.canTransition(row.status, newStatus)) {
                OutputProcessor.errorResponse(res, 409, "Conflict", "A " + row.status + " request cannot become " + newStatus + ".", req.getRequestURI()); return;
            }
            boolean terminal = newStatus.equals("FULFILLED") || newStatus.equals("REJECTED");
            try (PreparedStatement u = conn.prepareStatement("UPDATE rights_requests SET status = ?, outcome_note = COALESCE(?, outcome_note), resolution_timestamp = " + (terminal ? "NOW()" : "resolution_timestamp") + ", last_updated_at = NOW() WHERE id = ? AND status = ?")) {
                u.setString(1, newStatus); u.setString(2, note == null ? null : note.trim()); u.setObject(3, id); u.setString(4, row.status);
                if (u.executeUpdate() == 0) { OutputProcessor.errorResponse(res, 409, "Conflict", "The request changed while you were updating it. Reload and try again.", req.getRequestURI()); return; }
            }
        } finally { pool.cleanup(null, null, conn); }
        OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
        // Tracking only: nothing is sent to apps. The principal is told about the outcome.
        new Audit().logEventAsync(row.userId, row.fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, c.loginUserId, "RIGHTS_REQUEST_STATUS_UPDATED", "Ref: " + row.reference + " Status: " + newStatus + (note != null ? " Note: " + note.trim() : ""));
        String notif = newStatus.equals("FULFILLED") ? Constants.NOTIF_RIGHTS_FULFILLED : newStatus.equals("REJECTED") ? Constants.NOTIF_RIGHTS_REJECTED : null;
        if (notif != null) {
            try { new CESService().insertNotification("PRINCIPAL", row.userId, row.fiduciaryId.toString(), notif); } catch (SQLException e) { e.printStackTrace(); }
        }
    }

    // ---------------------------------------------------------------------------------------
    // The DPO's checklist: where does this principal's data live?
    // ---------------------------------------------------------------------------------------
    private JSONObject buildDataMap(Connection conn, UUID fiduciaryId, String userId) throws SQLException {
        JSONObject map = new JSONObject();

        // Apps and processors that checked consent for this principal, and for which purposes
        Map<String, JSONObject> apps = new LinkedHashMap<>();
        Set<String> purposeIds = new LinkedHashSet<>();
        try (PreparedStatement p = conn.prepareStatement(
                "SELECT cv.app_id, a.name, cv.purpose_id FROM consent_validations cv LEFT JOIN apps a ON a.id = cv.app_id " +
                "WHERE cv.fiduciary_id = ? AND cv.user_id = ? GROUP BY cv.app_id, a.name, cv.purpose_id ORDER BY a.name, cv.purpose_id")) {
            p.setObject(1, fiduciaryId); p.setString(2, userId);
            try (ResultSet r = p.executeQuery()) {
                while (r.next()) {
                    String appId = r.getString("app_id");
                    String key = appId == null ? "(no app)" : appId;
                    JSONObject a = apps.computeIfAbsent(key, k -> {
                        JSONObject o = new JSONObject(); o.put("app_id", appId); o.put("name", appId == null ? "(not linked to an app)" : "(unknown app)"); o.put("purposes", new JSONArray()); return o;
                    });
                    if (r.getString("name") != null) a.put("name", r.getString("name"));
                    ((JSONArray) a.get("purposes")).add(r.getString("purpose_id"));
                    purposeIds.add(r.getString("purpose_id"));
                }
            }
        }
        map.put("apps", new JSONArray() {{ addAll(apps.values()); }});

        // Purposes in the principal's latest consent record
        JSONArray consents = new JSONArray();
        try (PreparedStatement p = conn.prepareStatement(
                "SELECT policy_id, policy_version, consent_mechanism, data_point_consents FROM consent_records WHERE fiduciary_id = ? AND user_id = ? ORDER BY timestamp DESC, created_at DESC LIMIT 1")) {
            p.setObject(1, fiduciaryId); p.setString(2, userId);
            try (ResultSet r = p.executeQuery()) {
                if (r.next()) {
                    map.put("policy_id", r.getString("policy_id")); map.put("policy_version", r.getString("policy_version"));
                    map.put("latest_action", r.getString("consent_mechanism"));
                    try {
                        for (Object o : (JSONArray) new JSONParser().parse(r.getString("data_point_consents"))) {
                            JSONObject dp = (JSONObject) o;
                            JSONObject slim = new JSONObject();
                            slim.put("data_point_id", dp.get("data_point_id")); slim.put("consent_granted", dp.get("consent_granted"));
                            consents.add(slim);
                            if (dp.get("data_point_id") != null) purposeIds.add(dp.get("data_point_id").toString());
                        }
                    } catch (Exception ignored) { }
                }
            }
        }
        map.put("consents", consents);

        // ROPA entries for those purposes: what is processed, why, for how long
        JSONArray ropa = new JSONArray();
        if (!purposeIds.isEmpty()) {
            try (PreparedStatement p = conn.prepareStatement(
                    "SELECT id, activity_name, purpose, legal_basis, data_categories, retention_period_days, source_purpose_id FROM ropa_entries " +
                    "WHERE fiduciary_id = ? AND status = 'active' AND source_purpose_id = ANY (?) ORDER BY activity_name")) {
                p.setObject(1, fiduciaryId);
                p.setArray(2, conn.createArrayOf("text", purposeIds.toArray()));
                try (ResultSet r = p.executeQuery()) {
                    while (r.next()) {
                        JSONObject e = new JSONObject();
                        e.put("ropa_id", r.getString("id")); e.put("activity_name", r.getString("activity_name")); e.put("purpose", r.getString("purpose"));
                        e.put("legal_basis", r.getString("legal_basis")); e.put("source_purpose_id", r.getString("source_purpose_id"));
                        Object days = r.getObject("retention_period_days"); e.put("retention_period_days", days == null ? null : ((Number) days).longValue());
                        try { e.put("data_categories", new JSONParser().parse(r.getString("data_categories"))); } catch (Exception ex) { e.put("data_categories", new JSONArray()); }
                        ropa.add(e);
                    }
                }
            }
        }
        map.put("ropa", ropa);
        return map;
    }

    // ---------------------------------------------------------------------------------------
    // Nominations (s.14): who may exercise this principal's rights if they die or become incapacitated
    // The CMS records the nomination. Whether a nominee may act is for the DPO to verify; nothing here grants access.
    // ---------------------------------------------------------------------------------------
    private static java.time.Instant parseInstant(Object v) {
        if (v == null || v.toString().isBlank()) return null;
        String t = v.toString().trim();
        try { return java.time.Instant.parse(t); }
        catch (Exception e) { return java.time.LocalDate.parse(t).atStartOfDay(java.time.ZoneOffset.UTC).toInstant(); } // 2027-01-31
    }

    private void createNomination(JSONObject input, UUID fiduciaryId, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        if (c.isStaff()) { OutputProcessor.errorResponse(res, 403, "Forbidden", "A nomination is made by the data principal.", req.getRequestURI()); return; }
        String userId = c.principalId();
        if (userId == null || userId.isEmpty()) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'user_id' is required.", req.getRequestURI()); return; }
        if (c.principalSubject != null && c.bodyUserId != null && !c.bodyUserId.equals(c.principalSubject)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "A principal can only nominate for themselves.", req.getRequestURI()); return;
        }
        String name = (String) input.get("nominee_name"), contact = (String) input.get("nominee_contact");
        String relationship = input.get("nominee_relationship") == null ? null : input.get("nominee_relationship").toString().trim();
        if (relationship != null && relationship.length() > 50) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'nominee_relationship' is longer than 50 characters.", req.getRequestURI()); return; }
        java.time.Instant now = java.time.Instant.now(), from, until;
        try { from = parseInstant(input.get("valid_from")); until = parseInstant(input.get("valid_until")); }
        catch (Exception e) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Dates must be ISO-8601 (for example 2027-01-31).", req.getRequestURI()); return; }
        String problem = NominationRules.problem(name, contact, from, until, now);
        if (problem != null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid nomination: " + problem + ".", req.getRequestURI()); return; }
        java.time.Instant start = from != null ? from : now;
        String status = NominationRules.effectiveStatus("ACTIVE", start, until, now);

        PoolDB pool = new PoolDB(); Connection conn = null; String id;
        try {
            conn = pool.getConnection();
            try (PreparedStatement cnt = conn.prepareStatement("SELECT COUNT(*) FROM nominations WHERE fiduciary_id = ? AND user_id = ? AND status IN ('PENDING','ACTIVE') AND (valid_until IS NULL OR valid_until > NOW())")) {
                cnt.setObject(1, fiduciaryId); cnt.setString(2, userId);
                try (ResultSet cr = cnt.executeQuery()) {
                    cr.next();
                    if (cr.getInt(1) >= NominationRules.MAX_OPEN_PER_PRINCIPAL) {
                        OutputProcessor.errorResponse(res, 409, "Conflict", "You can have at most " + NominationRules.MAX_OPEN_PER_PRINCIPAL + " current nominations. Revoke one first.", req.getRequestURI()); return;
                    }
                }
            }
            try (PreparedStatement ins = conn.prepareStatement(
                    "INSERT INTO nominations (id, fiduciary_id, user_id, nominee_name_enc, nominee_contact_enc, nominee_relationship, valid_from, valid_until, status) " +
                    "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.ENCRYPT + ", ?, ?, ?, ?) RETURNING id")) {
                int i = 1;
                ins.setObject(i++, fiduciaryId); ins.setString(i++, userId);
                i = DbEncryption.bindEncrypt(ins, i, name.trim());
                i = DbEncryption.bindEncrypt(ins, i, contact.trim());
                ins.setString(i++, relationship == null || relationship.isEmpty() ? null : relationship);
                ins.setTimestamp(i++, Timestamp.from(start));
                ins.setTimestamp(i++, until == null ? null : Timestamp.from(until));
                ins.setString(i, status);
                try (ResultSet ir = ins.executeQuery()) { ir.next(); id = ir.getString(1); }
            }
        } finally { pool.cleanup(null, null, conn); }

        JSONObject out = new JSONObject();
        out.put("success", true); out.put("nomination_id", id); out.put("status", status);
        OutputProcessor.send(res, 201, out);
        // The audit text carries no nominee details (name and contact are personal data of a third party).
        new Audit().logEventAsync(userId, fiduciaryId, Constants.SERVICE_TYPE_APP, null, "NOMINATION_CREATED", "Nomination: " + id);
    }

    private void listNominations(UUID fiduciaryId, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        if (c.isOperatorRole()) { OutputProcessor.errorResponse(res, 403, "Forbidden", "Operators cannot view nominations.", req.getRequestURI()); return; }
        String userId = c.principalId();
        if (userId == null || userId.isEmpty()) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'user_id' is required.", req.getRequestURI()); return; }
        if (c.principalSubject != null && c.bodyUserId != null && !c.bodyUserId.equals(c.principalSubject)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "A principal can only list their own nominations.", req.getRequestURI()); return;
        }
        PoolDB pool = new PoolDB(); Connection conn = null;
        try {
            conn = pool.getConnection();
            JSONArray arr = new JSONArray();
            try (PreparedStatement p = conn.prepareStatement(
                    "SELECT id, " + DbEncryption.decryptCol("nominee_name_enc") + " AS nominee_name, " + DbEncryption.decryptCol("nominee_contact_enc") + " AS nominee_contact, " +
                    "nominee_relationship, valid_from, valid_until, status, created_at, revoked_at FROM nominations WHERE fiduciary_id = ? AND user_id = ? ORDER BY created_at DESC")) {
                int i = DbEncryption.bindKey(p, 1); i = DbEncryption.bindKey(p, i);
                p.setObject(i++, fiduciaryId); p.setString(i, userId);
                try (ResultSet r = p.executeQuery()) {
                    while (r.next()) {
                        JSONObject o = new JSONObject();
                        Timestamp from = r.getTimestamp("valid_from"), until = r.getTimestamp("valid_until");
                        o.put("nomination_id", r.getString("id"));
                        o.put("nominee_name", r.getString("nominee_name"));
                        // The principal sees what they entered; staff see enough to recognise it, not all of it.
                        o.put("nominee_contact", c.isStaff() ? NominationRules.maskContact(r.getString("nominee_contact")) : r.getString("nominee_contact"));
                        o.put("nominee_relationship", r.getString("nominee_relationship"));
                        o.put("valid_from", from.toInstant().toString());
                        o.put("valid_until", until == null ? null : until.toInstant().toString());
                        o.put("status", NominationRules.effectiveStatus(r.getString("status"), from.toInstant(), until == null ? null : until.toInstant(), java.time.Instant.now()));
                        o.put("created_at", r.getTimestamp("created_at").toInstant().toString());
                        arr.add(o);
                    }
                }
            }
            OutputProcessor.send(res, 200, arr);
        } finally { pool.cleanup(null, null, conn); }
    }

    private void revokeNomination(JSONObject input, UUID fiduciaryId, Caller c, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        if (c.isStaff()) { OutputProcessor.errorResponse(res, 403, "Forbidden", "Only the data principal can revoke a nomination.", req.getRequestURI()); return; }
        UUID id = parseUuid((String) input.get("nomination_id"));
        String userId = c.principalId();
        if (id == null || userId == null || userId.isEmpty()) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'nomination_id' and 'user_id' are required.", req.getRequestURI()); return; }
        if (c.principalSubject != null && c.bodyUserId != null && !c.bodyUserId.equals(c.principalSubject)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "A principal can only revoke their own nominations.", req.getRequestURI()); return;
        }
        PoolDB pool = new PoolDB(); Connection conn = null; int updated;
        try {
            conn = pool.getConnection();
            try (PreparedStatement u = conn.prepareStatement("UPDATE nominations SET status = 'REVOKED', revoked_at = NOW(), last_updated_at = NOW() WHERE id = ? AND fiduciary_id = ? AND user_id = ? AND status IN ('PENDING','ACTIVE')")) {
                u.setObject(1, id); u.setObject(2, fiduciaryId); u.setString(3, userId);
                updated = u.executeUpdate();
            }
        } finally { pool.cleanup(null, null, conn); }
        if (updated == 0) { OutputProcessor.errorResponse(res, 404, "Not Found", "No current nomination with that id.", req.getRequestURI()); return; }
        OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
        new Audit().logEventAsync(userId, fiduciaryId, Constants.SERVICE_TYPE_APP, null, "NOMINATION_REVOKED", "Nomination: " + id);
    }

    /**
     * Daily sweep (JobManager): nominations whose end date has passed become EXPIRED, and PENDING ones whose start
     * date has arrived become ACTIVE. Returns {expired, activated}.
     */
    public static int[] sweepNominations() throws SQLException {
        PoolDB pool = new PoolDB(); Connection conn = null;
        try {
            conn = pool.getConnection();
            int expired, activated;
            try (PreparedStatement e = conn.prepareStatement("UPDATE nominations SET status = 'EXPIRED', last_updated_at = NOW() WHERE status IN ('PENDING','ACTIVE') AND valid_until IS NOT NULL AND valid_until < NOW()")) { expired = e.executeUpdate(); }
            try (PreparedStatement a = conn.prepareStatement("UPDATE nominations SET status = 'ACTIVE', last_updated_at = NOW() WHERE status = 'PENDING' AND valid_from <= NOW() AND (valid_until IS NULL OR valid_until >= NOW())")) { activated = a.executeUpdate(); }
            return new int[]{expired, activated};
        } finally { pool.cleanup(null, null, conn); }
    }

    private static UUID parseUuid(String s) {
        if (s == null || s.isEmpty()) return null;
        try { return UUID.fromString(s); } catch (IllegalArgumentException e) { return null; }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}
