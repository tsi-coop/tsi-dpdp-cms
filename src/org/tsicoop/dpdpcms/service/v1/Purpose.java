package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.util.PurposeLifecycleRules;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The lifecycle of a processing purpose: OPEN or CLOSED.
 *
 * Closing a purpose (the campaign ended, the service was retired) does four things:
 *  1. records the purpose as CLOSED, so no new consent can be GRANTED for it (declining is still allowed);
 *  2. withdraws the purpose from every principal who had consented to it, using the normal withdrawal path, so the history
 *     is chained, the principal is told, and the purpose's retention timer starts;
 *  3. lets the existing retention machinery raise the purge once the governing retention period has run;
 *  4. stamps that purge with the action the DPO chose: ERASE or DE_IDENTIFY.
 * Reopening a purpose allows grants again; it does not bring old consents back, principals must opt in afresh.
 */
public class Purpose implements Action {

    private static final UUID SYSTEM_FID = new UUID(0L, 0L);
    /** Principals processed per call; a larger tenant simply calls again (closing is repeatable and picks up where it left off). */
    static final int MAX_PER_CALL = 2000;

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
            if (fiduciaryId == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "'fiduciary_id' is required.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_closed_purposes": listClosed(fiduciaryId, res); break;
                case "list_purpose_lifecycle":
                    if (callerRole == null) { forbidStaffOnly(res, req); return; }
                    listLifecycle(fiduciaryId, res);
                    break;
                case "set_purpose_state":
                case "close_purpose":
                case "reopen_purpose": {
                    if (callerRole == null) { forbidStaffOnly(res, req); return; }
                    if (InputProcessor.rejectIfOperator(req, res)) return; // governance: DPO / ADMIN only
                    String state = func.equalsIgnoreCase("close_purpose") ? "CLOSED" : func.equalsIgnoreCase("reopen_purpose") ? "OPEN" : (String) input.get("state");
                    changeState(input, state, fiduciaryId, loginUserId, InputProcessor.getEmail(req), res, req);
                    break;
                }
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown '_func': " + func, req.getRequestURI());
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", "An internal error occurred.", req.getRequestURI());
        }
    }

    private void forbidStaffOnly(HttpServletResponse res, HttpServletRequest req) {
        OutputProcessor.errorResponse(res, 403, "Forbidden", "Staff only.", req.getRequestURI());
    }

    // ---------------------------------------------------------------------------------------
    private void listClosed(UUID fiduciaryId, HttpServletResponse res) throws SQLException {
        JSONArray ids = new JSONArray();
        ids.addAll(new Consent().getClosedPurposes(fiduciaryId));
        OutputProcessor.send(res, 200, ids);
    }

    private void listLifecycle(UUID fiduciaryId, HttpServletResponse res) throws Exception {
        PoolDB pool = new PoolDB(); Connection conn = null;
        try {
            conn = pool.getConnection();
            Map<String, JSONObject> purposes = new LinkedHashMap<>();

            // Purposes declared in the fiduciary's live policies (ACTIVE wins over UNDER_REVIEW)
            try (PreparedStatement p = conn.prepareStatement("SELECT id, version, status, policy_content::text FROM consent_policies WHERE fiduciary_id = ? AND status IN ('ACTIVE', 'UNDER_REVIEW') ORDER BY CASE status WHEN 'ACTIVE' THEN 0 ELSE 1 END, effective_date DESC")) {
                p.setObject(1, fiduciaryId);
                try (ResultSet r = p.executeQuery()) {
                    while (r.next()) {
                        JSONObject content;
                        try { content = (JSONObject) new JSONParser().parse(r.getString(4)); } catch (Exception e) { continue; }
                        Object blockObj = content.get("en");
                        if (!(blockObj instanceof JSONObject) && !content.isEmpty()) blockObj = content.values().iterator().next();
                        if (!(blockObj instanceof JSONObject)) continue;
                        Object arr = ((JSONObject) blockObj).get("data_processing_purposes");
                        if (!(arr instanceof JSONArray)) continue;
                        for (Object o : (JSONArray) arr) {
                            if (!(o instanceof JSONObject) || !(((JSONObject) o).get("id") instanceof String)) continue;
                            JSONObject po = (JSONObject) o; String pid = (String) po.get("id");
                            if (purposes.containsKey(pid)) continue;
                            JSONObject row = new JSONObject();
                            row.put("purpose_id", pid); row.put("name", po.get("name"));
                            row.put("policy_id", r.getString("id")); row.put("policy_version", r.getString("version")); row.put("policy_status", r.getString("status"));
                            row.put("mandatory", Boolean.TRUE.equals(po.get("is_mandatory_for_service")));
                            row.put("state", "OPEN");
                            purposes.put(pid, row);
                        }
                    }
                }
            }
            // Recorded states (a closed purpose may no longer appear in any live policy)
            try (PreparedStatement p = conn.prepareStatement("SELECT purpose_id, state, retention_action, reason, changed_by, changed_at, closed_at, principals_invalidated FROM purpose_states WHERE fiduciary_id = ?")) {
                p.setObject(1, fiduciaryId);
                try (ResultSet r = p.executeQuery()) {
                    while (r.next()) {
                        JSONObject row = purposes.computeIfAbsent(r.getString("purpose_id"), k -> { JSONObject o = new JSONObject(); o.put("purpose_id", k); o.put("name", null); o.put("policy_status", "NOT_IN_A_LIVE_POLICY"); return o; });
                        row.put("state", r.getString("state"));
                        row.put("retention_action", r.getString("retention_action"));
                        row.put("reason", r.getString("reason"));
                        row.put("changed_by", r.getString("changed_by"));
                        row.put("changed_at", r.getTimestamp("changed_at").toInstant().toString());
                        row.put("closed_at", r.getTimestamp("closed_at") == null ? null : r.getTimestamp("closed_at").toInstant().toString());
                        row.put("principals_invalidated", r.getLong("principals_invalidated"));
                    }
                }
            }
            // Principals who currently have consent granted for each purpose
            for (Map.Entry<String, JSONObject> e : purposes.entrySet()) {
                try (PreparedStatement p = conn.prepareStatement("SELECT COUNT(DISTINCT user_id) FROM consent_records WHERE fiduciary_id = ? AND is_active_consent = TRUE AND data_point_consents @> ?::jsonb")) {
                    p.setObject(1, fiduciaryId);
                    p.setString(2, grantedFilter(e.getKey()));
                    try (ResultSet r = p.executeQuery()) { r.next(); e.getValue().put("principals_with_consent", r.getLong(1)); }
                }
            }
            JSONArray out = new JSONArray(); out.addAll(purposes.values());
            OutputProcessor.send(res, 200, out);
        } finally { pool.cleanup(null, null, conn); }
    }

    private static String grantedFilter(String purposeId) {
        JSONObject dp = new JSONObject(); dp.put("data_point_id", purposeId); dp.put("consent_granted", true);
        JSONArray a = new JSONArray(); a.add(dp);
        return a.toJSONString();
    }

    private static UUID parseUuid(String s) {
        if (s == null || s.isEmpty()) return null;
        try { return UUID.fromString(s); } catch (IllegalArgumentException e) { return null; }
    }

    // ---------------------------------------------------------------------------------------
    private void changeState(JSONObject input, String state, UUID fiduciaryId, UUID actorId, String actorEmail,
                             HttpServletResponse res, HttpServletRequest req) throws Exception {
        String purposeId = (String) input.get("purpose_id");
        String reason = (String) input.get("reason");
        boolean actionGiven = input.get("action") != null;
        String action = actionGiven ? input.get("action").toString().trim().toUpperCase() : "ERASE";
        if (purposeId == null || purposeId.isEmpty()) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'purpose_id' is required.", req.getRequestURI()); return; }
        if (!PurposeLifecycleRules.isKnownState(state)) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'state' must be OPEN or CLOSED.", req.getRequestURI()); return; }
        state = state.trim().toUpperCase();
        String problem = PurposeLifecycleRules.reasonProblem(reason);
        if (problem != null) { OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid reason: " + problem + ".", req.getRequestURI()); return; }
        if (state.equals("CLOSED") && !PurposeLifecycleRules.isKnownAction(action)) { OutputProcessor.errorResponse(res, 400, "Bad Request", "'action' must be ERASE or DE_IDENTIFY.", req.getRequestURI()); return; }

        PoolDB pool = new PoolDB(); Connection conn = null;
        List<String[]> principals = new ArrayList<>();
        boolean more = false;
        try {
            conn = pool.getConnection();
            if (!purposeExists(conn, fiduciaryId, purposeId)) {
                OutputProcessor.errorResponse(res, 404, "Not Found", "This fiduciary has no policy declaring that purpose.", req.getRequestURI());
                return;
            }
            // Running close again (to finish a large tenant) without naming an action keeps the one already chosen.
            if (state.equals("CLOSED") && !actionGiven) {
                try (PreparedStatement e = conn.prepareStatement("SELECT retention_action FROM purpose_states WHERE fiduciary_id = ? AND purpose_id = ? AND state = 'CLOSED'")) {
                    e.setObject(1, fiduciaryId); e.setString(2, purposeId);
                    try (ResultSet er = e.executeQuery()) { if (er.next()) action = er.getString(1); }
                }
            }
            // Record the state first, so grants are refused and purges are stamped from this moment.
            try (PreparedStatement u = conn.prepareStatement(
                    "INSERT INTO purpose_states (fiduciary_id, purpose_id, state, retention_action, reason, changed_by, changed_at, closed_at) VALUES (?, ?, ?, ?, ?, ?, NOW(), " + (state.equals("CLOSED") ? "NOW()" : "NULL") + ") " +
                    "ON CONFLICT (fiduciary_id, purpose_id) DO UPDATE SET state = EXCLUDED.state, retention_action = CASE WHEN EXCLUDED.state = 'CLOSED' THEN EXCLUDED.retention_action ELSE purpose_states.retention_action END, " +
                    "reason = EXCLUDED.reason, changed_by = EXCLUDED.changed_by, changed_at = NOW(), " +
                    "closed_at = CASE WHEN EXCLUDED.state = 'CLOSED' THEN COALESCE(purpose_states.closed_at, NOW()) ELSE NULL END")) {
                u.setObject(1, fiduciaryId); u.setString(2, purposeId); u.setString(3, state); u.setString(4, state.equals("CLOSED") ? action : "ERASE");
                u.setString(5, reason.trim()); u.setString(6, actorEmail == null ? "UNKNOWN" : actorEmail);
                u.executeUpdate();
            }
            if (state.equals("CLOSED")) {
                try (PreparedStatement p = conn.prepareStatement("SELECT DISTINCT user_id, policy_id FROM consent_records WHERE fiduciary_id = ? AND is_active_consent = TRUE AND data_point_consents @> ?::jsonb LIMIT " + (MAX_PER_CALL + 1))) {
                    p.setObject(1, fiduciaryId); p.setString(2, grantedFilter(purposeId));
                    try (ResultSet r = p.executeQuery()) { while (r.next()) principals.add(new String[]{r.getString(1), r.getString(2)}); }
                }
                if (principals.size() > MAX_PER_CALL) { more = true; principals = principals.subList(0, MAX_PER_CALL); }
            }
        } finally { pool.cleanup(null, null, conn); }

        int invalidated = 0, failed = 0;
        Consent consent = new Consent();
        for (String[] pr : principals) {
            try {
                JSONObject r = consent.withdrawPurposeBySystem(pr[0], fiduciaryId, pr[1], purposeId, Constants.SERVICE_TYPE_DPO_CONSOLE, actorId);
                if (Boolean.TRUE.equals(r.get("success"))) invalidated++; else failed++;
            } catch (Exception e) { failed++; e.printStackTrace(); }
        }
        if (invalidated > 0) {
            PoolDB p2 = new PoolDB(); Connection c2 = null;
            try {
                c2 = p2.getConnection();
                try (PreparedStatement u = c2.prepareStatement("UPDATE purpose_states SET principals_invalidated = principals_invalidated + ? WHERE fiduciary_id = ? AND purpose_id = ?")) {
                    u.setInt(1, invalidated); u.setObject(2, fiduciaryId); u.setString(3, purposeId); u.executeUpdate();
                }
            } finally { p2.cleanup(null, null, c2); }
        }

        JSONObject out = new JSONObject();
        out.put("success", true); out.put("purpose_id", purposeId); out.put("state", state);
        if (state.equals("CLOSED")) {
            out.put("retention_action", action); out.put("principals_invalidated", (long) invalidated); out.put("failed", (long) failed); out.put("more_to_process", more);
            if (more || failed > 0) out.put("message", "Some principals were not processed. Run close_purpose again to finish; it is safe to repeat.");
        }
        OutputProcessor.send(res, 200, out);

        JSONObject ctx = new JSONObject();
        ctx.put("purpose_id", purposeId); ctx.put("reason", reason.trim());
        if (state.equals("CLOSED")) { ctx.put("retention_action", action); ctx.put("principals_invalidated", invalidated); ctx.put("failed", failed); }
        new Audit().logEventAsync(actorEmail == null ? "UNKNOWN" : actorEmail, fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, actorId,
                state.equals("CLOSED") ? "PURPOSE_CLOSED" : "PURPOSE_REOPENED", ctx.toJSONString());
    }

    private boolean purposeExists(Connection conn, UUID fiduciaryId, String purposeId) throws SQLException {
        String sql = "SELECT 1 FROM (SELECT policy_content FROM consent_policies WHERE fiduciary_id = ? AND jsonb_typeof(policy_content) = 'object') p, " +
                "jsonb_each(p.policy_content) AS l(lang, block), " +
                "jsonb_array_elements(CASE WHEN jsonb_typeof(l.block -> 'data_processing_purposes') = 'array' THEN l.block -> 'data_processing_purposes' ELSE '[]'::jsonb END) AS pu " +
                "WHERE pu ->> 'id' = ? LIMIT 1";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setObject(1, fiduciaryId); p.setString(2, purposeId);
            try (ResultSet r = p.executeQuery()) { return r.next(); }
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}
