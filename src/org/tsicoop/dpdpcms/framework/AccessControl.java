package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.service.v1.Audit;
import org.tsicoop.dpdpcms.util.*;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Central access check for operator (admin) API calls: role permissions from {@link AccessMap} and
 * tenant binding from {@link TenantRule}.
 *
 * ACCESS_CONTROL_MODE=shadow (default): nothing is blocked or changed. Each decision that WOULD have
 * been a denial, an overwrite or a refusal is logged (stderr and an ACCESS_SHADOW_* audit event, once
 * per distinct case per hour) so the map can be corrected from real traffic before it is enforced.
 * ACCESS_CONTROL_MODE=enforce: denials return 403, a foreign fiduciary_id in the body is replaced by
 * the operator's own, and any internal error in the check refuses the request.
 */
public final class AccessControl {
    private AccessControl() {}

    public static final String MODE_VAR = "ACCESS_CONTROL_MODE";
    private static final UUID SYSTEM_FID = new UUID(0L, 0L);

    public static boolean enforcing() { return AccessPolicy.isEnforce(System.getenv(MODE_VAR)); }

    public static String describeMode() {
        String raw = System.getenv(MODE_VAR);
        if (!AccessPolicy.isRecognisedMode(raw))
            return "SHADOW (" + MODE_VAR + "='" + raw + "' is not recognised; use 'shadow' or 'enforce')";
        return enforcing() ? "ENFORCE" : "SHADOW (decisions are logged, nothing is blocked)";
    }

    // ---------------------------------------------------------------------------------------
    // Role -> permissions (roles table, 60 s cache, compiled-in defaults as fallback)
    // ---------------------------------------------------------------------------------------
    private static final long ROLE_CACHE_MS = 60_000L;
    private static final Map<String, Object[]> roleCache = new ConcurrentHashMap<>(); // role -> {List<String>, fetchedAt}

    /** Forget cached role permissions and report throttling (used by tests and after editing the roles table). */
    public static void clearCaches() { roleCache.clear(); lastReported.clear(); }

    static List<String> permissionsFor(String role) {
        if (role == null) return List.of();
        String key = role.trim().toUpperCase(Locale.ROOT);
        if (key.equals("ADMIN")) return List.of("*"); // never read from the table: cannot be locked out
        Object[] hit = roleCache.get(key);
        long now = System.currentTimeMillis();
        if (hit != null && now - (Long) hit[1] < ROLE_CACHE_MS) {
            @SuppressWarnings("unchecked") List<String> cached = (List<String>) hit[0];
            return cached;
        }
        List<String> perms = RolePermissions.defaults(key);
        PoolDB pool = null; Connection c = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            pool = new PoolDB();
            c = pool.getConnection();
            ps = c.prepareStatement("SELECT permissions FROM roles WHERE upper(name) = ? AND fiduciary_id IS NULL");
            ps.setString(1, key);
            rs = ps.executeQuery();
            if (rs.next()) {
                java.sql.Array arr = rs.getArray(1);
                if (arr != null) {
                    List<String> fromDb = new ArrayList<>();
                    for (Object o : (Object[]) arr.getArray()) if (o != null && Permissions.isWellFormed(o.toString())) fromDb.add(o.toString());
                    perms = fromDb; // an empty list is a valid (and strict) configuration
                }
            }
        } catch (Exception e) {
            System.err.println("[AccessControl] roles table unreadable, using built-in defaults for " + key + ": " + e.getMessage());
        } finally {
            if (pool != null) pool.cleanup(rs, ps, c);
        }
        roleCache.put(key, new Object[]{perms, now});
        return perms;
    }

    // ---------------------------------------------------------------------------------------
    // The check
    // ---------------------------------------------------------------------------------------
    /**
     * @return true to continue with the request; false if it was refused (a 403 has been sent).
     *         Always true in shadow mode.
     */
    public static boolean check(HttpServletRequest req, HttpServletResponse res, String service, String func) {
        boolean enforce = enforcing();
        try {
            String role = InputProcessor.getVerifiedRole(req);
            UUID opFid = InputProcessor.getVerifiedFiduciaryId(req);
            String who = InputProcessor.getEmail(req);

            AccessPolicy.Decision d = AccessPolicy.decide(role, permissionsFor(role), service, func);
            if (!d.allowed()) {
                report(enforce, "DENY", d.name(), who, role, opFid, service, func);
                if (enforce) { forbid(res, req, "You do not have permission for this action."); return false; }
            }

            // Tenant binding (only meaningful for a known operator on a function that is allowed or being observed)
            JSONObject body = InputProcessor.getInput(req);
            UUID bodyFid = null;
            boolean bodyFidInvalid = false;
            Object raw = body == null ? null : body.get("fiduciary_id");
            if (raw != null && !raw.toString().isBlank()) {
                try { bodyFid = UUID.fromString(raw.toString()); } catch (IllegalArgumentException e) { bodyFidInvalid = true; }
            }
            TenantRule.Result t = TenantRule.evaluate(role, opFid, bodyFidInvalid ? SYSTEM_FID : bodyFid);
            switch (t.outcome) {
                case UNBOUND:
                    report(enforce, "TENANT", "UNBOUND_ACCOUNT", who, role, opFid, service, func);
                    if (enforce) { forbid(res, req, "This account is not bound to a fiduciary."); return false; }
                    break;
                case OVERWRITE:
                    report(enforce, "TENANT", "FOREIGN_FIDUCIARY_IN_BODY", who, role, opFid, service, func);
                    if (enforce) setBodyFiduciary(req, body, t.fiduciaryId);
                    break;
                case FILL:
                    if (enforce && body != null) setBodyFiduciary(req, body, t.fiduciaryId);
                    break;
                default:
                    break;
            }
            return true;
        } catch (Exception e) {
            System.err.println("[AccessControl] check failed for " + service + "." + func + ": " + e);
            if (enforce) { forbid(res, req, "Access check failed."); return false; }
            return true; // shadow mode never blocks
        }
    }

    /**
     * Tenant binding for the client API (API key or principal token): the request is for the fiduciary the
     * credential belongs to, whatever {@code fiduciary_id} the body names. Same shadow/enforce behaviour as
     * {@link #check}. Record-level ownership checks inside the services apply in both modes.
     * @return true to continue; false if refused (403 sent, enforce mode only).
     */
    public static boolean checkClient(HttpServletRequest req, HttpServletResponse res, String func) {
        boolean enforce = enforcing();
        try {
            UUID bound = InputProcessor.getCallerFiduciaryId(req);
            String who = InputProcessor.getPrincipalSubject(req);
            if (who == null) who = "apikey:" + req.getHeader("X-API-Key");

            JSONObject body = InputProcessor.getInput(req);
            UUID bodyFid = null;
            boolean invalid = false;
            Object raw = body == null ? null : body.get("fiduciary_id");
            if (raw != null && !raw.toString().isBlank()) {
                try { bodyFid = UUID.fromString(raw.toString()); } catch (IllegalArgumentException e) { invalid = true; }
            }
            TenantRule.Result t = TenantRule.evaluate("CLIENT", bound, invalid ? SYSTEM_FID : bodyFid);
            switch (t.outcome) {
                case UNBOUND:
                    report(enforce, "TENANT", "CLIENT_UNBOUND_CREDENTIAL", who, "CLIENT", bound, "client", func);
                    if (enforce) { forbid(res, req, "This credential is not bound to a fiduciary."); return false; }
                    break;
                case OVERWRITE:
                    report(enforce, "TENANT", "CLIENT_FOREIGN_FIDUCIARY_IN_BODY", who, "CLIENT", bound, "client", func);
                    if (enforce) setBodyFiduciary(req, body, t.fiduciaryId);
                    break;
                case FILL:
                    if (enforce && body != null) setBodyFiduciary(req, body, t.fiduciaryId);
                    break;
                default:
                    break;
            }
            return true;
        } catch (Exception e) {
            System.err.println("[AccessControl] client check failed for " + func + ": " + e);
            if (enforce) { forbid(res, req, "Access check failed."); return false; }
            return true;
        }
    }

    private static void setBodyFiduciary(HttpServletRequest req, JSONObject body, UUID fid) {
        body.put("fiduciary_id", fid.toString());
        req.setAttribute(InputProcessor.REQUEST_DATA, body.toJSONString());
    }

    private static void forbid(HttpServletResponse res, HttpServletRequest req, String message) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", message, req.getRequestURI());
    }

    // ---------------------------------------------------------------------------------------
    // Reporting: one line + one audit event per distinct case per window, so a wrong map cannot flood the log
    // ---------------------------------------------------------------------------------------
    private static final Map<String, Long> lastReported = new ConcurrentHashMap<>();

    private static void report(boolean enforce, String kind, String reason, String who, String role, UUID fid,
                               String service, String func) {
        // Per person as well: a different user denied the same thing a moment later must leave their own trail.
        String key = kind + "|" + reason + "|" + who + "|" + role + "|" + service + "|" + func;
        long now = System.currentTimeMillis();
        long window = enforce ? 60_000L : 3_600_000L;
        Long last = lastReported.get(key);
        if (last != null && now - last < window) return;
        if (lastReported.size() > 5000) lastReported.clear();
        lastReported.put(key, now);

        String action = enforce ? "ACCESS_DENIED" : "ACCESS_SHADOW_" + kind;
        String detail = reason + " role=" + role + " " + service + "." + func + (enforce ? "" : " (not enforced)");
        System.err.println("[ACCESS-" + (enforce ? "ENFORCE" : "SHADOW") + "] " + kind + " " + detail + " operator_fiduciary=" + fid);
        try {
            new Audit().logEventAsync(who == null ? "UNKNOWN" : who, fid == null ? SYSTEM_FID : fid,
                    Constants.SERVICE_TYPE_SYSTEM, null, action, detail);
        } catch (Exception e) {
            System.err.println("[AccessControl] could not queue audit event: " + e.getMessage());
        }
    }
}
