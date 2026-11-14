package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tsicoop.dpdpcms.ces.CESService;
import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.Constants;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Purpose lifecycle (close / reopen), the closed-grant refusal, purge action, and withdrawal implications. Needs db/01..24. */
class PurposeLifecycleDbTest {
    private static final String SECRET = "s3cret-secret-secret-secret-0123456789";
    private static UUID fid, fidOther, key, keyOther, app;
    private static String policyId, dpoEmail, opEmail, otherDpoEmail;
    private static final String[] USERS = {"pl-user-a", "pl-user-b", "pl-user-c"};

    @BeforeAll
    static void fixtures() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        fid = fiduciary(); fidOther = fiduciary();
        key = apiKey(fid); keyOther = apiKey(fidOther);
        app = UUID.fromString(scalar("SELECT app_id::text FROM api_keys WHERE id = ?", key));
        dpoEmail = operator("DPO", fid); opEmail = operator("OPERATOR", fid); otherDpoEmail = operator("DPO", fidOther);
        policyId = "pol-" + UUID.randomUUID().toString().substring(0, 8);
        String content = "{\"en\":{\"data_processing_purposes\":[" +
                "{\"id\":\"p1\",\"name\":\"Service delivery\",\"is_mandatory_for_service\":true,\"legal_basis\":\"Contract\",\"retention_policy\":\"Kept 5 years after account closure.\",\"retention_duration_value\":5,\"retention_duration_unit\":\"YEARS\",\"retention_start_event\":\"CESSATION\"}," +
                "{\"id\":\"p2\",\"name\":\"Marketing\",\"is_mandatory_for_service\":false,\"legal_basis\":\"Consent\",\"retention_policy\":\"Deleted after the campaign.\",\"retention_duration_value\":30,\"retention_duration_unit\":\"DAYS\",\"retention_start_event\":\"CESSATION\"}]}}";
        sql("INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (?, '1', ?, NOW() - interval '1 day', 'ACTIVE', 'IN', ?::jsonb, NOW(), NOW())", policyId, fid, content);
    }

    @BeforeEach void reset() { OperatorSessions.useDatabaseStore(); }

    // ---- fixtures ----
    private static void sql(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); ps.executeUpdate(); } finally { pool.cleanup(null, ps, c); } }
    private static String scalar(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; ResultSet rs = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); rs = ps.executeQuery(); return rs.next() ? rs.getString(1) : null; } finally { pool.cleanup(rs, ps, c); } }
    private static UUID fiduciary() throws Exception { UUID id = UUID.randomUUID(); sql("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)", id, "f" + id.toString().substring(0, 8), id.toString().substring(0, 8) + ".test"); return id; }
    private static UUID apiKey(UUID f) throws Exception { UUID a = UUID.randomUUID(), k = UUID.randomUUID(); sql("INSERT INTO apps (id, fiduciary_id, name) VALUES (?, ?, ?)", a, f, "App " + a.toString().substring(0, 6)); sql("INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, status) VALUES (?, ?, ?, ?, 'ACTIVE')", k, new PasswordHasher().hashPassword(SECRET), f, a); return k; }
    private static String operator(String role, UUID f) throws Exception {
        String email = "pl-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", 'x', ?, 'ACTIVE', ?, NOW() - interval '1 hour', NOW())");
            int i = 1; ps.setString(i++, "u" + UUID.randomUUID().toString().substring(0, 8)); ps.setString(i++, email);
            i = DbEncryption.bindEncrypt(ps, i, email); i = DbEncryption.bindHmac(ps, i, email); ps.setString(i++, role); ps.setObject(i, f); ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return email;
    }

    // ---- fakes ----
    static final class Call { int status = 200; final StringWriter out = new StringWriter(); final Map<String, Object> attrs = new HashMap<>(); final Map<String, String> headers = new HashMap<>(); HttpServletRequest req; HttpServletResponse res; JSONObject json() throws Exception { return (JSONObject) new JSONParser().parse(out.toString()); } JSONArray array() throws Exception { return (JSONArray) new JSONParser().parse(out.toString()); } }
    private interface Svc { void run(HttpServletRequest q, HttpServletResponse r); }
    private static Call call(Svc svc, JSONObject body, Consumer<Call> cred) {
        Call k = new Call(); k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString()); cred.accept(k);
        k.req = (HttpServletRequest) Proxy.newProxyInstance(PurposeLifecycleDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> { switch (m.getName()) { case "getAttribute": return k.attrs.get((String) a[0]); case "setAttribute": k.attrs.put((String) a[0], a[1]); return null; case "getHeader": return k.headers.get((String) a[0]); case "getRemoteAddr": return "10.0.0.1"; case "getRequestURI": return "/api/v1/x"; default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(PurposeLifecycleDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> { switch (m.getName()) { case "setStatus": k.status = (Integer) a[0]; return null; case "getWriter": return new PrintWriter(k.out, true); default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        svc.run(k.req, k.res); return k;
    }
    private static Call purpose(JSONObject b, Consumer<Call> c) { return call((q, r) -> new Purpose().post(q, r), b, c); }
    private static Call consent(JSONObject b, Consumer<Call> c) { return call((q, r) -> new Consent().post(q, r), b, c); }
    private static Consumer<Call> apiKeyCred(UUID k) { return c -> { c.headers.put("X-API-Key", k.toString()); c.headers.put("X-API-Secret", SECRET); }; }
    private static Consumer<Call> principal(UUID f, String sub) { return c -> { c.attrs.put("auth_via_principal_jwt", Boolean.TRUE); c.attrs.put("fiduciary_id", f.toString()); c.attrs.put("principal_user_id", sub); }; }
    private static Consumer<Call> staff(String email) { return c -> { JSONObject t = new JSONObject(); t.put("email", email); t.put("mfa", true); c.attrs.put(InputProcessor.AUTH_TOKEN, t); }; }
    private static JSONObject body(Object... kv) { JSONObject o = new JSONObject(); for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]); return o; }
    private static JSONArray choices(boolean p1, boolean p2) { JSONArray a = new JSONArray(); JSONObject x = new JSONObject(); x.put("data_point_id", "p1"); x.put("consent_granted", p1); a.add(x); JSONObject y = new JSONObject(); y.put("data_point_id", "p2"); y.put("consent_granted", p2); a.add(y); return a; }

    private static UUID freshFid; // fiduciary used by the close test, so other tests are not disturbed
    private static void give(String user, boolean p1, boolean p2) {
        Call k = consent(body("_func", "record_consent", "user_id", user, "policy_id", policyId, "data_point_consents", choices(p1, p2)), apiKeyCred(key));
        assertEquals(201, k.status, k.out.toString());
    }
    private static String latest(String user, String col) throws Exception {
        return scalar("SELECT " + col + " FROM consent_records WHERE user_id = ? AND fiduciary_id = ? ORDER BY created_at DESC, id LIMIT 1", user, fid);
    }

    // ---- closing ----
    @Test
    void closingWithdrawsThePurposeFromEveryoneWhoGrantedItAndRefusesNewGrants() throws Exception {
        String u1 = "lc-" + UUID.randomUUID().toString().substring(0, 6), u2 = "lc-" + UUID.randomUUID().toString().substring(0, 6), u3 = "lc-" + UUID.randomUUID().toString().substring(0, 6);
        give(u1, true, true); give(u2, true, true); give(u3, true, false); // u3 never granted p2

        // governance only: an operator cannot close, nor can staff of another fiduciary, nor a short reason
        assertEquals(403, purpose(body("_func", "close_purpose", "purpose_id", "p2", "reason", "Campaign finished for good."), staff(opEmail)).status);
        assertEquals(404, purpose(body("_func", "close_purpose", "purpose_id", "p2", "reason", "Campaign finished for good."), staff(otherDpoEmail)).status, "their fiduciary has no such purpose");
        assertEquals(400, purpose(body("_func", "close_purpose", "purpose_id", "p2", "reason", "no"), staff(dpoEmail)).status);
        assertEquals(400, purpose(body("_func", "close_purpose", "purpose_id", "p2", "reason", "Campaign finished for good.", "action", "SHRED"), staff(dpoEmail)).status);
        assertEquals(404, purpose(body("_func", "close_purpose", "purpose_id", "nope", "reason", "Campaign finished for good."), staff(dpoEmail)).status);
        assertEquals(403, purpose(body("_func", "close_purpose", "purpose_id", "p2", "reason", "Campaign finished for good."), apiKeyCred(key)).status, "staff only");

        Call close = purpose(body("_func", "close_purpose", "purpose_id", "p2", "reason", "Campaign finished for good.", "action", "DE_IDENTIFY"), staff(dpoEmail));
        assertEquals(200, close.status, close.out.toString());
        assertTrue(((Long) close.json().get("principals_invalidated")) >= 2L, close.out.toString());
        assertEquals("CLOSED", scalar("SELECT state FROM purpose_states WHERE fiduciary_id = ? AND purpose_id = 'p2'", fid));
        assertEquals("DE_IDENTIFY", scalar("SELECT retention_action FROM purpose_states WHERE fiduciary_id = ? AND purpose_id = 'p2'", fid));

        for (String u : new String[]{u1, u2}) {
            // p2 is no longer granted, p1 is untouched, and the history is a chain
            assertEquals("0", scalar("SELECT COUNT(*)::text FROM consent_records WHERE user_id = ? AND fiduciary_id = ? AND is_active_consent AND data_point_consents @> '[{\"data_point_id\":\"p2\",\"consent_granted\":true}]'::jsonb", u, fid), u);
            assertEquals("1", scalar("SELECT COUNT(*)::text FROM consent_records WHERE user_id = ? AND fiduciary_id = ? AND is_active_consent AND data_point_consents @> '[{\"data_point_id\":\"p1\",\"consent_granted\":true}]'::jsonb", u, fid), u);
            assertEquals("PURPOSE_CLOSED", latest(u, "capture_mechanism"));
            assertNotNull(latest(u, "supersedes_record_id"));
            assertEquals("CONSENT_WITHDRAWN", latest(u, "consent_mechanism"), "same action value, so retention handling works unchanged");
            assertEquals("1", scalar("SELECT COUNT(*)::text FROM notifications WHERE recipient_id = ? AND notification_type = 'PURPOSE_CLOSED_NOTIFICATION'", u), "the principal is told");
        }
        assertNotEquals("PURPOSE_CLOSED", latest(u3, "capture_mechanism"), "someone who never granted it is left alone");

        // closing again is safe and finds nothing more to do
        Call again = purpose(body("_func", "close_purpose", "purpose_id", "p2", "reason", "Campaign finished for good."), staff(dpoEmail));
        assertEquals(200, again.status);
        assertEquals(0L, again.json().get("principals_invalidated"));
        assertEquals("DE_IDENTIFY", scalar("SELECT retention_action FROM purpose_states WHERE fiduciary_id = ? AND purpose_id = 'p2'", fid), "the chosen action is kept");

        // granting the closed purpose is refused (403) in every path; declining it, and granting others, is fine
        Call grant = consent(body("_func", "record_consent", "user_id", u3, "policy_id", policyId, "data_point_consents", choices(true, true)), apiKeyCred(key));
        assertEquals(403, grant.status, grant.out.toString());
        assertTrue(grant.out.toString().contains("p2"));
        Call decline = consent(body("_func", "record_consent", "user_id", u3, "policy_id", policyId, "data_point_consents", choices(true, false)), apiKeyCred(key));
        assertEquals(201, decline.status, decline.out.toString());

        // principals and keys can see which purposes are closed
        JSONArray closedForKey = purpose(body("_func", "list_closed_purposes"), apiKeyCred(key)).array();
        assertTrue(closedForKey.contains("p2"));
        assertTrue(purpose(body("_func", "list_closed_purposes"), principal(fid, u1)).array().contains("p2"));
        assertFalse(purpose(body("_func", "list_closed_purposes"), apiKeyCred(keyOther)).array().contains("p2"), "closed for this fiduciary only");

        // the DPO's view
        JSONArray life = purpose(body("_func", "list_purpose_lifecycle"), staff(dpoEmail)).array();
        JSONObject p2 = null, p1 = null;
        for (Object o : life) { JSONObject j = (JSONObject) o; if ("p2".equals(j.get("purpose_id"))) p2 = j; if ("p1".equals(j.get("purpose_id"))) p1 = j; }
        assertNotNull(p2); assertNotNull(p1);
        assertEquals("CLOSED", p2.get("state"));
        assertEquals("Campaign finished for good.", p2.get("reason"));
        assertEquals(0L, p2.get("principals_with_consent"));
        assertEquals("OPEN", p1.get("state"));
        assertTrue(((Long) p1.get("principals_with_consent")) >= 3L);
        assertEquals(403, purpose(body("_func", "list_purpose_lifecycle"), principal(fid, u1)).status, "staff only");

        // reopening lets grants through again but does not bring the old consents back
        Call reopen = purpose(body("_func", "reopen_purpose", "purpose_id", "p2", "reason", "The campaign was restarted."), staff(dpoEmail));
        assertEquals(200, reopen.status, reopen.out.toString());
        assertEquals("OPEN", scalar("SELECT state FROM purpose_states WHERE fiduciary_id = ? AND purpose_id = 'p2'", fid));
        assertEquals(201, consent(body("_func", "record_consent", "user_id", u1, "policy_id", policyId, "data_point_consents", choices(true, true)), apiKeyCred(key)).status);
    }

    @Test
    void theRetentionPurgeCarriesTheChosenActionButAnErasureRequestIsAlwaysErase() throws Exception {
        UUID f2 = fiduciary(); UUID k2 = apiKey(f2);
        UUID a2 = UUID.fromString(scalar("SELECT app_id::text FROM api_keys WHERE id = ?", k2));
        sql("INSERT INTO purpose_states (fiduciary_id, purpose_id, state, retention_action) VALUES (?, 'px', 'CLOSED', 'DE_IDENTIFY')", f2);
        CESService ces = new CESService();
        String retention = (String) ces.insertPurgeRequest("someone", f2.toString(), "px", a2.toString(), Constants.PURGE_TRIGGER_EXPIRY, Constants.EVENT_PURGE_INITIATED).get("id");
        String erasure = (String) ces.insertPurgeRequest("someone", f2.toString(), "px", a2.toString(), Constants.PURGE_TRIGGER_ERASURE, Constants.EVENT_PURGE_INITIATED).get("id");
        String open = (String) ces.insertPurgeRequest("someone", f2.toString(), "other-purpose", a2.toString(), Constants.PURGE_TRIGGER_EXPIRY, Constants.EVENT_PURGE_INITIATED).get("id");
        assertEquals("DE_IDENTIFY", scalar("SELECT action FROM purge_requests WHERE id = ?::uuid", retention));
        assertEquals("ERASE", scalar("SELECT action FROM purge_requests WHERE id = ?::uuid", erasure), "a principal's own erasure request is never downgraded");
        assertEquals("ERASE", scalar("SELECT action FROM purge_requests WHERE id = ?::uuid", open), "an open purpose keeps the default");

        // processors see the action
        Call get = call((q, r) -> new Compliance().post(q, r), body("_func", "get_purge_request", "id", retention), apiKeyCred(k2));
        assertEquals(200, get.status, get.out.toString());
        assertEquals("DE_IDENTIFY", get.json().get("action"));
    }

    // ---- withdrawal implications ----
    @Test
    void withdrawalImplicationsComeFromThePublishedPolicy() throws Exception {
        Call k = consent(body("_func", "get_withdrawal_implications", "policy_id", policyId), principal(fid, "anyone"));
        assertEquals(200, k.status, k.out.toString());
        JSONArray imps = (JSONArray) k.json().get("implications");
        assertEquals(2, imps.size());
        JSONObject p1 = (JSONObject) imps.get(0), p2 = (JSONObject) imps.get(1);
        assertEquals(Boolean.TRUE, p1.get("mandatory"));
        assertEquals("Kept 5 years after account closure.", p1.get("data_kept_after_withdrawal"));
        assertEquals(Boolean.FALSE, p2.get("mandatory"));
        assertNotEquals(p1.get("consequence"), p2.get("consequence"));

        Call one = consent(body("_func", "get_withdrawal_implications", "policy_id", policyId, "purpose_ids", new JSONArray() {{ add("p2"); }}), apiKeyCred(key));
        assertEquals(1, ((JSONArray) one.json().get("implications")).size());

        assertEquals(404, consent(body("_func", "get_withdrawal_implications", "policy_id", "no-such-policy"), apiKeyCred(key)).status);
        assertEquals(404, consent(body("_func", "get_withdrawal_implications", "policy_id", policyId), apiKeyCred(keyOther)).status, "another fiduciary has no such policy");
    }
}
