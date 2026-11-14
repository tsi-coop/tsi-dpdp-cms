package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tsicoop.dpdpcms.framework.*;

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

/** Access and correction requests: submit, privacy, lifecycle, data map, assignment. Needs db/01..23. */
class RightsDbTest {
    private static final String SECRET = "s3cret-secret-secret-secret-0123456789";
    private static UUID fid, fidOther, key, keyOther, app;
    private static String dpoEmail, dpoId, opEmail, opId, otherDpoEmail, otherOpId;
    private static final String U1 = "rights-user-1", U2 = "rights-user-2";

    @BeforeAll
    static void fixtures() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        fid = fiduciary(); fidOther = fiduciary();
        key = apiKey(fid); keyOther = apiKey(fidOther);
        dpoEmail = operator("DPO", fid); dpoId = opId(dpoEmail);
        opEmail = operator("OPERATOR", fid); opId = opId(opEmail);
        otherDpoEmail = operator("DPO", fidOther); otherOpId = opId(operator("OPERATOR", fidOther));
        app = UUID.fromString(scalar("SELECT app_id::text FROM api_keys WHERE id = ?", key));
        // data-map fixtures for U1
        sql("INSERT INTO consent_validations (fiduciary_id, app_id, user_id, purpose_id, status) VALUES (?, ?, ?, 'p1', 'VALID')", fid, app, U1);
        String pol = "pol-" + UUID.randomUUID().toString().substring(0, 8);
        sql("INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (?, '1', ?, NOW(), 'ACTIVE', 'IN', '{\"en\":{}}'::jsonb, NOW(), NOW())", pol, fid);
        sql("INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, data_point_consents, is_active_consent) VALUES (uuid_generate_v4(), ?, ?, ?, '1', NOW(), 'IN', 'en', 'CONSENT_GIVEN', 'CONSENT_GIVEN', 'x', '[{\"data_point_id\":\"p1\",\"consent_granted\":true}]'::jsonb, TRUE)", U1, fid, pol);
        sql("INSERT INTO ropa_entries (id, fiduciary_id, activity_name, purpose, legal_basis, status, source_purpose_id) VALUES (uuid_generate_v4(), ?, 'Newsletter', 'Send updates', 'consent', 'active', 'p1')", fid);
    }

    @BeforeEach void reset() { OperatorSessions.useDatabaseStore(); }

    // ---- fixtures ----
    private static void sql(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); ps.executeUpdate(); } finally { pool.cleanup(null, ps, c); } }
    private static String scalar(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; ResultSet rs = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); rs = ps.executeQuery(); return rs.next() ? rs.getString(1) : null; } finally { pool.cleanup(rs, ps, c); } }
    private static String opId(String email) throws Exception { return scalar("SELECT id::text FROM operators WHERE email_hmac = " + DbEncryption.HMAC, email, DbEncryption.key()); }
    private static UUID fiduciary() throws Exception { UUID id = UUID.randomUUID(); sql("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)", id, "f" + id.toString().substring(0, 8), id.toString().substring(0, 8) + ".test"); return id; }
    private static UUID apiKey(UUID f) throws Exception { UUID a = UUID.randomUUID(), k = UUID.randomUUID(); sql("INSERT INTO apps (id, fiduciary_id, name) VALUES (?, ?, ?)", a, f, "App " + a.toString().substring(0, 6)); sql("INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, status) VALUES (?, ?, ?, ?, 'ACTIVE')", k, new PasswordHasher().hashPassword(SECRET), f, a); return k; }
    private static String operator(String role, UUID f) throws Exception {
        String email = "rt-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
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
    private static Call call(JSONObject body, Consumer<Call> cred) {
        Call k = new Call(); k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString()); cred.accept(k);
        k.req = (HttpServletRequest) Proxy.newProxyInstance(RightsDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> { switch (m.getName()) { case "getAttribute": return k.attrs.get((String) a[0]); case "setAttribute": k.attrs.put((String) a[0], a[1]); return null; case "getHeader": return k.headers.get((String) a[0]); case "getRemoteAddr": return "10.0.0.1"; case "getRequestURI": return "/api/v1/rights"; default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(RightsDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> { switch (m.getName()) { case "setStatus": k.status = (Integer) a[0]; return null; case "getWriter": return new PrintWriter(k.out, true); default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        new Rights().post(k.req, k.res); return k;
    }
    private static Consumer<Call> apiKeyCred(UUID k) { return c -> { c.headers.put("X-API-Key", k.toString()); c.headers.put("X-API-Secret", SECRET); }; }
    private static Consumer<Call> principal(UUID f, String sub) { return c -> { c.attrs.put("auth_via_principal_jwt", Boolean.TRUE); c.attrs.put("fiduciary_id", f.toString()); c.attrs.put("principal_user_id", sub); }; }
    private static Consumer<Call> staff(String email) { return c -> { JSONObject t = new JSONObject(); t.put("email", email); t.put("mfa", true); c.attrs.put(InputProcessor.AUTH_TOKEN, t); }; }
    private static JSONObject body(Object... kv) { JSONObject o = new JSONObject(); for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]); return o; }

    private static String submit(Consumer<Call> cred, String type, String user) throws Exception {
        JSONObject b = body("_func", "submit_rights_request", "type", type, "description", "Please give me a copy of my data.");
        if (user != null) b.put("user_id", user);
        Call k = call(b, cred); assertEquals(201, k.status, k.out.toString()); return (String) k.json().get("request_id");
    }

    // ---- submit / privacy ----
    @Test
    void submittingGivesAReferenceNoInventedDeadlineAndTheFiduciarysDpo() throws Exception {
        assumeTrue(System.getenv("ACCESS_SLA_DAYS") == null, "assumes the SLA is unconfigured");
        long notifiedBefore = Long.parseLong(scalar("SELECT COUNT(*) FROM notifications WHERE recipient_id = ? AND notification_type = 'RIGHTS_REQUEST_SUBMITTED_NOTIFICATION' AND fiduciary_id = ?", U1, fid));
        Call k = call(body("_func", "submit_rights_request", "type", "access", "description", "Please give me a copy of my data."), principal(fid, U1));
        assertEquals(201, k.status, k.out.toString());
        JSONObject j = k.json();
        assertTrue(((String) j.get("reference_number")).matches("RR-\\d{4}-\\d{6}"));
        assertEquals("NEW", j.get("status"));
        assertNull(j.get("due_date"), "no deadline until one is configured");
        assertEquals(dpoId, scalar("SELECT assigned_dpo_user_id::text FROM rights_requests WHERE id = ?::uuid", j.get("request_id")));
        assertEquals("PRINCIPAL_PORTAL", scalar("SELECT channel FROM rights_requests WHERE id = ?::uuid", j.get("request_id")));
        assertEquals(notifiedBefore + 1, Long.parseLong(scalar("SELECT COUNT(*) FROM notifications WHERE recipient_id = ? AND notification_type = 'RIGHTS_REQUEST_SUBMITTED_NOTIFICATION' AND fiduciary_id = ?", U1, fid)), "the principal is told it was received");
    }

    @Test
    void onlyAccessAndCorrectionAreAccepted() throws Exception {
        assertEquals(400, call(body("_func", "submit_rights_request", "type", "ERASURE", "description", "Delete everything about me."), principal(fid, U1)).status);
        assertEquals(400, call(body("_func", "submit_rights_request", "type", "ACCESS", "description", "short"), principal(fid, U1)).status);
    }

    @Test
    void aPrincipalOnlyActsForThemselvesAndSeesOnlyTheirOwn() throws Exception {
        String mine = submit(principal(fid, U1), "ACCESS", null);
        assertEquals(403, call(body("_func", "submit_rights_request", "type", "ACCESS", "description", "Please give me a copy of U1 data.", "user_id", U1), principal(fid, U2)).status);
        assertEquals(403, call(body("_func", "get_rights_request", "request_id", mine), principal(fid, U2)).status);
        Call list = call(body("_func", "list_user_rights_requests"), principal(fid, U2));
        assertEquals(200, list.status);
        for (Object o : list.array()) assertEquals(U2, ((JSONObject) o).get("user_id"));
        Call own = call(body("_func", "get_rights_request", "request_id", mine), principal(fid, U1));
        assertEquals(200, own.status, own.out.toString());
        assertNull(own.json().get("data_map"), "the principal does not get the DPO's data map");
    }

    @Test
    void anApiKeyNamesThePrincipalAndCannotCrossFiduciaries() throws Exception {
        String id = submit(apiKeyCred(key), "CORRECTION", U1);
        assertEquals(403, call(body("_func", "get_rights_request", "request_id", id, "user_id", U2), apiKeyCred(key)).status, "wrong principal");
        assertEquals(403, call(body("_func", "get_rights_request", "request_id", id, "user_id", U1), apiKeyCred(keyOther)).status, "another fiduciary's key");
        assertEquals(200, call(body("_func", "get_rights_request", "request_id", id, "user_id", U1), apiKeyCred(key)).status);
        // a foreign fiduciary_id in the body is ignored: the key's own is used
        Call k = call(body("_func", "submit_rights_request", "type", "ACCESS", "description", "Please give me a copy of my data.", "user_id", U1, "fiduciary_id", fidOther.toString()), apiKeyCred(key));
        assertEquals(201, k.status);
        assertEquals(fid.toString(), scalar("SELECT fiduciary_id::text FROM rights_requests WHERE id = ?::uuid", k.json().get("request_id")));
    }

    // ---- staff view and data map ----
    @Test
    void theDpoSeesTheDataMapForThePrincipal() throws Exception {
        String id = submit(principal(fid, U1), "ACCESS", null);
        Call k = call(body("_func", "get_rights_request", "request_id", id), staff(dpoEmail));
        assertEquals(200, k.status, k.out.toString());
        JSONObject map = (JSONObject) k.json().get("data_map");
        assertNotNull(map);
        JSONArray apps = (JSONArray) map.get("apps");
        assertEquals(1, apps.size());
        assertTrue(((String) ((JSONObject) apps.get(0)).get("name")).startsWith("App "));
        assertEquals("p1", ((JSONArray) ((JSONObject) apps.get(0)).get("purposes")).get(0));
        assertEquals("p1", ((JSONObject) ((JSONArray) map.get("consents")).get(0)).get("data_point_id"));
        assertEquals("Newsletter", ((JSONObject) ((JSONArray) map.get("ropa")).get(0)).get("activity_name"));
    }

    @Test
    void staffOfAnotherFiduciaryCannotSeeOrChangeIt() throws Exception {
        String id = submit(principal(fid, U1), "ACCESS", null);
        assertEquals(403, call(body("_func", "get_rights_request", "request_id", id), staff(otherDpoEmail)).status);
        assertEquals(403, call(body("_func", "update_rights_request_status", "request_id", id, "status", "IN_PROGRESS"), staff(otherDpoEmail)).status);
        Call list = call(body("_func", "list_rights_requests", "fiduciary_id", fid.toString()), staff(otherDpoEmail));
        for (Object o : list.array()) assertNotEquals(id, ((JSONObject) o).get("request_id"));
    }

    // ---- lifecycle ----
    @Test
    void statusMovesForwardOnlyAndClosingNeedsAnOutcomeNote() throws Exception {
        String id = submit(principal(fid, U1), "CORRECTION", null);
        long appNotificationsBefore = Long.parseLong(scalar("SELECT COUNT(*) FROM notifications WHERE recipient_type = 'APP' AND fiduciary_id = ?", fid));
        long webhooksBefore = Long.parseLong(scalar("SELECT COUNT(*) FROM webhook_deliveries WHERE fiduciary_id = ?", fid));

        assertEquals(400, call(body("_func", "update_rights_request_status", "request_id", id, "status", "BOGUS"), staff(dpoEmail)).status);
        assertEquals(400, call(body("_func", "update_rights_request_status", "request_id", id, "status", "REJECTED"), staff(dpoEmail)).status, "a reason is required");
        assertEquals(200, call(body("_func", "update_rights_request_status", "request_id", id, "status", "IN_PROGRESS"), staff(dpoEmail)).status);
        Call done = call(body("_func", "update_rights_request_status", "request_id", id, "status", "FULFILLED", "outcome_note", "Corrected in the CRM and the billing app."), staff(dpoEmail));
        assertEquals(200, done.status, done.out.toString());
        assertEquals("FULFILLED", scalar("SELECT status FROM rights_requests WHERE id = ?::uuid", id));
        assertNotNull(scalar("SELECT resolution_timestamp FROM rights_requests WHERE id = ?::uuid", id));
        assertEquals(409, call(body("_func", "update_rights_request_status", "request_id", id, "status", "REJECTED", "outcome_note", "Changed my mind about this."), staff(dpoEmail)).status, "final");
        assertEquals(409, call(body("_func", "update_rights_request_status", "request_id", id, "status", "IN_PROGRESS"), staff(dpoEmail)).status);

        assertTrue(Long.parseLong(scalar("SELECT COUNT(*) FROM notifications WHERE recipient_id = ? AND notification_type = 'RIGHTS_REQUEST_FULFILLED_NOTIFICATION'", U1)) >= 1, "the principal is told");
        assertEquals(appNotificationsBefore, Long.parseLong(scalar("SELECT COUNT(*) FROM notifications WHERE recipient_type = 'APP' AND fiduciary_id = ?", fid)), "nothing is sent to apps");
        assertEquals(webhooksBefore, Long.parseLong(scalar("SELECT COUNT(*) FROM webhook_deliveries WHERE fiduciary_id = ?", fid)), "no webhook");
    }

    @Test
    void anOperatorWorksOnlyWhatIsAssignedAndAssigneesMustBeColleagues() throws Exception {
        String id = submit(principal(fid, U1), "ACCESS", null);
        assertEquals(403, call(body("_func", "get_rights_request", "request_id", id), staff(opEmail)).status, "not assigned");
        assertEquals(403, call(body("_func", "assign_rights_request", "request_id", id, "operator_id", opId), staff(opEmail)).status, "operators do not delegate");
        assertEquals(400, call(body("_func", "assign_rights_request", "request_id", id, "operator_id", otherOpId), staff(dpoEmail)).status, "another fiduciary's operator");
        assertEquals(200, call(body("_func", "assign_rights_request", "request_id", id, "operator_id", opId), staff(dpoEmail)).status);
        assertEquals(200, call(body("_func", "get_rights_request", "request_id", id), staff(opEmail)).status);
        assertEquals(200, call(body("_func", "update_rights_request_status", "request_id", id, "status", "IN_PROGRESS"), staff(opEmail)).status);
        Call mine = call(body("_func", "list_rights_requests", "fiduciary_id", fid.toString()), staff(opEmail));
        for (Object o : mine.array()) assertEquals(opId, ((JSONObject) o).get("assigned_dpo_user_id"));
    }

    @Test
    void overdueRequestsAreFlaggedWhenADeadlineExists() throws Exception {
        String id = submit(principal(fid, U1), "ACCESS", null);
        sql("UPDATE rights_requests SET due_date = NOW() - interval '2 days' WHERE id = ?::uuid", id);
        Call all = call(body("_func", "list_rights_requests", "fiduciary_id", fid.toString(), "overdue", true), staff(dpoEmail));
        boolean found = false;
        for (Object o : all.array()) { JSONObject j = (JSONObject) o; assertEquals(Boolean.TRUE, j.get("overdue")); if (id.equals(j.get("request_id"))) found = true; }
        assertTrue(found);
        sql("UPDATE rights_requests SET status = 'FULFILLED', outcome_note = 'delivered securely' WHERE id = ?::uuid", id);
        Call after = call(body("_func", "list_rights_requests", "fiduciary_id", fid.toString(), "overdue", true), staff(dpoEmail));
        for (Object o : after.array()) assertNotEquals(id, ((JSONObject) o).get("request_id"), "a closed request is not overdue");
    }
}
