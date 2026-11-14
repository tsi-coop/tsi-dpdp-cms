package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tsicoop.dpdpcms.framework.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
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

/**
 * Cross-tenant attack scenarios for "by id" requests: fiduciary A's credentials against fiduciary B's records.
 * Needs Postgres with db/01..20 applied (see tests/README.md); skipped otherwise.
 */
class ByIdOwnershipDbTest {
    private static final String SECRET = "s3cret-secret-secret-secret-0123456789";
    private static UUID fidA, fidB, keyA, keyB;
    private static String dpoA, adminOp;
    private static String policyIdB, userB = "userB-principal";
    private static UUID purgeB, grievanceB, consentB, notifB;

    @BeforeAll
    static void fixtures() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        fidA = fiduciary(); fidB = fiduciary();
        keyA = apiKey(fidA); keyB = apiKey(fidB);
        dpoA = operator("DPO", fidA); adminOp = operator("ADMIN", null);
        policyIdB = "pol-" + UUID.randomUUID().toString().substring(0, 8);
        sql("INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) " +
                "VALUES (?, '1', ?, NOW(), 'DRAFT', 'IN', '{\"en\":{}}'::jsonb, NOW(), NOW())", policyIdB, fidB);
        purgeB = UUID.randomUUID();
        // assigned to key B's app: a processor can only confirm purges assigned to its own app
        sql("INSERT INTO purge_requests (id, user_id, fiduciary_id, purpose_id, app_id, trigger_event, status) VALUES (?, ?, ?, 'p1', (SELECT app_id FROM api_keys WHERE id = ?), 'ErasureRequest', 'PURGE_INITIATED')", purgeB, userB, fidB, keyB);
        grievanceB = UUID.randomUUID();
        sql("INSERT INTO grievances (id, user_id, fiduciary_id, type, subject, description, due_date, status) VALUES (?, ?, ?, 'OTHER', 's', 'secret details', NOW() + interval '7 days', 'NEW')", grievanceB, userB, fidB);
        consentB = UUID.randomUUID();
        sql("INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, user_agent, data_point_consents, is_active_consent) " +
                "VALUES (?, ?, ?, ?, '1', NOW(), 'IN', 'en', 'CONSENT_GIVEN', 'CONSENT_GIVEN', '10.1.1.1'::inet, 'test', '[]'::jsonb, TRUE)", consentB, userB, fidB, policyIdB);
        notifB = UUID.randomUUID();
        sql("INSERT INTO notifications (id, recipient_type, recipient_id, fiduciary_id, notification_type) VALUES (?, 'PRINCIPAL', ?, ?, 'BREACH')", notifB, userB, fidB);
    }

    @BeforeEach
    void reset() { OperatorSessions.useDatabaseStore(); AccessControl.clearCaches(); }

    // ---- fixture helpers ----
    private static void sql(String sql, Object... p) throws Exception {
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try { ps = c.prepareStatement(sql); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); ps.executeUpdate(); }
        finally { pool.cleanup(null, ps, c); }
    }
    private static String scalar(String sql, Object... p) throws Exception {
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; ResultSet rs = null;
        try { ps = c.prepareStatement(sql); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); rs = ps.executeQuery(); return rs.next() ? rs.getString(1) : null; }
        finally { pool.cleanup(rs, ps, c); }
    }
    private static UUID fiduciary() throws Exception {
        UUID id = UUID.randomUUID();
        sql("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)", id, "f" + id.toString().substring(0, 8), id.toString().substring(0, 8) + ".test");
        return id;
    }
    private static UUID apiKey(UUID fid) throws Exception {
        UUID app = UUID.randomUUID(), key = UUID.randomUUID();
        sql("INSERT INTO apps (id, fiduciary_id, name) VALUES (?, ?, ?)", app, fid, "app" + app.toString().substring(0, 8));
        sql("INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, status) VALUES (?, ?, ?, ?, 'ACTIVE')", key, new PasswordHasher().hashPassword(SECRET), fid, app);
        return key;
    }
    private static String operator(String role, UUID fid) throws Exception {
        String email = "bi-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) " +
                    "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", 'x', ?, 'ACTIVE', ?, NOW(), NOW())");
            int i = 1; ps.setString(i++, "u" + UUID.randomUUID().toString().substring(0, 8)); ps.setString(i++, email);
            i = DbEncryption.bindEncrypt(ps, i, email); i = DbEncryption.bindHmac(ps, i, email);
            ps.setString(i++, role); ps.setObject(i, fid); ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return email;
    }

    // ---- servlet fakes ----
    static final class Call { int status = 200; final StringWriter out = new StringWriter(); final Map<String, Object> attrs = new HashMap<>(); final Map<String, String> headers = new HashMap<>(); HttpServletRequest req; HttpServletResponse res; }

    private static Call call(JSONObject body, Consumer<Call> credential) {
        Call k = new Call();
        k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString());
        credential.accept(k);
        k.req = (HttpServletRequest) Proxy.newProxyInstance(ByIdOwnershipDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "getAttribute": return k.attrs.get((String) a[0]);
                case "setAttribute": k.attrs.put((String) a[0], a[1]); return null;
                case "getHeader": return k.headers.get((String) a[0]);
                case "getRemoteAddr": return "10.0.0.1";
                case "getRequestURI": return "/api/v1/x";
                default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null;
            }
        });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(ByIdOwnershipDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "setStatus": k.status = (Integer) a[0]; return null;
                case "getWriter": return new PrintWriter(k.out, true);
                default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null;
            }
        });
        return k;
    }
    private static Consumer<Call> key(UUID id) { return k -> { k.headers.put("X-API-Key", id.toString()); k.headers.put("X-API-Secret", SECRET); }; }
    private static Consumer<Call> principal(UUID fid, String subject) { return k -> { k.attrs.put("auth_via_principal_jwt", Boolean.TRUE); k.attrs.put("fiduciary_id", fid.toString()); k.attrs.put("principal_user_id", subject); }; }
    private static Consumer<Call> operatorCred(String email) { return k -> { JSONObject t = new JSONObject(); t.put("email", email); t.put("mfa", true); k.attrs.put(InputProcessor.AUTH_TOKEN, t); k.headers.put("Authorization", "Bearer " + JWTUtil.generateToken(email, "n", "x", true)); }; }
    private static JSONObject body(Object... kv) { JSONObject o = new JSONObject(); for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]); return o; }

    // ---- scenarios ----
    @Test
    void policy_otherTenantsDraftCannotBeRead() throws Exception {
        JSONObject b = body("_func", "get_policy", "policy_id", policyIdB, "version", "1");
        Call dpo = call(b, operatorCred(dpoA));            new Policy().post(dpo.req, dpo.res);   assertEquals(403, dpo.status, dpo.out.toString());
        Call kA = call(b, key(keyA));                      new Policy().post(kA.req, kA.res);     assertEquals(403, kA.status);
        Call pA = call(b, principal(fidA, "anyone"));      new Policy().post(pA.req, pA.res);     assertEquals(403, pA.status);
        Call kB = call(b, key(keyB));                      new Policy().post(kB.req, kB.res);     assertEquals(200, kB.status, kB.out.toString());
        Call pB = call(b, principal(fidB, userB));         new Policy().post(pB.req, pB.res);     assertEquals(200, pB.status);
        Call adm = call(b, operatorCred(adminOp));         new Policy().post(adm.req, adm.res);   assertEquals(200, adm.status);
    }

    @Test
    void purge_apiKeyOfAnotherFiduciaryCannotChangeIt() throws Exception {
        // the attack: key A, body claims fiduciary B, names B's purge request
        Call atk = call(body("_func", "update_purge_status", "id", purgeB.toString(), "fiduciary_id", fidB.toString(), "status", "PURGE_COMPLETED", "details", "forged"), key(keyA));
        new Compliance().post(atk.req, atk.res);
        assertEquals(403, atk.status, atk.out.toString());
        assertEquals("PURGE_INITIATED", scalar("SELECT status FROM purge_requests WHERE id = ?", purgeB), "B's purge request must be untouched");

        Call atk2 = call(body("_func", "get_purge_request", "id", purgeB.toString(), "fiduciary_id", fidB.toString()), key(keyA));
        new Compliance().post(atk2.req, atk2.res);
        assertEquals(403, atk2.status);

        Call ok = call(body("_func", "update_purge_status", "id", purgeB.toString(), "status", "PURGE_IN_PROGRESS", "details", "working"), key(keyB));
        new Compliance().post(ok.req, ok.res);
        assertEquals(200, ok.status, ok.out.toString());
        assertEquals("PURGE_IN_PROGRESS", scalar("SELECT status FROM purge_requests WHERE id = ?", purgeB));
    }

    @Test
    void grievance_otherTenantAndOtherPrincipalCannotReadIt() throws Exception {
        JSONObject b = body("_func", "get_grievance", "grievance_id", grievanceB.toString());
        Call kA = call(b, key(keyA));                          new Grievance().post(kA.req, kA.res);   assertEquals(403, kA.status, kA.out.toString());
        Call other = call(b, principal(fidB, "someone-else")); new Grievance().post(other.req, other.res); assertEquals(403, other.status);
        Call otherTenant = call(b, principal(fidA, userB));    new Grievance().post(otherTenant.req, otherTenant.res); assertEquals(403, otherTenant.status);
        Call kB = call(b, key(keyB));                          new Grievance().post(kB.req, kB.res);   assertEquals(200, kB.status);
        Call own = call(b, principal(fidB, userB));            new Grievance().post(own.req, own.res); assertEquals(200, own.status);
    }

    @Test
    void consentRecord_otherTenantAndOtherPrincipalCannotReadIt() throws Exception {
        JSONObject b = body("_func", "get_consent_record_details", "record_id", consentB.toString());
        Call kA = call(b, key(keyA));                          new Consent().post(kA.req, kA.res);    assertEquals(403, kA.status, kA.out.toString());
        Call other = call(b, principal(fidB, "someone-else")); new Consent().post(other.req, other.res); assertEquals(403, other.status);
        Call kB = call(b, key(keyB));                          new Consent().post(kB.req, kB.res);    assertEquals(200, kB.status, kB.out.toString());
        Call own = call(b, principal(fidB, userB));            new Consent().post(own.req, own.res);  assertEquals(200, own.status);
    }

    @Test
    void linkUser_cannotRenameAnotherFiduciarysPrincipalRecords() throws Exception {
        // key A names B's principal as the "anonymous" id, hoping to move B's consent records to an id it controls
        Call atk = call(body("_func", "link_user", "fiduciary_id", fidA.toString(), "anonymous_user_id", userB, "authenticated_user_id", "attacker-owned-id"), key(keyA));
        new Consent().post(atk.req, atk.res);
        assertEquals("userB-principal", scalar("SELECT user_id FROM consent_records WHERE id = ?", consentB), "B's record must keep its principal");
        // and naming B outright is refused
        Call atk2 = call(body("_func", "link_user", "fiduciary_id", fidB.toString(), "anonymous_user_id", userB, "authenticated_user_id", "attacker-owned-id"), key(keyA));
        new Consent().post(atk2.req, atk2.res);
        assertEquals(403, atk2.status);
        assertEquals("userB-principal", scalar("SELECT user_id FROM consent_records WHERE id = ?", consentB));
    }

    @Test
    void recordConsent_forAnotherFiduciaryIsRefused() throws Exception {
        Call atk = call(body("_func", "record_consent", "user_id", userB, "fiduciary_id", fidB.toString(), "policy_id", policyIdB, "data_point_consents", new org.json.simple.JSONArray()), key(keyA));
        new Consent().post(atk.req, atk.res);
        assertEquals(403, atk.status, atk.out.toString());
    }

    @Test
    void notification_readReceiptsCannotBeSetByOthers() throws Exception {
        // principal clients send fiduciary_id (without it Notification.post fails on a null API key: an existing quirk)
        JSONObject b = body("_func", "mark_notification_read", "id", notifB.toString(), "fiduciary_id", fidB.toString());
        Call kA = call(b, key(keyA));                          new Notification().post(kA.req, kA.res); assertEquals(404, kA.status, kA.out.toString());
        Call other = call(b, principal(fidB, "someone-else")); new Notification().post(other.req, other.res); assertEquals(404, other.status);
        assertNull(scalar("SELECT read_at FROM notifications WHERE id = ?", notifB), "must still be unread");
        Call own = call(b, principal(fidB, userB));            new Notification().post(own.req, own.res); assertEquals(200, own.status, own.out.toString());
        assertNotNull(scalar("SELECT read_at FROM notifications WHERE id = ?", notifB));
    }

    @Test
    void audit_rowWithNoFiduciaryIsPlatformOnly() throws Exception {
        // A raw, unhashed row would break the audit chain for every other test, so it is removed again
        // (temporarily lifting the append-only trigger, which only a test with owner rights can do).
        UUID rowId = UUID.randomUUID();
        sql("INSERT INTO audit_logs (id, fiduciary_id, timestamp, user_id, service_type, audit_action, context_details, hash_version) VALUES (?, NULL, NOW(), 'x', 'SYSTEM', 'LEGACY_NULL_FID', 'old row', 1)", rowId);
        try {
            JSONObject b = body("_func", "get_audit_log", "id", rowId.toString());
            Call dpo = call(b, operatorCred(dpoA)); new Audit().post(dpo.req, dpo.res); assertEquals(403, dpo.status, dpo.out.toString());
            Call adm = call(b, operatorCred(adminOp)); new Audit().post(adm.req, adm.res); assertEquals(200, adm.status, adm.out.toString());
        } finally {
            sql("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_no_update_delete");
            try { sql("DELETE FROM audit_logs WHERE id = ?", rowId); }
            finally { sql("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_no_update_delete"); }
        }
    }

    @Test
    void assignment_assigneeMustBelongToTheSameFiduciary() throws Exception {
        UUID purgeA = UUID.randomUUID(), grievanceA = UUID.randomUUID();
        sql("INSERT INTO purge_requests (id, user_id, fiduciary_id, purpose_id, trigger_event, status) VALUES (?, 'uA', ?, 'p1', 'ErasureRequest', 'PENDING')", purgeA, fidA);
        sql("INSERT INTO grievances (id, user_id, fiduciary_id, type, subject, description, due_date, status) VALUES (?, 'uA', ?, 'OTHER', 's', 'd', NOW() + interval '7 days', 'NEW')", grievanceA, fidA);
        String opA = operator("OPERATOR", fidA), opB = operator("OPERATOR", fidB);
        String opAId = scalar("SELECT id FROM operators WHERE email_hmac = " + DbEncryption.HMAC, opA, DbEncryption.key());
        String opBId = scalar("SELECT id FROM operators WHERE email_hmac = " + DbEncryption.HMAC, opB, DbEncryption.key());

        Call p1 = call(body("_func", "assign_purge_request", "id", purgeA.toString(), "operator_id", opBId), operatorCred(dpoA));
        new Compliance().post(p1.req, p1.res);
        assertEquals(400, p1.status, p1.out.toString());
        assertNull(scalar("SELECT assigned_operator_id::text FROM purge_requests WHERE id = ?", purgeA));

        Call g1 = call(body("_func", "assign_grievance", "grievance_id", grievanceA.toString(), "operator_id", opBId), operatorCred(dpoA));
        new Grievance().post(g1.req, g1.res);
        assertEquals(400, g1.status, g1.out.toString());
        assertNull(scalar("SELECT assigned_dpo_user_id::text FROM grievances WHERE id = ?", grievanceA));

        Call p2 = call(body("_func", "assign_purge_request", "id", purgeA.toString(), "operator_id", opAId), operatorCred(dpoA));
        new Compliance().post(p2.req, p2.res);
        assertEquals(200, p2.status, p2.out.toString());
        Call g2 = call(body("_func", "assign_grievance", "grievance_id", grievanceA.toString(), "operator_id", opAId), operatorCred(dpoA));
        new Grievance().post(g2.req, g2.res);
        assertEquals(200, g2.status, g2.out.toString());
    }

    // ---- central client binding (follows ACCESS_CONTROL_MODE) ----
    @Test
    void clientBinding_shadowLogsButDoesNotChange() throws Exception {
        assumeTrue(!AccessControl.enforcing());
        Call k = call(body("_func", "record_consent", "fiduciary_id", fidB.toString()), key(keyA));
        PrintStream old = System.err; ByteArrayOutputStream buf = new ByteArrayOutputStream(); System.setErr(new PrintStream(buf, true));
        boolean ok; try { ok = AccessControl.checkClient(k.req, k.res, "record_consent"); } finally { System.setErr(old); }
        assertTrue(ok);
        assertTrue(buf.toString().contains("CLIENT_FOREIGN_FIDUCIARY_IN_BODY"), buf.toString());
        assertTrue(((String) k.attrs.get(InputProcessor.REQUEST_DATA)).contains(fidB.toString()), "shadow must not rewrite the body");
    }

    @Test
    void clientBinding_enforceOverwritesWithTheKeysOwnFiduciary() throws Exception {
        assumeTrue(AccessControl.enforcing());
        Call k = call(body("_func", "record_consent", "fiduciary_id", fidB.toString()), key(keyA));
        assertTrue(AccessControl.checkClient(k.req, k.res, "record_consent"));
        assertTrue(((String) k.attrs.get(InputProcessor.REQUEST_DATA)).contains(fidA.toString()));
        Call none = call(body("_func", "record_consent"), principal(fidB, userB));
        assertTrue(AccessControl.checkClient(none.req, none.res, "record_consent"));
        assertTrue(((String) none.attrs.get(InputProcessor.REQUEST_DATA)).contains(fidB.toString()));
    }
}
