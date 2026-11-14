package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.ConsentCaptureMode;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Consent capture evidence, explicit choices, history chain, minors and link_user. Needs Postgres with
 * db/01..21 applied (see tests/README.md); skipped otherwise. The strict-mode tests run only when
 * CONSENT_CAPTURE_MODE=strict, the warn-mode tests only when it is not.
 */
class ConsentCaptureDbTest {
    private static final String SECRET = "s3cret-secret-secret-secret-0123456789";
    private static UUID fid, key;
    private static String policyId;

    @BeforeAll
    static void fixtures() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        fid = UUID.randomUUID();
        sql("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)", fid, "f" + fid.toString().substring(0, 8), fid.toString().substring(0, 8) + ".test");
        UUID app = UUID.randomUUID(); key = UUID.randomUUID();
        sql("INSERT INTO apps (id, fiduciary_id, name) VALUES (?, ?, ?)", app, fid, "app" + app.toString().substring(0, 8));
        sql("INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, status) VALUES (?, ?, ?, ?, 'ACTIVE')", key, new PasswordHasher().hashPassword(SECRET), fid, app);
        policyId = "pol-" + UUID.randomUUID().toString().substring(0, 8);
        String purpose = "{\"id\":\"%s\",\"retention_start_event\":\"COLLECTION\",\"retention_duration_value\":1,\"retention_duration_unit\":\"YEARS\"}";
        String content = "{\"en\":{\"data_processing_purposes\":[" + String.format(purpose, "p1") + "," + String.format(purpose, "p2") + "]}}";
        sql("INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (?, '1', ?, NOW() - interval '1 day', 'ACTIVE', 'IN', ?::jsonb, NOW(), NOW())", policyId, fid, content);
    }

    // ---- db helpers ----
    private static void sql(String q, Object... p) throws Exception {
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); ps.executeUpdate(); } finally { pool.cleanup(null, ps, c); }
    }
    private static String scalar(String q, Object... p) throws Exception {
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; ResultSet rs = null;
        try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); rs = ps.executeQuery(); return rs.next() ? rs.getString(1) : null; } finally { pool.cleanup(rs, ps, c); }
    }

    // ---- servlet fakes ----
    static final class Call { int status = 200; final StringWriter out = new StringWriter(); final Map<String, Object> attrs = new HashMap<>(); final Map<String, String> headers = new HashMap<>(); HttpServletRequest req; HttpServletResponse res; JSONObject json() throws Exception { return (JSONObject) new JSONParser().parse(out.toString()); } }

    private static Call call(JSONObject body, boolean principal, String principalId) {
        Call k = new Call();
        k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString());
        if (principal) { k.attrs.put("auth_via_principal_jwt", Boolean.TRUE); k.attrs.put("fiduciary_id", fid.toString()); k.attrs.put("principal_user_id", principalId); }
        else { k.headers.put("X-API-Key", key.toString()); k.headers.put("X-API-Secret", SECRET); }
        k.headers.put("User-Agent", "Header-UA/1.0");
        k.req = (HttpServletRequest) Proxy.newProxyInstance(ConsentCaptureDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "getAttribute": return k.attrs.get((String) a[0]);
                case "setAttribute": k.attrs.put((String) a[0], a[1]); return null;
                case "getHeader": return k.headers.get((String) a[0]);
                case "getRemoteAddr": return "198.51.100.23";
                case "getRequestURI": return "/api/v1/client/consent";
                default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null;
            }
        });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(ConsentCaptureDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "setStatus": k.status = (Integer) a[0]; return null;
                case "getWriter": return new PrintWriter(k.out, true);
                default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null;
            }
        });
        return k;
    }
    private static JSONObject body(Object... kv) { JSONObject o = new JSONObject(); for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]); return o; }
    private static JSONArray choices(Object... kv) { JSONArray a = new JSONArray(); for (int i = 0; i < kv.length; i += 2) { JSONObject o = new JSONObject(); o.put("data_point_id", kv[i]); if (kv[i + 1] != null) o.put("consent_granted", kv[i + 1]); a.add(o); } return a; }
    private static String user() { return "u-" + UUID.randomUUID().toString().substring(0, 8); }
    private static Call record(String user, JSONArray cs, Object... extra) {
        JSONObject b = body("_func", "record_consent", "user_id", user, "policy_id", policyId, "data_point_consents", cs);
        for (int i = 0; i < extra.length; i += 2) b.put(extra[i], extra[i + 1]);
        Call k = call(b, false, null); new Consent().post(k.req, k.res); return k;
    }
    private static String consentId(Call k) throws Exception { return (String) ((JSONObject) k.json().get("data")).get("consent_record_id"); }
    private static long auditCount(String action, String user) throws Exception {
        new Audit().logEvents();
        return Long.parseLong(scalar("SELECT COUNT(*) FROM audit_logs WHERE audit_action = ? AND user_id = ?", action, user));
    }

    // ---- evidence ----
    @Test
    void evidenceIsWhatTheCmsObservedAndClaimsAreKeptApart() throws Exception {
        String u = user();
        Call k = record(u, choices("p1", true, "p2", false), "user_agent", "Claimed-UA/9", "ip_address", "9.9.9.9", "session_id", "sess-1");
        assertEquals(201, k.status, k.out.toString());
        String id = consentId(k);
        assertEquals("Header-UA/1.0", scalar("SELECT user_agent FROM consent_records WHERE id = ?::uuid", id), "user agent comes from the header");
        assertEquals("API_INTEGRATION", scalar("SELECT capture_mechanism FROM consent_records WHERE id = ?::uuid", id));
        assertEquals("Claimed-UA/9", scalar("SELECT client_metadata->>'user_agent' FROM consent_records WHERE id = ?::uuid", id));
        assertEquals("9.9.9.9", scalar("SELECT client_metadata->>'ip_address' FROM consent_records WHERE id = ?::uuid", id));
        assertEquals("sess-1", scalar("SELECT client_metadata->>'session_id' FROM consent_records WHERE id = ?::uuid", id));
        String expectedIp = new LookupHasher().hashData("198.51.100.23");
        assertEquals(expectedIp, scalar("SELECT ip_address FROM consent_records WHERE id = ?::uuid", id), "stored address is the observed socket address, not the claimed one");
        assertEquals("CONSENT_GIVEN", scalar("SELECT consent_mechanism FROM consent_records WHERE id = ?::uuid", id), "consent_mechanism keeps meaning the action");
    }

    @Test
    void principalTokenGivesPortalMechanism() throws Exception {
        String u = user();
        Call k = call(body("_func", "record_consent", "user_id", u, "policy_id", policyId, "data_point_consents", choices("p1", true, "p2", true)), true, u);
        new Consent().post(k.req, k.res);
        assertEquals(201, k.status, k.out.toString());
        assertEquals("PRINCIPAL_PORTAL", scalar("SELECT capture_mechanism FROM consent_records WHERE id = ?::uuid", consentId(k)));
    }

    // ---- history chain ----
    @Test
    void everyChangeLinksToTheRecordItReplaced() throws Exception {
        String u = user();
        String first = consentId(record(u, choices("p1", true, "p2", true)));
        assertNull(scalar("SELECT supersedes_record_id::text FROM consent_records WHERE id = ?::uuid", first));
        String second = consentId(record(u, choices("p1", true, "p2", false)));
        assertEquals(first, scalar("SELECT supersedes_record_id::text FROM consent_records WHERE id = ?::uuid", second));
        assertEquals("false", scalar("SELECT is_active_consent::text FROM consent_records WHERE id = ?::uuid", first), "old record stays, inactive");

        Call w = call(body("_func", "withdraw_consent", "user_id", u, "policy_id", policyId), false, null);
        new Consent().post(w.req, w.res);
        assertEquals(200, w.status, w.out.toString());
        String third = scalar("SELECT id::text FROM consent_records WHERE user_id = ? AND consent_mechanism = 'CONSENT_WITHDRAWN'", u);
        assertNotNull(third);
        assertEquals(second, scalar("SELECT supersedes_record_id::text FROM consent_records WHERE id = ?::uuid", third));
        assertEquals("Header-UA/1.0", scalar("SELECT user_agent FROM consent_records WHERE id = ?::uuid", third), "withdrawal records the real user agent");
        assertEquals(new LookupHasher().hashData("198.51.100.23"), scalar("SELECT ip_address FROM consent_records WHERE id = ?::uuid", third), "and the real address, not a placeholder");
        assertEquals("API_INTEGRATION", scalar("SELECT capture_mechanism FROM consent_records WHERE id = ?::uuid", third));
        assertEquals("3", scalar("SELECT COUNT(*)::text FROM consent_records WHERE user_id = ? AND fiduciary_id = ?", u, fid), "nothing was overwritten");
    }

    // ---- explicit choices ----
    @Test
    void missingConsentGrantedIsA400NotA500() throws Exception {
        Call k = record(user(), choices("p1", true, "p2", null));
        assertEquals(400, k.status, k.out.toString());
    }

    @Test
    void incompleteChoicesAreAcceptedWithAWarningInWarnMode() throws Exception {
        assumeTrue(!ConsentCaptureMode.strict(), "warn-mode test");
        String u = user();
        Call k = record(u, choices("p1", true)); // p2 not answered
        assertEquals(201, k.status, k.out.toString());
        assertEquals(1, auditCount("CONSENT_CAPTURE_WARNING", u));
    }

    @Test
    void incompleteChoicesAreRejectedInStrictMode() throws Exception {
        assumeTrue(ConsentCaptureMode.strict(), "strict-mode test");
        String u = user();
        Call k = record(u, choices("p1", true));
        assertEquals(400, k.status, k.out.toString());
        assertTrue(k.out.toString().contains("p2"));
        assertEquals("0", scalar("SELECT COUNT(*)::text FROM consent_records WHERE user_id = ?", u), "nothing recorded");
        Call dup = record(u, choices("p1", true, "p1", false, "p2", true));
        assertEquals(400, dup.status);
        Call unknown = record(u, choices("p1", true, "p2", true, "zzz", true));
        assertEquals(400, unknown.status);
        assertEquals(201, record(u, choices("p1", true, "p2", false)).status);
    }

    // ---- minors ----
    private static String parentalLog(String child, String guardian) throws Exception {
        Call k = call(body("_func", "record_parent_consent", "child_principal_id", child, "guardian_principal_id", guardian, "verification_mechanism", "INTERNAL_OTP", "provider_name", "T", "verification_ref_id", "r1"), false, null);
        new Consent().post(k.req, k.res);
        assertEquals(201, k.status, k.out.toString());
        return (String) k.json().get("verification_log_id");
    }

    @Test
    void aRecordedGuardianVerificationFlagsTheChildAsMinorOnTheServer() throws Exception {
        String child = user();
        parentalLog(child, "guardian-1");
        assertEquals("MINOR", scalar("SELECT age_category FROM data_principal WHERE user_id = ? AND fiduciary_id = ?", child, fid));
        assertEquals("guardian-1", scalar("SELECT guardian_id FROM data_principal WHERE user_id = ? AND fiduciary_id = ?", child, fid));
        assertEquals("VERIFIED", scalar("SELECT verification_status FROM data_principal WHERE user_id = ? AND fiduciary_id = ?", child, fid));
    }

    @Test
    void childAndGuardianMustBeDifferent() throws Exception {
        Call k = call(body("_func", "record_parent_consent", "child_principal_id", "same", "guardian_principal_id", "same"), false, null);
        new Consent().post(k.req, k.res);
        assertEquals(400, k.status);
    }

    @Test
    void minorConsentWithAVerifiedLogIsRecordedWithoutWarning() throws Exception {
        String child = user();
        String log = parentalLog(child, "guardian-2");
        Call k = record(child, choices("p1", true, "p2", true), "verification_log_id", log);
        assertEquals(201, k.status, k.out.toString());
        assertEquals(0, auditCount("CONSENT_CAPTURE_WARNING", child));
        assertEquals(log, scalar("SELECT verification_log_id::text FROM consent_records WHERE id = ?::uuid", consentId(k)));
    }

    @Test
    void minorConsentWithoutALogIsWarnedOrRejectedByMode() throws Exception {
        String child = user();
        parentalLog(child, "guardian-3");
        Call k = record(child, choices("p1", true, "p2", true)); // no verification_log_id
        if (ConsentCaptureMode.strict()) {
            assertEquals(400, k.status, k.out.toString());
        } else {
            assertEquals(201, k.status, k.out.toString());
            assertEquals(1, auditCount("CONSENT_CAPTURE_WARNING", child));
        }
        // a log that belongs to someone else does not count
        String other = user();
        String otherLog = parentalLog(other, "guardian-4");
        Call k2 = record(child, choices("p1", true, "p2", true), "verification_log_id", otherLog);
        if (ConsentCaptureMode.strict()) assertEquals(400, k2.status);
    }

    // ---- link_user ----
    @Test
    void linkUserCannotDowngradeAMinorOrDeclareOne() throws Exception {
        String minor = user();
        parentalLog(minor, "guardian-5");
        Call down = call(body("_func", "link_user", "anonymous_user_id", "anon-" + user(), "authenticated_user_id", minor,
                "age_category", "ADULT", "guardian_id", "attacker", "verification_status", "NOT_VERIFIED"), false, null);
        new Consent().post(down.req, down.res);
        assertEquals(200, down.status, down.out.toString());
        assertEquals("MINOR", scalar("SELECT age_category FROM data_principal WHERE user_id = ? AND fiduciary_id = ?", minor, fid), "a declared ADULT must not overwrite the stored MINOR");
        assertEquals("guardian-5", scalar("SELECT guardian_id FROM data_principal WHERE user_id = ? AND fiduciary_id = ?", minor, fid));
        assertEquals("VERIFIED", scalar("SELECT verification_status FROM data_principal WHERE user_id = ? AND fiduciary_id = ?", minor, fid));

        String adult = user();
        Call up = call(body("_func", "link_user", "anonymous_user_id", "anon-" + user(), "authenticated_user_id", adult, "age_category", "MINOR", "guardian_id", "g"), false, null);
        new Consent().post(up.req, up.res);
        assertEquals(200, up.status, up.out.toString());
        assertEquals("ADULT", scalar("SELECT age_category FROM data_principal WHERE user_id = ? AND fiduciary_id = ?", adult, fid), "a declared MINOR is ignored too");
        assertNull(scalar("SELECT guardian_id FROM data_principal WHERE user_id = ? AND fiduciary_id = ?", adult, fid));
        assertEquals(1, auditCount("LINK_USER_DECLARED_FIELDS_IGNORED", adult));
    }
}
