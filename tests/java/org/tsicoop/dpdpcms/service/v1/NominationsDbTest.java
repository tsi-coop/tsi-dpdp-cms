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

/** Nominations (s.14): privacy, validation, status over time, the 5-nomination cap, and the daily sweep. Needs db/01..24. */
class NominationsDbTest {
    private static final String SECRET = "s3cret-secret-secret-secret-0123456789";
    private static UUID fid, fidOther, key, keyOther;
    private static String dpoEmail, opEmail;

    @BeforeAll
    static void fixtures() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        fid = fiduciary(); fidOther = fiduciary();
        key = apiKey(fid); keyOther = apiKey(fidOther);
        dpoEmail = operator("DPO", fid); opEmail = operator("OPERATOR", fid);
    }
    @BeforeEach void reset() { OperatorSessions.useDatabaseStore(); }

    private static void sql(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); ps.executeUpdate(); } finally { pool.cleanup(null, ps, c); } }
    private static String scalar(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; ResultSet rs = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); rs = ps.executeQuery(); return rs.next() ? rs.getString(1) : null; } finally { pool.cleanup(rs, ps, c); } }
    private static UUID fiduciary() throws Exception { UUID id = UUID.randomUUID(); sql("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)", id, "f" + id.toString().substring(0, 8), id.toString().substring(0, 8) + ".test"); return id; }
    private static UUID apiKey(UUID f) throws Exception { UUID a = UUID.randomUUID(), k = UUID.randomUUID(); sql("INSERT INTO apps (id, fiduciary_id, name) VALUES (?, ?, ?)", a, f, "App " + a.toString().substring(0, 6)); sql("INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, status) VALUES (?, ?, ?, ?, 'ACTIVE')", k, new PasswordHasher().hashPassword(SECRET), f, a); return k; }
    private static String operator(String role, UUID f) throws Exception {
        String email = "nm-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", 'x', ?, 'ACTIVE', ?, NOW() - interval '1 hour', NOW())");
            int i = 1; ps.setString(i++, "u" + UUID.randomUUID().toString().substring(0, 8)); ps.setString(i++, email);
            i = DbEncryption.bindEncrypt(ps, i, email); i = DbEncryption.bindHmac(ps, i, email); ps.setString(i++, role); ps.setObject(i, f); ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return email;
    }

    static final class Call { int status = 200; final StringWriter out = new StringWriter(); final Map<String, Object> attrs = new HashMap<>(); final Map<String, String> headers = new HashMap<>(); HttpServletRequest req; HttpServletResponse res; JSONObject json() throws Exception { return (JSONObject) new JSONParser().parse(out.toString()); } JSONArray array() throws Exception { return (JSONArray) new JSONParser().parse(out.toString()); } }
    private static Call call(JSONObject body, Consumer<Call> cred) {
        Call k = new Call(); k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString()); cred.accept(k);
        k.req = (HttpServletRequest) Proxy.newProxyInstance(NominationsDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> { switch (m.getName()) { case "getAttribute": return k.attrs.get((String) a[0]); case "setAttribute": k.attrs.put((String) a[0], a[1]); return null; case "getHeader": return k.headers.get((String) a[0]); case "getRemoteAddr": return "10.0.0.1"; case "getRequestURI": return "/api/v1/rights"; default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(NominationsDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> { switch (m.getName()) { case "setStatus": k.status = (Integer) a[0]; return null; case "getWriter": return new PrintWriter(k.out, true); default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        new Rights().post(k.req, k.res); return k;
    }
    private static Consumer<Call> apiKeyCred(UUID k) { return c -> { c.headers.put("X-API-Key", k.toString()); c.headers.put("X-API-Secret", SECRET); }; }
    private static Consumer<Call> principal(UUID f, String sub) { return c -> { c.attrs.put("auth_via_principal_jwt", Boolean.TRUE); c.attrs.put("fiduciary_id", f.toString()); c.attrs.put("principal_user_id", sub); }; }
    private static Consumer<Call> staff(String email) { return c -> { JSONObject t = new JSONObject(); t.put("email", email); t.put("mfa", true); c.attrs.put(InputProcessor.AUTH_TOKEN, t); }; }
    private static JSONObject body(Object... kv) { JSONObject o = new JSONObject(); for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]); return o; }
    private static String user() { return "nm-" + UUID.randomUUID().toString().substring(0, 8); }
    private static String nominate(String u, Object... extra) throws Exception {
        JSONObject b = body("_func", "create_nomination", "nominee_name", "Asha Rao", "nominee_contact", "asha.rao@example.com", "nominee_relationship", "sister");
        for (int i = 0; i < extra.length; i += 2) b.put(extra[i], extra[i + 1]);
        Call k = call(b, principal(fid, u)); assertEquals(201, k.status, k.out.toString()); return (String) k.json().get("nomination_id");
    }

    @Test
    void nomineeDetailsAreEncryptedAtRestAndVisibleToTheOwner() throws Exception {
        String u = user(); String id = nominate(u);
        assertNotEquals("Asha Rao", scalar("SELECT nominee_name_enc FROM nominations WHERE id = ?::uuid", id), "stored encrypted");
        assertFalse(scalar("SELECT nominee_contact_enc FROM nominations WHERE id = ?::uuid", id).contains("example.com"));
        Call list = call(body("_func", "list_nominations"), principal(fid, u));
        assertEquals(200, list.status, list.out.toString());
        JSONObject n = (JSONObject) list.array().get(0);
        assertEquals("Asha Rao", n.get("nominee_name"));
        assertEquals("asha.rao@example.com", n.get("nominee_contact"));
        assertEquals("ACTIVE", n.get("status"));
        assertEquals("sister", n.get("nominee_relationship"));
    }

    @Test
    void theAuditTrailRecordsTheEventButNotTheNomineesDetails() throws Exception {
        String u = user(); nominate(u);
        new Audit().logEvents();
        String ctx = scalar("SELECT context_details FROM audit_logs WHERE audit_action = 'NOMINATION_CREATED' AND user_id = ?", u);
        assertNotNull(ctx);
        assertFalse(ctx.contains("Asha") || ctx.contains("example.com"));
    }

    @Test
    void onlyTheOwnerSeesFullDetailsAndStaffSeeAMaskedContact() throws Exception {
        String u = user(); nominate(u);
        assertTrue(call(body("_func", "list_nominations"), principal(fid, user())).array().isEmpty(), "another principal sees nothing");
        assertEquals(403, call(body("_func", "list_nominations", "user_id", u), principal(fid, user())).status, "cannot name someone else");
        Call dpo = call(body("_func", "list_nominations", "user_id", u), staff(dpoEmail));
        assertEquals(200, dpo.status, dpo.out.toString());
        assertEquals("a***@example.com", ((JSONObject) dpo.array().get(0)).get("nominee_contact"));
        assertEquals(403, call(body("_func", "list_nominations", "user_id", u), staff(opEmail)).status, "operators do not see nominations");
        assertEquals(403, call(body("_func", "create_nomination", "nominee_name", "X Y", "nominee_contact", "x@y.com", "user_id", u), staff(dpoEmail)).status, "the principal makes it");
        // an API key names the principal and cannot reach another fiduciary's
        assertEquals(200, call(body("_func", "list_nominations", "user_id", u), apiKeyCred(key)).status);
        assertTrue(call(body("_func", "list_nominations", "user_id", u), apiKeyCred(keyOther)).array().isEmpty());
    }

    @Test
    void invalidNominationsAreRefused() throws Exception {
        String u = user();
        assertEquals(400, call(body("_func", "create_nomination", "nominee_name", "A", "nominee_contact", "a@b.com"), principal(fid, u)).status);
        assertEquals(400, call(body("_func", "create_nomination", "nominee_name", "Asha Rao", "nominee_contact", "not a contact"), principal(fid, u)).status);
        assertEquals(400, call(body("_func", "create_nomination", "nominee_name", "Asha Rao", "nominee_contact", "a@b.com", "valid_until", "2001-01-01"), principal(fid, u)).status);
        assertEquals(400, call(body("_func", "create_nomination", "nominee_name", "Asha Rao", "nominee_contact", "a@b.com", "valid_until", "garbage"), principal(fid, u)).status);
        assertEquals("0", scalar("SELECT COUNT(*)::text FROM nominations WHERE user_id = ?", u));
    }

    @Test
    void aFutureStartIsPendingAndAtMostFiveAreCurrent() throws Exception {
        String u = user();
        String future = java.time.LocalDate.now().plusDays(30).toString();
        String id = nominate(u, "valid_from", future);
        assertEquals("PENDING", scalar("SELECT status FROM nominations WHERE id = ?::uuid", id));
        for (int i = 0; i < 4; i++) nominate(u);
        assertEquals(409, call(body("_func", "create_nomination", "nominee_name", "Sixth Person", "nominee_contact", "six@example.com"), principal(fid, u)).status, "cap");
    }

    @Test
    void revokingIsTheOwnersAndFinal() throws Exception {
        String u = user(); String id = nominate(u);
        assertEquals(404, call(body("_func", "revoke_nomination", "nomination_id", id), principal(fid, user())).status, "someone else's");
        assertEquals(403, call(body("_func", "revoke_nomination", "nomination_id", id), staff(dpoEmail)).status);
        assertEquals(200, call(body("_func", "revoke_nomination", "nomination_id", id), principal(fid, u)).status);
        assertEquals("REVOKED", ((JSONObject) call(body("_func", "list_nominations"), principal(fid, u)).array().get(0)).get("status"));
        assertEquals(404, call(body("_func", "revoke_nomination", "nomination_id", id), principal(fid, u)).status, "already revoked");
    }

    @Test
    void theDailySweepExpiresOldNominationsAndActivatesDueOnes() throws Exception {
        String u = user();
        String ending = nominate(u), starting = nominate(u, "valid_from", java.time.LocalDate.now().plusDays(10).toString());
        sql("UPDATE nominations SET valid_until = NOW() - interval '1 day', valid_from = NOW() - interval '30 days' WHERE id = ?::uuid", ending);
        sql("UPDATE nominations SET valid_from = NOW() - interval '1 hour' WHERE id = ?::uuid", starting);
        int[] r = Rights.sweepNominations();
        assertTrue(r[0] >= 1 && r[1] >= 1, java.util.Arrays.toString(r));
        assertEquals("EXPIRED", scalar("SELECT status FROM nominations WHERE id = ?::uuid", ending));
        assertEquals("ACTIVE", scalar("SELECT status FROM nominations WHERE id = ?::uuid", starting));
        int[] again = Rights.sweepNominations();
        assertEquals(0, again[0] + again[1], "a second sweep finds nothing");
    }
}
