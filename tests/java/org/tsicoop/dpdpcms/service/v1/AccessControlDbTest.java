package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
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
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * AccessControl.check against Postgres (db/01..20 applied). Skipped without POSTGRES_* and DB_ENCRYPTION_KEY.
 * The mode comes from the environment, so run it twice:
 *   (default)                          shadow-mode tests
 *   ACCESS_CONTROL_MODE=enforce        enforce-mode tests
 */
class AccessControlDbTest {
    private static UUID FID_A, FID_B;

    @BeforeAll
    static void setup() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        FID_A = fiduciary("A"); FID_B = fiduciary("B");
    }

    @BeforeEach
    void reset() { AccessControl.clearCaches(); }

    // ---- fixtures -------------------------------------------------------------------------
    private static UUID fiduciary(String tag) throws Exception {
        UUID id = UUID.randomUUID();
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)");
            ps.setObject(1, id); ps.setString(2, "f" + tag + id.toString().substring(0, 6)); ps.setString(3, id.toString().substring(0, 8) + ".test");
            ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return id;
    }

    private static String operator(String role, UUID fid) throws Exception {
        String email = "ac-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) " +
                    "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", ?, ?, 'ACTIVE', ?, NOW(), NOW())");
            int i = 1;
            ps.setString(i++, "u" + UUID.randomUUID().toString().substring(0, 8));
            ps.setString(i++, email);
            i = DbEncryption.bindEncrypt(ps, i, email);
            i = DbEncryption.bindHmac(ps, i, email);
            ps.setString(i++, "x");
            ps.setString(i++, role);
            ps.setObject(i, fid);
            ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return email;
    }

    // ---- servlet fakes --------------------------------------------------------------------
    static final class Call { HttpServletRequest req; int status = 200; StringWriter out = new StringWriter(); Map<String, Object> attrs = new HashMap<>(); HttpServletResponse res; }

    private static Call request(String email, JSONObject body) {
        Call k = new Call();
        JSONObject token = new JSONObject();
        token.put("email", email);
        k.attrs.put(InputProcessor.AUTH_TOKEN, token);
        k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString());
        k.req = (HttpServletRequest) Proxy.newProxyInstance(AccessControlDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "getAttribute": return k.attrs.get((String) a[0]);
                case "setAttribute": k.attrs.put((String) a[0], a[1]); return null;
                case "getRequestURI": return "/api/v1/admin/x";
                default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null;
            }
        });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(AccessControlDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "setStatus": k.status = (Integer) a[0]; return null;
                case "getWriter": return new PrintWriter(k.out, true);
                default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null;
            }
        });
        return k;
    }

    private static JSONObject body(Object... kv) {
        JSONObject o = new JSONObject();
        for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]);
        return o;
    }

    private static String bodyFid(Call k) throws Exception {
        return (String) ((JSONObject) new JSONParser().parse((String) k.attrs.get(InputProcessor.REQUEST_DATA))).get("fiduciary_id");
    }

    /** Runs the check and also returns what was written to stderr. */
    private static String[] checkCapturingStderr(Call k, String service, String func, boolean[] result) {
        PrintStream old = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setErr(new PrintStream(buf, true));
        try { result[0] = AccessControl.check(k.req, k.res, service, func); } finally { System.setErr(old); }
        return new String[]{buf.toString()};
    }

    // ---- shadow mode ----------------------------------------------------------------------
    @Test
    void shadow_logsButNeverBlocksOrChanges() throws Exception {
        assumeTrue(!AccessControl.enforcing(), "shadow-mode test");
        String dpo = operator("DPO", FID_A);
        Call k = request(dpo, body("_func", "generate_api_key", "fiduciary_id", FID_B.toString()));
        boolean[] ok = new boolean[1];
        String err = checkCapturingStderr(k, "apikey", "generate_api_key", ok)[0];
        assertTrue(ok[0], "shadow mode must not block");
        assertEquals(200, k.status);
        assertEquals(FID_B.toString(), bodyFid(k), "shadow mode must not rewrite the request");
        assertTrue(err.contains("[ACCESS-SHADOW] DENY DENY_NO_PERMISSION"), err);
        assertTrue(err.contains("[ACCESS-SHADOW] TENANT FOREIGN_FIDUCIARY_IN_BODY"), err);
    }

    @Test
    void shadow_sameCaseIsReportedOncePerWindow() throws Exception {
        assumeTrue(!AccessControl.enforcing());
        String dpo = operator("DPO", FID_A);
        boolean[] ok = new boolean[1];
        String first = checkCapturingStderr(request(dpo, body("_func", "x")), "apikey", "list_api_keys", ok)[0];
        String second = checkCapturingStderr(request(dpo, body("_func", "x")), "apikey", "list_api_keys", ok)[0];
        assertTrue(first.contains("DENY_NO_PERMISSION"));
        assertFalse(second.contains("DENY_NO_PERMISSION"), "repeat must be throttled so a wrong map cannot flood the log");
    }

    @Test
    void shadow_aDifferentPersonDeniedTheSameThingIsReportedToo() throws Exception {
        assumeTrue(!AccessControl.enforcing());
        String first = operator("DPO", FID_A), second = operator("DPO", FID_A);
        boolean[] ok = new boolean[1];
        String a = checkCapturingStderr(request(first, body("_func", "x")), "apikey", "list_api_keys", ok)[0];
        String b = checkCapturingStderr(request(second, body("_func", "x")), "apikey", "list_api_keys", ok)[0];
        assertTrue(a.contains("DENY_NO_PERMISSION"));
        assertTrue(b.contains("DENY_NO_PERMISSION"), "each person leaves their own trail");
    }

    @Test
    void shadow_allowedRequestsAreSilent() throws Exception {
        assumeTrue(!AccessControl.enforcing());
        String dpo = operator("DPO", FID_A);
        boolean[] ok = new boolean[1];
        String err = checkCapturingStderr(request(dpo, body("_func", "x", "fiduciary_id", FID_A.toString())), "policy", "publish_policy", ok)[0];
        assertTrue(ok[0]);
        assertFalse(err.contains("ACCESS-"), err);
    }

    @Test
    void shadow_auditorAccountCannotBeCreatedYet() throws Exception {
        assumeTrue(!AccessControl.enforcing());
        String admin = operator("ADMIN", null);
        Call k = request(admin, body("_func", "create_user", "username", "aud" + UUID.randomUUID().toString().substring(0, 6),
                "email", "aud-" + UUID.randomUUID().toString().substring(0, 6) + "@example.test", "password", "Passw0rd!Passw0rd!", "role", "AUDITOR"));
        new Operator().post(k.req, k.res);
        assertEquals(400, k.status, k.out.toString());
        assertTrue(k.out.toString().contains("ACCESS_CONTROL_MODE=enforce"));
    }

    // ---- enforce mode ---------------------------------------------------------------------
    @Test
    void enforce_dpoCannotUseAdminOnlyFunctions() throws Exception {
        assumeTrue(AccessControl.enforcing(), "enforce-mode test");
        String dpo = operator("DPO", FID_A);
        Call k = request(dpo, body("_func", "generate_api_key"));
        assertFalse(AccessControl.check(k.req, k.res, "apikey", "generate_api_key"));
        assertEquals(403, k.status);
    }

    @Test
    void enforce_auditorReadsButCannotWrite() throws Exception {
        assumeTrue(AccessControl.enforcing());
        String aud = operator("AUDITOR", FID_A);
        assertTrue(AccessControl.check(request(aud, body("_func", "x")).req, request(aud, body()).res, "policy", "list_policies"));
        Call w = request(aud, body("_func", "publish_policy"));
        assertFalse(AccessControl.check(w.req, w.res, "policy", "publish_policy"));
        assertEquals(403, w.status);
        Call a = request(aud, body("_func", "list_audit_logs"));
        assertTrue(AccessControl.check(a.req, a.res, "audit", "list_audit_logs"));
    }

    @Test
    void enforce_foreignFiduciaryIsOverwrittenAndMissingOneIsFilled() throws Exception {
        assumeTrue(AccessControl.enforcing());
        String dpo = operator("DPO", FID_A);
        Call foreign = request(dpo, body("_func", "list_policies", "fiduciary_id", FID_B.toString()));
        assertTrue(AccessControl.check(foreign.req, foreign.res, "policy", "list_policies"));
        assertEquals(FID_A.toString(), bodyFid(foreign));
        Call none = request(dpo, body("_func", "list_policies"));
        assertTrue(AccessControl.check(none.req, none.res, "policy", "list_policies"));
        assertEquals(FID_A.toString(), bodyFid(none));
        Call junk = request(dpo, body("_func", "list_policies", "fiduciary_id", "not-a-uuid"));
        assertTrue(AccessControl.check(junk.req, junk.res, "policy", "list_policies"));
        assertEquals(FID_A.toString(), bodyFid(junk));
    }

    @Test
    void enforce_adminIsNeverRestrictedOrRewritten() throws Exception {
        assumeTrue(AccessControl.enforcing());
        String admin = operator("ADMIN", null);
        Call k = request(admin, body("_func", "list_policies", "fiduciary_id", FID_B.toString()));
        assertTrue(AccessControl.check(k.req, k.res, "apikey", "generate_api_key"));
        assertEquals(FID_B.toString(), bodyFid(k));
    }

    @Test
    void enforce_nonAdminWithoutFiduciaryAndUnknownRoleAreRefused() throws Exception {
        assumeTrue(AccessControl.enforcing());
        String unbound = operator("DPO", null);
        Call u = request(unbound, body("_func", "list_policies"));
        assertFalse(AccessControl.check(u.req, u.res, "policy", "list_policies"));
        assertEquals(403, u.status);
        String weird = operator("HACKER", FID_A);
        Call h = request(weird, body("_func", "list_policies"));
        assertFalse(AccessControl.check(h.req, h.res, "policy", "list_policies"));
        assertEquals(403, h.status);
    }

    @Test
    void enforce_unmappedFunctionIsDeniedEvenForAdmin() throws Exception {
        assumeTrue(AccessControl.enforcing());
        String admin = operator("ADMIN", null);
        Call k = request(admin, body("_func", "brand_new"));
        assertFalse(AccessControl.check(k.req, k.res, "policy", "brand_new"));
        assertEquals(403, k.status);
    }

    @Test
    void enforce_rolesTableCanTightenARole() throws Exception {
        assumeTrue(AccessControl.enforcing());
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection();
        try (PreparedStatement ps = c.prepareStatement("UPDATE roles SET permissions = ARRAY['policies:read'] WHERE name = 'OPERATOR' AND fiduciary_id IS NULL")) {
            ps.executeUpdate();
            AccessControl.clearCaches();
            String op = operator("OPERATOR", FID_A);
            Call ok = request(op, body("_func", "x"));
            assertTrue(AccessControl.check(ok.req, ok.res, "policy", "list_policies"));
            Call no = request(op, body("_func", "x"));
            assertFalse(AccessControl.check(no.req, no.res, "grievance", "update_grievance_status"), "table value must override the default");
        } finally {
            try (PreparedStatement restore = c.prepareStatement("UPDATE roles SET permissions = ARRAY['users:read','fiduciaries:read','apps:read','policies:read','ropa:read','breaches:read','purges:write','grievances:write','jobs:write','settings:read','certificates:read','audit:read','dashboard:read'] WHERE name = 'OPERATOR' AND fiduciary_id IS NULL")) { restore.executeUpdate(); }
            pool.cleanup(null, null, c);
            AccessControl.clearCaches();
        }
    }

    @Test
    void enforce_auditorAccountCanBeCreatedByAdmin() throws Exception {
        assumeTrue(AccessControl.enforcing());
        String admin = operator("ADMIN", null);
        Call k = request(admin, body("_func", "create_user", "username", "aud" + UUID.randomUUID().toString().substring(0, 6),
                "email", "aud-" + UUID.randomUUID().toString().substring(0, 6) + "@example.test", "password", "Passw0rd!Passw0rd!",
                "role", "auditor", "fiduciary_id", FID_A.toString()));
        new Operator().post(k.req, k.res);
        assertEquals(201, k.status, k.out.toString());
        Call bad = request(admin, body("_func", "create_user", "username", "x" + UUID.randomUUID().toString().substring(0, 6),
                "email", "x-" + UUID.randomUUID().toString().substring(0, 6) + "@example.test", "password", "Passw0rd!Passw0rd!", "role", "ROOT"));
        new Operator().post(bad.req, bad.res);
        assertEquals(400, bad.status);
    }
}
