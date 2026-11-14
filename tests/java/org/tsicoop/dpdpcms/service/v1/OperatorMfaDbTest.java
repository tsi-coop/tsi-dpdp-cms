package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.MfaPolicy;
import org.tsicoop.dpdpcms.util.Totp;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Drives the real Operator service against Postgres (db/01..19 applied) through minimal servlet fakes.
 * Skipped unless POSTGRES_* and DB_ENCRYPTION_KEY (equal to the database's app.enc_key) are set.
 * Uses a throwaway database. Run once normally (MFA optional) and once with MFA_ENFORCE=true.
 */
class OperatorMfaDbTest {
    private static final AtomicInteger IP = new AtomicInteger(1);

    @BeforeAll
    static void setup() {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
    }

    @BeforeEach
    void realStore() { OperatorSessions.useDatabaseStore(); } // other tests install an in-memory store

    // ---- minimal servlet fakes ------------------------------------------------------------
    static final class Resp { int status; JSONObject body; String cookie; }

    private static Resp call(String ip, String bearer, JSONObject body) throws Exception {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString());
        HttpServletRequest req = (HttpServletRequest) Proxy.newProxyInstance(
                OperatorMfaDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> {
                    switch (m.getName()) {
                        case "getAttribute": return attrs.get((String) a[0]);
                        case "setAttribute": attrs.put((String) a[0], a[1]); return null;
                        case "getHeader": return "Authorization".equals(a[0]) && bearer != null ? "Bearer " + bearer : null;
                        case "getRemoteAddr": return ip;
                        case "getRequestURI": return "/api/v1/admin/operator";
                        default: return defaultFor(m.getReturnType());
                    }
                });
        StringWriter sw = new StringWriter();
        Resp r = new Resp();
        HttpServletResponse res = (HttpServletResponse) Proxy.newProxyInstance(
                OperatorMfaDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> {
                    switch (m.getName()) {
                        case "setStatus": r.status = (Integer) a[0]; return null;
                        case "getWriter": return new PrintWriter(sw, true);
                        case "addHeader": if ("Set-Cookie".equals(a[0])) r.cookie = (String) a[1]; return null;
                        default: return defaultFor(m.getReturnType());
                    }
                });
        new Operator().post(req, res);
        r.body = sw.toString().isBlank() ? new JSONObject() : (JSONObject) new JSONParser().parse(sw.toString());
        return r;
    }

    private static Object defaultFor(Class<?> t) {
        if (t == boolean.class) return false;
        if (t == int.class) return 0;
        if (t == long.class) return 0L;
        return null;
    }

    private static JSONObject j(Object... kv) {
        JSONObject o = new JSONObject();
        for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]);
        return o;
    }

    private static String newIp() { return "10.99." + (IP.incrementAndGet() / 250) + "." + (IP.get() % 250); }

    private static String createOperator(String role, String email, String password) throws Exception {
        PoolDB pool = new PoolDB();
        Connection c = pool.getConnection();
        PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, created_at, last_updated_at) " +
                    "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", ?, ?, 'ACTIVE', NOW(), NOW())");
            int i = 1;
            ps.setString(i++, "u" + UUID.randomUUID().toString().substring(0, 8));
            ps.setString(i++, email);
            i = DbEncryption.bindEncrypt(ps, i, email);
            i = DbEncryption.bindHmac(ps, i, email);
            ps.setString(i++, new PasswordHasher().hashPassword(password));
            ps.setString(i, role);
            ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return email;
    }

    private static String email() { return "mfa-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test"; }

    private static String wrongCode(String secret) {
        long step = Totp.stepAt(System.currentTimeMillis());
        java.util.Set<String> valid = new java.util.HashSet<>();
        for (long s = step - 2; s <= step + 2; s++) valid.add(Totp.code(secret, s));
        for (int i = 0; i < 1000; i++) { String c = String.format("%06d", i * 997 % 1000000); if (!valid.contains(c)) return c; }
        throw new IllegalStateException();
    }

    // ---- tests ----------------------------------------------------------------------------

    @Test
    void enrolConfirmChallengeReplayAndRevocation() throws Exception {
        assumeTrue(!MfaPolicy.enforcing(), "this flow assumes MFA is optional (enforcement off)");
        String em = createOperator("OPERATOR", email(), "Passw0rd!Passw0rd!");
        String ip = newIp();

        // plain login: session without MFA
        Resp login = call(ip, null, j("_func", "login", "identifier", em, "password", "Passw0rd!Passw0rd!"));
        assertEquals(200, login.status);
        String oldToken = (String) login.body.get("token");
        assertNotNull(oldToken);
        assertFalse(JWTUtil.hasMfa(oldToken));

        // enrol
        Resp enrol = call(ip, oldToken, j("_func", "enrol_mfa"));
        assertEquals(200, enrol.status);
        String secret = (String) enrol.body.get("secret");
        assertNotNull(secret);
        assertTrue(((String) enrol.body.get("otpauth_uri")).startsWith("otpauth://totp/"));

        // wrong code first: refused
        assertEquals(401, call(ip, oldToken, j("_func", "verify_mfa", "code", wrongCode(secret))).status);

        // right code confirms, returns an MFA session, and signs out older tokens
        Thread.sleep(1100); // JWT iat has 1 s resolution
        long step = Totp.stepAt(System.currentTimeMillis());
        Resp confirm = call(ip, oldToken, j("_func", "verify_mfa", "code", Totp.code(secret, step)));
        assertEquals(200, confirm.status, String.valueOf(confirm.body));
        String newToken = (String) confirm.body.get("token");
        assertTrue(JWTUtil.hasMfa(newToken));
        assertNotNull(confirm.cookie);
        assertFalse(JWTUtil.isTokenValid(oldToken), "tokens issued before first enrolment must stop working");
        assertTrue(JWTUtil.isTokenValid(newToken));

        // cannot enrol again
        assertEquals(409, call(ip, newToken, j("_func", "enrol_mfa")).status);

        // login now demands the code and gives no session yet
        Resp ch = call(ip, null, j("_func", "login", "identifier", em, "password", "Passw0rd!Passw0rd!"));
        assertEquals(200, ch.status);
        assertEquals(Boolean.TRUE, ch.body.get("mfa_required"));
        assertNull(ch.body.get("token"));
        String mfaToken = (String) ch.body.get("mfa_token");
        assertFalse(JWTUtil.isTokenValid(mfaToken), "challenge token is not a session");

        // the step already used cannot be replayed...
        assertEquals(401, call(ip, null, j("_func", "verify_mfa", "mfa_token", mfaToken, "code", Totp.code(secret, step))).status);
        // ...the next step works once
        Resp ok = call(ip, null, j("_func", "verify_mfa", "mfa_token", mfaToken, "code", Totp.code(secret, step + 1)));
        assertEquals(200, ok.status, String.valueOf(ok.body));
        assertTrue(JWTUtil.hasMfa((String) ok.body.get("token")));
        assertEquals(401, call(ip, null, j("_func", "verify_mfa", "mfa_token", mfaToken, "code", Totp.code(secret, step + 1))).status);
    }

    @Test
    void fiveWrongCodesLockMfa() throws Exception {
        assumeTrue(!MfaPolicy.enforcing());
        String em = createOperator("OPERATOR", email(), "Passw0rd!Passw0rd!");
        String ip = newIp();
        String tok = (String) call(ip, null, j("_func", "login", "identifier", em, "password", "Passw0rd!Passw0rd!")).body.get("token");
        String secret = (String) call(ip, tok, j("_func", "enrol_mfa")).body.get("secret");
        call(ip, tok, j("_func", "verify_mfa", "code", Totp.code(secret, Totp.stepAt(System.currentTimeMillis()))));

        String mfaToken = (String) call(ip, null, j("_func", "login", "identifier", em, "password", "Passw0rd!Passw0rd!")).body.get("mfa_token");
        for (int i = 0; i < 5; i++) {
            assertEquals(401, call(ip, null, j("_func", "verify_mfa", "mfa_token", mfaToken, "code", wrongCode(secret))).status);
        }
        // locked: even a correct code is refused
        long step = Totp.stepAt(System.currentTimeMillis());
        assertEquals(429, call(ip, null, j("_func", "verify_mfa", "mfa_token", mfaToken, "code", Totp.code(secret, step + 1))).status);
    }

    @Test
    void passwordChangeAndDeactivationEndSessions() throws Exception {
        assumeTrue(!MfaPolicy.enforcing());
        String em = createOperator("OPERATOR", email(), "Passw0rd!Passw0rd!");
        String ip = newIp();
        String tok = (String) call(ip, null, j("_func", "login", "identifier", em, "password", "Passw0rd!Passw0rd!")).body.get("token");
        assertTrue(JWTUtil.isTokenValid(tok));
        Thread.sleep(1100);
        PoolDB pool = new PoolDB();
        Connection c = pool.getConnection();
        try (PreparedStatement ps = c.prepareStatement("UPDATE operators SET tokens_valid_after = ? WHERE email_hmac = " + DbEncryption.HMAC)) {
            ps.setTimestamp(1, new java.sql.Timestamp(System.currentTimeMillis()));
            DbEncryption.bindHmac(ps, 2, em);
            ps.executeUpdate();
        } finally { pool.cleanup(null, null, c); }
        OperatorSessions.forget(em);
        assertFalse(JWTUtil.isTokenValid(tok));
    }

    @Test
    void logoutRevocationIsPersisted() throws Exception {
        assumeTrue(!MfaPolicy.enforcing());
        String em = createOperator("OPERATOR", email(), "Passw0rd!Passw0rd!");
        String ip = newIp();
        String tok = (String) call(ip, null, j("_func", "login", "identifier", em, "password", "Passw0rd!Passw0rd!")).body.get("token");
        assertEquals(200, call(ip, tok, j("_func", "logout")).status);
        assertFalse(JWTUtil.isTokenValid(tok));
        // it is in the table, so it survives a restart and is visible to other instances
        PoolDB pool = new PoolDB();
        Connection c = pool.getConnection();
        try (PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM revoked_tokens WHERE jti = ?")) {
            ps.setString(1, JWTUtil.getJtiFromToken(tok));
            try (java.sql.ResultSet rs = ps.executeQuery()) { rs.next(); assertEquals(1, rs.getInt(1)); }
        } finally { pool.cleanup(null, null, c); }
    }

    @Test
    void whenEnforcedAdminAndDpoGetEnrolOnlyTokenUntilEnrolled() throws Exception {
        assumeTrue(MfaPolicy.enforcing(), "run with MFA_ENFORCE=true");
        for (String role : new String[]{"DPO", "ADMIN", "AUDITOR"}) {
            String em = createOperator(role, email(), "Passw0rd!Passw0rd!");
            String ip = newIp();
            Resp login = call(ip, null, j("_func", "login", "identifier", em, "password", "Passw0rd!Passw0rd!"));
            assertEquals(200, login.status);
            assertEquals(Boolean.TRUE, login.body.get("mfa_enrol_required"));
            assertNull(login.body.get("token"), "no working session before enrolment");
            String enrolToken = (String) login.body.get("enrol_token");
            assertFalse(JWTUtil.isTokenValid(enrolToken), "enrol token is not a session");

            String secret = (String) call(ip, enrolToken, j("_func", "enrol_mfa")).body.get("secret");
            assertNotNull(secret);
            Resp done = call(ip, enrolToken, j("_func", "verify_mfa", "code", Totp.code(secret, Totp.stepAt(System.currentTimeMillis()))));
            assertEquals(200, done.status, String.valueOf(done.body));
            assertTrue(JWTUtil.hasMfa((String) done.body.get("token")));
        }
        // an OPERATOR is not forced
        String em = createOperator("OPERATOR", email(), "Passw0rd!Passw0rd!");
        assertNotNull(call(newIp(), null, j("_func", "login", "identifier", em, "password", "Passw0rd!Passw0rd!")).body.get("token"));
    }
}
