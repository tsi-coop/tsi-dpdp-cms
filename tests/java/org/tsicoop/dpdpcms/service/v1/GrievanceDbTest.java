package org.tsicoop.dpdpcms.service.v1;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tsicoop.dpdpcms.framework.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Grievance reference number, channel, auto-assignment, resolution summary, attachments and feedback. Needs db/01..22. */
class GrievanceDbTest {
    private static final String SECRET = "s3cret-secret-secret-secret-0123456789";
    private static UUID fid, fidOther, key, keyOther;
    private static String dpoEmail, dpoId, opEmail, opId, consentOfUser1;
    private static final String USER1 = "principal-one", USER2 = "principal-two";

    @BeforeAll
    static void fixtures() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        fid = fiduciary(); fidOther = fiduciary();
        key = apiKey(fid); keyOther = apiKey(fidOther);
        dpoEmail = operator("DPO", fid); dpoId = scalar("SELECT id::text FROM operators WHERE email_hmac = " + DbEncryption.HMAC, dpoEmail, DbEncryption.key());
        opEmail = operator("OPERATOR", fid); opId = scalar("SELECT id::text FROM operators WHERE email_hmac = " + DbEncryption.HMAC, opEmail, DbEncryption.key());
        String pol = "pol-" + UUID.randomUUID().toString().substring(0, 8);
        sql("INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (?, '1', ?, NOW(), 'ACTIVE', 'IN', '{\"en\":{}}'::jsonb, NOW(), NOW())", pol, fid);
        consentOfUser1 = UUID.randomUUID().toString();
        sql("INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, data_point_consents, is_active_consent) VALUES (?::uuid, ?, ?, ?, '1', NOW(), 'IN', 'en', 'CONSENT_GIVEN', 'CONSENT_GIVEN', 'x', '[]'::jsonb, TRUE)", consentOfUser1, USER1, fid, pol);
    }

    @BeforeEach void reset() { OperatorSessions.useDatabaseStore(); }

    // ---- fixtures ----
    private static void sql(String q, Object... p) throws Exception {
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); ps.executeUpdate(); } finally { pool.cleanup(null, ps, c); }
    }
    private static String scalar(String q, Object... p) throws Exception {
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; ResultSet rs = null;
        try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); rs = ps.executeQuery(); return rs.next() ? rs.getString(1) : null; } finally { pool.cleanup(rs, ps, c); }
    }
    private static UUID fiduciary() throws Exception { UUID id = UUID.randomUUID(); sql("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)", id, "f" + id.toString().substring(0, 8), id.toString().substring(0, 8) + ".test"); return id; }
    private static UUID apiKey(UUID f) throws Exception {
        UUID app = UUID.randomUUID(), k = UUID.randomUUID();
        sql("INSERT INTO apps (id, fiduciary_id, name) VALUES (?, ?, ?)", app, f, "app" + app.toString().substring(0, 8));
        sql("INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, status) VALUES (?, ?, ?, ?, 'ACTIVE')", k, new PasswordHasher().hashPassword(SECRET), f, app);
        return k;
    }
    private static String operator(String role, UUID f) throws Exception {
        String email = "gv-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", 'x', ?, 'ACTIVE', ?, NOW() - interval '1 hour', NOW())");
            int i = 1; ps.setString(i++, "u" + UUID.randomUUID().toString().substring(0, 8)); ps.setString(i++, email);
            i = DbEncryption.bindEncrypt(ps, i, email); i = DbEncryption.bindHmac(ps, i, email);
            ps.setString(i++, role); ps.setObject(i, f); ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return email;
    }

    // ---- fakes ----
    static final class Call { int status = 200; final StringWriter out = new StringWriter(); final Map<String, Object> attrs = new HashMap<>(); final Map<String, String> headers = new HashMap<>(); HttpServletRequest req; HttpServletResponse res; JSONObject json() throws Exception { return (JSONObject) new JSONParser().parse(out.toString()); } }
    private static Call call(JSONObject body, Consumer<Call> cred) {
        Call k = new Call(); k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString()); cred.accept(k);
        k.req = (HttpServletRequest) Proxy.newProxyInstance(GrievanceDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "getAttribute": return k.attrs.get((String) a[0]);
                case "setAttribute": k.attrs.put((String) a[0], a[1]); return null;
                case "getHeader": return k.headers.get((String) a[0]);
                case "getRemoteAddr": return "10.0.0.1";
                case "getRequestURI": return "/api/v1/x";
                default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null;
            }
        });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(GrievanceDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "setStatus": k.status = (Integer) a[0]; return null;
                case "getWriter": return new PrintWriter(k.out, true);
                default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null;
            }
        });
        new Grievance().post(k.req, k.res);
        return k;
    }
    private static Consumer<Call> apiKeyCred(UUID k) { return c -> { c.headers.put("X-API-Key", k.toString()); c.headers.put("X-API-Secret", SECRET); }; }
    private static Consumer<Call> principal(UUID f, String sub) { return c -> { c.attrs.put("auth_via_principal_jwt", Boolean.TRUE); c.attrs.put("fiduciary_id", f.toString()); c.attrs.put("principal_user_id", sub); }; }
    private static Consumer<Call> operatorCred(String email) { return c -> { JSONObject t = new JSONObject(); t.put("email", email); t.put("mfa", true); c.attrs.put(InputProcessor.AUTH_TOKEN, t); }; }
    private static JSONObject body(Object... kv) { JSONObject o = new JSONObject(); for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]); return o; }

    private static String submit(Consumer<Call> cred, String user, Object... extra) throws Exception {
        JSONObject b = body("_func", "submit_grievance", "user_id", user, "fiduciary_id", fid.toString(), "type", "OTHER", "subject", "s", "description", "d");
        for (int i = 0; i < extra.length; i += 2) b.put(extra[i], extra[i + 1]);
        Call k = call(b, cred);
        assertEquals(201, k.status, k.out.toString());
        return (String) k.json().get("grievance_id");
    }
    private static String pdfB64() { return Base64.getEncoder().encodeToString("%PDF-1.4 test".getBytes(StandardCharsets.US_ASCII)); }
    private static void resolve(String gid) throws Exception {
        Call k = call(body("_func", "update_grievance_status", "grievance_id", gid, "status", "RESOLVED", "resolution_details", "Checked the record and corrected it."), operatorCred(dpoEmail));
        assertEquals(200, k.status, k.out.toString());
    }

    // ---- submit ----
    @Test
    void submissionGetsAReferenceChannelAndTheFiduciarysDpo() throws Exception {
        Call k = call(body("_func", "submit_grievance", "user_id", USER1, "fiduciary_id", fid.toString(), "type", "OTHER", "subject", "s", "description", "d"), apiKeyCred(key));
        assertEquals(201, k.status, k.out.toString());
        JSONObject j = k.json();
        assertTrue(((String) j.get("reference_number")).matches("GRV-\\d{4}-\\d{6}"), (String) j.get("reference_number"));
        assertEquals("API_INTEGRATION", j.get("channel"));
        assertEquals(dpoId, scalar("SELECT assigned_dpo_user_id::text FROM grievances WHERE id = ?::uuid", j.get("grievance_id")), "routed to the DPO, not the plain operator");
        assertEquals(j.get("reference_number"), scalar("SELECT reference_number FROM grievances WHERE id = ?::uuid", j.get("grievance_id")));
        // two submissions never share a reference
        String second = (String) call(body("_func", "submit_grievance", "user_id", USER1, "fiduciary_id", fid.toString(), "type", "OTHER", "subject", "s", "description", "d"), apiKeyCred(key)).json().get("reference_number");
        assertNotEquals(j.get("reference_number"), second);
    }

    @Test
    void channelFollowsTheAuthenticatedPath() throws Exception {
        String viaPrincipal = submit(principal(fid, USER1), USER1, "channel", "PHONE");
        assertEquals("PRINCIPAL_PORTAL", scalar("SELECT channel FROM grievances WHERE id = ?::uuid", viaPrincipal), "a principal token cannot claim another channel");
        String relayed = submit(apiKeyCred(key), USER1, "channel", "phone");
        assertEquals("PHONE", scalar("SELECT channel FROM grievances WHERE id = ?::uuid", relayed));
        Call bad = call(body("_func", "submit_grievance", "user_id", USER1, "fiduciary_id", fid.toString(), "type", "OTHER", "subject", "s", "description", "d", "channel", "PRINCIPAL_PORTAL"), apiKeyCred(key));
        assertEquals(400, bad.status, "an API key cannot claim the portal channel");
    }

    @Test
    void consentRecordLinkMustBelongToThePrincipal() throws Exception {
        String ok = submit(apiKeyCred(key), USER1, "consent_record_id", consentOfUser1);
        assertEquals(consentOfUser1, scalar("SELECT consent_record_id::text FROM grievances WHERE id = ?::uuid", ok));
        Call other = call(body("_func", "submit_grievance", "user_id", USER2, "fiduciary_id", fid.toString(), "type", "OTHER", "subject", "s", "description", "d", "consent_record_id", consentOfUser1), apiKeyCred(key));
        assertEquals(400, other.status, other.out.toString());
    }

    @Test
    void aKeyCannotFileAGrievanceAgainstAnotherFiduciary() throws Exception {
        Call k = call(body("_func", "submit_grievance", "user_id", USER1, "fiduciary_id", fid.toString(), "type", "OTHER", "subject", "s", "description", "d"), apiKeyCred(keyOther));
        assertEquals(403, k.status, k.out.toString());
    }

    // ---- resolution ----
    @Test
    void resolvingNeedsARealSummaryAndAKnownStatus() throws Exception {
        String g = submit(apiKeyCred(key), USER1);
        Call unknown = call(body("_func", "update_grievance_status", "grievance_id", g, "status", "DONE", "resolution_details", "Plenty of words here."), operatorCred(dpoEmail));
        assertEquals(400, unknown.status);
        Call shortSummary = call(body("_func", "update_grievance_status", "grievance_id", g, "status", "RESOLVED", "resolution_details", "ok"), operatorCred(dpoEmail));
        assertEquals(400, shortSummary.status, shortSummary.out.toString());
        assertEquals("NEW", scalar("SELECT status FROM grievances WHERE id = ?::uuid", g), "nothing changed");
        Call inProgress = call(body("_func", "update_grievance_status", "grievance_id", g, "status", "IN_PROGRESS", "resolution_details", "x"), operatorCred(dpoEmail));
        assertEquals(200, inProgress.status, "a short note is fine for IN_PROGRESS");
        resolve(g);
        assertEquals("RESOLVED", scalar("SELECT status FROM grievances WHERE id = ?::uuid", g));
    }

    // ---- attachments ----
    @Test
    void attachmentsAreValidatedStoredAndReadableByTheRightPeopleOnly() throws Exception {
        String g = submit(principal(fid, USER1), USER1);
        Call up = call(body("_func", "upload_grievance_attachment", "grievance_id", g, "file_name", "../../proof.pdf", "content_type", "application/pdf", "content_base64", pdfB64()), principal(fid, USER1));
        assertEquals(201, up.status, up.out.toString());
        String att = (String) up.json().get("attachment_id");
        assertEquals("proof.pdf", up.json().get("file_name"), "path components are stripped");

        Call get = call(body("_func", "get_grievance_attachment", "attachment_id", att), operatorCred(dpoEmail));
        assertEquals(200, get.status, get.out.toString());
        assertEquals(pdfB64(), get.json().get("content_base64"));
        assertEquals(64, ((String) get.json().get("sha256")).length());

        assertEquals(403, call(body("_func", "get_grievance_attachment", "attachment_id", att), principal(fid, USER2)).status, "another principal");
        assertEquals(403, call(body("_func", "get_grievance_attachment", "attachment_id", att), operatorCred(opEmail)).status, "an operator it is not assigned to");
        assertEquals(403, call(body("_func", "get_grievance_attachment", "attachment_id", att), apiKeyCred(keyOther)).status, "another fiduciary's key");
        assertEquals(403, call(body("_func", "get_grievance_attachment", "attachment_id", att, "user_id", USER2), apiKeyCred(key)).status, "own key but the wrong principal");
        assertEquals(200, call(body("_func", "get_grievance_attachment", "attachment_id", att, "user_id", USER1), apiKeyCred(key)).status);

        Call meta = call(body("_func", "get_grievance", "grievance_id", g), operatorCred(dpoEmail));
        assertEquals(200, meta.status, meta.out.toString());
        assertEquals(1, ((org.json.simple.JSONArray) meta.json().get("files")).size());
    }

    @Test
    void badAttachmentsAreRefused() throws Exception {
        String g = submit(principal(fid, USER1), USER1);
        String html = Base64.getEncoder().encodeToString("<script>alert(1)</script>".getBytes(StandardCharsets.US_ASCII));
        assertEquals(400, call(body("_func", "upload_grievance_attachment", "grievance_id", g, "content_type", "text/html", "content_base64", html), principal(fid, USER1)).status);
        assertEquals(400, call(body("_func", "upload_grievance_attachment", "grievance_id", g, "content_type", "application/pdf", "content_base64", html), principal(fid, USER1)).status, "script labelled as a pdf");
        assertEquals(400, call(body("_func", "upload_grievance_attachment", "grievance_id", g, "content_type", "application/pdf", "content_base64", "not base64!!"), principal(fid, USER1)).status);
        String huge = "A".repeat(8 * 1024 * 1024);
        assertEquals(413, call(body("_func", "upload_grievance_attachment", "grievance_id", g, "content_type", "application/pdf", "content_base64", huge), principal(fid, USER1)).status);
        assertEquals("0", scalar("SELECT COUNT(*)::text FROM grievance_attachments WHERE grievance_id = ?::uuid", g));
        assertEquals(403, call(body("_func", "upload_grievance_attachment", "grievance_id", g, "content_type", "application/pdf", "content_base64", pdfB64()), principal(fid, USER2)).status, "someone else's grievance");
    }

    @Test
    void atMostFiveAttachmentsAndNoneOnAClosedGrievance() throws Exception {
        String g = submit(principal(fid, USER1), USER1);
        for (int i = 0; i < 5; i++)
            assertEquals(201, call(body("_func", "upload_grievance_attachment", "grievance_id", g, "file_name", "f" + i + ".pdf", "content_type", "application/pdf", "content_base64", pdfB64()), principal(fid, USER1)).status);
        assertEquals(409, call(body("_func", "upload_grievance_attachment", "grievance_id", g, "content_type", "application/pdf", "content_base64", pdfB64()), principal(fid, USER1)).status);
        String closed = submit(principal(fid, USER1), USER1);
        Call c = call(body("_func", "update_grievance_status", "grievance_id", closed, "status", "CLOSED", "resolution_details", "Closed after the principal confirmed."), operatorCred(dpoEmail));
        assertEquals(200, c.status, c.out.toString());
        assertEquals(409, call(body("_func", "upload_grievance_attachment", "grievance_id", closed, "content_type", "application/pdf", "content_base64", pdfB64()), principal(fid, USER1)).status);
    }

    // ---- feedback ----
    @Test
    void feedbackIsTheOwnersOnlyOnceAndOnlyAfterResolution() throws Exception {
        String g = submit(principal(fid, USER1), USER1);
        assertEquals(409, call(body("_func", "submit_grievance_feedback", "grievance_id", g, "rating", 5L), principal(fid, USER1)).status, "not resolved yet");
        resolve(g);
        assertEquals(403, call(body("_func", "submit_grievance_feedback", "grievance_id", g, "rating", 5L), principal(fid, USER2)).status, "another principal");
        assertEquals(403, call(body("_func", "submit_grievance_feedback", "grievance_id", g, "rating", 5L), operatorCred(dpoEmail)).status, "an operator cannot give it for them");
        assertEquals(400, call(body("_func", "submit_grievance_feedback", "grievance_id", g, "rating", 9L), principal(fid, USER1)).status);
        Call ok = call(body("_func", "submit_grievance_feedback", "grievance_id", g, "rating", 4L, "comment", "Helpful, thank you"), principal(fid, USER1));
        assertEquals(200, ok.status, ok.out.toString());
        assertEquals("4", scalar("SELECT feedback_rating::text FROM grievances WHERE id = ?::uuid", g));
        assertEquals(409, call(body("_func", "submit_grievance_feedback", "grievance_id", g, "rating", 1L), principal(fid, USER1)).status, "once only");
        Call view = call(body("_func", "get_grievance", "grievance_id", g), principal(fid, USER1));
        assertEquals(200, view.status, view.out.toString());
        assertEquals(4L, view.json().get("feedback_rating"));
    }
}
