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

/** Purge confirmation rules, API-key erasure, legal holds and the sweeps. Needs db/01..25. */
class PurgeAndHoldsDbTest {
    private static final String SECRET = "s3cret-secret-secret-secret-0123456789";
    private static UUID fid, fidOther, key1, key2, keyOther, app1, app2;
    private static String dpoEmail, opEmail, otherDpoEmail;
    private static UUID opId;

    @BeforeAll
    static void fixtures() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        fid = fiduciary(); fidOther = fiduciary();
        key1 = apiKey(fid); key2 = apiKey(fid); keyOther = apiKey(fidOther);
        app1 = UUID.fromString(scalar("SELECT app_id::text FROM api_keys WHERE id = ?", key1));
        app2 = UUID.fromString(scalar("SELECT app_id::text FROM api_keys WHERE id = ?", key2));
        dpoEmail = operator("DPO", fid); opEmail = operator("OPERATOR", fid); otherDpoEmail = operator("DPO", fidOther);
        opId = UUID.fromString(scalar("SELECT id::text FROM operators WHERE email_hmac = " + DbEncryption.HMAC, opEmail, DbEncryption.key()));
    }
    @BeforeEach void reset() { OperatorSessions.useDatabaseStore(); }

    // ---- fixtures ----
    private static void sql(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); ps.executeUpdate(); } finally { pool.cleanup(null, ps, c); } }
    private static String scalar(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; ResultSet rs = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); rs = ps.executeQuery(); return rs.next() ? rs.getString(1) : null; } finally { pool.cleanup(rs, ps, c); } }
    private static UUID fiduciary() throws Exception { UUID id = UUID.randomUUID(); sql("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)", id, "f" + id.toString().substring(0, 8), id.toString().substring(0, 8) + ".test"); return id; }
    private static UUID apiKey(UUID f) throws Exception { UUID a = UUID.randomUUID(), k = UUID.randomUUID(); sql("INSERT INTO apps (id, fiduciary_id, name) VALUES (?, ?, ?)", a, f, "App " + a.toString().substring(0, 6)); sql("INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, status) VALUES (?, ?, ?, ?, 'ACTIVE')", k, new PasswordHasher().hashPassword(SECRET), f, a); return k; }
    private static String operator(String role, UUID f) throws Exception {
        String email = "ph-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", 'x', ?, 'ACTIVE', ?, NOW() - interval '1 hour', NOW())");
            int i = 1; ps.setString(i++, "u" + UUID.randomUUID().toString().substring(0, 8)); ps.setString(i++, email);
            i = DbEncryption.bindEncrypt(ps, i, email); i = DbEncryption.bindHmac(ps, i, email); ps.setString(i++, role); ps.setObject(i, f); ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return email;
    }
    private static String principal() throws Exception { String u = "ph-" + UUID.randomUUID().toString().substring(0, 8); sql("INSERT INTO data_principal (user_id, fiduciary_id) VALUES (?, ?)", u, fid); return u; }
    private static String purge(String user, UUID app, String purpose, String status) throws Exception {
        UUID id = UUID.randomUUID();
        sql("INSERT INTO purge_requests (id, user_id, fiduciary_id, purpose_id, app_id, trigger_event, status) VALUES (?, ?, ?, ?, ?, 'RetentionPolicyExpiry', ?)", id, user, fid, purpose, app, status);
        return id.toString();
    }

    // ---- fakes ----
    static final class Call { int status = 200; final StringWriter out = new StringWriter(); final Map<String, Object> attrs = new HashMap<>(); final Map<String, String> headers = new HashMap<>(); HttpServletRequest req; HttpServletResponse res; JSONObject json() throws Exception { return (JSONObject) new JSONParser().parse(out.toString()); } JSONArray array() throws Exception { return (JSONArray) new JSONParser().parse(out.toString()); } }
    private static Call compliance(JSONObject body, Consumer<Call> cred) {
        Call k = new Call(); k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString()); cred.accept(k);
        k.req = (HttpServletRequest) Proxy.newProxyInstance(PurgeAndHoldsDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> { switch (m.getName()) { case "getAttribute": return k.attrs.get((String) a[0]); case "setAttribute": k.attrs.put((String) a[0], a[1]); return null; case "getHeader": return k.headers.get((String) a[0]); case "getRemoteAddr": return "10.0.0.1"; case "getRequestURI": return "/api/v1/compliance"; default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(PurgeAndHoldsDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> { switch (m.getName()) { case "setStatus": k.status = (Integer) a[0]; return null; case "getWriter": return new PrintWriter(k.out, true); default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        new Compliance().post(k.req, k.res); return k;
    }
    private static Call consent(JSONObject body, Consumer<Call> cred) {
        Call k = new Call(); k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString()); cred.accept(k);
        k.req = (HttpServletRequest) Proxy.newProxyInstance(PurgeAndHoldsDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> { switch (m.getName()) { case "getAttribute": return k.attrs.get((String) a[0]); case "setAttribute": k.attrs.put((String) a[0], a[1]); return null; case "getHeader": return k.headers.get((String) a[0]); case "getRemoteAddr": return "10.0.0.1"; case "getRequestURI": return "/api/v1/consent"; default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(PurgeAndHoldsDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> { switch (m.getName()) { case "setStatus": k.status = (Integer) a[0]; return null; case "getWriter": return new PrintWriter(k.out, true); default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        new Consent().post(k.req, k.res); return k;
    }
    private static Consumer<Call> apiKeyCred(UUID k) { return c -> { c.headers.put("X-API-Key", k.toString()); c.headers.put("X-API-Secret", SECRET); }; }
    private static Consumer<Call> staff(String email) { return c -> { JSONObject t = new JSONObject(); t.put("email", email); t.put("mfa", true); c.attrs.put(InputProcessor.AUTH_TOKEN, t); }; }
    private static JSONObject body(Object... kv) { JSONObject o = new JSONObject(); for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]); return o; }
    private static Call update(String id, String status, Consumer<Call> cred, Object... extra) { JSONObject b = body("_func", "update_purge_status", "id", id, "status", status); for (int i = 0; i < extra.length; i += 2) b.put(extra[i], extra[i + 1]); return compliance(b, cred); }

    // ---- purge confirmation ----
    @Test
    void onlyTheAppTheRequestWasAssignedToMayConfirmIt() throws Exception {
        String u = principal(); String id = purge(u, app1, "p1", "PURGE_INITIATED");
        assertEquals(403, update(id, "PURGE_COMPLETED", apiKeyCred(key2)).status, "another app of the same fiduciary");
        assertEquals(403, update(id, "PURGE_COMPLETED", apiKeyCred(keyOther)).status, "another fiduciary");
        assertEquals("PURGE_INITIATED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", id));
        String orphan = purge(u, null, "p1", "PURGE_INITIATED");
        assertEquals(403, update(orphan, "PURGE_COMPLETED", apiKeyCred(key1)).status, "no linked app: a key cannot confirm it");
    }

    @Test
    void confirmationEvidenceComesFromTheCredentialAndTheCountIsOnlyAClaim() throws Exception {
        String u = principal(); String id = purge(u, app1, "p1", "PURGE_INITIATED");
        Call prog = update(id, "PURGE_IN_PROGRESS", apiKeyCred(key1), "records_affected", 5L, "confirmed_by", "someone-else");
        assertEquals(200, prog.status, prog.out.toString());
        assertNull(scalar("SELECT confirmed_by FROM purge_requests WHERE id = ?::uuid", id), "not confirmed yet");
        Call done = update(id, "PURGE_COMPLETED", apiKeyCred(key1), "records_affected", 7L, "confirmed_by", "someone-else", "confirmed_by_type", "OPERATOR");
        assertEquals(200, done.status, done.out.toString());
        assertEquals(app1.toString(), scalar("SELECT confirmed_by FROM purge_requests WHERE id = ?::uuid", id), "from the key, not the body");
        assertEquals("API_KEY", scalar("SELECT confirmed_by_type FROM purge_requests WHERE id = ?::uuid", id));
        assertNotNull(scalar("SELECT confirmed_at FROM purge_requests WHERE id = ?::uuid", id));
        assertEquals("7", scalar("SELECT claimed_record_count::text FROM purge_requests WHERE id = ?::uuid", id));
        Call get = compliance(body("_func", "get_purge_request", "id", id), apiKeyCred(key1));
        assertEquals(200, get.status, get.out.toString());
        assertEquals(7L, get.json().get("claimed_record_count"));
        assertEquals("API_KEY", get.json().get("confirmed_by_type"));
        // a final state is evidence: nobody changes it afterwards
        assertEquals(409, update(id, "PURGE_FAILED", apiKeyCred(key1)).status);
        assertEquals(409, update(id, "PURGE_CANCELLED", staff(dpoEmail)).status);
        assertEquals("PURGE_COMPLETED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", id));
    }

    @Test
    void anOperatorConfirmingIsRecordedAsTheOperator() throws Exception {
        String u = principal(); String id = purge(u, app1, "p1", "PURGE_INITIATED");
        assertEquals(403, update(id, "PURGE_COMPLETED", staff(opEmail)).status, "not assigned to this operator");
        sql("UPDATE purge_requests SET assigned_operator_id = ? WHERE id = ?::uuid", opId, id);
        assertEquals(200, update(id, "PURGE_COMPLETED", staff(opEmail)).status);
        assertEquals("OPERATOR", scalar("SELECT confirmed_by_type FROM purge_requests WHERE id = ?::uuid", id));
        assertEquals(opId.toString(), scalar("SELECT confirmed_by FROM purge_requests WHERE id = ?::uuid", id));
    }

    @Test
    void cancellingAndLegalHoldAreTheDposDecisionAndInputIsValidated() throws Exception {
        String u = principal(); String id = purge(u, app1, "p1", "PURGE_INITIATED");
        assertEquals(403, update(id, "PURGE_CANCELLED", apiKeyCred(key1)).status);
        assertEquals(403, update(id, "LEGAL_HOLD_APPLIED", apiKeyCred(key1)).status);
        sql("UPDATE purge_requests SET assigned_operator_id = ? WHERE id = ?::uuid", opId, id);
        assertEquals(403, update(id, "PURGE_CANCELLED", staff(opEmail)).status, "an operator cannot cancel either");
        assertEquals(400, update(id, "DONE", apiKeyCred(key1)).status);
        assertEquals(400, update(id, "PURGE_IN_PROGRESS", apiKeyCred(key1), "records_affected", -3L).status);
        assertEquals(400, update(id, "PURGE_IN_PROGRESS", apiKeyCred(key1), "records_affected", "many").status);
        assertEquals(409, update(id, "PURGE_INITIATED", staff(dpoEmail)).status, "only the system re-initiates");
        assertEquals(200, update(id, "PURGE_CANCELLED", staff(dpoEmail), "details", "Request withdrawn by the principal.").status);
        assertEquals(404, update(UUID.randomUUID().toString(), "PURGE_COMPLETED", apiKeyCred(key1)).status);
    }

    // ---- erasure through an API key ----
    @Test
    void anIntegrationCanOnlyEraseSomeoneItHoldsConsentFor() throws Exception {
        String stranger = "nobody-" + UUID.randomUUID().toString().substring(0, 8);
        Call none = consent(body("_func", "erasure_request", "user_id", stranger, "fiduciary_id", fid.toString()), apiKeyCred(key1));
        assertEquals(404, none.status, none.out.toString());
        assertEquals("0", scalar("SELECT COUNT(*)::text FROM consent_records WHERE user_id = ?", stranger), "no erasure record was created for a stranger");

        String known = "known-" + UUID.randomUUID().toString().substring(0, 8);
        String pol = "pol-" + UUID.randomUUID().toString().substring(0, 8);
        sql("INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (?, '1', ?, NOW(), 'ACTIVE', 'IN', '{\"en\":{\"data_processing_purposes\":[{\"id\":\"p1\",\"retention_start_event\":\"COLLECTION\",\"retention_duration_value\":1,\"retention_duration_unit\":\"YEARS\"}]}}'::jsonb, NOW(), NOW())", pol, fid);
        sql("INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, language_selected, consent_status_general, consent_mechanism, ip_address, data_point_consents, is_active_consent) VALUES (uuid_generate_v4(), ?, ?, ?, '1', NOW(), 'IN', 'en', 'CONSENT_GIVEN', 'CONSENT_GIVEN', 'x', '[{\"data_point_id\":\"p1\",\"consent_granted\":true}]'::jsonb, TRUE)", known, fid, pol);
        Call ok = consent(body("_func", "erasure_request", "user_id", known, "fiduciary_id", fid.toString()), apiKeyCred(key1));
        assertEquals(200, ok.status, ok.out.toString());
    }

    // ---- legal holds ----
    private static Call place(Consumer<Call> cred, Object... kv) { return compliance(body(kv), cred); }
    private static String in(int days) { return java.time.Instant.now().plus(days, java.time.temporal.ChronoUnit.DAYS).toString(); }

    @Test
    void aHoldNeedsAReasonAnEndDateAndALegitimatePlacer() throws Exception {
        String u = principal();
        assertEquals(403, place(staff(opEmail), "_func", "place_legal_hold", "user_id", u, "reason", "Court order pending.", "valid_until", in(30)).status);
        assertEquals(403, place(apiKeyCred(key1), "_func", "place_legal_hold", "user_id", u, "reason", "Court order pending.", "valid_until", in(30)).status);
        assertEquals(400, place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "reason", "short", "valid_until", in(30)).status);
        assertEquals(400, place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "reason", "Court order pending.").status, "must be time-bound");
        assertEquals(400, place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "reason", "Court order pending.", "valid_until", in(-1)).status);
        assertEquals(400, place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "reason", "Court order pending.", "valid_until", in(900)).status);
        assertEquals(404, place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", "no-such-principal", "reason", "Court order pending.", "valid_until", in(30)).status);
        assertEquals("0", scalar("SELECT COUNT(*)::text FROM legal_holds WHERE user_id = ?", u));
    }

    @Test
    void placingAHoldDefersExistingAndFuturePurgesAndReleasingResumesThem() throws Exception {
        String u = principal();
        String running = purge(u, app1, "p1", "PURGE_IN_PROGRESS"), done = purge(u, app1, "p1", "PURGE_COMPLETED");
        Call placed = place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "reason", "Court order 42/2026 pending.", "reference", "CASE-42/2026", "valid_until", in(30));
        assertEquals(201, placed.status, placed.out.toString());
        String holdId = (String) placed.json().get("hold_id");
        assertEquals(1L, placed.json().get("purges_held"));
        assertEquals("LEGAL_HOLD_APPLIED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", running));
        assertEquals(holdId, scalar("SELECT legal_hold_id::text FROM purge_requests WHERE id = ?::uuid", running));
        assertEquals("PURGE_COMPLETED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", done), "a finished purge is not touched");

        // a purge that falls due while the hold is active is recorded but not released to the processor
        long appNotificationsBefore = Long.parseLong(scalar("SELECT COUNT(*) FROM notifications WHERE recipient_type = 'APP' AND recipient_id = ?", app1.toString()));
        JSONObject created = new CESService().insertPurgeRequest(u, fid.toString(), "p2", app1.toString(), Constants.PURGE_TRIGGER_EXPIRY, Constants.EVENT_PURGE_INITIATED);
        assertEquals(Boolean.TRUE, created.get("held"));
        assertEquals("LEGAL_HOLD_APPLIED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", (String) created.get("id")));
        assertEquals(appNotificationsBefore, Long.parseLong(scalar("SELECT COUNT(*) FROM notifications WHERE recipient_type = 'APP' AND recipient_id = ?", app1.toString())));

        // other principals are not affected
        JSONObject other = new CESService().insertPurgeRequest(principal(), fid.toString(), "p2", app1.toString(), Constants.PURGE_TRIGGER_EXPIRY, Constants.EVENT_PURGE_INITIATED);
        assertNull(other.get("held"));

        // the holds are listed
        Call list = place(staff(dpoEmail), "_func", "list_legal_holds", "user_id", u, "active_only", true);
        assertEquals(1, list.array().size());
        assertEquals("ACTIVE", ((JSONObject) list.array().get(0)).get("status"));

        // another fiduciary's DPO cannot release it; this one can, with a reason
        assertEquals(404, place(staff(otherDpoEmail), "_func", "release_legal_hold", "hold_id", holdId, "reason", "Trying to release it.").status);
        assertEquals(400, place(staff(dpoEmail), "_func", "release_legal_hold", "hold_id", holdId, "reason", "no").status);
        Call rel = place(staff(dpoEmail), "_func", "release_legal_hold", "hold_id", holdId, "reason", "Order lifted by the court.");
        assertEquals(200, rel.status, rel.out.toString());
        assertEquals(2L, rel.json().get("purges_resumed"));
        assertEquals("PURGE_INITIATED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", running));
        assertNull(scalar("SELECT legal_hold_id::text FROM purge_requests WHERE id = ?::uuid", running));
        assertEquals(404, place(staff(dpoEmail), "_func", "release_legal_hold", "hold_id", holdId, "reason", "Releasing it again.").status);
    }

    @Test
    void aHoldNamingOnePurposeLeavesTheOthersAlone() throws Exception {
        String u = principal();
        place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "purpose_id", "p1", "reason", "Investigation touching p1 only.", "valid_until", in(30));
        assertEquals(Boolean.TRUE, new CESService().insertPurgeRequest(u, fid.toString(), "p1", app1.toString(), Constants.PURGE_TRIGGER_EXPIRY, Constants.EVENT_PURGE_INITIATED).get("held"));
        assertNull(new CESService().insertPurgeRequest(u, fid.toString(), "p2", app1.toString(), Constants.PURGE_TRIGGER_EXPIRY, Constants.EVENT_PURGE_INITIATED).get("held"));
    }

    @Test
    void theSweepEndsOldHoldsResumesTheirPurgesAndLeavesManualHoldsAlone() throws Exception {
        String u = principal();
        String held = purge(u, app1, "p1", "PURGE_INITIATED");
        String holdId = (String) place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "reason", "Court order 7/2026 pending.", "valid_until", in(30)).json().get("hold_id");
        String manual = purge(u, app1, "p9", "LEGAL_HOLD_APPLIED"); // put on hold by hand: no hold record behind it
        sql("UPDATE legal_holds SET valid_until = NOW() - interval '1 minute' WHERE id = ?::uuid", holdId);
        int[] r = Compliance.sweepLegalHolds();
        assertTrue(r[0] >= 1 && r[1] >= 1, java.util.Arrays.toString(r));
        assertEquals("SYSTEM_SWEEP", scalar("SELECT released_by FROM legal_holds WHERE id = ?::uuid", holdId));
        assertEquals("PURGE_INITIATED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", held));
        assertEquals("LEGAL_HOLD_APPLIED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", manual), "a hold the DPO set by hand is the DPO's to lift");
        assertEquals(0, Compliance.sweepLegalHolds()[1], "nothing left to resume");
    }

    @Test
    void aPurgeStaysHeldWhileAnotherHoldStillCoversIt() throws Exception {
        String u = principal();
        String id = purge(u, app1, "p1", "PURGE_INITIATED");
        String first = (String) place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "reason", "First legal reason here.", "valid_until", in(30)).json().get("hold_id");
        place(staff(dpoEmail), "_func", "place_legal_hold", "user_id", u, "reason", "Second legal reason here.", "valid_until", in(60));
        Call rel = place(staff(dpoEmail), "_func", "release_legal_hold", "hold_id", first, "reason", "First reason no longer applies.");
        assertEquals(0L, rel.json().get("purges_resumed"));
        assertEquals("LEGAL_HOLD_APPLIED", scalar("SELECT status FROM purge_requests WHERE id = ?::uuid", id));
    }

    // ---- SLA ----
    @Test
    void purgesStillUnconfirmedPastTheLimitAreFlaggedOnceAndTheDpoIsTold() throws Exception {
        UUID f3 = fiduciary(); UUID k3 = apiKey(f3); UUID a3 = UUID.fromString(scalar("SELECT app_id::text FROM api_keys WHERE id = ?", k3));
        String dpo3 = operator("DPO", f3);
        sql("INSERT INTO data_principal (user_id, fiduciary_id) VALUES ('sla-user', ?)", f3);
        UUID oldOpen = UUID.randomUUID(), oldDone = UUID.randomUUID(), oldHeld = UUID.randomUUID(), recent = UUID.randomUUID();
        for (Object[] r : new Object[][]{{oldOpen, "PURGE_IN_PROGRESS", 40}, {oldDone, "PURGE_COMPLETED", 40}, {oldHeld, "LEGAL_HOLD_APPLIED", 40}, {recent, "PURGE_INITIATED", 5}})
            sql("INSERT INTO purge_requests (id, user_id, fiduciary_id, purpose_id, app_id, trigger_event, status, initiated_at) VALUES (?, 'sla-user', ?, 'p1', ?, 'ErasureRequest', ?, NOW() - (? || ' days')::interval)", r[0], f3, a3, r[1], String.valueOf(r[2]));
        assertEquals(0, Compliance.sweepPurgeSla(null), "no SLA configured: nothing is flagged");
        assertEquals(1, Compliance.sweepPurgeSla(30));
        assertNotNull(scalar("SELECT sla_flagged_at::text FROM purge_requests WHERE id = ?", oldOpen));
        for (UUID u : new UUID[]{oldDone, oldHeld, recent}) assertNull(scalar("SELECT sla_flagged_at::text FROM purge_requests WHERE id = ?", u));
        assertEquals(0, Compliance.sweepPurgeSla(30), "flagged once");
        assertEquals("1", scalar("SELECT COUNT(*)::text FROM notifications WHERE fiduciary_id = ? AND notification_type = 'PURGE_SLA_BREACH_NOTIFICATION'", f3), "the DPO is told");
        Call get = compliance(body("_func", "get_purge_request", "id", oldOpen.toString(), "fiduciary_id", f3.toString()), staff(dpo3));
        assertEquals(Boolean.TRUE, get.json().get("sla_overdue"));
    }
}
