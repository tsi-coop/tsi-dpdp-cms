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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Breach intimation to the Data Protection Board: tracking, recording, alerts. Needs db/01..26. */
class BreachBoardDbTest {
    private static UUID fid, fidOther;
    private static String dpoEmail, opEmail, otherDpoEmail;

    @BeforeAll
    static void fixtures() throws Exception {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("DB_ENCRYPTION_KEY") != null, "DB env not set: skipping");
        SystemConfig.loadAppConfig(null);
        fid = fiduciary(); fidOther = fiduciary();
        dpoEmail = operator("DPO", fid); opEmail = operator("OPERATOR", fid); otherDpoEmail = operator("DPO", fidOther);
    }
    @BeforeEach void reset() { OperatorSessions.useDatabaseStore(); }

    private static void sql(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); ps.executeUpdate(); } finally { pool.cleanup(null, ps, c); } }
    private static String scalar(String q, Object... p) throws Exception { PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null; ResultSet rs = null; try { ps = c.prepareStatement(q); for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); rs = ps.executeQuery(); return rs.next() ? rs.getString(1) : null; } finally { pool.cleanup(rs, ps, c); } }
    private static UUID fiduciary() throws Exception { UUID id = UUID.randomUUID(); sql("INSERT INTO fiduciaries (id, name, primary_domain) VALUES (?, ?, ?)", id, "f" + id.toString().substring(0, 8), id.toString().substring(0, 8) + ".test"); return id; }
    private static String operator(String role, UUID f) throws Exception {
        String email = "bb-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
        PoolDB pool = new PoolDB(); Connection c = pool.getConnection(); PreparedStatement ps = null;
        try {
            ps = c.prepareStatement("INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", 'x', ?, 'ACTIVE', ?, NOW() - interval '1 hour', NOW())");
            int i = 1; ps.setString(i++, "u" + UUID.randomUUID().toString().substring(0, 8)); ps.setString(i++, email);
            i = DbEncryption.bindEncrypt(ps, i, email); i = DbEncryption.bindHmac(ps, i, email); ps.setString(i++, role); ps.setObject(i, f); ps.executeUpdate();
        } finally { pool.cleanup(null, ps, c); }
        return email;
    }

    static final class Call { int status = 200; final StringWriter out = new StringWriter(); final Map<String, Object> attrs = new HashMap<>(); HttpServletRequest req; HttpServletResponse res; JSONObject json() throws Exception { return (JSONObject) new JSONParser().parse(out.toString()); } JSONArray array() throws Exception { return (JSONArray) new JSONParser().parse(out.toString()); } }
    private static Call breach(JSONObject body, String staffEmail) {
        Call k = new Call(); k.attrs.put(InputProcessor.REQUEST_DATA, body.toJSONString());
        JSONObject t = new JSONObject(); t.put("email", staffEmail); t.put("mfa", true); k.attrs.put(InputProcessor.AUTH_TOKEN, t);
        k.req = (HttpServletRequest) Proxy.newProxyInstance(BreachBoardDbTest.class.getClassLoader(), new Class[]{HttpServletRequest.class}, (p, m, a) -> { switch (m.getName()) { case "getAttribute": return k.attrs.get((String) a[0]); case "setAttribute": k.attrs.put((String) a[0], a[1]); return null; case "getRemoteAddr": return "10.0.0.1"; case "getRequestURI": return "/api/v1/breach"; default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        k.res = (HttpServletResponse) Proxy.newProxyInstance(BreachBoardDbTest.class.getClassLoader(), new Class[]{HttpServletResponse.class}, (p, m, a) -> { switch (m.getName()) { case "setStatus": k.status = (Integer) a[0]; return null; case "getWriter": return new PrintWriter(k.out, true); default: return m.getReturnType() == boolean.class ? false : m.getReturnType() == int.class ? 0 : null; } });
        new Breach().post(k.req, k.res); return k;
    }
    private static JSONObject body(Object... kv) { JSONObject o = new JSONObject(); for (int i = 0; i < kv.length; i += 2) o.put(kv[i], kv[i + 1]); return o; }

    private static String report(Instant detectedAt) throws Exception {
        Call k = breach(body("_func", "report_breach", "fiduciary_id", fid.toString(), "title", "Test breach " + UUID.randomUUID().toString().substring(0, 6),
                "description", "d", "detected_at", detectedAt.toString(), "actionable_steps", "Change your password."), dpoEmail);
        assertEquals(201, k.status, k.out.toString());
        return (String) k.json().get("id");
    }
    private static JSONObject get(String id) throws Exception { Call k = breach(body("_func", "get_breach", "id", id), dpoEmail); assertEquals(200, k.status, k.out.toString()); return k.json(); }

    @Test
    void aNewBreachIsTrackedForTheBoardFromTheMomentItIsReported() throws Exception {
        Instant detected = Instant.now().minus(1, ChronoUnit.HOURS);
        String id = report(detected);
        JSONObject b = get(id);
        assertEquals("COUNTING", b.get("board_state"));
        Instant deadline = Instant.parse((String) b.get("board_notification_deadline"));
        assertEquals(72, ChronoUnit.HOURS.between(detected, deadline), 1, "detected + the fiduciary's window (default 72 hours)");
        assertNull(b.get("board_notified_at"));
        Call list = breach(body("_func", "list_breaches", "fiduciary_id", fid.toString()), dpoEmail);
        boolean found = false;
        for (Object o : list.array()) if (id.equals(((JSONObject) o).get("id"))) { found = true; assertEquals("COUNTING", ((JSONObject) o).get("board_state")); }
        assertTrue(found);
    }

    @Test
    void theDpoRecordsTheIntimationOnceAndOnlyForTheirOwnBreach() throws Exception {
        String id = report(Instant.now().minus(2, ChronoUnit.HOURS));
        assertEquals(403, breach(body("_func", "record_board_intimation", "id", id), opEmail).status, "an operator does not do this");
        assertEquals(403, breach(body("_func", "record_board_intimation", "id", id), otherDpoEmail).status, "another fiduciary's DPO");
        assertEquals(400, breach(body("_func", "record_board_intimation", "id", id, "notified_at", Instant.now().plus(2, ChronoUnit.HOURS).toString()), dpoEmail).status, "not in the future");
        assertEquals(400, breach(body("_func", "record_board_intimation", "id", id, "notified_at", Instant.now().minus(30, ChronoUnit.HOURS).toString()), dpoEmail).status, "not before detection");
        assertEquals(400, breach(body("_func", "record_board_intimation", "id", id, "notified_at", "tomorrowish"), dpoEmail).status);
        assertNull(scalar("SELECT board_notified_at::text FROM breach_incidents WHERE id = ?::uuid", id));

        Call ok = breach(body("_func", "record_board_intimation", "id", id, "notified_at", Instant.now().minus(1, ChronoUnit.HOURS).toString(), "board_reference", "DPB/2026/0042"), dpoEmail);
        assertEquals(200, ok.status, ok.out.toString());
        assertEquals(Boolean.TRUE, ok.json().get("on_time"));
        JSONObject b = get(id);
        assertEquals("MET", b.get("board_state"));
        assertEquals("DPB/2026/0042", b.get("board_reference"));
        assertEquals(409, breach(body("_func", "record_board_intimation", "id", id), dpoEmail).status, "a statement of fact is not edited");
        new Audit().logEvents();
        assertEquals("1", scalar("SELECT COUNT(*)::text FROM audit_logs WHERE audit_action = 'BREACH_BOARD_NOTIFIED' AND context_details LIKE ?", "%" + id + "%"));
    }

    @Test
    void anIntimationAfterTheDeadlineIsRecordedAsLate() throws Exception {
        String id = report(Instant.now().minus(100, ChronoUnit.HOURS)); // 72-hour window already gone
        assertEquals("OVERDUE", get(id).get("board_state"));
        Call late = breach(body("_func", "record_board_intimation", "id", id), dpoEmail);
        assertEquals(200, late.status, late.out.toString());
        assertEquals(Boolean.FALSE, late.json().get("on_time"));
        assertEquals("MET_LATE", get(id).get("board_state"));
    }

    @Test
    void theSweepWarnsOnceWhenTheDeadlineIsNearAndOnceWhenItIsMissed() throws Exception {
        UUID f2 = fiduciary(); String dpo2 = operator("DPO", f2);
        UUID soon = UUID.randomUUID(), missed = UUID.randomUUID(), done = UUID.randomUUID(), farOff = UUID.randomUUID(), untracked = UUID.randomUUID();
        Object[][] rows = {{soon, 6}, {missed, -3}, {done, -3}, {farOff, 48}, {untracked, null}};
        for (Object[] r : rows) {
            sql("INSERT INTO breach_incidents (id, fiduciary_id, title, description, detected_at, actionable_steps, severity, status, board_notification_deadline, board_notified_at) VALUES (?, ?, 'sweep test', 'd', NOW() - interval '70 hours', 'steps', 'MEDIUM', 'OPEN', " +
                    (r[1] == null ? "NULL" : "NOW() + (? || ' hours')::interval") + ", " + (r[0].equals(done) ? "NOW() - interval '5 hours'" : "NULL") + ")",
                    r[1] == null ? new Object[]{r[0], f2} : new Object[]{r[0], f2, String.valueOf(r[1])});
        }
        int[] first = Breach.sweepBoardDeadlines();
        assertTrue(first[0] >= 1 && first[1] >= 1, java.util.Arrays.toString(first));
        assertNotNull(scalar("SELECT board_due_alert_at::text FROM breach_incidents WHERE id = ?", soon));
        assertNotNull(scalar("SELECT board_missed_alert_at::text FROM breach_incidents WHERE id = ?", missed));
        for (UUID u : new UUID[]{done, farOff, untracked}) {
            assertNull(scalar("SELECT board_due_alert_at::text FROM breach_incidents WHERE id = ?", u), "no alert for a breach already informed, far off or untracked");
            assertNull(scalar("SELECT board_missed_alert_at::text FROM breach_incidents WHERE id = ?", u));
        }
        Breach.sweepBoardDeadlines(); // a second sweep must not raise the same alerts again (checked by the counts below)
        assertEquals("2", scalar("SELECT COUNT(*)::text FROM notifications WHERE fiduciary_id = ? AND notification_type = 'BREACH_BOARD_DEADLINE_NOTIFICATION'", f2), "the DPO is told, once for each alert");
        new Audit().logEvents();
        assertNotNull(scalar("SELECT id::text FROM audit_logs WHERE audit_action = 'BREACH_BOARD_DEADLINE_MISSED' AND context_details LIKE ?", "%" + missed + "%"));
        assertNotNull(scalar("SELECT id::text FROM audit_logs WHERE audit_action = 'BREACH_BOARD_DEADLINE_DUE' AND context_details LIKE ?", "%" + soon + "%"));
    }
}
