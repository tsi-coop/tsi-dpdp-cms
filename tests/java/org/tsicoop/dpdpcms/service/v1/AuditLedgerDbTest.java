package org.tsicoop.dpdpcms.service.v1;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tsicoop.dpdpcms.framework.PoolDB;
import org.tsicoop.dpdpcms.framework.SystemConfig;
import org.tsicoop.dpdpcms.util.AuditChain;

import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs against a real Postgres with db/01..18 applied. Skipped unless POSTGRES_HOST, POSTGRES_DB,
 * POSTGRES_USER and POSTGRES_PASSWD are set (and TSI_DPDP_CMS_ENV=local for sslmode=prefer).
 * Use a throwaway database: audit_logs is append-only, so the rows these tests write stay.
 */
class AuditLedgerDbTest {

    @BeforeAll
    static void connect() {
        assumeTrue(System.getenv("POSTGRES_HOST") != null && System.getenv("POSTGRES_DB") != null,
                "POSTGRES_* not set: skipping DB tests");
        SystemConfig.loadAppConfig(null);
    }

    private static long count(Connection c) throws SQLException {
        try (Statement s = c.createStatement(); ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM audit_logs")) {
            rs.next(); return rs.getLong(1);
        }
    }

    private static void sqlFails(Connection c, String sql) {
        assertThrows(SQLException.class, () -> { try (Statement s = c.createStatement()) { s.execute(sql); } }, sql);
    }

    @Test
    void updateDeleteAndTruncateAreRefused() throws Exception {
        Audit audit = new Audit();
        audit.logEventSync("t", null, "TEST", null, "SEED", "x");
        audit.recordVerification(audit.verifyChain(), "MANUAL"); // ensure a row exists for the row-level trigger
        PoolDB pool = new PoolDB();
        Connection c = pool.getConnection();
        try {
            sqlFails(c, "UPDATE audit_logs SET user_id = 'x'");
            sqlFails(c, "DELETE FROM audit_logs");
            sqlFails(c, "TRUNCATE audit_logs");
            sqlFails(c, "UPDATE audit_chain_verifications SET verdict = 'INTACT'");
            sqlFails(c, "DELETE FROM audit_chain_verifications");
            sqlFails(c, "TRUNCATE audit_chain_verifications");
        } finally { pool.cleanup(null, null, c); }
    }

    @Test
    void concurrentFlushesProduceOneLinearChain() throws Exception {
        PoolDB pool = new PoolDB();
        Connection c = pool.getConnection();
        long before;
        try { before = count(c); } finally { pool.cleanup(null, null, c); }

        int threads = 8, per = 50;
        ExecutorService ex = Executors.newFixedThreadPool(threads);
        List<Future<?>> fs = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int id = t;
            fs.add(ex.submit(() -> {
                Audit a = new Audit();
                for (int i = 0; i < per; i++) {
                    a.logEventAsync("u" + id, null, "TEST", null, "CONCURRENT", "n=" + i);
                    if (i % 10 == 0) a.logEvents();
                }
                a.logEvents();
            }));
        }
        for (Future<?> f : fs) f.get(60, TimeUnit.SECONDS);
        ex.shutdown();
        new Audit().logEvents();

        c = new PoolDB().getConnection();
        try { assertEquals(before + threads * per, count(c)); } finally { c.close(); }
        AuditChain.Result r = new Audit().verifyChain();
        assertTrue(r.intact(), "chain broken at seq " + r.firstBreakSeq);
    }

    /** Proves the cross-instance lock: a writer waits while another session holds the advisory lock. */
    @Test
    void writerWaitsForAdvisoryLock() throws Exception {
        PoolDB holderPool = new PoolDB();
        Connection holder = holderPool.getConnection();
        holder.setAutoCommit(false);
        try (PreparedStatement ps = holder.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
            ps.setLong(1, AuditChain.ADVISORY_LOCK_KEY); ps.execute();
        }
        ExecutorService ex = Executors.newSingleThreadExecutor();
        Future<?> writer = ex.submit(() -> {
            new Audit().logEventSync("w", null, "TEST", null, "LOCKED_WRITE", "x");
            return null;
        });
        Thread.sleep(700);
        assertFalse(writer.isDone(), "writer must block while the lock is held");
        holder.commit();
        holderPool.cleanup(null, null, holder);
        writer.get(10, TimeUnit.SECONDS);
        ex.shutdown();
    }

    @Test
    void tamperedContextIsDetectedThenRepaired() throws Exception {
        new Audit().logEventSync("tamper", null, "TEST", null, "TAMPER_TARGET", "original");
        PoolDB pool = new PoolDB();
        Connection c = pool.getConnection();
        UUID id; 
        try (Statement s = c.createStatement(); ResultSet rs = s.executeQuery(
                "SELECT id FROM audit_logs WHERE audit_action='TAMPER_TARGET' ORDER BY seq DESC LIMIT 1")) {
            rs.next(); id = (UUID) rs.getObject(1);
        }
        try (Statement s = c.createStatement()) {
            s.execute("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_no_update_delete");
            try {
                s.execute("UPDATE audit_logs SET context_details='tampered' WHERE id='" + id + "'");
                AuditChain.Result r = new Audit().verifyChain();
                assertFalse(r.intact());
                assertEquals(id, r.firstBreakId);
                s.execute("UPDATE audit_logs SET context_details='original' WHERE id='" + id + "'");
            } finally {
                s.execute("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_no_update_delete");
            }
        } finally { pool.cleanup(null, null, c); }
        assertTrue(new Audit().verifyChain().intact());
    }

    @Test
    void verdictCanBeRecorded() throws Exception {
        Audit a = new Audit();
        a.recordVerification(a.verifyChain(), "MANUAL");
    }
}
