package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class AuditChainTest {
    private static String T(long ms) { return java.time.LocalDateTime.of(2026,1,1,0,0).plusNanos(ms*1_000_000).format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS")); }


    private static final UUID FID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID SID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    private static AuditChain.Row v2(long seq, String prev, String action, String ctx, String t) {
        AuditChain.Row r = new AuditChain.Row();
        r.seq = seq; r.id = UUID.randomUUID(); r.fiduciaryId = FID; r.userId = "u"; r.serviceType = "APP";
        r.serviceId = SID; r.action = action; r.eventTime = t; r.context = ctx;
        r.prevHash = prev; r.hashVersion = 2;
        r.currentHash = AuditChain.hashV2(prev, FID, "u", "APP", SID, action, t, ctx);
        return r;
    }

    private static AuditChain.Row legacy(long seq, String prev, String hash) {
        AuditChain.Row r = new AuditChain.Row();
        r.seq = seq; r.id = UUID.randomUUID(); r.fiduciaryId = FID; r.userId = "u"; r.serviceType = "APP";
        r.action = "A"; r.eventTime = "2026-01-01T00:00:00.001"; r.prevHash = prev; r.currentHash = hash; r.hashVersion = 1;
        return r;
    }

    @Test
    void hashCoversServiceTypeServiceIdAndEventTime() {
        String base = AuditChain.hashV2("p", FID, "u", "APP", SID, "A", T(1000), "c");
        assertNotEquals(base, AuditChain.hashV2("p", FID, "u", "DPO", SID, "A", T(1000), "c"));
        assertNotEquals(base, AuditChain.hashV2("p", FID, "u", "APP", UUID.randomUUID(), "A", T(1000), "c"));
        assertNotEquals(base, AuditChain.hashV2("p", FID, "u", "APP", null, "A", T(1000), "c"));
        assertNotEquals(base, AuditChain.hashV2("p", FID, "u", "APP", SID, "A", T(1001), "c"));
        assertEquals(base, AuditChain.hashV2("p", FID, "u", "APP", SID, "A", T(1000), "c"));
    }

    @Test
    void fieldBoundariesAreUnambiguous() {
        // "ab"+"c" must not hash like "a"+"bc"
        assertNotEquals(
            AuditChain.hashV2("p", FID, "ab", "APP", SID, "c", T(1), null),
            AuditChain.hashV2("p", FID, "a", "APP", SID, "bc", T(1), null));
    }

    @Test
    void intactChainIsVerified() {
        AuditChain.Walker w = new AuditChain.Walker();
        AuditChain.Row a = v2(1, AuditChain.GENESIS, "A", "x", T(1000));
        AuditChain.Row b = v2(2, a.currentHash, "B", "y", T(2000));
        w.accept(a); w.accept(b);
        AuditChain.Result r = w.result();
        assertTrue(r.intact());
        assertEquals(2, r.rowsChecked);
        assertEquals(2, r.rowsVerified);
        assertEquals(0, r.legacyLinkageOnly);
    }

    @Test
    void tamperedContextIsReported() {
        AuditChain.Walker w = new AuditChain.Walker();
        AuditChain.Row a = v2(1, AuditChain.GENESIS, "A", "x", T(1000));
        AuditChain.Row b = v2(2, a.currentHash, "B", "original", T(2000));
        b.context = "tampered";
        w.accept(a); w.accept(b);
        AuditChain.Result r = w.result();
        assertFalse(r.intact());
        assertEquals(b.id, r.firstBreakId);
        assertEquals(2L, r.firstBreakSeq);
        assertEquals(1, r.breaks.size());
    }

    @Test
    void deletedRowBreaksLinkage() {
        AuditChain.Row a = v2(1, AuditChain.GENESIS, "A", "x", T(1000));
        AuditChain.Row b = v2(2, a.currentHash, "B", "y", T(2000));
        AuditChain.Row c = v2(3, b.currentHash, "C", "z", T(3000));
        AuditChain.Walker w = new AuditChain.Walker();
        w.accept(a); w.accept(c); // b removed
        assertFalse(w.result().intact());
        assertEquals(c.id, w.result().firstBreakId);
    }

    @Test
    void legacyRowsAreCheckedForLinkageOnly() {
        AuditChain.Walker w = new AuditChain.Walker();
        AuditChain.Row l1 = legacy(1, AuditChain.GENESIS, "h1");
        AuditChain.Row l2 = legacy(2, "h1", "h2");
        AuditChain.Row n = v2(3, "h2", "N", null, T(5000));
        w.accept(l1); w.accept(l2); w.accept(n);
        AuditChain.Result r = w.result();
        assertTrue(r.intact());
        assertEquals(3, r.rowsChecked);
        assertEquals(1, r.rowsVerified);
        assertEquals(2, r.legacyLinkageOnly);
    }

    @Test
    void legacyLinkageBreakIsStillDetected() {
        AuditChain.Walker w = new AuditChain.Walker();
        w.accept(legacy(1, AuditChain.GENESIS, "h1"));
        w.accept(legacy(2, "WRONG", "h2"));
        assertFalse(w.result().intact());
    }

    @Test
    void walkerResyncsSoLaterBreaksAreCountedSeparately() {
        AuditChain.Row a = v2(1, AuditChain.GENESIS, "A", "x", T(1000));
        AuditChain.Row b = v2(2, a.currentHash, "B", "y", T(2000));
        b.context = "tampered";
        AuditChain.Row c = v2(3, b.currentHash, "C", "z", T(3000));
        AuditChain.Walker w = new AuditChain.Walker();
        w.accept(a); w.accept(b); w.accept(c);
        assertEquals(1, w.result().breaks.size()); // c links to b's stored hash, so only b is bad
    }
}
