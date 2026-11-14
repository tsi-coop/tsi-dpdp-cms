package org.tsicoop.dpdpcms.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Hash-chain rules for audit_logs, kept free of database code so they can be unit tested.
 *
 * hash_version 1 (legacy): hash covered only some columns and used a JVM-timezone-dependent
 *   timestamp, so it cannot be recomputed reliably. Such rows are verified for linkage only.
 * hash_version 2: hash covers fiduciary_id, user_id, service_type, service_id, audit_action,
 *   the event time exactly as stored in the (timezone-less) timestamp column, to the millisecond and context_details, chained to the previous row's hash.
 */
public final class AuditChain {
    public static final String GENESIS = "GENESIS_BLOCK";
    public static final int HASH_VERSION = 2;
    /** Postgres advisory lock key that serialises every writer of the chain. */
    public static final long ADVISORY_LOCK_KEY = 727001L;

    private AuditChain() {}

    private static final java.time.format.DateTimeFormatter TIME_FMT =
            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");

    /** Canonical text of a stored timestamp (millisecond precision) used inside the hash. */
    public static String formatTime(java.time.LocalDateTime t) {
        return t.truncatedTo(java.time.temporal.ChronoUnit.MILLIS).format(TIME_FMT);
    }

    /** Length-prefixed fields so no choice of values can shift a boundary and collide. */
    public static String hashV2(String prevHash, UUID fiduciaryId, String userId, String serviceType,
                                UUID serviceId, String action, String eventTime, String context) {
        StringBuilder sb = new StringBuilder("v2");
        field(sb, prevHash);
        field(sb, fiduciaryId == null ? null : fiduciaryId.toString());
        field(sb, userId);
        field(sb, serviceType);
        field(sb, serviceId == null ? null : serviceId.toString());
        field(sb, action);
        field(sb, eventTime);
        field(sb, context);
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(d);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void field(StringBuilder sb, String v) {
        if (v == null) { sb.append("|-1:"); return; }
        sb.append('|').append(v.length()).append(':').append(v);
    }

    /** One stored audit row, as read back for verification. */
    public static final class Row {
        public long seq;
        public UUID id;
        public UUID fiduciaryId;
        public String userId, serviceType, action, context, prevHash, currentHash;
        public UUID serviceId;
        public String eventTime;
        public int hashVersion;
    }

    public static final class Break {
        public final UUID id;
        public final long seq;
        public final UUID fiduciaryId;
        public final String reason;
        Break(UUID id, long seq, UUID fiduciaryId, String reason) {
            this.id = id; this.seq = seq; this.fiduciaryId = fiduciaryId; this.reason = reason;
        }
    }

    public static final class Result {
        public long rowsChecked, rowsVerified, legacyLinkageOnly;
        public UUID firstBreakId;
        public Long firstBreakSeq;
        public final List<Break> breaks = new ArrayList<>();
        public boolean intact() { return breaks.isEmpty(); }
    }

    /** Streams rows in seq order; call accept() for each, then result(). */
    public static final class Walker {
        private static final int MAX_BREAKS_KEPT = 1000;
        private final Result result = new Result();
        private String expectedPrev = null;   // null until the first row
        private boolean first = true;
        private long breakCount = 0;

        public void accept(Row r) {
            result.rowsChecked++;
            String problem = null;

            boolean linkOk = first
                    ? (r.prevHash == null || GENESIS.equals(r.prevHash))
                    : (expectedPrev != null && expectedPrev.equals(r.prevHash));
            if (!linkOk) problem = "LINK_MISMATCH";

            if (r.hashVersion >= HASH_VERSION) {
                String recomputed = hashV2(r.prevHash, r.fiduciaryId, r.userId, r.serviceType,
                        r.serviceId, r.action, r.eventTime, r.context);
                if (!recomputed.equals(r.currentHash)) problem = problem == null ? "HASH_MISMATCH" : problem + "+HASH_MISMATCH";
                else if (problem == null) result.rowsVerified++;
            } else {
                result.legacyLinkageOnly++;
            }

            if (problem != null) {
                breakCount++;
                if (result.firstBreakId == null) { result.firstBreakId = r.id; result.firstBreakSeq = r.seq; }
                if (result.breaks.size() < MAX_BREAKS_KEPT) result.breaks.add(new Break(r.id, r.seq, r.fiduciaryId, problem));
            }
            // Resync on the stored hash so one bad row is reported once, not for the rest of the chain.
            expectedPrev = r.currentHash;
            first = false;
        }

        public Result result() { return result; }
        public long breakCount() { return breakCount; }
    }
}
