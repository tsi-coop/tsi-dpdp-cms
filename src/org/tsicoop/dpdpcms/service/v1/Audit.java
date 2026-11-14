package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import org.tsicoop.dpdpcms.util.AuditChain;
import org.tsicoop.dpdpcms.util.AuditLimits;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Audit Service for managing immutable DPDP compliance logs.
 * Implements Hash Chaining for tamper-evidence as per BSA Section 62.
 */
public class Audit implements Action {

    // Thread-safe in-memory cache for incoming audit events
    private static final Queue<AuditEntry> auditCache = new ConcurrentLinkedQueue<>();
    
    // Serialises flushes inside this JVM; the Postgres advisory lock serialises across instances.
    private static final Object FLUSH_LOCK = new Object();

    /**
     * DTO to hold audit data in memory before batch writing.
     */
    private static class AuditEntry {
        String userId;
        UUID fiduciaryId;
        String serviceType;
        UUID serviceId;
        String auditAction;
        String contextDetails;
        LocalDateTime eventtime;

        AuditEntry(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails, LocalDateTime eventtime) {
            this.userId = userId;
            this.fiduciaryId = fiduciaryId;
            this.serviceType = serviceType;
            this.serviceId = serviceId;
            this.auditAction = auditAction;
            this.contextDetails = contextDetails;
            this.eventtime = eventtime;
        }
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            req.setCharacterEncoding("UTF-8");
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing _func.", req.getRequestURI());
                return;
            }

            // Audit data needs a session that passed MFA for every role whose MFA is mandatory (ADMIN, DPO, AUDITOR) once MFA is
            // enforced (production / MFA_ENFORCE). An OPERATOR is never prompted to enrol, so it is not held to this.
            if (org.tsicoop.dpdpcms.util.MfaPolicy.required(InputProcessor.getVerifiedRole(req), org.tsicoop.dpdpcms.util.MfaPolicy.enforcing())
                    && !InputProcessor.hasMfa(req)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Audit access requires a session verified with MFA.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "log_event":
                    // Not called by any console UI - internal audit writes go through
                    // logEventAsync() directly. Keep the HTTP path ADMIN-only so an
                    // authenticated DPO/Operator can't inject arbitrary audit entries
                    // (which Legal.java's evidence certificates treat as trustworthy).
                    if (!"ADMIN".equalsIgnoreCase(InputProcessor.getVerifiedRole(req))) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Only ADMIN users may write audit events directly.", req.getRequestURI());
                        return;
                    }
                    handleLogRequest(input, res, req);
                    break;
                case "list_audit_logs":
                    handleListLogs(input, res, req);
                    break;
                case "get_audit_log":
                    handleGetLog(input, res, req);
                    break;
                case "verify_audit_chain":
                    handleVerifyChain(res, req);
                    break;
                case "get_audit_chain_status":
                    handleChainStatus(res, req);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function: " + func, req.getRequestURI());
                    break;
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    private void handleListLogs(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String search = (String) input.get("search");
        String fidFilter = (String) input.get("fiduciary_id");
        String actFilter = (String) input.get("action_filter");

        if (fidFilter == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "fiduciary_id required.", req.getRequestURI());
            return;
        }
        if (rejectIfNotOwnFiduciary(UUID.fromString(fidFilter), req, res)) return;

        int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
        int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 50;

        JSONArray outputArray = listAuditLogsFromDb(search, UUID.fromString(fidFilter), actFilter, page, limit);
        OutputProcessor.send(res, 200, outputArray);
    }
   
    private void handleLogRequest(JSONObject input, HttpServletResponse res, HttpServletRequest req) {
        String userId = (String) input.get("user_id");
        String fidStr = (String) input.get("fiduciary_id");
        String serviceType = (String) input.get("service_type");
        String sidStr = (String) input.get("service_id");
        String action = (String) input.get("audit_action");

        Object contextObj = input.get("context_details");
        String details = (contextObj instanceof JSONObject) ? ((JSONObject)contextObj).toJSONString() : (String)contextObj;

        if (userId == null || fidStr == null || serviceType == null || action == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing parameters.", req.getRequestURI());
            return;
        }

        UUID fiduciaryId = UUID.fromString(fidStr);
        UUID serviceId = (sidStr != null && !sidStr.isEmpty()) ? UUID.fromString(sidStr) : null;

        logEventAsync(userId, fiduciaryId, serviceType, serviceId, action, details);

        JSONObject output = new JSONObject();
        output.put("success", true);
        output.put("message", "Audit event buffered in memory cache.");
        OutputProcessor.send(res, 202, output);
    }

    // Events with no owning fiduciary (e.g. a failed login for an unknown user) are filed under
    // the system/admin fiduciary, matching the ADMIN_FID_UUID convention used across the services.
    private static final UUID SYSTEM_FIDUCIARY_ID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    public void logEventAsync(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) {
        // A null fiduciary or user would make the whole batch fail in flush() (the hash step and the
        // NOT NULL user_id column), and the failed batch is re-queued, blocking every later audit event.
        if (fiduciaryId == null) fiduciaryId = SYSTEM_FIDUCIARY_ID;
        // Some fields are chosen by unauthenticated callers (the login name of a failed login): clean and clip them to
        // their columns here, so one oversized value cannot make the table reject a batch and block everything behind it.
        auditCache.add(new AuditEntry(AuditLimits.userId(userId), fiduciaryId, AuditLimits.serviceType(serviceType), serviceId,
                AuditLimits.action(auditAction), AuditLimits.context(contextDetails), LocalDateTime.now()));
    }

    /**
     * Writes the event (and anything already buffered) to the chain before returning. Use for
     * security events (logins, purge confirmations, PII reveals) that must not be lost if the
     * process dies before the next periodic flush. Throws if the write fails, so the caller can
     * fail closed; the event stays queued and is retried by the periodic flush.
     */
    public void logEventSync(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) throws SQLException {
        logEventAsync(userId, fiduciaryId, serviceType, serviceId, auditAction, contextDetails);
        flush();
    }

    /** Periodic flush of buffered events. Never throws; failures stay queued for the next run. */
    public void logEvents() {
        try {
            flush();
        } catch (Exception e) {
            System.err.println("Audit Flush Error: " + e.getMessage());
        }
    }

    /**
     * Drains the buffer into the hash chain. Each batch runs in one transaction that first takes a
     * Postgres advisory lock and then reads the chain head, so concurrent writers (threads or app
     * instances) queue up behind each other and the chain stays linear. Nothing about the head is
     * cached in memory, so a failed or re-queued batch cannot fork it.
     */
    private void flush() throws SQLException {
        synchronized (FLUSH_LOCK) {
            if (auditCache.isEmpty()) return;

            PoolDB pool = new PoolDB();
            Connection conn = null;
            try {
                conn = pool.getConnection();
                while (!auditCache.isEmpty()) {
                    List<AuditEntry> batch = new ArrayList<>();
                    AuditEntry entry;
                    while (batch.size() < 500 && (entry = auditCache.poll()) != null) batch.add(entry);
                    if (batch.isEmpty()) break;

                    try {
                        writeBatch(conn, batch);
                    } catch (SQLException | RuntimeException e) {
                        try { conn.rollback(); } catch (SQLException ignored) { }
                        System.err.println("CRITICAL: Failed to write audit batch: " + e.getMessage());
                        // A batch can fail because ONE entry can never be stored. Find it by writing the entries one at a
                        // time: store what can be stored, set aside only the entry the database refuses for its content
                        // (a data or constraint error), and keep for retry anything that failed for another reason
                        // (connection down, lock timeout), so a bad entry never blocks the entries behind it.
                        List<AuditEntry> retry = new ArrayList<>();
                        SQLException lastTransient = null;
                        for (AuditEntry single : batch) {
                            try {
                                writeBatch(conn, List.of(single));
                            } catch (SQLException | RuntimeException one) {
                                try { conn.rollback(); } catch (SQLException ignored) { }
                                String state = one instanceof SQLException ? ((SQLException) one).getSQLState() : null;
                                if (AuditLimits.isPoison(state)) {
                                    System.err.println("CRITICAL: audit entry refused by the database and set aside (" + state + "): action="
                                            + single.auditAction + " service_type=" + single.serviceType + " user_id_length=" + single.userId.length());
                                } else {
                                    retry.add(single);
                                    lastTransient = one instanceof SQLException ? (SQLException) one : new SQLException(one);
                                }
                            }
                        }
                        if (!retry.isEmpty()) {
                            auditCache.addAll(retry);
                            throw lastTransient;
                        }
                    }
                }
            } finally {
                if (conn != null) {
                    try { conn.setAutoCommit(true); } catch (SQLException ignored) { }
                    pool.cleanup(null, null, conn);
                }
            }
        }
    }

    private void writeBatch(Connection conn, List<AuditEntry> batch) throws SQLException {
        conn.setAutoCommit(false);

        try (PreparedStatement lock = conn.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
            lock.setLong(1, AuditChain.ADVISORY_LOCK_KEY);
            lock.execute();
        }

        // Chain head, read inside the lock.
        String prevHash = AuditChain.GENESIS;
        LocalDateTime lastTime = null;
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT current_log_hash, \"timestamp\" FROM audit_logs ORDER BY seq DESC LIMIT 1")) {
            if (rs.next()) {
                if (rs.getString(1) != null) prevHash = rs.getString(1);
                lastTime = rs.getObject(2, LocalDateTime.class);
            }
        }

        String sql = "INSERT INTO audit_logs (id, fiduciary_id, timestamp, user_id, service_type, service_id, audit_action, context_details, prev_log_hash, current_log_hash, hash_version) " +
                "VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?, ?, " + AuditChain.HASH_VERSION + ")";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (AuditEntry log : batch) {
                // Millisecond precision (what the hash covers) and strictly increasing along the chain.
                LocalDateTime t = log.eventtime.truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
                if (lastTime != null && !t.isAfter(lastTime)) t = lastTime.plusNanos(1_000_000);
                lastTime = t;

                String currentHash = AuditChain.hashV2(prevHash, log.fiduciaryId, log.userId, log.serviceType,
                        log.serviceId, log.auditAction, AuditChain.formatTime(t), log.contextDetails);

                pstmt.setObject(1, log.fiduciaryId);
                pstmt.setObject(2, t);
                pstmt.setString(3, log.userId);
                pstmt.setString(4, log.serviceType);
                pstmt.setObject(5, log.serviceId);
                pstmt.setString(6, log.auditAction);
                pstmt.setString(7, log.contextDetails);
                pstmt.setString(8, prevHash);
                pstmt.setString(9, currentHash);
                pstmt.addBatch();

                prevHash = currentHash;
            }
            pstmt.executeBatch();
        }
        conn.commit();
    }

    // --- Chain verification ---------------------------------------------------------------

    private static final int VERIFY_PAGE = 5000;
    private static final long VERIFY_REUSE_MS = 5 * 60_000L;

    /**
     * Walks the whole chain in seq order, recomputing hashes (v2 rows) and checking linkage.
     * Always walks the UNFILTERED chain: filtering by fiduciary first would report false breaks.
     */
    public AuditChain.Result verifyChain() throws SQLException {
        AuditChain.Walker walker = new AuditChain.Walker();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        try {
            conn = pool.getConnection();
            long afterSeq = 0;
            String sql = "SELECT seq, id, fiduciary_id, \"timestamp\", user_id, service_type, service_id, audit_action, context_details, " +
                    "prev_log_hash, current_log_hash, hash_version FROM audit_logs WHERE seq > ? ORDER BY seq LIMIT " + VERIFY_PAGE;
            while (true) {
                int n = 0;
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setLong(1, afterSeq);
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            AuditChain.Row r = new AuditChain.Row();
                            r.seq = rs.getLong("seq");
                            r.id = (UUID) rs.getObject("id");
                            r.fiduciaryId = (UUID) rs.getObject("fiduciary_id");
                            r.eventTime = AuditChain.formatTime(rs.getObject("timestamp", LocalDateTime.class));
                            r.userId = rs.getString("user_id");
                            r.serviceType = rs.getString("service_type");
                            r.serviceId = (UUID) rs.getObject("service_id");
                            r.action = rs.getString("audit_action");
                            r.context = rs.getString("context_details");
                            r.prevHash = rs.getString("prev_log_hash");
                            r.currentHash = rs.getString("current_log_hash");
                            r.hashVersion = rs.getInt("hash_version");
                            walker.accept(r);
                            afterSeq = r.seq;
                            n++;
                        }
                    }
                }
                if (n < VERIFY_PAGE) break;
            }
        } finally {
            pool.cleanup(null, null, conn);
        }
        return walker.result();
    }

    /** Stores a verdict in the append-only audit_chain_verifications table. */
    public void recordVerification(AuditChain.Result r, String source) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement ps = null;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("INSERT INTO audit_chain_verifications (trigger_source, verdict, rows_checked, rows_verified, legacy_linkage_only, first_break_id, first_break_seq) VALUES (?,?,?,?,?,?,?)");
            ps.setString(1, source);
            ps.setString(2, r.intact() ? "INTACT" : "BROKEN");
            ps.setLong(3, r.rowsChecked);
            ps.setLong(4, r.rowsVerified);
            ps.setLong(5, r.legacyLinkageOnly);
            ps.setObject(6, r.firstBreakId);
            ps.setObject(7, r.firstBreakSeq);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, conn);
        }
    }

    private void handleVerifyChain(HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String role = InputProcessor.getVerifiedRole(req);
        boolean admin = "ADMIN".equalsIgnoreCase(role);
        boolean dpo = "DPO".equalsIgnoreCase(role);
        if (!admin && !dpo) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Only ADMIN or DPO users may verify the audit chain.", req.getRequestURI());
            return;
        }
        UUID callerFid = null;
        if (dpo) {
            UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);
            callerFid = loginUserId != null ? getCallerFiduciaryId(loginUserId) : null;
            if (callerFid == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "No fiduciary is bound to this account.", req.getRequestURI());
                return;
            }
        }

        // The walk reads every audit row and is the same for everyone, so a recent verdict is reused instead of letting
        // repeated calls load the database for all tenants.
        PoolDB lastPool = new PoolDB();
        Connection lastConn = null;
        PreparedStatement lastPs = null;
        ResultSet lastRs = null;
        Long lastRunMillis = null;
        String lastVerdict = null;
        try {
            lastConn = lastPool.getConnection();
            lastPs = lastConn.prepareStatement("SELECT run_at, verdict FROM audit_chain_verifications ORDER BY run_at DESC LIMIT 1");
            lastRs = lastPs.executeQuery();
            if (lastRs.next()) { lastRunMillis = lastRs.getTimestamp(1).getTime(); lastVerdict = lastRs.getString(2); }
        } finally { lastPool.cleanup(lastRs, lastPs, lastConn); }
        if (AuditLimits.reuseVerdict(lastRunMillis, System.currentTimeMillis(), VERIFY_REUSE_MS)) {
            JSONObject cached = new JSONObject();
            cached.put("verdict", lastVerdict);
            cached.put("cached", true);
            cached.put("message", "Verified less than " + (VERIFY_REUSE_MS / 60000) + " minutes ago; showing that result."
                    + ("BROKEN".equals(lastVerdict) ? " Ask an administrator for the details of the break." : ""));
            cached.put("broken_entries", new JSONArray());
            OutputProcessor.send(res, 200, cached);
            return;
        }

        logEvents(); // include anything still buffered
        AuditChain.Result r = verifyChain();
        recordVerification(r, "MANUAL");

        JSONObject out = new JSONObject();
        out.put("verdict", r.intact() ? "INTACT" : "BROKEN");
        JSONArray broken = new JSONArray();
        long ownBroken = 0;
        for (AuditChain.Break b : r.breaks) {
            if (admin || callerFid.equals(b.fiduciaryId)) {
                JSONObject bj = new JSONObject();
                bj.put("id", b.id.toString());
                bj.put("seq", b.seq);
                bj.put("reason", b.reason);
                broken.add(bj);
                ownBroken++;
            }
        }
        if (admin) {
            // Whole-chain figures are system-wide; a tenant DPO only learns about their own rows.
            out.put("rows_checked", r.rowsChecked);
            out.put("rows_verified", r.rowsVerified);
            out.put("legacy_linkage_only", r.legacyLinkageOnly);
            out.put("first_break_id", r.firstBreakId == null ? null : r.firstBreakId.toString());
        } else {
            out.put("verdict", ownBroken == 0 ? "INTACT" : "BROKEN");
            out.put("chain_wide_verdict", r.intact() ? "INTACT" : "BROKEN");
        }
        out.put("broken_entries", broken);
        OutputProcessor.send(res, 200, out);
    }

    private void handleChainStatus(HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String role = InputProcessor.getVerifiedRole(req);
        if (!"ADMIN".equalsIgnoreCase(role) && !"DPO".equalsIgnoreCase(role)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Only ADMIN or DPO users may view the audit chain status.", req.getRequestURI());
            return;
        }
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        JSONObject out = new JSONObject();
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT run_at, trigger_source, verdict FROM audit_chain_verifications ORDER BY run_at DESC LIMIT 1");
            rs = ps.executeQuery();
            if (rs.next()) {
                out.put("verdict", rs.getString("verdict"));
                out.put("run_at", rs.getTimestamp("run_at").toInstant().toString());
                out.put("trigger_source", rs.getString("trigger_source"));
            } else {
                out.put("verdict", "NOT_RUN");
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
        OutputProcessor.send(res, 200, out);
    }

    // --- List and Detail Methods (Unchanged Logic, added hash retrieval) ---

    protected JSONArray listAuditLogsFromDb(String search, UUID fiduciaryId, String action, int page, int limit) throws SQLException {
        JSONArray logs = new JSONArray();
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_logs WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (action != null && !action.isEmpty()) { sql.append(" AND audit_action = ?"); params.add(action); }
        if (search != null && !search.isEmpty()) {
            sql.append(" AND (user_id ILIKE ? OR context_details ILIKE ?)");
            params.add("%" + search + "%"); params.add("%" + search + "%");
        }

        sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) pstmt.setObject(i + 1, params.get(i));

            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("id", rs.getObject("id").toString());
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("user_id", rs.getString("user_id"));
                log.put("service_type", rs.getString("service_type"));
                log.put("audit_action", rs.getString("audit_action"));
                log.put("context_details", rs.getString("context_details"));
                log.put("current_hash", rs.getString("current_log_hash")); // Exposed for auditor verification
                logs.add(log);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return logs;
    }

    private void handleGetLog(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String logIdStr = (String) input.get("id");
        if (logIdStr == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Log ID required.", req.getRequestURI());
            return;
        }

        Optional<JSONObject> logEntry = getAuditLogEntryFromDb(UUID.fromString(logIdStr));
        if (logEntry.isPresent()) {
            String logFidStr = (String) logEntry.get().get("fiduciary_id");
            if (logFidStr == null) {
                // A row with no fiduciary is platform-level: only ADMIN may read it.
                if (!InputProcessor.isAdminCaller(req)) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You may only access audit logs for your own fiduciary.", req.getRequestURI());
                    return;
                }
            } else if (rejectIfNotOwnFiduciary(UUID.fromString(logFidStr), req, res)) return;
            OutputProcessor.send(res, 200, logEntry.get());
        }
        else OutputProcessor.errorResponse(res, 404, "Not Found", "Audit log not found.", req.getRequestURI());
    }

    private Optional<JSONObject> getAuditLogEntryFromDb(UUID id) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM audit_logs WHERE id = ?");
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("id", rs.getObject("id").toString());
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("user_id", rs.getString("user_id"));
                log.put("fiduciary_id", rs.getString("fiduciary_id"));
                log.put("service_type", rs.getString("service_type"));
                log.put("audit_action", rs.getString("audit_action"));
                log.put("prev_hash", rs.getString("prev_log_hash"));
                log.put("current_hash", rs.getString("current_log_hash"));

                String details = rs.getString("context_details");
                try { log.put("context_details", new org.json.simple.parser.JSONParser().parse(details)); } 
                catch (Exception e) { log.put("context_details", details); }
                return Optional.of(log);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return Optional.empty();
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }

    /**
     * Blocks a non-ADMIN DPO/Operator from reading audit log entries for a fiduciary
     * other than their own. No-op for ADMIN or callers not authenticated as an
     * operator at all. Returns true (and sends a 403) if blocked; caller must
     * return immediately.
     */
    private boolean rejectIfNotOwnFiduciary(UUID targetFiduciaryId, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        String callerRole = InputProcessor.getVerifiedRole(req);
        if (callerRole == null || "ADMIN".equalsIgnoreCase(callerRole)) {
            return false;
        }
        UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);
        UUID callerFid = loginUserId != null ? getCallerFiduciaryId(loginUserId) : null;
        if (callerFid == null || !callerFid.equals(targetFiduciaryId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You may only access audit logs for your own fiduciary.", req.getRequestURI());
            return true;
        }
        return false;
    }

    /** Looks up the fiduciary_id an operator account is bound to (null for ADMIN accounts). */
    private UUID getCallerFiduciaryId(UUID operatorId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fiduciary_id FROM operators WHERE id = ?");
            pstmt.setObject(1, operatorId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                return (UUID) rs.getObject("fiduciary_id");
            }
            return null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }
}