package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.util.MfaPolicy;
import org.tsicoop.dpdpcms.util.Totp;
import org.tsicoop.dpdpcms.util.PassphraseGenerator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Operator class for managing CMS backend users and recovery keys.
 * Refactored to include loggedInUserId and standardized ADMIN audit logging after cleanup.
 */
public class Operator implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();
    private static final UUID ADMIN_FID_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{12,}$");
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing _func attribute.", req.getRequestURI());
                return;
            }

            // Get the ID of the Admin performing the action
            UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);

            switch (func.toLowerCase()) {
                case "login":
                    handleLogin(input, res, req);
                    break;
                case "logout":
                    handleLogout(req, res);
                    break;
                case "enrol_mfa":
                    handleEnrolMfa(req, res);
                    break;
                case "verify_mfa":
                    handleVerifyMfa(input, res, req);
                    break;
                case "generate_recovery_key":
                    handleGenerateRecoveryKey(input, loginUserId, res, req);
                    break;
                case "verify_recovery_key":
                    handleVerifyRecoveryKey(input, res, req);
                    break;
                case "reset_password_via_recovery":
                    handleResetViaRecovery(input, loginUserId, res, req);
                    break;
                case "list_users":
                    handleListUsers(input, loginUserId, res, req);
                    break;
                case "get_user":
                    handleGetUser(input, loginUserId, res, req);
                    break;
                case "create_user":
                    handleCreateUser(input, loginUserId, res, req);
                    break;
                case "update_user":
                    handleUpdateUser(input, loginUserId, res, req);
                    break;
                case "deactivate_user":
                    handleDeactivateUser(input, loginUserId, res, req);
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unsupported function: " + func, req.getRequestURI());
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Operator.service: " + e);
            OutputProcessor.errorResponse(res, 500, "Internal Error", "An internal error occurred.", req.getRequestURI());
        }
    }

    private void handleLogin(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String clientIp = LoginRateLimiter.getClientIp(req);
        if (!LoginRateLimiter.isAllowed(clientIp)) {
            OutputProcessor.errorResponse(res, 429, "Too Many Requests", "Too many login attempts. Please try again later.", req.getRequestURI());
            return;
        }

        String identifier = (String) input.get("identifier");
        String password = (String) input.get("password");

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        boolean success = false;
        String principalEmail = null;
        UUID userUid = null;
        UUID fidUid = null;
        String role = null;
        String operatorName = null;
        JSONObject out = null;
        String loginStage = "SESSION";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "SELECT o.id, o.name, " + DbEncryption.decryptCol("o.email_enc") + " AS email, o.password_hash, o.status, o.role, o.fiduciary_id, o.mfa_enabled, f.name AS fiduciary_name " +
                "FROM operators o LEFT JOIN fiduciaries f ON o.fiduciary_id = f.id " +
                "WHERE o.name = ? OR o.email_hmac = " + DbEncryption.HMAC);
            int loginIdx = DbEncryption.bindKey(pstmt, 1);    // param 1: decrypt key
            pstmt.setString(loginIdx++, identifier);           // param 2: name match
            DbEncryption.bindHmac(pstmt, loginIdx, identifier); // params 3,4: email_hmac match
            rs = pstmt.executeQuery();

            if (rs.next() && "ACTIVE".equals(rs.getString("status"))) {
                if (passwordHasher.verifyPassword(password, rs.getString("password_hash"))) {
                    principalEmail = rs.getString("email");
                    operatorName = rs.getString("name");
                    role = rs.getString("role");
                    userUid = (UUID) rs.getObject("id");
                    fidUid = rs.getObject("fiduciary_id") != null ? (UUID) rs.getObject("fiduciary_id") : ADMIN_FID_UUID;

                    out = new JSONObject();
                    out.put("success", true);
                    if (rs.getBoolean("mfa_enabled")) {
                        // Password is right; the session is only issued after verify_mfa.
                        loginStage = "MFA_CHALLENGE";
                        out.put("mfa_required", true);
                        out.put("mfa_token", JWTUtil.generateMfaChallengeToken(principalEmail));
                    } else if (MfaPolicy.requiredFor(role)) {
                        // MFA is mandatory here but not enrolled yet: enrol-only token, no working session.
                        loginStage = "MFA_ENROL";
                        out.put("mfa_enrol_required", true);
                        out.put("enrol_token", JWTUtil.generateMfaEnrolToken(principalEmail, identifier, role));
                    } else {
                        out.put("token", JWTUtil.generateToken(principalEmail, identifier, role, false));
                    }
                    out.put("role", role);
                    out.put("username", operatorName);
                    out.put("fiduciary_id", fidUid.toString());
                    String fidName = rs.getString("fiduciary_name");
                    if (fidName != null) out.put("fiduciary_name", fidName);
                    success = true;
                }
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        String serviceType = null;
        if(role != null && role.equalsIgnoreCase("DPO")){
            serviceType = Constants.SERVICE_TYPE_DPO_CONSOLE;
        }else{
            serviceType = Constants.SERVICE_TYPE_ADMIN_CONSOLE;
        }

        if (success && !"SESSION".equals(loginStage)) {
            // The password was right, so this is not a failed attempt: reset the counter (the MFA step has its own).
            LoginRateLimiter.recordSuccess(clientIp);
            // Password verified but no session yet (MFA step still to come). Not a "login success".
            try {
                new Audit().logEventSync(identifier, fidUid, serviceType, userUid, "LOGIN_PASSWORD_VERIFIED", loginStage);
            } catch (SQLException e) {
                System.err.println("[ERROR] Operator login refused: audit write failed: " + e.getMessage());
                OutputProcessor.errorResponse(res, 503, "Service Unavailable", "Login could not be recorded. Try again shortly.", req.getRequestURI());
                return;
            }
            OutputProcessor.send(res, 200, out);
        } else if (success) {
            LoginRateLimiter.recordSuccess(clientIp);
            try {
                // Security event: written before the session is issued, so a login can't happen unrecorded.
                new Audit().logEventSync(identifier, fidUid, serviceType, userUid, "LOGIN_SUCCESS", "Operator Access Granted");
            } catch (SQLException e) {
                System.err.println("[ERROR] Operator login refused: audit write failed: " + e.getMessage());
                OutputProcessor.errorResponse(res, 503, "Service Unavailable", "Login could not be recorded. Try again shortly.", req.getRequestURI());
                return;
            }
            InputProcessor.setConsoleSessionCookie(res, out.get("token").toString());
            OutputProcessor.send(res, 200, out);
        }else{
            // fidUid is only resolved after a successful password check, so it is null here
            // Queued, not written inline: this path is open to anyone, and a synchronous write would take the audit
            // lock for every guess. (A successful login is still written before the session is issued.)
            new Audit().logEventAsync(identifier, fidUid != null ? fidUid : ADMIN_FID_UUID, serviceType, userUid, "LOGIN_FAILURE", "Invalid credentials or account inactive.");
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid credentials or account inactive.", req.getRequestURI());
        }
    }

    // ------------------------------------------------------------------------------------------
    // TOTP MFA
    //   login      -> password ok: mfa_token (account has MFA) / enrol_token (MFA mandatory, not enrolled) / token
    //   enrol_mfa  -> new secret + otpauth URI. Session or enrol token. Refused once MFA is enabled.
    //   verify_mfa -> {mfa_token, code}: finishes login.  {code} + session/enrol token: confirms enrolment.
    // Each 30-second step is accepted once; 5 wrong codes lock MFA for 15 minutes.
    // ------------------------------------------------------------------------------------------
    private static final int MFA_MAX_FAILURES = 5;
    private static final long MFA_LOCK_MINUTES = 15;
    private static final String MFA_ISSUER = "TSI DPDP CMS";

    private static final class OpRow {
        UUID id, fid;
        String name, role, status, secret, fidName;
        boolean mfaEnabled;
        Long lastStep;
        Timestamp lockedUntil;
    }

    private OpRow loadOperatorByEmail(String email) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement(
                "SELECT o.id, o.name, o.role, o.status, o.fiduciary_id, o.mfa_enabled, o.mfa_last_step, o.mfa_locked_until, f.name AS fiduciary_name, " +
                "CASE WHEN o.mfa_secret_enc IS NULL THEN NULL ELSE " + DbEncryption.decryptCol("o.mfa_secret_enc") + " END AS mfa_secret " +
                "FROM operators o LEFT JOIN fiduciaries f ON o.fiduciary_id = f.id WHERE o.email_hmac = " + DbEncryption.HMAC);
            int i = DbEncryption.bindKey(ps, 1);
            DbEncryption.bindHmac(ps, i, email);
            rs = ps.executeQuery();
            if (!rs.next()) return null;
            OpRow o = new OpRow();
            o.id = (UUID) rs.getObject("id");
            o.name = rs.getString("name");
            o.role = rs.getString("role");
            o.status = rs.getString("status");
            o.fid = rs.getObject("fiduciary_id") != null ? (UUID) rs.getObject("fiduciary_id") : ADMIN_FID_UUID;
            o.fidName = rs.getString("fiduciary_name");
            o.mfaEnabled = rs.getBoolean("mfa_enabled");
            long step = rs.getLong("mfa_last_step");
            o.lastStep = rs.wasNull() ? null : step;
            o.lockedUntil = rs.getTimestamp("mfa_locked_until");
            o.secret = rs.getString("mfa_secret");
            return o;
        } finally {
            pool.cleanup(rs, ps, conn);
        }
    }

    private static String bearer(HttpServletRequest req) {
        String h = req.getHeader("Authorization");
        return (h != null && h.startsWith("Bearer ")) ? h.substring(7).trim() : null;
    }

    /** Email of the caller of an MFA function: a normal session token or an enrol-only token. */
    private String mfaCallerEmail(HttpServletRequest req) {
        String t = bearer(req);
        if (t == null) return null;
        try {
            if (JWTUtil.isTokenValid(t)) return JWTUtil.getEmailFromToken(t);
            io.jsonwebtoken.Claims c = JWTUtil.getMfaEnrolClaims(t);
            return c == null ? null : c.getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    private void handleEnrolMfa(HttpServletRequest req, HttpServletResponse res) throws SQLException {
        String email = mfaCallerEmail(req);
        OpRow op = email == null ? null : loadOperatorByEmail(email);
        if (op == null || !"ACTIVE".equals(op.status)) {
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Authentication required.", req.getRequestURI());
            return;
        }
        if (op.mfaEnabled) {
            OutputProcessor.errorResponse(res, 409, "Conflict", "MFA is already enabled for this account.", req.getRequestURI());
            return;
        }

        String secret = Totp.generateSecret();
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement ps = null;
        int updated;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("UPDATE operators SET mfa_secret_enc = " + DbEncryption.ENCRYPT + ", mfa_last_step = NULL, last_updated_at = NOW() WHERE id = ? AND mfa_enabled = FALSE");
            int i = DbEncryption.bindEncrypt(ps, 1, secret);
            ps.setObject(i, op.id);
            updated = ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, conn);
        }
        if (updated == 0) {
            OutputProcessor.errorResponse(res, 409, "Conflict", "MFA is already enabled for this account.", req.getRequestURI());
            return;
        }
        new Audit().logEventAsync(email, op.fid, Constants.SERVICE_TYPE_ADMIN_CONSOLE, op.id, "MFA_ENROLMENT_STARTED", "Secret issued; not active until a code is confirmed");

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("secret", secret);
        out.put("otpauth_uri", Totp.otpauthUri(MFA_ISSUER, email, secret));
        out.put("issuer", MFA_ISSUER);
        OutputProcessor.send(res, 200, out);
    }

    private void handleVerifyMfa(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String clientIp = LoginRateLimiter.getClientIp(req);
        if (!LoginRateLimiter.isAllowed("mfa:ip:" + clientIp, 20, 15 * 60 * 1000L)) {
            OutputProcessor.errorResponse(res, 429, "Too Many Requests", "Too many attempts. Please try again later.", req.getRequestURI());
            return;
        }

        String code = (String) input.get("code");
        String mfaToken = (String) input.get("mfa_token");
        boolean loginMode = mfaToken != null && !mfaToken.isEmpty();
        String email = loginMode ? JWTUtil.getMfaChallengeSubject(mfaToken) : mfaCallerEmail(req);
        OpRow op = email == null ? null : loadOperatorByEmail(email);
        if (op == null || !"ACTIVE".equals(op.status)) {
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Verification failed.", req.getRequestURI());
            return;
        }
        // login mode needs MFA already on; confirm mode needs a pending (not yet enabled) secret
        if (loginMode != op.mfaEnabled || op.secret == null) {
            OutputProcessor.errorResponse(res, 409, "Conflict", loginMode ? "MFA is not enabled for this account." : "Start enrolment with enrol_mfa first, or MFA is already enabled.", req.getRequestURI());
            return;
        }
        if (op.lockedUntil != null && op.lockedUntil.after(new Timestamp(System.currentTimeMillis()))) {
            OutputProcessor.errorResponse(res, 429, "Too Many Requests", "Too many wrong codes. MFA is locked for a few minutes.", req.getRequestURI());
            return;
        }

        long step = Totp.verify(op.secret, code, System.currentTimeMillis(), op.lastStep == null ? 0 : op.lastStep);
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            if (step < 0) {
                ps = conn.prepareStatement(
                    "UPDATE operators SET mfa_failed_attempts = CASE WHEN mfa_failed_attempts + 1 >= ? THEN 0 ELSE mfa_failed_attempts + 1 END, " +
                    "mfa_locked_until = CASE WHEN mfa_failed_attempts + 1 >= ? THEN ? ELSE mfa_locked_until END WHERE id = ? RETURNING mfa_locked_until");
                ps.setInt(1, MFA_MAX_FAILURES);
                ps.setInt(2, MFA_MAX_FAILURES);
                ps.setTimestamp(3, new Timestamp(System.currentTimeMillis() + MFA_LOCK_MINUTES * 60_000L));
                ps.setObject(4, op.id);
                rs = ps.executeQuery();
                boolean locked = rs.next() && rs.getTimestamp(1) != null && rs.getTimestamp(1).after(new Timestamp(System.currentTimeMillis()));
                auditSecurity(email, op, locked ? "MFA_LOCKED" : "MFA_FAILED", loginMode ? "login" : "enrolment");
                OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid or already used code.", req.getRequestURI());
                return;
            }

            // Correct code. Accept the step only if it is still newer than the last one used.
            String sql = "UPDATE operators SET mfa_last_step = ?, mfa_failed_attempts = 0, mfa_locked_until = NULL" +
                    (loginMode ? "" : ", mfa_enabled = TRUE, tokens_valid_after = ?") +
                    ", last_updated_at = NOW() WHERE id = ? AND (mfa_last_step IS NULL OR mfa_last_step < ?)";
            ps = conn.prepareStatement(sql);
            int i = 1;
            ps.setLong(i++, step);
            if (!loginMode) ps.setTimestamp(i++, new Timestamp(System.currentTimeMillis())); // first enrolment: older tokens stop working
            ps.setObject(i++, op.id);
            ps.setLong(i, step);
            if (ps.executeUpdate() == 0) {
                auditSecurity(email, op, "MFA_FAILED", "replayed code");
                OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid or already used code.", req.getRequestURI());
                return;
            }
        } finally {
            pool.cleanup(rs, ps, conn);
        }
        if (!loginMode) OperatorSessions.forget(email);

        String serviceType = "DPO".equalsIgnoreCase(op.role) ? Constants.SERVICE_TYPE_DPO_CONSOLE : Constants.SERVICE_TYPE_ADMIN_CONSOLE;
        try {
            if (!loginMode) new Audit().logEventSync(email, op.fid, serviceType, op.id, "MFA_ENABLED", "TOTP enrolment confirmed");
            new Audit().logEventSync(email, op.fid, serviceType, op.id, "LOGIN_SUCCESS", "Operator Access Granted (MFA)");
        } catch (SQLException e) {
            System.err.println("[ERROR] MFA login refused: audit write failed: " + e.getMessage());
            OutputProcessor.errorResponse(res, 503, "Service Unavailable", "Login could not be recorded. Try again shortly.", req.getRequestURI());
            return;
        }
        LoginRateLimiter.recordSuccess("mfa:ip:" + clientIp);

        String token = JWTUtil.generateToken(email, op.name, op.role, true);
        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("token", token);
        out.put("role", op.role);
        out.put("username", op.name);
        out.put("fiduciary_id", op.fid.toString());
        if (op.fidName != null) out.put("fiduciary_name", op.fidName);
        InputProcessor.setConsoleSessionCookie(res, token);
        OutputProcessor.send(res, 200, out);
    }

    private void auditSecurity(String email, OpRow op, String action, String detail) {
        String serviceType = "DPO".equalsIgnoreCase(op.role) ? Constants.SERVICE_TYPE_DPO_CONSOLE : Constants.SERVICE_TYPE_ADMIN_CONSOLE;
        try {
            new Audit().logEventSync(email, op.fid, serviceType, op.id, action, detail);
        } catch (SQLException e) {
            System.err.println("[ERROR] " + action + " audit write failed (event stays queued): " + e.getMessage());
        }
    }

    private void handleLogout(HttpServletRequest req, HttpServletResponse res) {
        try {
            String authorization = req.getHeader("Authorization");
            if (authorization != null && authorization.startsWith("Bearer ")) {
                String token = authorization.substring(7);
                String jti = JWTUtil.getJtiFromToken(token);
                java.util.Date expiry = JWTUtil.getExpiryFromToken(token);
                if (jti != null && expiry != null) {
                    TokenBlocklist.revoke(jti, expiry.getTime());
                }
            }
            InputProcessor.clearConsoleSessionCookie(res);
            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("message", "Logged out successfully.");
            OutputProcessor.send(res, 200, out);
        } catch (Exception e) {
            System.err.println("[ERROR] Operator.handleLogout: " + e);
            OutputProcessor.errorResponse(res, 500, "Internal Error", "Logout failed.", req.getRequestURI());
        }
    }

    private void handleCreateUser(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String user = (String) input.get("username");
        String mail = (String) input.get("email");
        String pass = (String) input.get("password");
        String role = (String) input.get("role");
        String callerRole = InputProcessor.getVerifiedRole(req);
        if (!org.tsicoop.dpdpcms.util.RolePermissions.isKnownRole(role)) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown role. Use ADMIN, DPO, OPERATOR or AUDITOR.", req.getRequestURI());
            return;
        }
        role = role.trim().toUpperCase();
        if ("AUDITOR".equals(role) && !AccessControl.enforcing()) {
            // The read-only guarantee comes from the central access check; until it is enforced a
            // service that only blocks OPERATOR would treat an AUDITOR like a DPO.
            OutputProcessor.errorResponse(res, 400, "Bad Request", "AUDITOR accounts can only be created when " + AccessControl.MODE_VAR + "=enforce.", req.getRequestURI());
            return;
        }
        if ("ADMIN".equalsIgnoreCase(role) && !"ADMIN".equalsIgnoreCase(callerRole)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "Only ADMIN users may assign the ADMIN role.", req.getRequestURI());
            return;
        }
        String fidStr = (String) input.get("fiduciary_id");
        UUID fid = (fidStr != null && !fidStr.isEmpty()) ? UUID.fromString(fidStr) : ADMIN_FID_UUID;

        if ("DPO".equalsIgnoreCase(callerRole)) {
            // DPOs can only delegate to Operators within their own fiduciary -- never mint
            // another DPO/ADMIN, and never bind the new account to a different fiduciary
            // than their own (regardless of what the request body claims).
            if (!"OPERATOR".equalsIgnoreCase(role)) {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "DPO users may only create OPERATOR accounts.", req.getRequestURI());
                return;
            }
            UUID callerFid = getOperatorFiduciaryId(loginUserId);
            if (callerFid == null) {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "Caller is not bound to a fiduciary.", req.getRequestURI());
                return;
            }
            fid = callerFid;
        }

        if (mail == null || !EMAIL_PATTERN.matcher(mail).matches() || pass == null || !PASSWORD_PATTERN.matcher(pass).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid email or weak password.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        boolean success = false;
        UUID newId = null;

        try {
            String sql = "INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) " +
                    "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", ?, ?, 'ACTIVE', ?, NOW(), NOW()) RETURNING id";

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            int ci = 1;
            pstmt.setString(ci++, user);
            pstmt.setString(ci++, mail);                              // email_plaintext
            ci = DbEncryption.bindEncrypt(pstmt, ci, mail);          // email_enc
            ci = DbEncryption.bindHmac(pstmt, ci, mail);             // email_hmac
            pstmt.setString(ci++, passwordHasher.hashPassword(pass));
            pstmt.setString(ci++, role);
            pstmt.setObject(ci++, fid.equals(ADMIN_FID_UUID) ? null : fid);

            rs = pstmt.executeQuery();
            if (rs.next()) {
                newId = (UUID) rs.getObject(1);
                OutputProcessor.send(res, 201, new JSONObject() {{ put("success", true); }});
                success = true;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(mail, fid, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "USER_CREATED", "Role assigned: " + role);
        }
    }

    private void handleUpdateUser(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        String callerRole = InputProcessor.getVerifiedRole(req);
        boolean isSelf = uid.equals(loginUserId);

        if (!"ADMIN".equalsIgnoreCase(callerRole) && !isSelf) {
            // Only a DPO managing an Operator within their own fiduciary may update someone else.
            if (!"DPO".equalsIgnoreCase(callerRole)) {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "You may only update your own profile.", req.getRequestURI());
                return;
            }
            UUID callerFid = getOperatorFiduciaryId(loginUserId);
            UUID targetFid = getOperatorFiduciaryId(uid);
            String targetRole = getOperatorRole(uid);
            if (callerFid == null || !callerFid.equals(targetFid) || !"OPERATOR".equalsIgnoreCase(targetRole)) {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "DPO users may only update Operators within their own fiduciary.", req.getRequestURI());
                return;
            }
        }

        String user = (String) input.get("username");
        String pass = (String) input.get("password");
        // Non-ADMIN callers cannot move an account between fiduciaries (even their own); only
        // ADMIN may set fiduciary_id from the request body.
        UUID fid;
        if ("ADMIN".equalsIgnoreCase(callerRole)) {
            String fidStr = (String) input.get("fiduciary_id");
            fid = (fidStr != null && !fidStr.isEmpty()) ? UUID.fromString(fidStr) : ADMIN_FID_UUID;
        } else {
            UUID existingFid = getOperatorFiduciaryId(uid);
            fid = existingFid != null ? existingFid : ADMIN_FID_UUID;
        }

        if (pass != null && !pass.isEmpty() && !PASSWORD_PATTERN.matcher(pass).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Weak password.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        boolean success = false;
        String targetEmail = null;

        try {
            conn = pool.getConnection();
            // Fetch target email for audit principal
            try (PreparedStatement p = conn.prepareStatement(
                    "SELECT " + DbEncryption.decryptCol("email_enc") + " AS email FROM operators WHERE id = ?")) {
                int pi = DbEncryption.bindKey(p, 1);
                p.setObject(pi, uid);
                try (ResultSet rs = p.executeQuery()) {
                    if (rs.next()) targetEmail = rs.getString("email");
                }
            }

            String sql = "UPDATE operators SET name = ?, fiduciary_id = ?, last_updated_at = NOW() " +
                    (pass != null && !pass.isEmpty() ? ", password_hash = ?, tokens_valid_after = ?" : "") +
                    " WHERE id = ? AND role != 'ADMIN'";

            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            pstmt.setObject(2, fid.equals(ADMIN_FID_UUID) ? null : fid);
            int paramIdx = 3;
            boolean passwordChanged = pass != null && !pass.isEmpty();
            if (passwordChanged) {
                pstmt.setString(paramIdx++, passwordHasher.hashPassword(pass));
                pstmt.setTimestamp(paramIdx++, new Timestamp(System.currentTimeMillis())); // password change signs the user out everywhere
            }
            pstmt.setObject(paramIdx, uid);

            if (pstmt.executeUpdate() > 0) {
                if (passwordChanged) OperatorSessions.forget(targetEmail);
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                success = true;
            } else {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "Action restricted for system accounts.", req.getRequestURI());
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(targetEmail, fid, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "USER_UPDATED", "Profile modified");
        }
    }

    private void handleDeactivateUser(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        String callerRole = InputProcessor.getVerifiedRole(req);

        if (!"ADMIN".equalsIgnoreCase(callerRole)) {
            // Non-ADMIN (DPO) callers may only deactivate an Operator within their own fiduciary.
            UUID callerFid = getOperatorFiduciaryId(loginUserId);
            UUID targetFid = getOperatorFiduciaryId(uid);
            String targetRole = getOperatorRole(uid);
            if (callerFid == null || !callerFid.equals(targetFid) || !"OPERATOR".equalsIgnoreCase(targetRole)) {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "You may only deactivate Operators within your own fiduciary.", req.getRequestURI());
                return;
            }
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        boolean success = false;
        String targetEmail = null;

        try {
            conn = pool.getConnection();
            // Fetch email for audit
            try (PreparedStatement p = conn.prepareStatement(
                    "SELECT " + DbEncryption.decryptCol("email_enc") + " AS email FROM operators WHERE id = ?")) {
                int pi = DbEncryption.bindKey(p, 1);
                p.setObject(pi, uid);
                try (ResultSet rs = p.executeQuery()) {
                    if (rs.next()) targetEmail = rs.getString("email");
                }
            }

            pstmt = conn.prepareStatement("UPDATE operators SET status = 'INACTIVE', tokens_valid_after = ?, last_updated_at = NOW() WHERE id = ? AND role != 'ADMIN'");
            pstmt.setTimestamp(1, new Timestamp(System.currentTimeMillis())); // deactivation ends live sessions
            pstmt.setObject(2, uid);
            pstmt.executeUpdate();
            OperatorSessions.forget(targetEmail);
            success = true;
        } catch(Exception e) {
            System.err.println("[ERROR] Operator.deactivateUser: " + e);
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(targetEmail, ADMIN_FID_UUID, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "USER_DEACTIVATED", "Account disabled");
        }
    }

    /**
     * Recovery-key paths are guessable by an online attacker, so each attempt is limited per IP and per
     * account (5 per 15 minutes each) and audited. The account key is an HMAC of the normalised e-mail,
     * so the raw address is never held in the limiter. Returns false (after sending 429) when blocked.
     */
    private boolean recoveryAttemptAllowed(String clientIp, String email, String func, HttpServletRequest req, HttpServletResponse res) {
        String acct = "unknown";
        try {
            acct = new LookupHasher().hashData(email == null ? "" : email.trim().toLowerCase());
        } catch (Exception ignored) { }
        boolean ipOk = LoginRateLimiter.isAllowed("recovery:ip:" + clientIp);
        boolean acctOk = LoginRateLimiter.isAllowed("recovery:email:" + acct);
        new Audit().logEventAsync(acct, ADMIN_FID_UUID, Constants.SERVICE_TYPE_ADMIN_CONSOLE, null,
                ipOk && acctOk ? "RECOVERY_ATTEMPT" : "RECOVERY_RATE_LIMITED", func + " ip=" + clientIp);
        if (!ipOk || !acctOk) {
            OutputProcessor.errorResponse(res, 429, "Too Many Requests", "Too many recovery attempts. Please try again later.", req.getRequestURI());
            return false;
        }
        return true;
    }

    private void handleResetViaRecovery(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String clientIp = LoginRateLimiter.getClientIp(req);
        String email = (String) input.get("email");
        if (!recoveryAttemptAllowed(clientIp, email, "reset_password_via_recovery", req, res)) return;

        String passphrase = (String) input.get("passphrase");
        String newPassword = (String) input.get("new_password");

        if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Password complexity failed.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        boolean success = false;
        UUID userId = null;
        UUID fidId = null;

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement("SELECT id, recovery_key_hash, fiduciary_id FROM operators WHERE email_hmac = " + DbEncryption.HMAC + " AND status = 'ACTIVE' FOR UPDATE");
            DbEncryption.bindHmac(pstmt, 1, email);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("recovery_key_hash");
                userId = (UUID) rs.getObject("id");
                fidId = rs.getObject("fiduciary_id") != null ? (UUID) rs.getObject("fiduciary_id") : ADMIN_FID_UUID;

                if (storedHash != null && passwordHasher.verifyPassword(passphrase, storedHash)) {
                    try (PreparedStatement uPstmt = conn.prepareStatement("UPDATE operators SET password_hash = ?, recovery_key_hash = NULL, tokens_valid_after = ?, last_updated_at = NOW() WHERE id = ?")) {
                        uPstmt.setString(1, passwordHasher.hashPassword(newPassword));
                        uPstmt.setTimestamp(2, new Timestamp(System.currentTimeMillis())); // password reset signs the user out everywhere
                        uPstmt.setObject(3, userId);
                        uPstmt.executeUpdate();
                    }
                    conn.commit();
                    OperatorSessions.forget(email);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    success = true;
                    LoginRateLimiter.recordSuccess("recovery:ip:" + clientIp);
                }
            }
            if (!success) {
                conn.rollback();
                OutputProcessor.errorResponse(res, 401, "Unauthorized", "Reset failed.", req.getRequestURI());
            }
        } catch (Exception e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(email, fidId, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId != null ? loginUserId : userId, "PASSWORD_RECOVERY_SUCCESS", "Self-service recovery");
        }
    }

    private void handleGenerateRecoveryKey(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        String callerRole = InputProcessor.getVerifiedRole(req);

        if (!"ADMIN".equalsIgnoreCase(callerRole) && !uid.equals(loginUserId)) {
            // Non-ADMIN callers may only rotate the recovery key of an Operator within their own fiduciary.
            UUID callerFid = getOperatorFiduciaryId(loginUserId);
            UUID targetFid = getOperatorFiduciaryId(uid);
            String targetRole = getOperatorRole(uid);
            if (callerFid == null || !callerFid.equals(targetFid) || !"OPERATOR".equalsIgnoreCase(targetRole)) {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "Cannot rotate the recovery key for a user outside your fiduciary.", req.getRequestURI());
                return;
            }
        }

        String plainKey = PassphraseGenerator.generate();

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        boolean success = false;
        String targetEmail = null;

        try {
            conn = pool.getConnection();
            try (PreparedStatement p = conn.prepareStatement(
                    "SELECT " + DbEncryption.decryptCol("email_enc") + " AS email FROM operators WHERE id = ?")) {
                int pi = DbEncryption.bindKey(p, 1);
                p.setObject(pi, uid);
                try (ResultSet rs = p.executeQuery()) {
                    if (rs.next()) targetEmail = rs.getString("email");
                }
            }

            pstmt = conn.prepareStatement("UPDATE operators SET recovery_key_hash = ?, last_updated_at = NOW() WHERE id = ?");
            pstmt.setString(1, passwordHasher.hashPassword(plainKey));
            pstmt.setObject(2, uid);

            if (pstmt.executeUpdate() > 0) {
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); put("passphrase", plainKey); }});
                success = true;
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(targetEmail, ADMIN_FID_UUID, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "RECOVERY_KEY_ROTATED", "New Master Key generated");
        }
    }

    private void handleVerifyRecoveryKey(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String clientIp = LoginRateLimiter.getClientIp(req);
        String email = (String) input.get("email");
        if (!recoveryAttemptAllowed(clientIp, email, "verify_recovery_key", req, res)) return;

        String passphrase = (String) input.get("passphrase");

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT recovery_key_hash FROM operators WHERE email_hmac = " + DbEncryption.HMAC + " AND status = 'ACTIVE'");
            DbEncryption.bindHmac(pstmt, 1, email);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("recovery_key_hash");
                if (storedHash != null && passwordHasher.verifyPassword(passphrase, storedHash)) {
                    LoginRateLimiter.recordSuccess("recovery:ip:" + clientIp);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    return;
                }
            }
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid verification key.", req.getRequestURI());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleListUsers(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        JSONArray arr = new JSONArray();
        String callerRole = InputProcessor.getVerifiedRole(req);
        // Non-ADMIN callers (DPO/OPERATOR) only see operators within their own fiduciary.
        boolean scopeToCaller = !"ADMIN".equalsIgnoreCase(callerRole);

        try {
            String sql = "SELECT u.id, u.name, " + DbEncryption.decryptCol("u.email_enc") + " AS email, u.status, u.role, u.fiduciary_id, f.name as fiduciary_name " +
                    "FROM operators u LEFT JOIN fiduciaries f ON u.fiduciary_id = f.id " +
                    (scopeToCaller ? "WHERE u.fiduciary_id = (SELECT fiduciary_id FROM operators WHERE id = ?) " : "") +
                    "ORDER BY u.created_at DESC";

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            int ki = DbEncryption.bindKey(pstmt, 1);
            if (scopeToCaller) {
                pstmt.setObject(ki, loginUserId);
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject u = new JSONObject();
                u.put("user_id", rs.getString("id"));
                u.put("username", rs.getString("name"));
                u.put("email", rs.getString("email"));
                u.put("status", rs.getString("status"));
                u.put("role", rs.getString("role"));
                u.put("fiduciary_id", rs.getString("fiduciary_id"));
                u.put("fiduciary_name", rs.getString("fiduciary_name"));
                arr.add(u);
            }
            OutputProcessor.send(res, 200, arr);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleGetUser(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        String callerRole = InputProcessor.getVerifiedRole(req);
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT id, name, " + DbEncryption.decryptCol("email_enc") + " AS email, fiduciary_id, role FROM operators WHERE id = ?");
            int gi = DbEncryption.bindKey(pstmt, 1);
            pstmt.setObject(gi, uid);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                UUID targetFid = (UUID) rs.getObject("fiduciary_id");
                // Non-ADMIN callers (DPO/OPERATOR) may only view operators within their own fiduciary.
                if (!"ADMIN".equalsIgnoreCase(callerRole)) {
                    UUID callerFid = getOperatorFiduciaryId(loginUserId);
                    if (callerFid == null || !callerFid.equals(targetFid)) {
                        OutputProcessor.errorResponse(res, 403, "Forbidden", "Cannot view a user outside your fiduciary.", req.getRequestURI());
                        return;
                    }
                }
                JSONObject u = new JSONObject();
                u.put("user_id", rs.getString("id"));
                u.put("username", rs.getString("name"));
                u.put("email", rs.getString("email"));
                u.put("fiduciary_id", rs.getString("fiduciary_id"));
                u.put("role_name", rs.getString("role"));
                OutputProcessor.send(res, 200, u);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /** Looks up the role string of an operator account. */
    private String getOperatorRole(UUID operatorId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT role FROM operators WHERE id = ?");
            pstmt.setObject(1, operatorId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getString("role");
            }
            return null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /** Looks up the fiduciary_id an operator account is bound to (null for global/ADMIN accounts). */
    private UUID getOperatorFiduciaryId(UUID operatorId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
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

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}