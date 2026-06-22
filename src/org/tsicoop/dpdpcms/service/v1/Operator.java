package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.Constants;
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

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "SELECT o.id, o.name, " + DbEncryption.decryptCol("o.email_enc") + " AS email, o.password_hash, o.status, o.role, o.fiduciary_id, f.name AS fiduciary_name " +
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
                    final String token = JWTUtil.generateToken(principalEmail, identifier, role);
                    userUid = (UUID) rs.getObject("id");
                    fidUid = rs.getObject("fiduciary_id") != null ? (UUID) rs.getObject("fiduciary_id") : ADMIN_FID_UUID;

                    out = new JSONObject();
                    out.put("success", true);
                    out.put("token", token);
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

        if (success) {
            LoginRateLimiter.recordSuccess(clientIp);
            new Audit().logEventAsync(identifier, fidUid, serviceType, userUid, "LOGIN_SUCCESS", "Operator Access Granted");
            OutputProcessor.send(res, 200, out);
        }else{
            new Audit().logEventAsync(identifier, fidUid, serviceType, userUid, "LOGIN_FAILURE", "Invalid credentials or account inactive.");
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid credentials or account inactive.", req.getRequestURI());
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
                    (pass != null && !pass.isEmpty() ? ", password_hash = ?" : "") +
                    " WHERE id = ? AND role != 'ADMIN'";

            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            pstmt.setObject(2, fid.equals(ADMIN_FID_UUID) ? null : fid);
            int paramIdx = 3;
            if (pass != null && !pass.isEmpty()) {
                pstmt.setString(paramIdx++, passwordHasher.hashPassword(pass));
            }
            pstmt.setObject(paramIdx, uid);

            if (pstmt.executeUpdate() > 0) {
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

            pstmt = conn.prepareStatement("UPDATE operators SET status = 'INACTIVE', last_updated_at = NOW() WHERE id = ? AND role != 'ADMIN'");
            pstmt.setObject(1, uid);
            pstmt.executeUpdate();
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

    private void handleResetViaRecovery(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String email = (String) input.get("email");
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
                    try (PreparedStatement uPstmt = conn.prepareStatement("UPDATE operators SET password_hash = ?, recovery_key_hash = NULL, last_updated_at = NOW() WHERE id = ?")) {
                        uPstmt.setString(1, passwordHasher.hashPassword(newPassword));
                        uPstmt.setObject(2, userId);
                        uPstmt.executeUpdate();
                    }
                    conn.commit();
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    success = true;
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
        String email = (String) input.get("email");
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