package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
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
 * Refactored to include 'fiduciary_id' in successful login response.
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

            switch (func.toLowerCase()) {
                case "login":
                    handleLogin(input, res, req);
                    break;
                case "generate_recovery_key":
                    handleGenerateRecoveryKey(input, res, req);
                    break;
                case "verify_recovery_key":
                    handleVerifyRecoveryKey(input, res, req);
                    break;
                case "reset_password_via_recovery":
                    handleResetViaRecovery(input, res, req);
                    break;
                case "list_users":
                    handleListUsers(input, res, req);
                    break;
                case "get_user":
                    handleGetUser(input, res, req);
                    break;
                case "create_user":
                    handleCreateUser(input, res, req);
                    break;
                case "update_user":
                    handleUpdateUser(input, res, req);
                    break;
                case "deactivate_user":
                    handleDeactivateUser(input, res, req);
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unsupported function: " + func, req.getRequestURI());
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Authenticates operator and returns session token, role, username, and fiduciary_id.
     */
    private void handleLogin(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String identifier = (String) input.get("identifier");
        String password = (String) input.get("password");

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT id, name, email, password_hash, status, role, fiduciary_id FROM operators WHERE name = ? OR email = ?");
            pstmt.setString(1, identifier);
            pstmt.setString(2, identifier);
            rs = pstmt.executeQuery();

            if (rs.next() && "ACTIVE".equals(rs.getString("status"))) {
                if (passwordHasher.verifyPassword(password, rs.getString("password_hash"))) {
                    final String operatorName = rs.getString("name");
                    final String role = rs.getString("role");
                    final String token = JWTUtil.generateToken(rs.getString("email"), identifier, role);
                    final UUID userUid = (UUID) rs.getObject("id");

                    // Retrieve Fiduciary ID (defaults to system admin if null)
                    final Object fidObj = rs.getObject("fiduciary_id");
                    final String fidIdStr = fidObj != null ? fidObj.toString() : ADMIN_FID_UUID.toString();
                    final UUID fidUid = fidObj != null ? (UUID) fidObj : ADMIN_FID_UUID;

                    JSONObject out = new JSONObject();
                    out.put("success", true);
                    out.put("token", token);
                    out.put("role", role);
                    out.put("username", operatorName);
                    out.put("fiduciary_id", fidIdStr); // Added as requested
                    OutputProcessor.send(res, 200, out);

                    // Log Audit Event
                    new Audit().logEventAsync(identifier, fidUid, "DPO", userUid, "LOGIN_SUCCESS", "Role: " + role);
                    return;
                }
            }
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid credentials or account inactive.", req.getRequestURI());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleListUsers(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        JSONArray arr = new JSONArray();

        try {
            String sql = "SELECT u.id, u.name, u.email, u.status, u.role, u.fiduciary_id, f.name as fiduciary_name " +
                    "FROM operators u LEFT JOIN fiduciaries f ON u.fiduciary_id = f.id " +
                    "ORDER BY u.created_at DESC";

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
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

    private void handleCreateUser(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String user = (String) input.get("username");
        String mail = (String) input.get("email");
        String pass = (String) input.get("password");
        String role = (String) input.get("role");
        String fidStr = (String) input.get("fiduciary_id");
        UUID fid = (fidStr != null && !fidStr.isEmpty()) ? UUID.fromString(fidStr) : ADMIN_FID_UUID;

        if (mail == null || !EMAIL_PATTERN.matcher(mail).matches() || pass == null || !PASSWORD_PATTERN.matcher(pass).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid email or weak password.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            String sql = "INSERT INTO operators (id, name, email, password_hash, role, status, fiduciary_id, created_at, last_updated_at) " +
                    "VALUES (uuid_generate_v4(), ?, ?, ?, ?, 'ACTIVE', ?, NOW(), NOW()) RETURNING id";

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            pstmt.setString(2, mail);
            pstmt.setString(3, passwordHasher.hashPassword(pass));
            pstmt.setString(4, role);
            pstmt.setObject(5, fid.equals(ADMIN_FID_UUID) ? null : fid);

            rs = pstmt.executeQuery();
            if (rs.next()) {
                UUID newId = (UUID) rs.getObject(1);
                new Audit().logEventAsync(mail, fid, "DPO", newId, "USER_CREATED", "Assigned Role: " + role);
                OutputProcessor.send(res, 201, new JSONObject() {{ put("success", true); }});
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleUpdateUser(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        String user = (String) input.get("username");
        String pass = (String) input.get("password");
        String fidStr = (String) input.get("fiduciary_id");
        UUID fid = (fidStr != null && !fidStr.isEmpty()) ? UUID.fromString(fidStr) : ADMIN_FID_UUID;

        if (pass != null && !pass.isEmpty() && !PASSWORD_PATTERN.matcher(pass).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Weak password.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;

        try {
            String sql = "UPDATE operators SET name = ?, fiduciary_id = ?, last_updated_at = NOW() " +
                    (pass != null && !pass.isEmpty() ? ", password_hash = ?" : "") +
                    " WHERE id = ? AND role != 'ADMIN'";

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            pstmt.setObject(2, fid.equals(ADMIN_FID_UUID) ? null : fid);
            int paramIdx = 3;
            if (pass != null && !pass.isEmpty()) {
                pstmt.setString(paramIdx++, passwordHasher.hashPassword(pass));
            }
            pstmt.setObject(paramIdx, uid);

            if (pstmt.executeUpdate() > 0) {
                new Audit().logEventAsync("SYSTEM", fid, "DPO", uid, "USER_UPDATED", "Metadata/Auth modified");
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
            } else {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "Modifying system accounts is restricted.", req.getRequestURI());
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private void handleDeactivateUser(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE operators SET status = 'INACTIVE', last_updated_at = NOW() WHERE id = ? AND role != 'ADMIN'");
            pstmt.setObject(1, uid);

            if (pstmt.executeUpdate() > 0) {
                new Audit().logEventAsync("SYSTEM", ADMIN_FID_UUID, "DPO", uid, "USER_DEACTIVATED", "Status set to INACTIVE");
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
            } else {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "Cannot deactivate system administrator.", req.getRequestURI());
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
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
            pstmt = conn.prepareStatement("SELECT recovery_key_hash FROM operators WHERE email = ? AND status = 'ACTIVE'");
            pstmt.setString(1, email);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("recovery_key_hash");
                if (storedHash != null && passwordHasher.verifyPassword(passphrase, storedHash)) {
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    return;
                }
            }
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid key.", req.getRequestURI());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleResetViaRecovery(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String email = (String) input.get("email");
        String passphrase = (String) input.get("passphrase");
        String newPassword = (String) input.get("new_password");

        if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Weak password.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement("SELECT id, recovery_key_hash, fiduciary_id FROM operators WHERE email = ? AND status = 'ACTIVE' FOR UPDATE");
            pstmt.setString(1, email);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("recovery_key_hash");
                UUID userId = (UUID) rs.getObject("id");
                UUID fidId = rs.getObject("fiduciary_id") != null ? (UUID) rs.getObject("fiduciary_id") : ADMIN_FID_UUID;

                if (storedHash != null && passwordHasher.verifyPassword(passphrase, storedHash)) {
                    // Update and clear key
                    try (PreparedStatement uPstmt = conn.prepareStatement("UPDATE operators SET password_hash = ?, recovery_key_hash = NULL, last_updated_at = NOW() WHERE id = ?")) {
                        uPstmt.setString(1, passwordHasher.hashPassword(newPassword));
                        uPstmt.setObject(2, userId);
                        uPstmt.executeUpdate();
                    }
                    conn.commit();
                    new Audit().logEventAsync(email, fidId, "DPO", userId, "PASSWORD_RECOVERY_SUCCESS", "Reset via Master Key");
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    return;
                }
            }
            conn.rollback();
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Reset transaction failed.", req.getRequestURI());
        } catch (Exception e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleGenerateRecoveryKey(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID userId = UUID.fromString((String) input.get("user_id"));
        String plainKey = PassphraseGenerator.generate();

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE operators SET recovery_key_hash = ?, last_updated_at = NOW() WHERE id = ?");
            pstmt.setString(1, passwordHasher.hashPassword(plainKey));
            pstmt.setObject(2, userId);

            if (pstmt.executeUpdate() > 0) {
                new Audit().logEventAsync("SYSTEM", ADMIN_FID_UUID, "DPO", userId, "RECOVERY_KEY_ROTATED", "Key generated by Administrator");
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); put("passphrase", plainKey); }});
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private void handleGetUser(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT id, name, email, fiduciary_id, role FROM operators WHERE id = ?");
            pstmt.setObject(1, uid);
            rs = pstmt.executeQuery();

            if (rs.next()) {
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

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}