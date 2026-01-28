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
import java.util.*;
import java.util.regex.Pattern;

/**
 * Operator class for managing CMS backend users and recovery keys.
 */
public class Operator implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{8,}$");
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            UUID userId = null;
            String userIdStr = (String) input.get("user_id");
            if (userIdStr != null && !userIdStr.isEmpty()) {
                try {
                    userId = UUID.fromString(userIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'user_id' format.", req.getRequestURI());
                    return;
                }
            }

            String role = (String) input.get("role");

            switch (func.toLowerCase()) {
                case "login":
                    handleLogin(input, res, req);
                    break;

                case "generate_recovery_key":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, 400, "Bad Request", "user_id is required.", req.getRequestURI());
                        return;
                    }
                    output = generateAndStoreRecoveryKey(userId);
                    OutputProcessor.send(res, 200, output);
                    break;

                case "reset_password":
                    handleResetPassword(input, res, req);
                    break;

                case "list_users":
                    String userStatusFilter = (String) input.get("status");
                    String userSearch = (String) input.get("search");
                    int userPage = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int userLimit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;
                    outputArray = listOperatorsFromDb(userStatusFilter, userSearch, userPage, userLimit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, 400, "Bad Request", "user_id required.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> userOptional = getUserByIdFromDb(userId);
                    if (userOptional.isPresent()) {
                        OutputProcessor.send(res, 200, userOptional.get());
                    } else {
                        OutputProcessor.errorResponse(res, 404, "Not Found", "User not found.", req.getRequestURI());
                    }
                    break;

                case "create_user":
                    handleCreateUser(input, res, req);
                    break;

                case "update_user":
                    handleUpdateUser(input, userId, res, req);
                    break;

                case "delete_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, 400, "Bad Request", "user_id required.", req.getRequestURI());
                        return;
                    }
                    deleteUserFromDb(userId);
                    OutputProcessor.send(res, 204, null);
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unsupported function: " + func, req.getRequestURI());
            }

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for setup operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    /**
     * Generates a new 5-word passphrase, hashes it, and stores it for the user.
     * Returns the plain text passphrase to the Admin once.
     */
    private JSONObject generateAndStoreRecoveryKey(UUID userId) throws SQLException {
        String plainPassphrase = PassphraseGenerator.generate();
        String hashedKey = passwordHasher.hashPassword(plainPassphrase);

        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE operators SET recovery_key_hash = ?, last_updated_at = NOW() WHERE id = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, hashedKey);
            pstmt.setObject(2, userId);

            if (pstmt.executeUpdate() == 0) {
                throw new SQLException("Failed to update recovery key. User not found.");
            }

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("passphrase", plainPassphrase);
            result.put("message", "Master Recovery Key generated and hashed in registry.");
            return result;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private void handleLogin(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String identifier = (String) input.get("identifier");
        String password = (String) input.get("password");

        if (identifier == null || password == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Identifier and password required.", req.getRequestURI());
            return;
        }

        JSONObject output = authenticateUser(identifier, password);
        if (output.containsKey("error")) {
            OutputProcessor.errorResponse(res, (Integer) output.get("status_code"), (String) output.get("error_message"), (String) output.get("error_details"), req.getRequestURI());
        } else {
            OutputProcessor.send(res, 200, output);
        }
    }

    private JSONObject authenticateUser(String identifier, String password) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        JSONObject result = new JSONObject();

        String sql = "SELECT u.id, u.name, u.email, u.password_hash, u.status, u.role, u.fiduciary_id, f.name " +
                "FROM operators u LEFT OUTER JOIN fiduciaries f ON u.fiduciary_id = f.id " +
                "WHERE (u.name = ? OR u.email = ?)";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, identifier);
            pstmt.setString(2, identifier);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String userId = rs.getString("id");
                String username = rs.getString("name");
                String email = rs.getString("email");
                String storedHash = rs.getString("password_hash");
                String status = rs.getString("status");
                String role = rs.getString("role");
                String fidId = rs.getString("fiduciary_id");
                String fidName = rs.getString("name");

                if (!"ACTIVE".equalsIgnoreCase(status)) {
                    result.put("error", true);
                    result.put("status_code", 403);
                    result.put("error_message", "Account is " + status);
                    return result;
                }

                if (passwordHasher.verifyPassword(password, storedHash)) {
                    updateLastLoginTime(UUID.fromString(userId));
                    String token = JWTUtil.generateToken(email, username, role);

                    result.put("success", true);
                    result.put("user_id", userId);
                    result.put("username", username);
                    result.put("role", role);
                    result.put("token", token);
                    result.put("fiduciary_id", fidId != null ? fidId : "");
                    result.put("fiduciary_name", fidName != null ? fidName : "");

                    new Audit().logEventAsync(identifier, UUID.fromString(fidId != null ? fidId : "00000000-0000-0000-0000-000000000000"), "USER", UUID.fromString(userId), "LOGIN_SUCCESS", "-");
                } else {
                    result.put("error", true);
                    result.put("status_code", 401);
                    result.put("error_message", "Invalid credentials.");
                }
            } else {
                result.put("error", true);
                result.put("status_code", 401);
                result.put("error_message", "User not found.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private void handleResetPassword(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String email = (String) input.get("email");
        String newPass = (String) input.get("new_password");
        if (email == null || newPass == null || !EMAIL_PATTERN.matcher(email).matches() || !PASSWORD_PATTERN.matcher(newPass).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid input for reset.", req.getRequestURI());
            return;
        }
        JSONObject output = resetUserPassword(email, newPass);
        OutputProcessor.send(res, 200, output);
    }

    private JSONObject resetUserPassword(String email, String newPass) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE operators SET password_hash = ?, status = 'ACTIVE', last_updated_at = NOW() WHERE email = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, passwordHasher.hashPassword(newPass));
            pstmt.setString(2, email);
            if (pstmt.executeUpdate() > 0) {
                return new JSONObject() {{ put("success", true); put("message", "Password reset successful."); }};
            }
        } finally { pool.cleanup(null, pstmt, conn); }
        return new JSONObject() {{ put("error", true); put("status_code", 404); }};
    }

    private void handleCreateUser(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String user = (String) input.get("username");
        String mail = (String) input.get("email");
        String pass = (String) input.get("password");
        String role = (String) input.get("role");
        String fidStr = (String) input.get("fiduciary_id");
        UUID fid = (fidStr != null && !fidStr.isEmpty()) ? UUID.fromString(fidStr) : null;

        if (isUsernameOrEmailPresent(user, mail, null)) {
            OutputProcessor.errorResponse(res, 409, "Conflict", "Identity exists.", req.getRequestURI());
            return;
        }
        JSONObject output = saveUserToDb(user, mail, passwordHasher.hashPassword(pass), role, "ACTIVE", fid);
        OutputProcessor.send(res, 201, output);
    }

    private void handleUpdateUser(JSONObject input, UUID userId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String user = (String) input.get("username");
        String pass = (String) input.get("password");
        String stat = (String) input.get("status");
        String role = (String) input.get("role");
        String hashed = (pass != null && !pass.isEmpty()) ? passwordHasher.hashPassword(pass) : null;

        JSONObject out = updateUserInDb(userId, user, null, hashed, role, stat);
        OutputProcessor.send(res, 200, out);
    }

    private void updateLastLoginTime(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE operators SET last_login_at = NOW() WHERE id = ?");
            pstmt.setObject(1, userId);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private boolean isUsernameOrEmailPresent(String username, String email, UUID excludeId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT COUNT(*) FROM operators WHERE (name = ? OR email = ?) " + (excludeId != null ? "AND id != ?" : "");
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
            pstmt.setString(2, email);
            if (excludeId != null) pstmt.setObject(3, excludeId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONArray listOperatorsFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray arr = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            StringBuilder sql = new StringBuilder("SELECT id, name, email, status, fiduciary_id, last_login_at, created_at, role FROM operators WHERE 1=1");
            if (statusFilter != null) sql.append(" AND status = '").append(statusFilter).append("'");
            if (search != null) sql.append(" AND (name LIKE '%").append(search).append("%' OR email LIKE '%").append(search).append("%')");
            sql.append(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

            pstmt = conn.prepareStatement(sql.toString());
            pstmt.setInt(1, limit);
            pstmt.setInt(2, (page - 1) * limit);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject u = new JSONObject();
                u.put("user_id", rs.getString("id"));
                u.put("username", rs.getString("name"));
                u.put("email", rs.getString("email"));
                u.put("status", rs.getString("status"));
                u.put("fiduciary_id", rs.getString("fiduciary_id"));
                u.put("role", rs.getString("role"));
                u.put("last_login_at", rs.getTimestamp("last_login_at") != null ? rs.getTimestamp("last_login_at").toString() : null);
                u.put("created_at", rs.getTimestamp("created_at").toString());
                arr.add(u);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    private Optional<JSONObject> getUserByIdFromDb(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM operators WHERE id = ?");
            pstmt.setObject(1, userId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject u = new JSONObject();
                u.put("user_id", rs.getString("id"));
                u.put("username", rs.getString("name"));
                u.put("email", rs.getString("email"));
                u.put("status", rs.getString("status"));
                u.put("fiduciary_id", rs.getString("fiduciary_id"));
                u.put("role_name", rs.getString("role"));
                return Optional.of(u);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return Optional.empty();
    }

    private JSONObject saveUserToDb(String user, String mail, String hash, String role, String status, UUID fid) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO operators (id, name, email, password_hash, role, status, fiduciary_id, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, NOW(), NOW()) RETURNING id";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, user); pstmt.setString(2, mail); pstmt.setString(3, hash);
            pstmt.setString(4, role); pstmt.setString(5, status); pstmt.setObject(6, fid);
            pstmt.executeUpdate();
            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                JSONObject o = new JSONObject();
                o.put("user_id", rs.getString(1));
                return o;
            }
        } finally { pool.cleanup(null, pstmt, conn); }
        throw new SQLException("Insert failed.");
    }

    private JSONObject updateUserInDb(UUID id, String user, String mail, String hash, String role, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        StringBuilder sql = new StringBuilder("UPDATE operators SET last_updated_at = NOW()");
        if (user != null) sql.append(", name = '").append(user).append("'");
        if (hash != null) sql.append(", password_hash = '").append(hash).append("'");
        if (role != null) sql.append(", role = '").append(role).append("'");
        if (status != null) sql.append(", status = '").append(status).append("'");
        sql.append(" WHERE id = ?");
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            pstmt.setObject(1, id);
            pstmt.executeUpdate();
            return new JSONObject() {{ put("success", true); }};
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void deleteUserFromDb(UUID id) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("DELETE FROM operators WHERE id = ?");
            pstmt.setObject(1, id);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }
}