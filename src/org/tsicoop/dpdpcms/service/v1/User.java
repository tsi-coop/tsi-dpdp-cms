package org.tsicoop.dpdpcms.service.v1; // Package changed as requested

import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.*; // Assuming these framework classes are available in the new package structure
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement; // Added for Statement.RETURN_GENERATED_KEYS
import java.util.*;
import java.util.regex.Pattern;

/**
 * UserService class for managing CMS backend users and roles.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the User and Role Management modules
 * of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS (based on provided template):
 * - Users table is named 'users' (not 'backend_users').
 * - 'users' table has a 'user_id' (UUID PK), 'username', 'email', 'password_hash', 'status', 'last_login_at', 'created_at', 'updated_at', and a 'role_id' (FK to roles.role_id).
 * - Roles table is named 'roles' (not 'backend_roles').
 * - 'roles' table has a 'role_id' (UUID PK), 'name', 'description', 'is_system_role', 'created_at', 'updated_at'.
 * - There is a 'role_permissions' junction table (role_id, resource, action) for role permissions.
 *
 * If your actual database schema (from init.sql) differs, the SQL queries within this class
 * will need to be adjusted to match your 'backend_users', 'backend_roles', 'backend_user_roles'
 * and the JSONB permissions column in 'backend_roles'.
 */
public class User implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    // Regex for password complexity (same as in Register class)
    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{8,}$");
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    /**
     * Handles all User and Role Management operations via a single POST endpoint.
     * The specific operation is determined by the '_func' attribute in the JSON request body.
     *
     * @param req The HttpServletRequest containing the JSON input.
     * @param res The HttpServletResponse for sending the JSON output.
     */
    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract IDs if present in input for specific operations
            UUID userId = null;
            String userIdStr = (String) input.get("user_id");
            if (userIdStr != null && !userIdStr.isEmpty()) { // Check for null before isEmpty()
                try {
                    userId = UUID.fromString(userIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'user_id' format.", req.getRequestURI());
                    return;
                }
            }

            String role = (String) input.get("role");

            switch (func.toLowerCase()) {
                // --- User Authentication ---
                case "login":
                    String loginIdentifier = (String) input.get("identifier"); // Can be username or email
                    String loginPassword = (String) input.get("password");

                    if (loginIdentifier == null || loginIdentifier.isEmpty() || loginPassword == null || loginPassword.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Identifier and password are required for login.", req.getRequestURI());
                        return;
                    }

                    output = authenticateUser(loginIdentifier, loginPassword);
                    if (output.containsKey("error")) { // Check if authentication failed
                        int statusCode = (Integer) output.get("status_code");
                        OutputProcessor.errorResponse(res, statusCode, (String) output.get("error_message"), (String) output.get("error_details"), req.getRequestURI());
                    } else {
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    }
                    break;

                case "reset_password": // Modified function for general password reset
                    String emailToReset = (String) input.get("email");
                    String newPassword = (String) input.get("new_password");

                    if (emailToReset == null || emailToReset.isEmpty() || newPassword == null || newPassword.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Email and new password are required for 'reset_password'.", req.getRequestURI());
                        return;
                    }
                    // Validate email format
                    if (!EMAIL_PATTERN.matcher(emailToReset).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid email format for password reset.", req.getRequestURI());
                        return;
                    }

                    // Validate new password complexity
                    if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "New password does not meet complexity requirements.", req.getRequestURI());
                        return;
                    }

                    // In a real system, you'd add authorization check here:
                    // Only an Admin/DPO (with specific permission) or a valid password reset token holder should call this.
                    // AuthContext authContext = (AuthContext) req.getAttribute("authContext");
                    // if (authContext == null || !authContext.hasPermission("user:reset_password")) { // Example permission
                    //    OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Not authorized to reset user password.", req.getRequestURI());
                    //    return;
                    // }

                    output = resetUserPassword(emailToReset, newPassword);
                    if (output.containsKey("error")) {
                        int statusCode = (Integer) output.get("status_code");
                        OutputProcessor.errorResponse(res, statusCode, (String) output.get("error_message"), (String) output.get("error_details"), req.getRequestURI());
                    } else {
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    }
                    break;
                case "list_users":
                    String userStatusFilter = (String) input.get("status");
                    String userSearch = (String) input.get("search");
                    // Handle potential nulls or incorrect types for page/limit
                    int userPage = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int userLimit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 10;
                    outputArray = listUsersFromDb(userStatusFilter, userSearch, userPage, userLimit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required for 'get_user' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> userOptional = getUserByIdFromDb(userId);
                    if (userOptional.isPresent()) {
                        output = userOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "User with ID '" + userId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "create_user":
                    String username = (String) input.get("username");
                    String email = (String) input.get("email");
                    String password = (String) input.get("password");

                    UUID fiduciaryId = null;
                    String fiduciaryIdStr = (String) input.get("fiduciary_id");
                    if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) { // Check for null before isEmpty()
                        try {
                            fiduciaryId = UUID.fromString(fiduciaryIdStr);
                        } catch (IllegalArgumentException e) {
                            fiduciaryId = null;
                        }
                    }

                    if (username == null || username.isEmpty() || email == null || email.isEmpty() || password == null || password.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (username, email, password, role_id) for 'create_user'.", req.getRequestURI());
                        return;
                    }
                    // For create, password and confirmPassword are the same as password input
                    String validationError = validateUserInput(username, email, password, password);
                    if (validationError != null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", validationError, req.getRequestURI());
                        return;
                    }

                    if (isUsernameOrEmailPresent(username, email, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Username or Email already exists.", req.getRequestURI());
                        return;
                    }

                    String hashedPassword = passwordHasher.hashPassword(password);
                    output = saveUserToDb(username, email, hashedPassword, role, "ACTIVE", fiduciaryId); // Default status to ACTIVE
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required for 'update_user' function.", req.getRequestURI());
                        return;
                    }
                    if (getUserByIdFromDb(userId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "User with ID '" + userId + "' not found.", req.getRequestURI());
                        return;
                    }

                    username = (String) input.get("username");
                    email = (String) input.get("email");
                    password = (String) input.get("password");
                    userStatusFilter = (String) input.get("status"); // 'status' is the field name in JSON

                    // Check if at least one field for update is provided
                    if ((username == null || username.isEmpty()) &&
                            (email == null || email.isEmpty()) &&
                            (password == null || password.isEmpty()) &&
                            (role == null || role.isEmpty()) &&
                            (userStatusFilter == null || userStatusFilter.isEmpty())) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_user'.", req.getRequestURI());
                        return;
                    }

                    // Validate format of provided fields
                    if (password != null && !password.isEmpty() && !PASSWORD_PATTERN.matcher(password).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "New password does not meet complexity requirements.", req.getRequestURI());
                        return;
                    }
                    if (email != null && !email.isEmpty() && !EMAIL_PATTERN.matcher(email).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid email format for update.", req.getRequestURI());
                        return;
                    }

                    // Check for uniqueness if username or email is being updated
                    if ((username != null && !username.isEmpty()) || (email != null && !email.isEmpty())) {
                        if (isUsernameOrEmailPresent(username, email, userId)) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Updated Username or Email conflicts with an existing user.", req.getRequestURI());
                            return;
                        }
                    }

                    output = updateUserInDb(userId, username, email, (password != null && !password.isEmpty()) ? passwordHasher.hashPassword(password) : null, role, userStatusFilter);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required for 'delete_user' function.", req.getRequestURI());
                        return;
                    }
                    if (getUserByIdFromDb(userId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "User with ID '" + userId + "' not found.", req.getRequestURI());
                        return;
                    }
                    deleteUserFromDb(userId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred: " + e.getMessage(), req.getRequestURI());
        } catch (ParseException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid JSON input: " + e.getMessage(), req.getRequestURI());
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid UUID format in input: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Authenticates a user based on identifier (username or email) and password.
     * @param identifier Username or email.
     * @param password Raw password.
     * @return JSONObject containing user details and JWT on success, or error details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject authenticateUser(String identifier, String password) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        JSONObject result = new JSONObject();

        // Query by username or email
        String sql = "SELECT u.id, u.username, u.email, u.password_hash, u.status, u.mfa_enabled, u.role, u.fiduciary_id, f.name FROM users u LEFT OUTER JOIN fiduciaries f ON u.fiduciary_id = f.id WHERE (u.username = ? OR u.email = ?)";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, identifier);
            pstmt.setString(2, identifier);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String userId = rs.getString("id");
                String username = rs.getString("username");
                String email = rs.getString("email");
                String storedHashedPassword = rs.getString("password_hash");
                String status = rs.getString("status");
                boolean mfaEnabled = rs.getBoolean("mfa_enabled");
                String roleName = rs.getString("role");
                String fiduciaryId = rs.getString("fiduciary_id");
                if(fiduciaryId == null) fiduciaryId = "";
                String fiduciaryName = rs.getString("name");
                if(fiduciaryName == null) fiduciaryName = "";

                if (!"ACTIVE".equalsIgnoreCase(status)) {
                    result.put("error", true);
                    result.put("status_code", HttpServletResponse.SC_FORBIDDEN);
                    result.put("error_message", "Account is not active.");
                    result.put("error_details", "User account status: " + status);
                    return result;
                }

                if (passwordHasher.verifyPassword(password, storedHashedPassword)) {
                    // Update last login time
                    updateLastLoginTime(UUID.fromString(userId));

                    if (mfaEnabled) {
                        result.put("success", true);
                        result.put("message", "MFA required.");
                        result.put("user_id", userId);
                        result.put("mfa_required", true);
                        // In a real system, trigger MFA challenge here (e.g., send OTP to email/phone)
                    } else {
                        // Generate JWT token
                        // This is a placeholder for actual JWT generation logic
                        // In a real system, you'd use a library like jjwt (e.g., io.jsonwebtoken)
                        JSONObject claims = new JSONObject();
                        claims.put("userId", userId);
                        claims.put("username", username);
                        claims.put("email", email);
                        claims.put("role", roleName);

                        String generatedToken = JWTUtil.generateToken(email,username,roleName);

                        result.put("success", true);
                        result.put("message", "Login successful.");
                        result.put("user_id", userId);
                        result.put("username", username);
                        result.put("email", email);
                        result.put("role", roleName);
                        result.put("token", generatedToken);
                        result.put("fiduciary_id", fiduciaryId);
                        result.put("fiduciary_name", fiduciaryName);
                    }
                } else {
                    result.put("error", true);
                    result.put("status_code", HttpServletResponse.SC_UNAUTHORIZED);
                    result.put("error_message", "Invalid credentials.");
                    result.put("error_details", "Password mismatch.");
                }
            } else {
                result.put("error", true);
                result.put("status_code", HttpServletResponse.SC_UNAUTHORIZED);
                result.put("error_message", "Invalid credentials.");
                result.put("error_details", "User not found.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    /**
     * Allows an authorized user to reset the password for any user.
     * This function should be protected by strong authorization (e.g., Admin/DPO permission).
     * @param email The email of the user whose password is to be reset.
     * @param newPassword The new password (raw string).
     * @return JSONObject indicating success or error.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject resetUserPassword(String email, String newPassword) throws SQLException {
        JSONObject result = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Find the user by email
        String checkSql = "SELECT id, status FROM users WHERE email = ? AND deleted_at IS NULL";
        // Update password and set status to ACTIVE if it was PENDING_PASSWORD_SETUP or similar
        String updateSql = "UPDATE users SET password_hash = ?, status = 'ACTIVE', last_updated_at = NOW() WHERE id = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(checkSql);
            pstmt.setString(1, email);
            rs = pstmt.executeQuery();

            if (!rs.next()) {
                result.put("error", true);
                result.put("status_code", HttpServletResponse.SC_NOT_FOUND);
                result.put("error_message", "User not found with email: " + email + ".");
                return result;
            }

            UUID userId = UUID.fromString(rs.getString("id")); // Get the actual user_id
            String currentStatus = rs.getString("status");

            // User exists, proceed to update password
            pstmt = conn.prepareStatement(updateSql);
            pstmt.setString(1, passwordHasher.hashPassword(newPassword));
            pstmt.setObject(2, userId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows > 0) {
                result.put("success", true);
                result.put("message", "Password reset successfully.");
                result.put("user_id", userId.toString());
            } else {
                result.put("error", true);
                result.put("status_code", HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                result.put("error_message", "Failed to reset password.");
            }

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    /**
     * Updates the last_login_at timestamp for a user.
     */
    private void updateLastLoginTime(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE users SET last_login_at = NOW() WHERE id = ?"; // Use 'id' as PK
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, userId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for User & Role Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for User Management ---

    /**
     * Validates the input for user creation/update.
     * @param username The username.
     * @param email The email.
     * @param password The password.
     * @param confirmPassword The confirmed password (for create, this would be the same as password).
     * @return null if valid, otherwise an error message.
     */
    private String validateUserInput(String username, String email, String password, String confirmPassword) {
        if (username != null && (username.length() < 1 || username.length() > 50)) {
            return "Username must be between 3 and 50 characters.";
        }
        if (email != null && !EMAIL_PATTERN.matcher(email).matches()) {
            return "Invalid email format.";
        }
        // Only validate password if it's provided (for update, it might be null)
        if (password != null) {
            if (confirmPassword != null && !password.equals(confirmPassword)) { // For create, confirmPassword would be same as password
                return "Passwords do not match.";
            }
            if (!PASSWORD_PATTERN.matcher(password).matches()) {
                return "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.";
            }
        }
        return null; // Input is valid
    }

    /**
     * Checks if a username or email already exists (for uniqueness).
     * @param username The username to check.
     * @param email The email to check.
     * @param excludeUserId Optional UUID to exclude from the check (for update operations).
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isUsernameOrEmailPresent(String username, String email, UUID excludeUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM users WHERE (1=0"); // Start with 1=0 to easily append OR clauses
        List<Object> params = new ArrayList<>();

        if (username != null && !username.isEmpty()) {
            sqlBuilder.append(" OR username = ?");
            params.add(username);
        }
        if (email != null && !email.isEmpty()) {
            sqlBuilder.append(" OR email = ?");
            params.add(email);
        }
        sqlBuilder.append(")"); // Close the OR group

        if (excludeUserId != null) {
            sqlBuilder.append(" AND id != ?");
            params.add(excludeUserId);
        }

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Retrieves a list of users from the database with optional filtering and pagination.
     * @return JSONArray of user JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listUsersFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray usersArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, username, email, status, fiduciary_id, last_login_at, created_at, last_updated_at, role FROM users WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (username LIKE ? OR email LIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject user = new JSONObject();
                user.put("user_id", rs.getString("id"));
                user.put("username", rs.getString("username"));
                user.put("email", rs.getString("email"));
                user.put("status", rs.getString("status"));
                user.put("fiduciary_id", rs.getString("fiduciary_id"));
                user.put("role", rs.getString("role")); // Single role name
                user.put("last_login_at", rs.getTimestamp("last_login_at") != null ? rs.getTimestamp("last_login_at").toInstant().toString() : null);
                user.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                user.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString()); // Corrected column name
                usersArray.add(user);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return usersArray;
    }

    /**
     * Retrieves a single user by ID from the database.
     * @param userId The UUID of the user.
     * @return An Optional containing the user JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getUserByIdFromDb(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT id, username, email, password_hash, status, fiduciary_id, last_login_at, created_at, last_updated_at, role FROM users WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, userId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject user = new JSONObject();
                user.put("user_id", rs.getString("id"));
                user.put("username", rs.getString("username"));
                user.put("email", rs.getString("email"));
                // user.put("password_hash", rs.getString("password_hash")); // Do NOT expose password hash via API
                user.put("status", rs.getString("status"));
                user.put("fiduciary_id", rs.getString("fiduciary_id"));
                user.put("role_name", rs.getString("role"));
                user.put("last_login_at", rs.getTimestamp("last_login_at") != null ? rs.getTimestamp("last_login_at").toInstant().toString() : null);
                user.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                user.put("last_updated_at", rs.getTimestamp("last_updated_at").toInstant().toString()); // Corrected column name
                return Optional.of(user);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new user to the database.
     * @return JSONObject containing the new user's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveUserToDb(String username, String email, String hashedPassword, String role, String status, UUID fiduciaryId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        // Use RETURNING user_id to get the generated UUID
        String sql = "INSERT INTO users (id, username, email, password_hash, role, status, fiduciary_id, created_at, last_updated_at) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?,NOW(), NOW()) RETURNING id";

        try {
            conn = pool.getConnection();
            // Use Statement.RETURN_GENERATED_KEYS to get the UUID from RETURNING clause
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, username);
            pstmt.setString(2, email);
            pstmt.setString(3, hashedPassword);
            pstmt.setString(4, role);
            pstmt.setString(5, status);
            pstmt.setObject(6, fiduciaryId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating user failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String userId = rs.getString(1); // Get the UUID from the first column of generated keys
                output.put("user_id", userId);
                output.put("username", username);
                output.put("email", email);
                output.put("status", status);
                output.put("role", role);
                output.put("message", "User created successfully.");
            } else {
                throw new SQLException("Creating user failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing user in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateUserInDb(UUID userId, String username, String email, String hashedPassword, String role, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE users SET last_updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (username != null && !username.isEmpty()) { sqlBuilder.append(", username = ?"); params.add(username); }
        if (email != null && !email.isEmpty()) { sqlBuilder.append(", email = ?"); params.add(email); }
        if (hashedPassword != null && !hashedPassword.isEmpty()) { sqlBuilder.append(", password_hash = ?"); params.add(hashedPassword); }
        if (role != null) { sqlBuilder.append(", role = ?"); params.add(role); }
        if (status != null && !status.isEmpty()) { sqlBuilder.append(", status = ?"); params.add(status); }

        sqlBuilder.append(" WHERE id = ?");
        params.add(userId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating user failed, user not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "User updated successfully."); }};
    }

    /**
     * Deletes a user from the database.
     * @param userId The UUID of the user to delete.
     * @throws SQLException if a database access error occurs.
     */
    private void deleteUserFromDb(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "DELETE FROM users WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, userId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting user failed, user not found.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}