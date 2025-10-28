package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.Action;
import org.tsicoop.dpdpcms.framework.InputProcessor;
import org.tsicoop.dpdpcms.framework.OutputProcessor;
import org.tsicoop.dpdpcms.framework.PoolDB;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.sql.*;
import java.util.UUID;

// NOTE: This service assumes the 'users' and 'roles' tables exist and that
// user passwords are hashed using a secure method (e.g., BCrypt).
// We simulate the hashing and role lookup process.

public class AdminSetup implements Action {

    // Define the fixed role ID for the Super Administrator setup
    private static final String SUPER_ADMIN_ROLE_NAME = "ADMIN";

    // --- Mock Hashing Utility ---
    // In a production environment, use a secure library like Spring Security's BCrypt
    private String hashPassword(String password) {
        // Placeholder: Use a mock hash for demonstration purposes
        return "MOCK_HASH_" + password.substring(0, Math.min(password.length(), 8)) + "_" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (!"initial_setup".equals(func)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unsupported function for setup service: " + func, req.getRequestURI());
                return;
            }

            String email = (String) input.get("email");
            String name = (String) input.get("name");
            String password = (String) input.get("password");

            if (email == null || name == null || password == null || email.isEmpty() || name.isEmpty() || password.length() < 12) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing or invalid required fields (email, name, password must be >= 12 chars).", req.getRequestURI());
                return;
            }

            // Execute setup logic
            JSONObject result = performInitialSetup(email, name, password);

            if (result.containsKey("error")) {
                int status = "System is already configured.".equals(result.get("error")) ? HttpServletResponse.SC_CONFLICT : HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                OutputProcessor.errorResponse(res, status, "Setup Failure", (String) result.get("error"), req.getRequestURI());
            } else {
                OutputProcessor.send(res, HttpServletResponse.SC_CREATED, new JSONObject() {{
                    put("success", true);
                    put("message", "Super Administrator created successfully.");
                    put("data", result);
                }});
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred during setup: " + e.getMessage(), req.getRequestURI());
        } catch (ParseException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid JSON input: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Executes the setup logic: checks if an admin exists, and if not, creates the first user.
     * @param email The email of the first admin.
     * @param name The name of the first admin.
     * @param password The password for the first admin.
     * @return JSONObject with success data or error message.
     */
    private JSONObject performInitialSetup(String email, String name, String password) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;

        try {
            conn = pool.getConnection();

            // 1. CHECK FOR EXISTING ADMIN USERS
            if (isAdminUserExists(conn)) {
                  return new JSONObject() {{ put("error", "System is already configured. Cannot run initial setup."); }};
            }

           // 2. HASH PASSWORD
            String hashedPassword = hashPassword(password);

            // 3. CREATE USER AND ASSIGN ROLE (in a single transaction)
            UUID newUserId = createUser(conn, email, name, hashedPassword);

            return new JSONObject() {{ put("user_id", newUserId.toString()); put("role", SUPER_ADMIN_ROLE_NAME); }};

        } catch (SQLException e) {
            throw e; // Re-throw SQL exception for generic handler
        } finally {
            pool.cleanup(null, null, conn);
        }
    }

    /**
     * Checks if any user is currently assigned the Super Admin role.
     */
    private boolean isAdminUserExists(Connection conn) throws SQLException {
        String sql = "SELECT COUNT(*) FROM users where role=?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, SUPER_ADMIN_ROLE_NAME);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        }
        return false;
    }

    /**
     * Inserts the new user into the 'users' table.
     */
    private UUID createUser(Connection conn, String email, String name, String hashedPassword) throws SQLException {
        String sql = "INSERT INTO users (id, username, email, name, password_hash, status, created_at, last_updated_at,role) VALUES (uuid_generate_v4(), ?, ?, ?, ?, 'ACTIVE', NOW(), NOW(),?) RETURNING id";

        try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, email); // Use email as username for initial setup
            pstmt.setString(2, email);
            pstmt.setString(3, name);
            pstmt.setString(4, hashedPassword);
            pstmt.setString(5, SUPER_ADMIN_ROLE_NAME);

            if (pstmt.executeUpdate() == 0) {
                throw new SQLException("Creating user failed, no rows affected.");
            }

            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return (UUID) rs.getObject(1);
                } else {
                    throw new SQLException("Creating user failed, no ID obtained.");
                }
            }
        }
    }

    /**
     * Validates the HTTP method.
     */
    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for setup operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }
}
