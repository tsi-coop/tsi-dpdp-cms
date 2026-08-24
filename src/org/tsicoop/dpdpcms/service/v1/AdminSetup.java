package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.UUID;

// NOTE: This service assumes the 'users' and 'roles' tables exist and that
// user passwords are hashed using a secure method (e.g., BCrypt).
// We simulate the hashing and role lookup process.

public class AdminSetup implements Action {

    // Define the fixed role ID for the Super Administrator setup
    private static final String SUPER_ADMIN_ROLE_NAME = "ADMIN";

    // Shared secret gating initial_setup. Must be set by whoever deploys the app
    // (e.g. injected from their secrets manager) — there is no built-in fallback,
    // so setup stays disabled (fails closed) until this is explicitly configured.
    private static final String BOOTSTRAP_TOKEN_ENV = "TSI_BOOTSTRAP_TOKEN";

    // --- Mock Hashing Utility ---
    // In a production environment, use a secure library like Spring Security's BCrypt

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

            String bootstrapToken = System.getenv(BOOTSTRAP_TOKEN_ENV);
            if (bootstrapToken == null || bootstrapToken.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Setup Disabled", "Initial setup is disabled: " + BOOTSTRAP_TOKEN_ENV + " is not configured on the server.", req.getRequestURI());
                return;
            }

            String providedToken = (String) input.get("setup_token");
            if (providedToken == null || !constantTimeEquals(providedToken, bootstrapToken)) {
                // Checked before any DB access so a caller without the token learns
                // nothing about whether the system has already been configured.
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or missing setup token.", req.getRequestURI());
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
                boolean alreadyConfigured = Boolean.TRUE.equals(result.get("already_configured"));
                int status = alreadyConfigured ? HttpServletResponse.SC_CONFLICT : HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
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
            // SERIALIZABLE + explicit commit closes the check-then-insert race: two
            // requests that both observe an empty operators table can no longer both
            // succeed — Postgres aborts the loser with SQLState 40001 below.
            conn.setAutoCommit(false);
            conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);

            // 1. CHECK FOR EXISTING ADMIN USERS
            if (isAdminUserExists(conn)) {
                conn.rollback();
                return new JSONObject() {{ put("error", "System is already configured. Cannot run initial setup."); put("already_configured", true); }};
            }

           // 2. HASH PASSWORD
            String hashedPassword = new PasswordHasher().hashPassword(password);

            // 3. CREATE USER AND ASSIGN ROLE (in a single transaction)
            UUID newUserId = createUser(conn, email, name, hashedPassword);
            conn.commit();

            return new JSONObject() {{ put("user_id", newUserId.toString()); put("role", SUPER_ADMIN_ROLE_NAME); }};

        } catch (SQLException e) {
            if (conn != null) {
                try { conn.rollback(); } catch (SQLException ignored) {}
            }
            if ("40001".equals(e.getSQLState())) {
                return new JSONObject() {{ put("error", "System is already configured. Cannot run initial setup."); put("already_configured", true); }};
            }
            throw e; // Re-throw SQL exception for generic handler
        } finally {
            if (conn != null) {
                try {
                    conn.setAutoCommit(true);
                    conn.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
                } catch (SQLException ignored) {}
            }
            pool.cleanup(null, null, conn);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Checks if any user is currently assigned the Super Admin role.
     */
    private boolean isAdminUserExists(Connection conn) throws SQLException {
        String sql = "SELECT COUNT(*) FROM operators where role=?";

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
        String sql = "INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, status, created_at, last_updated_at, role) " +
                "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", ?, 'ACTIVE', NOW(), NOW(), ?) RETURNING id";

        try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            int ci = 1;
            pstmt.setString(ci++, name);
            pstmt.setString(ci++, email);                              // email_plaintext
            ci = DbEncryption.bindEncrypt(pstmt, ci, email);          // email_enc
            ci = DbEncryption.bindHmac(pstmt, ci, email);             // email_hmac
            pstmt.setString(ci++, hashedPassword);
            pstmt.setString(ci++, SUPER_ADMIN_ROLE_NAME);

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
