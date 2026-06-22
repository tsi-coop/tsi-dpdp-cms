package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Data Principal self-service portal authentication service.
 * Exposes public endpoints (no auth required) for:
 *   - principal_login: authenticate with fiduciary_id + user_id + OTP, returns a PRINCIPAL JWT
 *   - list_active_fiduciaries: public listing of active fiduciaries for portal dropdown
 *   - request_principal_otp: triggers real OTP delivery (EMAIL_OTP/MOBILE_OTP fiduciaries)
 */
public class Principal implements Action {

    private static final String DUMMY_OTP_MODE = "DUMMY_OTP";
    private static final String PLACEHOLDER_OTP = "1234"; // Used for DUMMY_OTP-mode fiduciaries (demo/eval)
    private static final long OTP_TTL_MS = 5 * 60 * 1000L; // 5 minutes, single-use
    private static final SecureRandom OTP_RANDOM = new SecureRandom();

    private static class PendingOtp {
        final String otp;
        final long expiresAt;
        PendingOtp(String otp) {
            this.otp = otp;
            this.expiresAt = System.currentTimeMillis() + OTP_TTL_MS;
        }
        boolean isExpired() { return System.currentTimeMillis() > expiresAt; }
    }

    // fiduciaryId:userId -> pending OTP. In-memory is fine: short-lived, single-use,
    // and only meaningful on the instance that issues/verifies it within the TTL window.
    private static final ConcurrentHashMap<String, PendingOtp> pendingOtps = new ConcurrentHashMap<>();

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input;
        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func'.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_active_fiduciaries":
                    JSONArray fiduciaries = listActiveFiduciaries();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, fiduciaries);
                    break;

                case "principal_login":
                    handleLogin(input, req, res);
                    break;

                case "request_principal_otp":
                    handleRequestOtp(input, req, res);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function: " + func, req.getRequestURI());
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    private void handleLogin(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        String fiduciaryIdStr = (String) input.get("fiduciary_id");
        String userId = (String) input.get("user_id");
        String otp = (String) input.get("otp");

        if (fiduciaryIdStr == null || fiduciaryIdStr.isEmpty() || userId == null || userId.isEmpty() || otp == null || otp.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "fiduciary_id, user_id, and otp are required.", req.getRequestURI());
            return;
        }

        UUID fiduciaryId;
        try {
            fiduciaryId = UUID.fromString(fiduciaryIdStr);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid fiduciary_id format.", req.getRequestURI());
            return;
        }

        // Validate fiduciary is ACTIVE
        String fiduciaryName = getActiveFiduciaryName(fiduciaryId);
        if (fiduciaryName == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Fiduciary not found or inactive.", req.getRequestURI());
            return;
        }

        String otpMode = getOtpMode(fiduciaryId);
        boolean pcaQrEnabled = getPcaQrEnabled(fiduciaryId);

        if (DUMMY_OTP_MODE.equals(otpMode)) {
            if (!PLACEHOLDER_OTP.equals(otp)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid OTP.", req.getRequestURI());
                return;
            }
        } else {
            String cacheKey = fiduciaryIdStr + ":" + userId;
            PendingOtp pending = pendingOtps.get(cacheKey);
            if (pending == null || pending.isExpired() || !pending.otp.equals(otp)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or expired OTP.", req.getRequestURI());
                return;
            }
            pendingOtps.remove(cacheKey); // single-use
        }

        // Fetch all active policies for this fiduciary
        JSONArray policies = getActivePolicies(fiduciaryId);

        // Generate principal portal token
        String token = JWTUtil.generatePrincipalToken(userId, fiduciaryIdStr);

        // Audit the login
        new Audit().logEventAsync(userId, fiduciaryId, "PRINCIPAL_PORTAL", null, "PRINCIPAL_LOGIN", "Portal login for " + userId);

        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("token", token);
        response.put("user_id", userId);
        response.put("fiduciary_id", fiduciaryIdStr);
        response.put("fiduciary_name", fiduciaryName);
        response.put("policies", policies);
        response.put("pca_qr_enabled", pcaQrEnabled);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, response);
    }

    /**
     * Generates and dispatches a real OTP for EMAIL_OTP/MOBILE_OTP fiduciaries via the
     * fiduciary's configured 'OTP' webhook (WebhookDispatcher); no-ops for DUMMY_OTP
     * fiduciaries (the frontend just shows the static "use 1234" hint in that case).
     * Always returns a generic success -- never echoes the OTP back in the response.
     */
    private void handleRequestOtp(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        String fiduciaryIdStr = (String) input.get("fiduciary_id");
        String userId = (String) input.get("user_id");

        if (fiduciaryIdStr == null || fiduciaryIdStr.isEmpty() || userId == null || userId.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "fiduciary_id and user_id are required.", req.getRequestURI());
            return;
        }

        UUID fiduciaryId;
        try {
            fiduciaryId = UUID.fromString(fiduciaryIdStr);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid fiduciary_id format.", req.getRequestURI());
            return;
        }

        if (getActiveFiduciaryName(fiduciaryId) == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Fiduciary not found or inactive.", req.getRequestURI());
            return;
        }

        String otpMode = getOtpMode(fiduciaryId);
        if (!DUMMY_OTP_MODE.equals(otpMode)) {
            String otp = String.format("%06d", OTP_RANDOM.nextInt(1_000_000));
            pendingOtps.put(fiduciaryIdStr + ":" + userId, new PendingOtp(otp));

            String template = getOtpMessageTemplate(fiduciaryId);
            String message = (template != null && !template.isEmpty() ? template : "Your verification code is {{otp}}")
                    .replace("{{otp}}", otp);

            JSONObject payload = new JSONObject();
            payload.put("user_id", userId);
            payload.put("otp_mode", otpMode);
            payload.put("message", message);
            WebhookDispatcher.dispatch(fiduciaryIdStr, "OTP", "principal_otp_requested", payload);
        }

        OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); }});
    }

    private String getOtpMode(UUID fiduciaryId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT otp_mode FROM rights_app_config WHERE fiduciary_id = ?");
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) return rs.getString("otp_mode");
            return DUMMY_OTP_MODE;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private String getOtpMessageTemplate(UUID fiduciaryId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT otp_message_template FROM rights_app_config WHERE fiduciary_id = ?");
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) return rs.getString("otp_message_template");
            return null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private boolean getPcaQrEnabled(UUID fiduciaryId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT pca_qr_enabled FROM rights_app_config WHERE fiduciary_id = ?");
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) return rs.getBoolean("pca_qr_enabled");
            return true;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private JSONArray listActiveFiduciaries() throws SQLException {
        JSONArray result = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String sql = "SELECT f.id, f.name, f.primary_domain, " +
                "COALESCE(rac.otp_mode, 'DUMMY_OTP') AS otp_mode, " +
                "COALESCE(rac.pca_qr_enabled, TRUE) AS pca_qr_enabled " +
                "FROM fiduciaries f LEFT JOIN rights_app_config rac ON rac.fiduciary_id = f.id " +
                "WHERE f.status = 'ACTIVE' ORDER BY f.name ASC";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject fid = new JSONObject();
                fid.put("fiduciary_id", rs.getString("id"));
                fid.put("name", rs.getString("name"));
                fid.put("primary_domain", rs.getString("primary_domain"));
                fid.put("otp_mode", rs.getString("otp_mode"));
                fid.put("pca_qr_enabled", rs.getBoolean("pca_qr_enabled"));
                result.add(fid);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private String getActiveFiduciaryName(UUID fiduciaryId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String sql = "SELECT name FROM fiduciaries WHERE id = ? AND status = 'ACTIVE'";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) return rs.getString("name");
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }

    private JSONArray getActivePolicies(UUID fiduciaryId) throws SQLException {
        JSONArray result = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String sql = "SELECT id, version, jurisdiction, effective_date, policy_content " +
                "FROM consent_policies WHERE fiduciary_id = ? AND status = 'ACTIVE' AND effective_date <= NOW() " +
                "ORDER BY effective_date DESC";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject entry = new JSONObject();
                entry.put("policy_id", rs.getString("id"));
                entry.put("version", rs.getString("version"));
                entry.put("jurisdiction", rs.getString("jurisdiction"));
                entry.put("effective_date", rs.getTimestamp("effective_date").toInstant().toString());
                entry.put("title", extractPolicyTitle(rs.getString("policy_content")));
                result.add(entry);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private String extractPolicyTitle(String policyContentJson) {
        try {
            org.json.simple.JSONObject map = (org.json.simple.JSONObject)
                    new org.json.simple.parser.JSONParser().parse(policyContentJson);
            org.json.simple.JSONObject lc = map.containsKey("en")
                    ? (org.json.simple.JSONObject) map.get("en")
                    : (org.json.simple.JSONObject) map.values().iterator().next();
            if (lc != null && lc.containsKey("title")) return (String) lc.get("title");
        } catch (Exception ignored) {}
        return "Privacy Policy";
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST is supported.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }
}
