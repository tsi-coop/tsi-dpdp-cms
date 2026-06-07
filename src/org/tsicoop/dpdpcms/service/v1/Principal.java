package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Data Principal self-service portal authentication service.
 * Exposes public endpoints (no auth required) for:
 *   - principal_login: authenticate with fiduciary_id + user_id + OTP, returns a PRINCIPAL JWT
 *   - list_active_fiduciaries: public listing of active fiduciaries for portal dropdown
 */
public class Principal implements Action {

    private static final String PLACEHOLDER_OTP = "1234"; // TODO: replace with real OTP service

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

        // TODO: replace with real OTP verification (SMS/email)
        if (!PLACEHOLDER_OTP.equals(otp)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid OTP.", req.getRequestURI());
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
        OutputProcessor.send(res, HttpServletResponse.SC_OK, response);
    }

    private JSONArray listActiveFiduciaries() throws SQLException {
        JSONArray result = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String sql = "SELECT id, name FROM fiduciaries WHERE status = 'ACTIVE' ORDER BY name ASC";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject fid = new JSONObject();
                fid.put("fiduciary_id", rs.getString("id"));
                fid.put("name", rs.getString("name"));
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
