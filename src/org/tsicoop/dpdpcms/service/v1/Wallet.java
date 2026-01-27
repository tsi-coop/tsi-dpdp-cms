package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import java.sql.*;
import java.util.UUID;
import java.time.Instant;

/**
 * Wallet handles lifecycle commands originating from the user's Portable Wallet.
 * Maintains provenance by recording new consent artifacts for every action.
 * Background purging (CES) is triggered by the state transitions in consent_records.
 */
public class Wallet implements Action {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String command = (String) input.get("command");
            String syncToken = (String) input.get("sync_token");
            String fiduciaryIdStr = (String) input.get("fiduciary_id");
            String userId = (String) input.get("user_id"); // DYNAMIC: Identity passed from Wallet

            if (command == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing command.", req.getRequestURI());
                return;
            }

            // Utility function: Get Fiduciary Name (Non-authenticated context)
            if ("GET_FIDUCIARY_NAME".equalsIgnoreCase(command)) {
                if (fiduciaryIdStr == null) {
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing fiduciary_id.", req.getRequestURI());
                    return;
                }
                String name = getFiduciaryName(fiduciaryIdStr);
                JSONObject nameRes = new JSONObject();
                nameRes.put("success", true);
                nameRes.put("fiduciary_name", name);
                OutputProcessor.send(res, 200, nameRes);
                return;
            }

            // Security Check for protected lifecycle commands
            if (syncToken == null || fiduciaryIdStr == null || userId == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing sync parameters (token, fid, or uid).", req.getRequestURI());
                return;
            }

            // Load PrincipalContext based on provided credentials
            PrincipalContext ctx = validateSyncToken(syncToken, fiduciaryIdStr, userId);
            if (ctx == null) {
                OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid or expired Sync Token.", req.getRequestURI());
                return;
            }

            JSONObject result = new JSONObject();
            switch (command.toUpperCase()) {
                case "GET_CONSENT_DETAILS":
                    result = handleGetConsentDetails(ctx);
                    break;
                case "REVOKE_PURPOSE":
                    String purposeId = (String) input.get("purpose_id");
                    result = handleRevokePurpose(ctx, purposeId);
                    break;
                case "GLOBAL_ERASURE":
                    result = handleGlobalErasure(ctx);
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unsupported wallet command.", req.getRequestURI());
                    return;
            }

            OutputProcessor.send(res, 200, result);

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Retrieves the latest active consent record for the authenticated principal.
     */
    private JSONObject handleGetConsentDetails(PrincipalContext ctx) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "SELECT data_point_consents, policy_id, policy_version, timestamp FROM consent_records " +
                "WHERE user_id = ? AND fiduciary_id::text = ? AND is_active_consent = TRUE LIMIT 1";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, ctx.userId);
            pstmt.setString(2, ctx.fiduciaryId);
            rs = pstmt.executeQuery();

            JSONObject res = new JSONObject();
            if (rs.next()) {
                res.put("success", true);
                res.put("policy_id", rs.getString("policy_id"));
                res.put("policy_version", rs.getString("policy_version"));
                res.put("timestamp", rs.getTimestamp("timestamp").toString());
                res.put("data_point_consents", new JSONParser().parse(rs.getString("data_point_consents")));
            } else {
                res.put("success", false);
                res.put("message", "No active consent records found in registry.");
            }
            return res;
        } catch (SQLException e) {
            System.err.println("SQL Error in handleGetConsentDetails: " + e.getMessage());
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private String getFiduciaryName(String fiduciaryIdStr) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT name FROM fiduciaries WHERE id::text = ? OR name = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, fiduciaryIdStr);
            pstmt.setString(2, fiduciaryIdStr);
            rs = pstmt.executeQuery();
            if (rs.next()) return rs.getString("name");
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return fiduciaryIdStr;
    }

    private JSONObject handleRevokePurpose(PrincipalContext ctx, String purposeId) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String selectSql = "SELECT id, policy_id, policy_version, data_point_consents FROM consent_records " +
                "WHERE user_id = ? AND fiduciary_id::text = ? AND is_active_consent = TRUE LIMIT 1";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement(selectSql);
            pstmt.setString(1, ctx.userId);
            pstmt.setString(2, ctx.fiduciaryId);
            rs = pstmt.executeQuery();

            if (!rs.next()) throw new Exception("No active record found to revoke.");

            String oldId = rs.getString("id");
            String pId = rs.getString("policy_id");
            String pVer = rs.getString("policy_version");
            JSONArray consents = (JSONArray) new JSONParser().parse(rs.getString("data_point_consents"));

            for (Object obj : consents) {
                JSONObject item = (JSONObject) obj;
                if (purposeId.equals(item.get("data_point_id"))) {
                    item.put("consent_granted", false);
                    item.put("timestamp_updated", Instant.now().toString());
                }
            }

            String dSql = "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE id = ?";
            try (PreparedStatement dStmt = conn.prepareStatement(dSql)) {
                dStmt.setObject(1, UUID.fromString(oldId));
                dStmt.executeUpdate();
            }

            String iSql = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, consent_status_general, consent_mechanism, data_point_consents, is_active_consent, created_at, language_selected, ip_address) VALUES (uuid_generate_v4(), ?, ?, ?, ?, NOW(), 'IN', 'WITHDRAWN', 'WALLET_REVOKE', ?::jsonb, TRUE, NOW(), 'en', '0.0.0.0')";
            try (PreparedStatement iStmt = conn.prepareStatement(iSql)) {
                iStmt.setString(1, ctx.userId);
                try { iStmt.setObject(2, UUID.fromString(ctx.fiduciaryId)); } catch (Exception ex) { iStmt.setString(2, ctx.fiduciaryId); }
                iStmt.setString(3, pId);
                iStmt.setString(4, pVer);
                iStmt.setString(5, consents.toJSONString());
                iStmt.executeUpdate();
            }

            conn.commit();
            JSONObject res = new JSONObject();
            res.put("success", true);
            res.put("message", "Revoked and new artifact recorded.");
            return res;
        } catch (Exception e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private JSONObject handleGlobalErasure(PrincipalContext ctx) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sSql = "SELECT id, policy_id, policy_version, data_point_consents FROM consent_records WHERE user_id = ? AND fiduciary_id::text = ? AND is_active_consent = TRUE LIMIT 1";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);
            pstmt = conn.prepareStatement(sSql);
            pstmt.setString(1, ctx.userId);
            pstmt.setString(2, ctx.fiduciaryId);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String oldId = rs.getString("id");
                String pId = rs.getString("policy_id");
                String pVer = rs.getString("policy_version");
                JSONArray consents = (JSONArray) new JSONParser().parse(rs.getString("data_point_consents"));

                for (Object obj : consents) {
                    JSONObject item = (JSONObject) obj;
                    item.put("consent_granted", false);
                    item.put("timestamp_updated", Instant.now().toString());
                }

                String dSql = "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE id = ?";
                try (PreparedStatement dStmt = conn.prepareStatement(dSql)) {
                    dStmt.setObject(1, UUID.fromString(oldId));
                    dStmt.executeUpdate();
                }

                String iSql = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, consent_status_general, consent_mechanism, data_point_consents, is_active_consent, created_at, language_selected, ip_address) VALUES (uuid_generate_v4(), ?, ?, ?, ?, NOW(), 'IN', 'ERASURE_REQUEST', 'ERASURE_REQUEST', ?::jsonb, FALSE, NOW(), 'en', '0.0.0.0')";
                try (PreparedStatement iStmt = conn.prepareStatement(iSql)) {
                    iStmt.setString(1, ctx.userId);
                    try { iStmt.setObject(2, UUID.fromString(ctx.fiduciaryId)); } catch (Exception ex) { iStmt.setString(2, ctx.fiduciaryId); }
                    iStmt.setString(3, pId);
                    iStmt.setString(4, pVer);
                    iStmt.setString(5, consents.toJSONString());
                    iStmt.executeUpdate();
                }
            }
            conn.commit();
            JSONObject res = new JSONObject();
            res.put("success", true);
            res.put("message", "Global erasure request recorded.");
            return res;
        } catch (Exception e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Maps the scoped Sync Token and provided User ID to the PrincipalContext.
     */
    private PrincipalContext validateSyncToken(String token, String fiduciaryId, String userId) throws SQLException {
        // In production, this would verify the token in a session/registry table linked to the userId.
        if (token != null && (token.startsWith("SECURE_JWT_TOKEN_") || token.startsWith("BRH_SYNC_TK_") || token.startsWith("PCA_TOKEN_"))) {
            return new PrincipalContext(userId, fiduciaryId);
        }
        return null;
    }

    private static class PrincipalContext {
        String userId; String fiduciaryId;
        PrincipalContext(String u, String f) { this.userId = u; this.fiduciaryId = f; }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}