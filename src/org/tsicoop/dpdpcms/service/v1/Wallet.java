package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.ces.CESUtil;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.framework.*;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import java.sql.*;
import java.util.LinkedHashSet;
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
            if (syncToken == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing sync_token.", req.getRequestURI());
                return;
            }

            // userId and fiduciaryId are extracted from the signed token — request body values are not trusted
            PrincipalContext ctx = validateSyncToken(syncToken);
            if (ctx == null) {
                OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid or expired Sync Token.", req.getRequestURI());
                return;
            }

            JSONObject result = new JSONObject();
            switch (command.toUpperCase()) {
                case "GET_CONSENT_DETAILS":
                    // policy_id is an optional fallback (sourced from the PCA) used only when no
                    // active consent record exists yet, so the wallet can still show the
                    // organisation's policy title/persona and offer to collect first-time consent.
                    result = handleGetConsentDetails(ctx, (String) input.get("policy_id"));
                    break;
                case "REVOKE_PURPOSE":
                    String purposeId = (String) input.get("purpose_id");
                    result = handleRevokePurpose(ctx, purposeId);
                    break;
                case "GLOBAL_ERASURE":
                    result = handleGlobalErasure(ctx);
                    break;
                case "GET_POLICY_PURPOSES":
                    result = handleGetPolicyPurposes(ctx, (String) input.get("policy_id"));
                    break;
                case "GRANT_CONSENT":
                    result = handleGrantConsent(ctx, (String) input.get("policy_id"), (JSONArray) input.get("data_point_consents"));
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
     * Always attempts to attach policy_title/personas metadata -- even when there's no active
     * consent yet -- falling back to the caller-supplied fallbackPolicyId (sourced from the PCA)
     * so the wallet can show "who this is with, as what persona" and offer first-time consent.
     */
    private JSONObject handleGetConsentDetails(PrincipalContext ctx, String fallbackPolicyId) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "SELECT data_point_consents, policy_id, policy_version, timestamp FROM consent_records " +
                "WHERE user_id = ? AND fiduciary_id::text = ? AND is_active_consent = TRUE LIMIT 1";

        JSONObject res = new JSONObject();
        String policyIdForMeta = fallbackPolicyId;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, ctx.userId);
            pstmt.setString(2, ctx.fiduciaryId);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                res.put("success", true);
                res.put("policy_id", rs.getString("policy_id"));
                res.put("policy_version", rs.getString("policy_version"));
                res.put("timestamp", rs.getTimestamp("timestamp").toString());
                res.put("data_point_consents", new JSONParser().parse(rs.getString("data_point_consents")));
                policyIdForMeta = rs.getString("policy_id");
            } else {
                res.put("success", false);
                res.put("message", "No active consent records found in registry.");
            }
        } catch (SQLException e) {
            System.err.println("SQL Error in handleGetConsentDetails: " + e.getMessage());
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        if (policyIdForMeta != null) {
            JSONObject policyContent = new Consent().getPolicy(policyIdForMeta, "", UUID.fromString(ctx.fiduciaryId));
            if (policyContent != null) {
                res.put("policy_id", policyIdForMeta);
                res.put("policy_title", extractPolicyTitle(policyContent));
                res.put("personas", extractPersonas(policyContent));
            }
        }
        return res;
    }

    /**
     * Returns the purposes a policy offers, for the wallet to render a first-time consent form
     * when the principal has no active consent record yet.
     */
    private JSONObject handleGetPolicyPurposes(PrincipalContext ctx, String policyId) throws Exception {
        JSONObject res = new JSONObject();
        if (policyId == null || policyId.isEmpty()) {
            res.put("success", false);
            res.put("message", "Missing policy_id.");
            return res;
        }
        JSONObject policyContent = new Consent().getPolicy(policyId, "", UUID.fromString(ctx.fiduciaryId));
        if (policyContent == null) {
            res.put("success", false);
            res.put("message", "Policy not found or not active for this fiduciary.");
            return res;
        }
        res.put("success", true);
        res.put("policy_id", policyId);
        res.put("policy_title", extractPolicyTitle(policyContent));
        res.put("personas", extractPersonas(policyContent));
        res.put("purposes", extractPurposes(policyContent));
        return res;
    }

    /**
     * Records first-time (or renewed) consent originating from the wallet, reusing
     * Consent.recordConsentToDb so CES/ROPA registration and audit logging stay in one place.
     */
    private JSONObject handleGrantConsent(PrincipalContext ctx, String policyId, JSONArray dataPointConsents) throws Exception {
        JSONObject res = new JSONObject();
        if (policyId == null || policyId.isEmpty() || dataPointConsents == null) {
            res.put("success", false);
            res.put("message", "Missing policy_id or data_point_consents.");
            return res;
        }
        UUID fiduciaryUuid = UUID.fromString(ctx.fiduciaryId);
        JSONObject policy = new Consent().getPolicy(policyId, "", fiduciaryUuid);
        if (policy == null) {
            res.put("success", false);
            res.put("message", "Referenced policy not found or does not belong to this fiduciary.");
            return res;
        }

        JSONArray revisedConsents = CESUtil.appendConsentExpiry(policy, dataPointConsents, Constants.ACTION_CONSENT_GIVEN);
        Timestamp timestamp = Timestamp.from(Instant.now());
        JSONObject dbResult = new Consent().recordConsentToDb(ctx.userId, fiduciaryUuid, policyId, "",
                timestamp, "IN", "en", "CONSENT_GIVEN", "WALLET_GRANT",
                "0.0.0.0", null, revisedConsents, null, null);

        res.put("success", true);
        res.put("message", "Consent recorded successfully.");
        return res;
    }

    private JSONObject resolveLangBlock(JSONObject policyContent) {
        if (policyContent.containsKey("en")) return (JSONObject) policyContent.get("en");
        for (Object v : policyContent.values()) {
            if (v instanceof JSONObject) return (JSONObject) v;
        }
        return null;
    }

    private String extractPolicyTitle(JSONObject policyContent) {
        JSONObject lc = resolveLangBlock(policyContent);
        if (lc != null && lc.get("title") != null) return (String) lc.get("title");
        return "Privacy Policy";
    }

    /**
     * Unions "data_subject_categories" across every language block -- mirrors
     * Principal.extractDataSubjectCategories, kept local here since Wallet already has the
     * policy content parsed (Consent.getPolicy returns a JSONObject, not a raw string).
     */
    @SuppressWarnings("unchecked")
    private JSONArray extractPersonas(JSONObject policyContent) {
        LinkedHashSet<String> categories = new LinkedHashSet<>();
        for (Object langBlockObj : policyContent.values()) {
            if (!(langBlockObj instanceof JSONObject)) continue;
            JSONObject langBlock = (JSONObject) langBlockObj;
            Object dsc = langBlock.get("data_subject_categories");
            if (dsc instanceof JSONArray) {
                for (Object c : (JSONArray) dsc) {
                    if (c != null && !c.toString().trim().isEmpty()) categories.add(c.toString().trim());
                }
            }
        }
        JSONArray result = new JSONArray();
        result.addAll(categories);
        return result;
    }

    private JSONArray extractPurposes(JSONObject policyContent) {
        JSONObject lc = resolveLangBlock(policyContent);
        if (lc == null) return new JSONArray();
        Object purposes = lc.get("data_processing_purposes");
        return purposes instanceof JSONArray ? (JSONArray) purposes : new JSONArray();
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

            // consent_mechanism must be the canonical CONSENT_WITHDRAWN action (matching
            // Consent.withdrawConsent and handleGlobalErasure below) -- the Rights Portal's
            // history tab does an exact string match on this value to decide whether to show
            // WITHDRAWN/PARTIALLY WITHDRAWN; a wallet-specific label like "WALLET_REVOKE" was
            // silently falling through to "ACTIVE" instead.
            String iSql = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, consent_status_general, consent_mechanism, data_point_consents, is_active_consent, created_at, language_selected, ip_address) VALUES (uuid_generate_v4(), ?, ?, ?, ?, NOW(), 'IN', '" + Constants.ACTION_CONSENT_WITHDRAWN + "', '" + Constants.ACTION_CONSENT_WITHDRAWN + "', ?::jsonb, TRUE, NOW(), 'en', '0.0.0.0')";
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
     * Validates the wallet sync token (a signed JWT with type=SYNC).
     * userId and fiduciaryId are extracted from the token claims — the request body is not trusted.
     */
    private PrincipalContext validateSyncToken(String token) {
        Claims claims = JWTUtil.getSyncClaimsFromToken(token);
        if (claims == null) return null;
        String tokenUserId = claims.getSubject();
        String tokenFiduciaryId = (String) claims.get("fid");
        if (tokenUserId == null || tokenFiduciaryId == null) return null;
        return new PrincipalContext(tokenUserId, tokenFiduciaryId);
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