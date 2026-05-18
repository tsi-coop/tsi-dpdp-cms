package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.PoolDB;

import java.sql.*;
import java.util.*;

public class RopaDeriver {

    /**
     * Reads a published consent policy and inserts a draft ropa_entry populated
     * from the policy content. Also writes the initial snapshot to ropa_history.
     *
     * @return the UUID of the created draft entry, or null if the policy is missing/unparseable.
     */
    public static UUID deriveFromPolicy(String policyId, String version, UUID fiduciaryId) throws Exception {
        String policyContentStr = loadPolicyContent(policyId, version, fiduciaryId);
        if (policyContentStr == null) return null;

        JSONObject content = (JSONObject) new JSONParser().parse(policyContentStr);
        if (content == null || content.isEmpty()) return null;

        // Use English section; fall back to first available language
        String lang = content.containsKey("en") ? "en" : (String) content.keySet().iterator().next();
        JSONObject langObj = (JSONObject) content.get(lang);
        if (langObj == null) return null;

        JSONArray purposes = (JSONArray) langObj.get("data_processing_purposes");
        JSONArray categories = (JSONArray) langObj.get("data_categories_details");

        String activityName = policyId;
        String purposeText = buildPurposeText(purposes);
        JSONArray dataCategoriesArr = extractCategoryIds(categories);
        int maxRetentionDays = computeMaxRetentionDays(purposes);
        String retentionStartEvent = extractRetentionStartEvent(purposes);

        JSONArray dataSubjectCategoriesArr = extractOrDefault(
                (JSONArray) langObj.get("data_subject_categories"), "data_principal");
        String securityMeasures = (String) langObj.get("security_measures");
        JSONArray processorsArr = langObj.get("processors") instanceof JSONArray
                ? (JSONArray) langObj.get("processors") : new JSONArray();
        JSONArray crossBorderArr = langObj.get("cross_border_transfers") instanceof JSONArray
                ? (JSONArray) langObj.get("cross_border_transfers") : new JSONArray();

        JSONArray linkedPolicyIds = new JSONArray();
        linkedPolicyIds.add(policyId);

        UUID entryId = insertDraftEntry(fiduciaryId, activityName, purposeText,
                dataCategoriesArr.toJSONString(), dataSubjectCategoriesArr.toJSONString(),
                linkedPolicyIds.toJSONString(), securityMeasures,
                processorsArr.toJSONString(), crossBorderArr.toJSONString(),
                maxRetentionDays > 0 ? maxRetentionDays : null, retentionStartEvent);

        if (entryId != null) {
            snapshotInitialHistory(entryId);
        }
        return entryId;
    }

    private static String loadPolicyContent(String policyId, String version, UUID fiduciaryId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String sql = "SELECT policy_content FROM consent_policies WHERE id = ? AND version = ? AND fiduciary_id = ? AND status = 'ACTIVE'";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            pstmt.setObject(3, fiduciaryId);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getString(1) : null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private static String buildPurposeText(JSONArray purposes) {
        if (purposes == null || purposes.isEmpty()) return "Processing activities derived from consent policy";
        List<String> names = new ArrayList<>();
        for (Object obj : purposes) {
            JSONObject p = (JSONObject) obj;
            String name = (String) p.get("name");
            if (name == null || name.isEmpty()) name = (String) p.get("id");
            if (name != null) names.add(name);
        }
        return String.join("; ", names);
    }

    private static JSONArray extractCategoryIds(JSONArray categories) {
        JSONArray result = new JSONArray();
        if (categories == null) return result;
        for (Object obj : categories) {
            JSONObject cat = (JSONObject) obj;
            String id = (String) cat.get("id");
            if (id != null) result.add(id);
        }
        return result;
    }

    private static int computeMaxRetentionDays(JSONArray purposes) {
        if (purposes == null) return 0;
        int max = 0;
        for (Object obj : purposes) {
            JSONObject p = (JSONObject) obj;
            Object valObj = p.get("retention_duration_value");
            Object unitObj = p.get("retention_duration_unit");
            if (valObj == null || unitObj == null) continue;
            try {
                int val = (int)(long) valObj;
                int days = toDays(val, unitObj.toString().toUpperCase());
                if (days > max) max = days;
            } catch (Exception ignored) {}
        }
        return max;
    }

    private static int toDays(int value, String unit) {
        switch (unit) {
            case "YEARS":   return value * 365;
            case "MONTHS":  return value * 30;
            case "DAYS":    return value;
            case "HOURS":   return Math.max(1, value / 24);
            case "MINUTES": return Math.max(1, value / 1440);
            default:        return value;
        }
    }

    private static String extractRetentionStartEvent(JSONArray purposes) {
        if (purposes == null || purposes.isEmpty()) return null;
        // When events are mixed, use the event from the longest-retention purpose
        // (most conservative for compliance — don't leave blank for DPO to guess)
        String first = null;
        boolean mixed = false;
        int maxDays = 0;
        String maxEvent = null;
        for (Object obj : purposes) {
            JSONObject p = (JSONObject) obj;
            String e = (String) p.get("retention_start_event");
            if (e == null || e.isEmpty()) continue;
            if (first == null) first = e;
            else if (!first.equals(e)) mixed = true;
            Object valObj  = p.get("retention_duration_value");
            Object unitObj = p.get("retention_duration_unit");
            if (valObj != null && unitObj != null) {
                try {
                    int days = toDays((int)(long) valObj, unitObj.toString().toUpperCase());
                    if (days >= maxDays) { maxDays = days; maxEvent = e; }
                } catch (Exception ignored) {}
            }
        }
        return mixed ? maxEvent : first;
    }

    private static JSONArray extractOrDefault(JSONArray src, String fallback) {
        if (src != null && !src.isEmpty()) return src;
        JSONArray a = new JSONArray();
        a.add(fallback);
        return a;
    }

    private static UUID insertDraftEntry(UUID fiduciaryId, String activityName, String purposeText,
                                         String dataCategories, String dataSubjectCategories,
                                         String linkedPolicyIds, String securityMeasures,
                                         String processors, String crossBorderTransfers,
                                         Integer retentionDays, String retentionStartEvent) throws SQLException {
        String sql = "INSERT INTO ropa_entries " +
                "(fiduciary_id, activity_name, purpose, legal_basis, data_categories, data_subject_categories, " +
                "linked_policy_ids, security_measures, processors, cross_border_transfers, " +
                "retention_period_days, retention_start_event, status, version) " +
                "VALUES (?, ?, ?, 'consent', ?::jsonb, ?::jsonb, ?::jsonb, ?, ?::jsonb, ?::jsonb, ?, ?, 'draft', 1) RETURNING id";

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, activityName);
            pstmt.setString(3, purposeText);
            pstmt.setString(4, dataCategories);
            pstmt.setString(5, dataSubjectCategories);
            pstmt.setString(6, linkedPolicyIds);
            pstmt.setString(7, securityMeasures);
            pstmt.setString(8, processors);
            pstmt.setString(9, crossBorderTransfers);
            if (retentionDays != null) pstmt.setInt(10, retentionDays);
            else pstmt.setNull(10, Types.INTEGER);
            pstmt.setString(11, retentionStartEvent);
            rs = pstmt.executeQuery();
            return rs.next() ? (UUID) rs.getObject(1) : null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private static void snapshotInitialHistory(UUID entryId) throws SQLException {
        String sql = "INSERT INTO ropa_history (ropa_entry_id, version, snapshot) " +
                "SELECT id, version, to_jsonb(ropa_entries) FROM ropa_entries WHERE id = ?";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, entryId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}
