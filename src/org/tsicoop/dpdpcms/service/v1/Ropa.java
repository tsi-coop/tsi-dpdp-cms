package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.util.RopaDeriver;
import org.tsicoop.dpdpcms.util.RopaValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.StringWriter;
import java.sql.*;
import java.util.*;

public class Ropa implements Action {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            req.setCharacterEncoding("UTF-8");
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func'.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "create_entry":            handleCreateEntry(input, res, req);           break;
                case "update_entry":            handleUpdateEntry(input, res, req);           break;
                case "publish_entry":           handlePublishEntry(input, res, req);          break;
                case "retire_entry":            handleRetireEntry(input, res, req);           break;
                case "list_entries":            handleListEntries(input, res, req);           break;
                case "get_entry":               handleGetEntry(input, res, req);              break;
                case "validate_completeness":   handleValidateCompleteness(input, res, req);  break;
                case "export_ropa":             handleExportRopa(input, res, req);            break;
                case "derive_from_policy":      handleDeriveFromPolicy(input, res, req);      break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown '_func': " + func, req.getRequestURI());
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    // --- Handlers ---

    private void handleCreateEntry(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID fiduciaryId = requireUUID(input, "fiduciary_id", res, req);
        if (fiduciaryId == null) return;

        String activityName = (String) input.get("activity_name");
        String purpose      = (String) input.get("purpose");
        String legalBasis   = (String) input.get("legal_basis");

        if (activityName == null || purpose == null || legalBasis == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "activity_name, purpose, and legal_basis are required.", req.getRequestURI());
            return;
        }

        UUID entryId = insertEntry(
                fiduciaryId,
                parseOptionalUUID(input, "app_id"),
                activityName, purpose, legalBasis,
                jsonStr(input, "data_categories", "[]"),
                jsonStr(input, "data_subject_categories", "[]"),
                parseOptionalInt(input, "retention_period_days"),
                (String) input.get("retention_start_event"),
                jsonStr(input, "processors", "[]"),
                jsonStr(input, "cross_border_transfers", "[]"),
                (String) input.get("security_measures"),
                parseOptionalUUID(input, "dpo_id"),
                jsonStr(input, "linked_policy_ids", "[]"),
                "draft", 1);

        snapshotToHistory(entryId, 1, null, null);

        new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, fiduciaryId,
                "ROPA_ENTRY_CREATED", "id:" + entryId);

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("id", entryId.toString());
        out.put("status", "draft");
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, out);
    }

    private void handleUpdateEntry(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws Exception {
        UUID entryId = requireUUID(input, "id", res, req);
        if (entryId == null) return;

        JSONObject existing = getEntryById(entryId);
        if (existing == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "ROPA entry not found.", req.getRequestURI());
            return;
        }

        String status = (String) existing.get("status");
        if ("active".equals(status) || "retired".equals(status)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                    "Cannot edit an entry with status '" + status + "'.", req.getRequestURI());
            return;
        }

        int currentVersion = ((Long) existing.get("version")).intValue();
        UUID changedBy = InputProcessor.getAuthenticatedUserId(req);
        snapshotToHistory(entryId, currentVersion, existing, changedBy);

        int newVersion = currentVersion + 1;
        applyUpdate(entryId, input, newVersion);

        UUID fiduciaryId = UUID.fromString((String) existing.get("fiduciary_id"));
        new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, fiduciaryId,
                "ROPA_ENTRY_UPDATED", "id:" + entryId + " v:" + newVersion);

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("version", (long) newVersion);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
    }

    private void handlePublishEntry(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID entryId = requireUUID(input, "id", res, req);
        if (entryId == null) return;

        JSONObject existing = getEntryById(entryId);
        if (existing == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "ROPA entry not found.", req.getRequestURI());
            return;
        }

        String status = (String) existing.get("status");
        if ("active".equals(status)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Entry is already active.", req.getRequestURI());
            return;
        }
        if ("retired".equals(status)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot publish a retired entry.", req.getRequestURI());
            return;
        }

        // Auto-record publishing DPO from session — sets dpo_id so validator sees it as complete
        UUID dpoFromSession = InputProcessor.getAuthenticatedUserId(req);
        if (dpoFromSession != null) {
            existing.put("dpo_id", dpoFromSession.toString());
            setDpoId(entryId, dpoFromSession);
        }

        JSONArray missingFields = RopaValidator.validate(existing);
        if (!missingFields.isEmpty()) {
            JSONObject err = new JSONObject();
            err.put("success", false);
            err.put("message", "Complete all required fields before publishing.");
            err.put("missing_fields", missingFields);
            OutputProcessor.send(res, HttpServletResponse.SC_BAD_REQUEST, err);
            return;
        }

        transitionStatus(entryId, "active");
        UUID fiduciaryId = UUID.fromString((String) existing.get("fiduciary_id"));
        new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, fiduciaryId,
                "ROPA_ENTRY_PUBLISHED", "id:" + entryId);

        // Activate each linked policy if all its non-retired ROPA entries are now active
        for (String policyId : parseLinkedPolicyIds(existing.get("linked_policy_ids"))) {
            activatePolicyIfComplete(policyId, fiduciaryId);
        }

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("message", "ROPA entry published.");
        OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
    }

    private void handleRetireEntry(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID entryId = requireUUID(input, "id", res, req);
        if (entryId == null) return;

        JSONObject existing = getEntryById(entryId);
        if (existing == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "ROPA entry not found.", req.getRequestURI());
            return;
        }
        if ("retired".equals(existing.get("status"))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Entry is already retired.", req.getRequestURI());
            return;
        }

        transitionStatus(entryId, "retired");
        UUID fiduciaryId = UUID.fromString((String) existing.get("fiduciary_id"));
        new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, fiduciaryId,
                "ROPA_ENTRY_RETIRED", "id:" + entryId);

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("message", "ROPA entry retired.");
        OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
    }

    private void handleListEntries(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID fiduciaryId = requireUUID(input, "fiduciary_id", res, req);
        if (fiduciaryId == null) return;

        String statusFilter    = (String) input.get("status");
        String legalBasisFilter = (String) input.get("legal_basis");
        String appIdStr        = (String) input.get("app_id");
        int page  = (input.get("page")  instanceof Long) ? ((Long) input.get("page")).intValue()  : 1;
        int limit = (input.get("limit") instanceof Long) ? ((Long) input.get("limit")).intValue() : 20;

        JSONArray entries = listEntries(fiduciaryId, statusFilter, legalBasisFilter, appIdStr, page, limit);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, entries);
    }

    private void handleGetEntry(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID entryId = requireUUID(input, "id", res, req);
        if (entryId == null) return;

        JSONObject entry = getEntryById(entryId);
        if (entry == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "ROPA entry not found.", req.getRequestURI());
            return;
        }
        entry.put("consent_count", getConsentCountForEntry(entryId, true));
        entry.put("inactive_consent_count", getConsentCountForEntry(entryId, false));
        entry.put("history", getHistoryForEntry(entryId));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, entry);
    }

    private void handleValidateCompleteness(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID entryId = requireUUID(input, "id", res, req);
        if (entryId == null) return;

        JSONObject entry = getEntryById(entryId);
        if (entry == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "ROPA entry not found.", req.getRequestURI());
            return;
        }

        JSONArray missing = RopaValidator.validate(entry);
        JSONObject out = new JSONObject();
        out.put("complete", missing.isEmpty());
        out.put("missing_fields", missing);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
    }

    private void handleExportRopa(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws Exception {
        UUID fiduciaryId = requireUUID(input, "fiduciary_id", res, req);
        if (fiduciaryId == null) return;

        JSONArray entries = listEntriesWithConsentCount(fiduciaryId);

        res.setContentType("text/csv; charset=UTF-8");
        res.setHeader("Content-Disposition", "attachment; filename=\"ropa_export.csv\"");

        StringWriter sw = new StringWriter();
        CsvWriter csv = new CsvWriter(sw, ',');
        csv.writeRecord(new String[]{
            "ID", "Activity Name", "Purpose", "Legal Basis", "Data Categories",
            "Data Subject Categories", "Retention Period Days", "Retention Start Event",
            "Processors", "Cross Border Transfers", "Security Measures",
            "Status", "Version", "Created At", "Active Consent Count", "Withdrawn Consent Count"
        });

        for (Object obj : entries) {
            JSONObject e = (JSONObject) obj;
            csv.writeRecord(new String[]{
                s(e, "id"), s(e, "activity_name"), s(e, "purpose"), s(e, "legal_basis"),
                s(e, "data_categories"), s(e, "data_subject_categories"),
                e.get("retention_period_days") != null ? e.get("retention_period_days").toString() : "",
                s(e, "retention_start_event"), s(e, "processors"), s(e, "cross_border_transfers"),
                s(e, "security_measures"), s(e, "status"),
                e.get("version") != null ? e.get("version").toString() : "",
                s(e, "created_at"),
                e.get("consent_count") != null ? e.get("consent_count").toString() : "0",
                e.get("inactive_consent_count") != null ? e.get("inactive_consent_count").toString() : "0"
            });
        }
        csv.flush();
        csv.close();
        res.getWriter().write(sw.toString());
    }

    private void handleDeriveFromPolicy(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws Exception {
        UUID fiduciaryId = requireUUID(input, "fiduciary_id", res, req);
        if (fiduciaryId == null) return;

        String policyId = (String) input.get("policy_id");
        if (policyId == null || policyId.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "policy_id is required.", req.getRequestURI());
            return;
        }
        String version = input.get("version") != null ? (String) input.get("version") : "";

        UUID entryId = RopaDeriver.deriveFromPolicy(policyId, version, fiduciaryId);
        if (entryId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "Policy not found or not yet active. Only active policies can be derived.", req.getRequestURI());
            return;
        }

        new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, fiduciaryId,
                "ROPA_ENTRY_DERIVED", "policy:" + policyId + " -> entry:" + entryId);

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("id", entryId.toString());
        out.put("status", "draft");
        out.put("message", "Draft ROPA entry created from policy. Review and complete remaining fields.");
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, out);
    }

    // --- DB operations ---

    private UUID insertEntry(UUID fiduciaryId, UUID appId, String activityName, String purpose,
                              String legalBasis, String dataCategories, String dataSubjectCategories,
                              Integer retentionDays, String retentionStartEvent, String processors,
                              String crossBorderTransfers, String securityMeasures, UUID dpoId,
                              String linkedPolicyIds, String status, int version) throws SQLException {
        String sql = "INSERT INTO ropa_entries " +
                "(fiduciary_id, app_id, activity_name, purpose, legal_basis, data_categories, " +
                "data_subject_categories, retention_period_days, retention_start_event, processors, " +
                "cross_border_transfers, security_measures, dpo_id, linked_policy_ids, status, version) " +
                "VALUES (?,?,?,?,?,?::jsonb,?::jsonb,?,?,?::jsonb,?::jsonb,?,?,?::jsonb,?,?) RETURNING id";

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setObject(2, appId);
            pstmt.setString(3, activityName);
            pstmt.setString(4, purpose);
            pstmt.setString(5, legalBasis);
            pstmt.setString(6, dataCategories);
            pstmt.setString(7, dataSubjectCategories);
            if (retentionDays != null) pstmt.setInt(8, retentionDays);
            else pstmt.setNull(8, Types.INTEGER);
            pstmt.setString(9, retentionStartEvent);
            pstmt.setString(10, processors);
            pstmt.setString(11, crossBorderTransfers);
            pstmt.setString(12, securityMeasures);
            pstmt.setObject(13, dpoId);
            pstmt.setString(14, linkedPolicyIds);
            pstmt.setString(15, status);
            pstmt.setInt(16, version);
            rs = pstmt.executeQuery();
            return rs.next() ? (UUID) rs.getObject(1) : null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void applyUpdate(UUID entryId, JSONObject input, int newVersion) throws SQLException {
        StringBuilder sql = new StringBuilder("UPDATE ropa_entries SET version = ?, updated_at = NOW()");
        List<Object> params = new ArrayList<>();
        params.add(newVersion);

        appendIfPresent(sql, params, input, "activity_name",           false);
        appendIfPresent(sql, params, input, "purpose",                  false);
        appendIfPresent(sql, params, input, "legal_basis",              false);
        appendIfPresent(sql, params, input, "data_categories",          true);
        appendIfPresent(sql, params, input, "data_subject_categories",  true);
        appendIfPresent(sql, params, input, "processors",               true);
        appendIfPresent(sql, params, input, "cross_border_transfers",   true);
        appendIfPresent(sql, params, input, "linked_policy_ids",        true);
        appendIfPresent(sql, params, input, "security_measures",        false);
        appendIfPresent(sql, params, input, "retention_start_event",    false);

        if (input.containsKey("retention_period_days")) {
            sql.append(", retention_period_days = ?");
            params.add(parseOptionalInt(input, "retention_period_days"));
        }
        if (input.containsKey("dpo_id")) {
            sql.append(", dpo_id = ?");
            params.add(parseOptionalUUID(input, "dpo_id"));
        }
        if (input.containsKey("app_id")) {
            sql.append(", app_id = ?");
            params.add(parseOptionalUUID(input, "app_id"));
        }

        sql.append(" WHERE id = ?");
        params.add(entryId);

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) pstmt.setObject(i + 1, params.get(i));
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private void appendIfPresent(StringBuilder sql, List<Object> params, JSONObject input, String field, boolean isJsonb) {
        if (!input.containsKey(field)) return;
        sql.append(", ").append(field).append(" = ?").append(isJsonb ? "::jsonb" : "");
        Object val = input.get(field);
        params.add(val != null ? val.toString() : null);
    }

    private void transitionStatus(UUID entryId, String newStatus) throws SQLException {
        String sql = "UPDATE ropa_entries SET status = ?, updated_at = NOW() WHERE id = ?";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, newStatus);
            pstmt.setObject(2, entryId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private void setDpoId(UUID entryId, UUID dpoId) throws SQLException {
        String sql = "UPDATE ropa_entries SET dpo_id = ?, updated_at = NOW() WHERE id = ?";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, dpoId);
            pstmt.setObject(2, entryId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    public void snapshotToHistory(UUID entryId, int version, JSONObject snapshot, UUID changedBy) throws SQLException {
        // If snapshot is null (initial creation), read from DB via to_jsonb
        String sql = snapshot != null
                ? "INSERT INTO ropa_history (ropa_entry_id, version, snapshot, changed_by) VALUES (?,?,?::jsonb,?)"
                : "INSERT INTO ropa_history (ropa_entry_id, version, snapshot, changed_by) SELECT id, version, to_jsonb(ropa_entries), ? FROM ropa_entries WHERE id = ?";

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            if (snapshot != null) {
                pstmt.setObject(1, entryId);
                pstmt.setInt(2, version);
                pstmt.setString(3, snapshot.toJSONString());
                pstmt.setObject(4, changedBy);
            } else {
                pstmt.setObject(1, changedBy);
                pstmt.setObject(2, entryId);
            }
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    protected JSONObject getEntryById(UUID entryId) throws SQLException {
        String sql = "SELECT id, fiduciary_id, app_id, activity_name, purpose, legal_basis, " +
                "data_categories, data_subject_categories, retention_period_days, retention_start_event, " +
                "processors, cross_border_transfers, security_measures, dpo_id, linked_policy_ids, " +
                "source_purpose_id, status, version, created_at, updated_at FROM ropa_entries WHERE id = ?";

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, entryId);
            rs = pstmt.executeQuery();
            return rs.next() ? mapEntry(rs) : null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private JSONArray listEntries(UUID fiduciaryId, String statusFilter, String legalBasisFilter,
                                   String appIdStr, int page, int limit) throws SQLException {
        StringBuilder sql = new StringBuilder(
                "SELECT r.id, r.fiduciary_id, r.app_id, r.activity_name, r.purpose, r.legal_basis, " +
                "r.data_categories, r.data_subject_categories, r.retention_period_days, r.retention_start_event, " +
                "r.processors, r.cross_border_transfers, r.security_measures, r.dpo_id, r.linked_policy_ids, " +
                "r.source_purpose_id, r.status, r.version, r.created_at, r.updated_at, " +
                "COUNT(c.id) FILTER (WHERE c.is_active_consent = TRUE AND c.purpose_granted = TRUE) AS consent_count, " +
                "COUNT(c.id) FILTER (WHERE c.is_active_consent = FALSE) AS inactive_consent_count " +
                "FROM ropa_entries r " +
                "LEFT JOIN LATERAL (" +
                "  SELECT cr.id, cr.is_active_consent, (dp->>'consent_granted')::boolean AS purpose_granted " +
                "  FROM consent_records cr, jsonb_array_elements(cr.data_point_consents) AS dp " +
                "  WHERE cr.fiduciary_id = r.fiduciary_id AND dp->>'data_point_id' = r.source_purpose_id" +
                ") c ON TRUE " +
                "WHERE r.fiduciary_id = ?");

        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sql.append(" AND r.status = ?");
            params.add(statusFilter);
        }
        if (legalBasisFilter != null && !legalBasisFilter.isEmpty()) {
            sql.append(" AND r.legal_basis = ?");
            params.add(legalBasisFilter);
        }
        if (appIdStr != null && !appIdStr.isEmpty()) {
            sql.append(" AND r.app_id = ?");
            try { params.add(UUID.fromString(appIdStr)); } catch (Exception ignored) {}
        }
        sql.append(" GROUP BY r.id ORDER BY r.created_at DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        JSONArray result = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) pstmt.setObject(i + 1, params.get(i));
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject e = mapEntry(rs);
                e.put("consent_count", rs.getLong("consent_count"));
                e.put("inactive_consent_count", rs.getLong("inactive_consent_count"));
                result.add(e);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private JSONArray getHistoryForEntry(UUID entryId) throws SQLException {
        String sql = "SELECT id, ropa_entry_id, version, snapshot, changed_by, changed_at " +
                "FROM ropa_history WHERE ropa_entry_id = ? ORDER BY version DESC";
        JSONArray history = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, entryId);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject h = new JSONObject();
                h.put("id", rs.getObject("id").toString());
                h.put("version", rs.getLong("version"));
                h.put("changed_by", rs.getObject("changed_by") != null ? rs.getObject("changed_by").toString() : null);
                h.put("changed_at", rs.getTimestamp("changed_at").toInstant().toString());
                String snap = rs.getString("snapshot");
                try { h.put("snapshot", new JSONParser().parse(snap)); }
                catch (Exception e) { h.put("snapshot", snap); }
                history.add(h);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return history;
    }

    private JSONObject mapEntry(ResultSet rs) throws SQLException {
        JSONObject e = new JSONObject();
        e.put("id",                     rs.getObject("id").toString());
        e.put("fiduciary_id",           rs.getObject("fiduciary_id").toString());
        e.put("app_id",                 rs.getObject("app_id") != null ? rs.getObject("app_id").toString() : null);
        e.put("activity_name",          rs.getString("activity_name"));
        e.put("purpose",                rs.getString("purpose"));
        e.put("legal_basis",            rs.getString("legal_basis"));
        e.put("data_categories",        rs.getString("data_categories"));
        e.put("data_subject_categories",rs.getString("data_subject_categories"));
        e.put("retention_period_days",  rs.getObject("retention_period_days") != null ? (long) rs.getInt("retention_period_days") : null);
        e.put("retention_start_event",  rs.getString("retention_start_event"));
        e.put("processors",             rs.getString("processors"));
        e.put("cross_border_transfers", rs.getString("cross_border_transfers"));
        e.put("security_measures",      rs.getString("security_measures"));
        e.put("dpo_id",                 rs.getObject("dpo_id") != null ? rs.getObject("dpo_id").toString() : null);
        e.put("linked_policy_ids",      rs.getString("linked_policy_ids"));
        e.put("source_purpose_id",      rs.getString("source_purpose_id"));
        e.put("status",                 rs.getString("status"));
        e.put("version",                rs.getLong("version"));
        e.put("created_at",             rs.getTimestamp("created_at").toInstant().toString());
        e.put("updated_at",             rs.getTimestamp("updated_at").toInstant().toString());
        return e;
    }

    private long getConsentCountForEntry(UUID entryId, boolean active) throws SQLException {
        String sql = active
            ? "SELECT COUNT(*) FROM ropa_entries r " +
              "JOIN consent_records cr ON cr.fiduciary_id = r.fiduciary_id " +
              "JOIN LATERAL jsonb_array_elements(cr.data_point_consents) AS dp " +
              "  ON dp->>'data_point_id' = r.source_purpose_id " +
              "WHERE r.id = ? AND cr.is_active_consent = TRUE AND (dp->>'consent_granted')::boolean = TRUE"
            : "SELECT COUNT(*) FROM ropa_entries r " +
              "JOIN consent_records cr ON cr.fiduciary_id = r.fiduciary_id " +
              "JOIN LATERAL jsonb_array_elements(cr.data_point_consents) AS dp " +
              "  ON dp->>'data_point_id' = r.source_purpose_id " +
              "WHERE r.id = ? AND cr.is_active_consent = FALSE";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, entryId);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getLong(1) : 0L;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private JSONArray listEntriesWithConsentCount(UUID fiduciaryId) throws SQLException {
        String sql = "SELECT r.id, r.fiduciary_id, r.app_id, r.activity_name, r.purpose, r.legal_basis, " +
                "r.data_categories, r.data_subject_categories, r.retention_period_days, r.retention_start_event, " +
                "r.processors, r.cross_border_transfers, r.security_measures, r.dpo_id, r.linked_policy_ids, " +
                "r.source_purpose_id, r.status, r.version, r.created_at, r.updated_at, " +
                "COUNT(c.id) FILTER (WHERE c.is_active_consent = TRUE AND c.purpose_granted = TRUE) AS consent_count, " +
                "COUNT(c.id) FILTER (WHERE c.is_active_consent = FALSE) AS inactive_consent_count " +
                "FROM ropa_entries r " +
                "LEFT JOIN LATERAL (" +
                "  SELECT cr.id, cr.is_active_consent, (dp->>'consent_granted')::boolean AS purpose_granted " +
                "  FROM consent_records cr, jsonb_array_elements(cr.data_point_consents) AS dp " +
                "  WHERE cr.fiduciary_id = r.fiduciary_id AND dp->>'data_point_id' = r.source_purpose_id" +
                ") c ON TRUE " +
                "WHERE r.fiduciary_id = ? AND r.status = 'active' " +
                "GROUP BY r.id " +
                "ORDER BY r.created_at DESC";
        JSONArray result = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject e = mapEntry(rs);
                e.put("consent_count", rs.getLong("consent_count"));
                e.put("inactive_consent_count", rs.getLong("inactive_consent_count"));
                result.add(e);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    // --- Utility helpers ---

    private UUID requireUUID(JSONObject input, String field, HttpServletResponse res, HttpServletRequest req) {
        String val = (String) input.get(field);
        if (val == null || val.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "'" + field + "' is required.", req.getRequestURI());
            return null;
        }
        try { return UUID.fromString(val); }
        catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "Invalid UUID format for '" + field + "'.", req.getRequestURI());
            return null;
        }
    }

    private UUID parseOptionalUUID(JSONObject input, String field) {
        String val = (String) input.get(field);
        if (val == null || val.isEmpty()) return null;
        try { return UUID.fromString(val); } catch (Exception e) { return null; }
    }

    private Integer parseOptionalInt(JSONObject input, String field) {
        Object val = input.get(field);
        if (val == null) return null;
        if (val instanceof Long) return ((Long) val).intValue();
        try { return Integer.parseInt(val.toString()); } catch (Exception e) { return null; }
    }

    private String jsonStr(JSONObject input, String field, String defaultVal) {
        Object val = input.get(field);
        return val != null ? val.toString() : defaultVal;
    }

    private String s(JSONObject obj, String key) {
        Object val = obj.get(key);
        return val != null ? val.toString() : "";
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }

    // --- Policy activation on ROPA approval ---

    @SuppressWarnings("unchecked")
    private List<String> parseLinkedPolicyIds(Object val) {
        List<String> ids = new ArrayList<>();
        if (val == null) return ids;
        try {
            JSONArray arr = val instanceof JSONArray
                    ? (JSONArray) val
                    : (JSONArray) new JSONParser().parse(val.toString());
            for (Object o : arr) if (o != null) ids.add(o.toString());
        } catch (Exception ignored) {}
        return ids;
    }

    private void activatePolicyIfComplete(String policyId, UUID fiduciaryId) {
        String countSql = "SELECT COUNT(*) FROM ropa_entries " +
                "WHERE linked_policy_ids @> ?::jsonb AND fiduciary_id = ? " +
                "AND status NOT IN ('active', 'retired')";
        String activateSql = "UPDATE consent_policies SET status = 'ACTIVE', last_updated_at = NOW() " +
                "WHERE id = ? AND status = 'UNDER_REVIEW'";
        PoolDB pool = null;
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(countSql);
            pstmt.setString(1, "[\"" + policyId + "\"]");
            pstmt.setObject(2, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next() && rs.getLong(1) == 0) {
                pool.cleanup(rs, pstmt, null);
                rs = null; pstmt = null;
                pstmt = conn.prepareStatement(activateSql);
                pstmt.setString(1, policyId);
                if (pstmt.executeUpdate() > 0) {
                    new Audit().logEventAsync("DPO", fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE,
                            fiduciaryId, "POLICY_ACTIVATED_BY_DPO", "policy:" + policyId);
                }
            }
        } catch (Exception e) {
            System.err.println("Policy activation check failed for " + policyId + ": " + e.getMessage());
        } finally {
            if (pool != null) try { pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }
}
