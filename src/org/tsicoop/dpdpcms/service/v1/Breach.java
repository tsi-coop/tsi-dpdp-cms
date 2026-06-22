package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.ces.CESService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;

import java.io.ByteArrayOutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Breach Notification service (DPDP Act Section 8(6)).
 * Lets a DPO report a personal data breach, notifies every affected Data
 * Principal via the existing notifications table -- either the generic
 * BREACH_NOTIFICATION type or a DPO-defined category (e.g.
 * BREACH_NOTIFICATION_PHISHING) configured via the Settings console screen --
 * tracks the incident's status, and produces a downloadable PDF report
 * suitable for management/Data Protection Board review.
 *
 * NOTE ON DATABASE SCHEMA (db/06_breach.sql, db/07_notification_message_templates.sql):
 * - Table 'breach_incidents': id (UUID PK), fiduciary_id (UUID), title, description,
 *   detected_at, reported_at, affected_purpose_id, affected_data_categories (JSONB),
 *   actionable_steps, severity, status, resolution_notes, affected_principal_count,
 *   notification_type, created_by_user_id, created_at, last_updated_at.
 * - Table 'breach_affected_principals': breach_id (UUID), user_id, notified_at.
 */
public class Breach implements Action {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONArray outputArray = null;
        UUID appId = null;
        UUID loginUserId = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            String apiKey = req.getHeader("X-API-Key");
            String apiSecret = req.getHeader("X-API-Secret");
            loginUserId = InputProcessor.getAuthenticatedUserId(req);
            appId = new ApiKey().getAppId(apiKey, apiSecret);

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = input.get("fiduciary_id") != null ? (String) input.get("fiduciary_id")
                    : (apiKey != null ? new Fiduciary().getFiduciaryId(UUID.fromString(apiKey), apiSecret) : null);
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                case "report_breach": {
                    if (InputProcessor.rejectIfOperator(req, res)) return;
                    String title = (String) input.get("title");
                    String description = (String) input.get("description");
                    String detectedAtStr = (String) input.get("detected_at");
                    String actionableSteps = (String) input.get("actionable_steps");
                    String severity = input.get("severity") != null ? (String) input.get("severity") : "MEDIUM";
                    String affectedPurposeId = (String) input.get("affected_purpose_id");
                    JSONArray affectedDataCategories = (JSONArray) input.get("affected_data_categories");
                    JSONArray explicitUserIds = (JSONArray) input.get("affected_user_ids");
                    String affectedUserIdsCsv = (String) input.get("affected_user_ids_csv");
                    String breachCategory = (String) input.get("breach_category");

                    if (fiduciaryId == null || title == null || title.isEmpty() || description == null || description.isEmpty()
                            || detectedAtStr == null || detectedAtStr.isEmpty() || actionableSteps == null || actionableSteps.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                                "'fiduciary_id', 'title', 'description', 'detected_at', and 'actionable_steps' are required for 'report_breach'.", req.getRequestURI());
                        return;
                    }

                    Timestamp detectedAt;
                    try {
                        detectedAt = Timestamp.from(Instant.parse(detectedAtStr));
                    } catch (Exception e) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'detected_at' timestamp format.", req.getRequestURI());
                        return;
                    }

                    // DPO-defined breach category (e.g. "phishing") -> BREACH_NOTIFICATION_PHISHING, so a
                    // DPO-configured message for that exact type surfaces via the existing list_notifications
                    // JOIN. Falls back to the generic BREACH_NOTIFICATION type when no category is given.
                    String notificationType = (breachCategory != null && !breachCategory.trim().isEmpty())
                            ? Constants.NOTIF_BREACH + "_" + breachCategory.trim().toUpperCase().replaceAll("[^A-Z0-9_]", "_")
                            : Constants.NOTIF_BREACH;

                    JSONObject output = reportBreach(fiduciaryId, title, description, detectedAt, severity, actionableSteps,
                            affectedPurposeId, affectedDataCategories, explicitUserIds, affectedUserIdsCsv, notificationType, loginUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;
                }

                case "list_breaches": {
                    if (fiduciaryId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'fiduciary_id' is required for 'list_breaches'.", req.getRequestURI());
                        return;
                    }
                    String statusFilter = (String) input.get("status");
                    int page = (input.get("page") instanceof Long) ? ((Long) input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long) input.get("limit")).intValue() : 20;

                    outputArray = listBreachesFromDb(fiduciaryId, statusFilter, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;
                }

                case "get_breach": {
                    String id = (String) input.get("id");
                    if (id == null || id.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'id' is required for 'get_breach'.", req.getRequestURI());
                        return;
                    }
                    JSONObject breach = getBreachFromDb(UUID.fromString(id));
                    if (breach == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Breach incident not found.", req.getRequestURI());
                        return;
                    }
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, breach);
                    break;
                }

                case "update_breach_status": {
                    if (InputProcessor.rejectIfOperator(req, res)) return;
                    String id = (String) input.get("id");
                    String status = (String) input.get("status");
                    String resolutionNotes = (String) input.get("resolution_notes");
                    if (id == null || id.isEmpty() || status == null || status.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'id' and 'status' are required for 'update_breach_status'.", req.getRequestURI());
                        return;
                    }
                    updateBreachStatus(UUID.fromString(id), status, resolutionNotes, loginUserId, appId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "Breach status updated."); }});
                    break;
                }

                case "download_breach_report": {
                    String id = (String) input.get("id");
                    if (id == null || id.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'id' is required for 'download_breach_report'.", req.getRequestURI());
                        return;
                    }
                    streamBreachReportPdf(UUID.fromString(id), res, req);
                    break;
                }

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid UUID or date format in input: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Breach Notification operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    // --- Helper Methods ---

    /**
     * Resolves the affected principal set, inserts the incident + affected-principal
     * rows, and notifies each affected principal via the existing notification
     * mechanism (CESService.insertNotification, unmodified) using notificationType --
     * either the generic BREACH_NOTIFICATION or a DPO-defined category such as
     * BREACH_NOTIFICATION_PHISHING. Any DPO-configured message for that exact type
     * surfaces automatically via Notification.java's existing list_notifications JOIN.
     */
    private JSONObject reportBreach(UUID fiduciaryId, String title, String description, Timestamp detectedAt,
                                     String severity, String actionableSteps, String affectedPurposeId,
                                     JSONArray affectedDataCategories, JSONArray explicitUserIds, String affectedUserIdsCsv,
                                     String notificationType, UUID loginUserId) throws SQLException {
        Set<String> affectedUserIds = new LinkedHashSet<>();
        if (explicitUserIds != null) {
            for (Object o : explicitUserIds) {
                if (o != null) affectedUserIds.add(o.toString());
            }
        }
        if (affectedPurposeId != null && !affectedPurposeId.isEmpty()) {
            affectedUserIds.addAll(resolveAffectedPrincipalsByPurpose(fiduciaryId, affectedPurposeId));
        }

        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        UUID breachId = null;

        String sqlInsert = "INSERT INTO breach_incidents (fiduciary_id, title, description, detected_at, affected_purpose_id, " +
                "affected_data_categories, actionable_steps, severity, affected_principal_count, created_by_user_id, notification_type) " +
                "VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlInsert);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, title);
            pstmt.setString(3, description);
            pstmt.setTimestamp(4, detectedAt);
            pstmt.setString(5, affectedPurposeId);
            pstmt.setString(6, affectedDataCategories != null ? affectedDataCategories.toJSONString() : "[]");
            pstmt.setString(7, actionableSteps);
            pstmt.setString(8, severity);
            pstmt.setInt(9, affectedUserIds.size());
            pstmt.setObject(10, loginUserId);
            pstmt.setString(11, notificationType);

            rs = pstmt.executeQuery();
            if (rs.next()) {
                breachId = (UUID) rs.getObject("id");
            } else {
                throw new SQLException("Reporting breach failed, no ID obtained.");
            }

            if (!affectedUserIds.isEmpty()) {
                String sqlAffected = "INSERT INTO breach_affected_principals (breach_id, user_id) VALUES (?, ?)";
                pstmt.close();
                pstmt = conn.prepareStatement(sqlAffected);
                for (String userId : affectedUserIds) {
                    pstmt.setObject(1, breachId);
                    pstmt.setString(2, userId);
                    pstmt.addBatch();
                }
                pstmt.executeBatch();
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        final UUID finalBreachId = breachId;
        new Audit().logEventAsync(loginUserId != null ? loginUserId.toString() : "SYSTEM", fiduciaryId,
                Constants.SERVICE_TYPE_DPO_CONSOLE, loginUserId, "BREACH_REPORTED",
                new JSONObject() {{ put("breach_id", finalBreachId.toString()); put("title", title); put("affected_count", affectedUserIds.size()); }}.toJSONString());

        // Notify every affected principal via the existing notification mechanism.
        // Fire-and-forget per principal -- one failed notification must not fail the report.
        for (String userId : affectedUserIds) {
            try {
                new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), notificationType);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        // A CSV upload can contain far more principals than the textarea path -- defer
        // parsing + notification fan-out to JobManager's background poller instead of
        // doing it on this request thread, the same way CES/EXPORT jobs are handled.
        boolean csvJobQueued = false;
        if (affectedUserIdsCsv != null && !affectedUserIdsCsv.trim().isEmpty()) {
            enqueueBreachNotifyJob(fiduciaryId, breachId, affectedUserIdsCsv);
            csvJobQueued = true;
        }

        JSONObject output = new JSONObject();
        output.put("success", true);
        output.put("id", breachId.toString());
        output.put("affected_principal_count", affectedUserIds.size());
        output.put("csv_job_queued", csvJobQueued);
        return output;
    }

    /**
     * Queues a BREACH_NOTIFY background job so JobManager can parse the uploaded CSV
     * and notify each affected principal without blocking the report_breach request.
     */
    private void enqueueBreachNotifyJob(UUID fiduciaryId, UUID breachId, String csvPayload) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                    "INSERT INTO jobs (id, fiduciary_id, job_type, subtype, status, input_payload, created_at) " +
                            "VALUES (uuid_generate_v4(), ?, 'BREACH_NOTIFY', ?, 'PENDING', ?, NOW())");
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, breachId.toString());
            pstmt.setString(3, csvPayload);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Read-only lookup of principals with an active, granted consent for the given
     * purpose under this fiduciary -- mirrors the resolution style already used in
     * CESService.getAppIdsByPurpose, but scoped to consent_records/principals.
     */
    private List<String> resolveAffectedPrincipalsByPurpose(UUID fiduciaryId, String purposeId) throws SQLException {
        List<String> userIds = new ArrayList<>();
        String sql = "SELECT DISTINCT user_id FROM consent_records cr " +
                "WHERE cr.fiduciary_id = ? AND cr.is_active_consent = TRUE " +
                "AND EXISTS (SELECT 1 FROM jsonb_array_elements(cr.data_point_consents) elem " +
                "WHERE elem->>'data_point_id' = ? AND (elem->>'consent_granted')::boolean = TRUE)";

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, purposeId);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                userIds.add(rs.getString("user_id"));
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return userIds;
    }

    private JSONArray listBreachesFromDb(UUID fiduciaryId, String statusFilter, int page, int limit) throws SQLException {
        JSONArray result = new JSONArray();
        StringBuilder sqlBuilder = new StringBuilder(
                "SELECT id, title, severity, status, affected_principal_count, detected_at, reported_at, notification_type FROM breach_incidents WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        sqlBuilder.append(" ORDER BY reported_at DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject row = new JSONObject();
                row.put("id", rs.getString("id"));
                row.put("title", rs.getString("title"));
                row.put("severity", rs.getString("severity"));
                row.put("status", rs.getString("status"));
                row.put("affected_principal_count", rs.getInt("affected_principal_count"));
                row.put("detected_at", rs.getTimestamp("detected_at").toInstant().toString());
                row.put("reported_at", rs.getTimestamp("reported_at").toInstant().toString());
                row.put("notification_type", rs.getString("notification_type"));
                result.add(row);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private JSONObject getBreachFromDb(UUID id) throws SQLException {
        JSONObject breach = null;
        String sql = "SELECT id, fiduciary_id, title, description, detected_at, reported_at, affected_purpose_id, " +
                "affected_data_categories, actionable_steps, severity, status, resolution_notes, affected_principal_count, notification_type " +
                "FROM breach_incidents WHERE id = ?";

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                breach = mapBreachRow(rs);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        if (breach != null) {
            breach.put("affected_principals", listAffectedPrincipals(id));
        }
        return breach;
    }

    private JSONObject mapBreachRow(ResultSet rs) throws SQLException {
        JSONObject breach = new JSONObject();
        breach.put("id", rs.getString("id"));
        breach.put("fiduciary_id", rs.getString("fiduciary_id"));
        breach.put("title", rs.getString("title"));
        breach.put("description", rs.getString("description"));
        breach.put("detected_at", rs.getTimestamp("detected_at").toInstant().toString());
        breach.put("reported_at", rs.getTimestamp("reported_at").toInstant().toString());
        breach.put("affected_purpose_id", rs.getString("affected_purpose_id"));
        breach.put("actionable_steps", rs.getString("actionable_steps"));
        breach.put("severity", rs.getString("severity"));
        breach.put("status", rs.getString("status"));
        breach.put("resolution_notes", rs.getString("resolution_notes"));
        breach.put("affected_principal_count", rs.getInt("affected_principal_count"));
        breach.put("notification_type", rs.getString("notification_type"));
        return breach;
    }

    private JSONArray listAffectedPrincipals(UUID breachId) throws SQLException {
        JSONArray result = new JSONArray();
        String sql = "SELECT user_id, notified_at FROM breach_affected_principals WHERE breach_id = ? ORDER BY notified_at ASC";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, breachId);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject row = new JSONObject();
                row.put("user_id", rs.getString("user_id"));
                row.put("notified_at", rs.getTimestamp("notified_at").toInstant().toString());
                result.add(row);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private void updateBreachStatus(UUID id, String status, String resolutionNotes, UUID loginUserId, UUID appId) throws SQLException {
        String sql = "UPDATE breach_incidents SET status = ?, resolution_notes = ?, last_updated_at = NOW() WHERE id = ?";
        String sqlFetchFiduciary = "SELECT fiduciary_id FROM breach_incidents WHERE id = ?";

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        UUID fiduciaryId = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, status);
            pstmt.setString(2, resolutionNotes);
            pstmt.setObject(3, id);
            int affected = pstmt.executeUpdate();
            if (affected == 0) {
                throw new SQLException("Updating breach status failed, breach incident not found.");
            }

            pstmt.close();
            pstmt = conn.prepareStatement(sqlFetchFiduciary);
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                fiduciaryId = (UUID) rs.getObject("fiduciary_id");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        String serviceType = appId != null ? Constants.SERVICE_TYPE_APP : Constants.SERVICE_TYPE_DPO_CONSOLE;
        new Audit().logEventAsync(loginUserId != null ? loginUserId.toString() : "SYSTEM", fiduciaryId,
                serviceType, loginUserId, "BREACH_STATUS_UPDATED",
                new JSONObject() {{ put("breach_id", id.toString()); put("status", status); put("resolution_notes", resolutionNotes); }}.toJSONString());
    }

    /**
     * Builds a PDF for one breach incident and streams it inline as the HTTP
     * response body -- a single incident's report is small/instant, so this is
     * synchronous rather than routed through Job.java's async CSV-export pipeline.
     */
    private void streamBreachReportPdf(UUID id, HttpServletResponse res, HttpServletRequest req) throws Exception {
        JSONObject breach = getBreachFromDb(id);
        if (breach == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Breach incident not found.", req.getRequestURI());
            return;
        }
        String status = (String) breach.get("status");
        if (!"CONTAINED".equals(status) && !"RESOLVED".equals(status)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "PDF report is only available once the breach is CONTAINED or RESOLVED (current status: " + status + ").", req.getRequestURI());
            return;
        }
        String fiduciaryName = getFiduciaryName(UUID.fromString((String) breach.get("fiduciary_id")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 50, 50, 50, 50);
        PdfWriter.getInstance(document, baos);
        document.open();

        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18);
        Font headingFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12);
        Font bodyFont = FontFactory.getFont(FontFactory.HELVETICA, 11);
        Font footerFont = FontFactory.getFont(FontFactory.HELVETICA_OBLIQUE, 9);

        document.add(new Paragraph("Personal Data Breach Report", titleFont));
        document.add(new Paragraph(" "));
        document.add(new Paragraph("Data Fiduciary: " + fiduciaryName, bodyFont));
        document.add(new Paragraph("Incident ID: " + breach.get("id"), bodyFont));
        document.add(new Paragraph("Severity: " + breach.get("severity"), bodyFont));
        document.add(new Paragraph("Status: " + breach.get("status"), bodyFont));
        document.add(new Paragraph("Detected At: " + breach.get("detected_at"), bodyFont));
        document.add(new Paragraph("Reported At: " + breach.get("reported_at"), bodyFont));
        document.add(new Paragraph(" "));

        document.add(new Paragraph("Description", headingFont));
        document.add(new Paragraph(String.valueOf(breach.get("description")), bodyFont));
        document.add(new Paragraph(" "));

        if (breach.get("affected_purpose_id") != null) {
            document.add(new Paragraph("Affected Purpose", headingFont));
            document.add(new Paragraph(String.valueOf(breach.get("affected_purpose_id")), bodyFont));
            document.add(new Paragraph(" "));
        }

        document.add(new Paragraph("Affected Data Principals", headingFont));
        document.add(new Paragraph("Count notified: " + breach.get("affected_principal_count"), bodyFont));
        document.add(new Paragraph(" "));

        document.add(new Paragraph("Actionable Steps Communicated to Affected Principals", headingFont));
        document.add(new Paragraph(String.valueOf(breach.get("actionable_steps")), bodyFont));
        document.add(new Paragraph(" "));

        if (breach.get("resolution_notes") != null) {
            document.add(new Paragraph("Resolution Notes", headingFont));
            document.add(new Paragraph(String.valueOf(breach.get("resolution_notes")), bodyFont));
            document.add(new Paragraph(" "));
        }

        Paragraph footer = new Paragraph("Generated " + Instant.now() + " -- Prepared for management / Data Protection Board review.", footerFont);
        footer.setAlignment(Element.ALIGN_LEFT);
        document.add(footer);

        document.close();

        byte[] pdfBytes = baos.toByteArray();
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"breach-report-" + id + ".pdf\"");
        res.setContentLength(pdfBytes.length);
        res.getOutputStream().write(pdfBytes);
        res.getOutputStream().flush();
    }

    private String getFiduciaryName(UUID fiduciaryId) throws SQLException {
        String sql = "SELECT name FROM fiduciaries WHERE id = ?";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getString("name");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return fiduciaryId.toString();
    }
}
