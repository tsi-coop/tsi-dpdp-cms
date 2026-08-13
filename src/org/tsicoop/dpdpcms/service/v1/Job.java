package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.io.*;
import java.sql.*;
import java.util.UUID;

/**
 * Job Service acts as the controller for background compliance operations.
 * It writes new job requests to the 'jobs' table for pick-up by the JobManager
 * and provides status updates to the DPO console.
 */
public class Job implements Action {

    private static final String EXPORT_DIR = System.getenv("TSI_EXPORT_PATH") != null
            ? System.getenv("TSI_EXPORT_PATH")
            : "/var/lib/tsi/exports/";

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            req.setCharacterEncoding("UTF-8");

            // Handle both JSON Body (Management) and Query Params (Downloads)
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null) {
                func = req.getParameter("_func");
            }

            if (func == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Missing Function", "Parameter _func is required.", req.getRequestURI());
                return;
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = (String) input.get("fiduciary_id");
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func) {
                case "create_job":
                    // Manual CES (compliance scan) runs stay DPO/ADMIN-only; EXPORT jobs (reports)
                    // remain available to Operators for their view/download access.
                    if ("CES".equalsIgnoreCase((String) input.get("job_type")) && InputProcessor.rejectIfOperator(req, res)) return;
                    handleCreateJob(fiduciaryId, input, req, res);
                    break;
                case "list_jobs":
                    handleListJobs(fiduciaryId, input, req, res);
                    break;
                case "download_file":
                    handleDownloadFile(req, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Invalid Function", "Unsupported job operation: " + func, req.getRequestURI());
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Job.service: " + e);
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Service Error", "An internal error occurred.", req.getRequestURI());
        }
    }

    /**
     * Submits a new background task into the jobs queue.
     * Status is set to 'PENDING' for the JobManager thread to process.
     */
    private void handleCreateJob(UUID fiduciaryId, JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        UUID[] fidHolder = { fiduciaryId };
        if (!scopeFiduciaryIdToCaller(fidHolder, req, res)) return; // error already sent
        fiduciaryId = fidHolder[0];

        String jobType = (String) input.get("job_type"); // CES or EXPORT
        String subtype = (String) input.get("subtype");   // CONSENT, PRINCIPAL, etc.
        String startDate = (String) input.get("start_date");
        String endDate = (String) input.get("end_date");

        String sql = "INSERT INTO jobs (id, fiduciary_id, job_type, subtype, start_date, end_date, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', NOW())";
        Connection conn = null;
        PreparedStatement pstmt = null;

        PoolDB pool = new PoolDB();
        try{
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);

            UUID jobId = UUID.randomUUID();
            pstmt.setObject(1, jobId);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setString(3, jobType != null ? jobType : "EXPORT");
            pstmt.setString(4, subtype != null ? subtype : null);

            // Convert String dates from frontend to SQL Dates
            pstmt.setDate(5, convert(startDate));
            pstmt.setDate(6, convert(endDate));

            pstmt.executeUpdate();

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("job_id", jobId.toString());
            result.put("message", "Job queued for background execution.");
            OutputProcessor.send(res, HttpServletResponse.SC_CREATED, result);
        }finally {
            pool.cleanup(null,pstmt,conn);
        }
    }

    private java.sql.Date convert(String startDate) {
        if (startDate != null && !startDate.isEmpty()) {
            return java.sql.Date.valueOf(startDate);
        }
        return null;
    }

    /**
     * Retrieves the status of the last 20 jobs for the DPO Monitor.
     */
    private void handleListJobs(UUID fiduciaryId, JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        UUID[] fidHolder = { fiduciaryId };
        if (!scopeFiduciaryIdToCaller(fidHolder, req, res)) return; // error already sent
        fiduciaryId = fidHolder[0];

        JSONArray jobs = new JSONArray();
        String jobType = (String) input.get("job_type");
        boolean hasJobType = jobType != null && (jobType.equals("CES") || jobType.equals("EXPORT"));
        String sql = null;
        if (hasJobType) {
            sql = "SELECT id, fiduciary_id, job_type, subtype, status, created_at FROM jobs where fiduciary_id=? AND job_type=? ORDER BY created_at DESC LIMIT 20";
        } else {
            sql = "SELECT id, fiduciary_id, job_type, subtype, status, created_at FROM jobs where fiduciary_id=? ORDER BY created_at DESC LIMIT 20";
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try{
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            if (hasJobType) {
                pstmt.setString(2, jobType);
            }
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject job = new JSONObject();
                job.put("id", rs.getObject("id").toString());
                job.put("job_type", rs.getString("job_type"));
                job.put("subtype", rs.getString("subtype"));
                job.put("status", rs.getString("status"));
                job.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                jobs.add(job);
            }
            OutputProcessor.send(res, HttpServletResponse.SC_OK, jobs);
        }finally{
            pool.cleanup(rs,pstmt,conn);
        }
    }

    private static final java.util.regex.Pattern UUID_PATTERN =
            java.util.regex.Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    /**
     * Streams a completed CSV artifact to the client.
     */
    private void handleDownloadFile(HttpServletRequest req, HttpServletResponse res) throws IOException, SQLException {
        if (req.getAttribute(InputProcessor.AUTH_TOKEN) == null) {
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required.");
            return;
        }

        String jobId = req.getParameter("job_id");
        if (jobId == null || !UUID_PATTERN.matcher(jobId.trim()).matches()) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid or missing job_id.");
            return;
        }
        jobId = jobId.trim();

        // Verify the job belongs to the caller's own fiduciary before streaming its file -
        // otherwise any authenticated operator could download any tenant's export by job_id.
        UUID jobFiduciaryId = getJobFiduciaryId(UUID.fromString(jobId));
        if (jobFiduciaryId == null) {
            res.sendError(HttpServletResponse.SC_NOT_FOUND, "The requested export file is not available or has expired.");
            return;
        }
        String callerRole = InputProcessor.getVerifiedRole(req);
        if (!"ADMIN".equalsIgnoreCase(callerRole)) {
            UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);
            UUID callerFid = loginUserId != null ? getCallerFiduciaryId(loginUserId) : null;
            if (callerFid == null || !callerFid.equals(jobFiduciaryId)) {
                res.sendError(HttpServletResponse.SC_FORBIDDEN, "You are not permitted to download this file.");
                return;
            }
        }

        File file = new File(EXPORT_DIR + jobId + ".csv");
        try {
            String canonical = file.getCanonicalPath();
            if (!canonical.startsWith(new File(EXPORT_DIR).getCanonicalPath())) {
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid job_id.");
                return;
            }
        } catch (IOException e) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid job_id.");
            return;
        }

        if (!file.exists()) {
            res.sendError(HttpServletResponse.SC_NOT_FOUND, "The requested export file is not available or has expired.");
            return;
        }

        // Set Headers for CSV Download
        res.setContentType("text/csv");
        res.setCharacterEncoding("UTF-8");
        res.setHeader("Content-Disposition", "attachment; filename=\"TSI_DPDP_Export_" + jobId.substring(0,8) + ".csv\"");
        res.setContentLength((int) file.length());

        // Stream from Disk to Response Output
        try (FileInputStream in = new FileInputStream(file);
             OutputStream out = res.getOutputStream()) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            out.flush();
        }
    }

    /**
     * For non-ADMIN callers, forces fiduciaryIdHolder[0] to the caller's own bound
     * fiduciary, ignoring whatever the client supplied - otherwise any authenticated
     * DPO/Operator could create or list jobs for a fiduciary that isn't theirs.
     * ADMIN callers keep the client-supplied value (including null) unchanged.
     * Returns false (and sends a 403) if a non-ADMIN caller isn't bound to any fiduciary.
     */
    private boolean scopeFiduciaryIdToCaller(UUID[] fiduciaryIdHolder, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        String callerRole = InputProcessor.getVerifiedRole(req);
        if ("ADMIN".equalsIgnoreCase(callerRole)) {
            return true;
        }
        UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);
        UUID callerFid = loginUserId != null ? getCallerFiduciaryId(loginUserId) : null;
        if (callerFid == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Caller is not bound to a fiduciary.", req.getRequestURI());
            return false;
        }
        fiduciaryIdHolder[0] = callerFid;
        return true;
    }

    /** Looks up the fiduciary_id an operator account is bound to (null for ADMIN accounts). */
    private UUID getCallerFiduciaryId(UUID operatorId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fiduciary_id FROM operators WHERE id = ?");
            pstmt.setObject(1, operatorId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                return (UUID) rs.getObject("fiduciary_id");
            }
            return null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /** Looks up which fiduciary a job belongs to (null if the job doesn't exist). */
    private UUID getJobFiduciaryId(UUID jobId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fiduciary_id FROM jobs WHERE id = ?");
            pstmt.setObject(1, jobId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                return (UUID) rs.getObject("fiduciary_id");
            }
            return null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
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