package org.tsicoop.dpdpcms.job;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.ces.CESService;
import org.tsicoop.dpdpcms.framework.PoolDB;
import org.tsicoop.dpdpcms.framework.SystemConfig;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.sql.*;
import java.sql.Date;
import java.time.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * JobManager orchestrates background tasks like CES and Bulk Exports.
 * It uses a single executor thread to process jobs sequentially from the 'jobs' table.
 */
@WebListener
public class JobManager implements ServletContextListener {

    private ExecutorService executor;
    private volatile boolean running = true;
    private static final String EXPORT_DIR = System.getProperty("os.name").toLowerCase().contains("win") ? "c:/tmp/" : "/tmp/";

    private static final int BATCH_SIZE = 10; // Fixed number of principals to fetch at a time

    // Track the last date a full CES run was scheduled to prevent duplicates
    private LocalDate lastFullRunDate = LocalDate.now().minusDays(1);

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("TSI DPDP CMS: Starting Background Job Manager...");

        // Ensure export directory exists
        File dir = new File(EXPORT_DIR);
        if (!dir.exists()) dir.mkdirs();

        executor = Executors.newSingleThreadExecutor();
        executor.submit(this::pollAndExecute);
    }

    private void pollAndExecute() {
        while (running) {
           try {
                // Sleep for 2 minutes as requested
                TimeUnit.MINUTES.sleep(2);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }

            try {
                // Check for midnight schedule
                scheduleNightlyFullRun();

                // Process Next Job
                processNextPendingJob();
            } catch (Exception e) {
                System.err.println("[JobManager Error] Loop failure: " + e.getMessage());
            }
        }
    }

    /**
     * Checks if it is past midnight and a job hasn't been scheduled for today yet.
     * If so, fetches all active fiduciaries and inserts a CES FULL job for each.
     */
    private void scheduleNightlyFullRun() {
        LocalDate today = LocalDate.now();
        LocalTime now = LocalTime.now();

        // Check if we are past midnight (e.g., 00:00 to 00:05) and haven't run today
        // The loop runs every 2 mins, so checking if hour is 0 is sufficient window.
        if (now.getHour() == 0 && !today.equals(lastFullRunDate)) {
            System.out.println("[JobManager] Initiating Nightly Full CES Run for: " + today);

            PoolDB pool = null;
            Connection conn = null;

            try {
                pool = new PoolDB();
                conn = pool.getConnection();

                // 1. Fetch all active Fiduciary IDs
                List<UUID> activeFiduciaries = new ArrayList<>();
                // Assuming 'status' column exists or similar active check, defaulting to all for now
                String fidSql = "SELECT id FROM fiduciaries where status='ACTIVE'";
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery(fidSql)) {
                    while (rs.next()) {
                        activeFiduciaries.add((UUID) rs.getObject("id"));
                    }
                }

                if (activeFiduciaries.isEmpty()) {
                    System.out.println("[JobManager] No active fiduciaries found. Skipping scheduling.");
                    lastFullRunDate = today;
                    return;
                }

                // 2. Insert CES Job for each Fiduciary
                String insertSql = "INSERT INTO jobs (id, job_type, subtype, status, fiduciary_id, created_at) VALUES (?, 'CES', 'FULL', 'PENDING', ?, NOW())";
                int scheduledCount = 0;

                try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
                    for (UUID fid : activeFiduciaries) {
                        pstmt.setObject(1, UUID.randomUUID());
                        pstmt.setObject(2, fid);
                        pstmt.addBatch();
                        scheduledCount++;
                    }
                    pstmt.executeBatch();
                }

                lastFullRunDate = today; // Mark today as scheduled
                System.out.println("[JobManager] Nightly jobs successfully queued for " + scheduledCount + " fiduciaries.");

            } catch (SQLException e) {
                System.err.println("[JobManager] Failed to schedule nightly job batch: " + e.getMessage());
            } finally {
                if (pool != null && conn != null) pool.cleanup(null, null, conn);
            }
        }
    }

    private void processNextPendingJob() {
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        UUID jobId = null;
        UUID fiduciaryId = null;
        String type = null;
        String subtype = null;
        Date startDate = null;
        Date endDate = null;
        boolean pending = false;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            // Fetch the oldest pending job
            String selectSql = "SELECT * FROM jobs WHERE status = 'PENDING' ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED";
            pstmt = conn.prepareStatement(selectSql);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                jobId = (UUID) rs.getObject("id");
                fiduciaryId = (UUID) rs.getObject("fiduciary_id");
                type = rs.getString("job_type");
                subtype = rs.getString("subtype");
                startDate = rs.getDate("start_date");
                endDate = rs.getDate("end_date");
                pending = true;
            }
        } catch (Exception e) {
            System.err.println("[JobManager] DB Polling error: " + e.getMessage());
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, conn);
        }

        if(pending) {
            updateJobStatus(jobId, "RUNNING", null);

            try {
                if ("CES".equalsIgnoreCase(type)) {
                    executeCESJob(fiduciaryId, subtype);
                } else if ("EXPORT".equalsIgnoreCase(type)) {
                    executeExportJob(fiduciaryId, jobId, subtype, startDate, endDate);
                }
                updateJobStatus(jobId, "COMPLETED", EXPORT_DIR + jobId + ".csv");
            } catch (Exception jobEx) {
                updateJobStatus(jobId, "FAILED", jobEx.getMessage());
            }
        }
    }

    private void executeCESJob(UUID fiduciaryId, String target) {
        System.out.println("[JobManager] Executing Compliance Enforcement Run at "+ LocalDateTime.now()+" Target:"+target+" Pool Status:"+PoolDB.getPoolStatus());
        this.enforce(fiduciaryId, target);
    }

    public void enforce(UUID fiduciaryId, String target) {
        JSONObject principal = null;
        CESService cesService = null;
        try {
            cesService = new CESService();
            // 1. Iterate through all active data principals in batches
            int offset = 0;
            boolean hasMore = true;

            while (hasMore) {
                List<JSONObject> principals = cesService.getPrincipalsBatch(fiduciaryId, target, BATCH_SIZE, offset);

                if (principals.isEmpty()) {
                    hasMore = false;
                } else {
                    Iterator<JSONObject> it = principals.iterator();
                    while(it.hasNext()){
                        principal = (JSONObject) it.next();
                        //System.out.println(principal);
                        // Identify and execute necessary purge requests
                        cesService.processPrincipal(   (String) principal.get("fiduciary_id"),
                                (String) principal.get("user_id"),
                                (Timestamp) principal.get("last_ces_run"),
                                (String) principal.get("consent_mechanism"));
                    }
                    offset += BATCH_SIZE;
                    //System.out.println("Processed batch ending at offset: " + offset);
                }
            }
            //System.out.println("CES execution completed successfully at " + LocalDateTime.now());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Compliance Batch failed due to Database Error: " + e.getMessage(), e);
        }
    }

    /**
     * Returns a java.sql.Date representing the next day of the given date.
     * Uses the local time zone via Calendar.
     * * @param currentDate The starting java.sql.Date
     * @return java.sql.Date representing (currentDate + 1 day)
     */

    public static java.sql.Date getNextDate(java.sql.Date currentDate) {
        if (currentDate == null) {
            return null;
        }

        // Use Calendar to handle month/year transitions (e.g., Dec 31 to Jan 1)
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.setTime(currentDate);
        cal.add(java.util.Calendar.DATE, 1);

        return new java.sql.Date(cal.getTimeInMillis());
    }

    private void executeExportJob(UUID fiduciaryId, UUID jobId, String subtype, Date start, Date end) throws Exception {
        System.out.println("[JobManager] Executing Export: " + subtype+"-"+start+"-"+end);
        String sql = "";

        // Define SQL based on subtype
        switch (subtype.toUpperCase()) {
            case "CONSENT":
                sql = "SELECT user_id as principal, policy_id, jurisdiction, language_selected as language, consent_mechanism as action, ip_address, user_agent, data_point_consents as consents, is_active_consent as active, created_at, last_updated_at, verification_log_id FROM consent_records WHERE fiduciary_id=? AND timestamp BETWEEN ? AND ?";
                break;
            case "PRINCIPAL":
                sql = "SELECT user_id as principal, created_at, last_consent_mechanism as last_action, last_ces_run FROM data_principal WHERE fiduciary_id=? AND created_at BETWEEN ? AND ?";
                break;
            case "COMPLIANCE":
                sql = "SELECT pr.user_id, pr.purpose_id, a.name, pr.trigger_event, pr.status, pr.initiated_at, pr.details FROM purge_requests pr, apps a WHERE pr.app_id=a.id and pr.fiduciary_id=? AND pr.initiated_at BETWEEN ? AND ?";
                break;
            case "GRIEVANCE":
                sql = "SELECT user_id as principal, type, subject, description, submission_timestamp, status, resolution_details FROM grievances WHERE fiduciary_id=? AND submission_timestamp BETWEEN ? AND ?";
                break;
            case "AUDIT":
                sql = "SELECT timestamp, user_id as principal, audit_action as action, context_details FROM audit_logs WHERE fiduciary_id=? AND timestamp BETWEEN ? AND ?";
                break;
            case "PARENT_CONSENT":
                sql = "SELECT verified_at, child_principal_id as principal, guardian_principal_id as guardian, verification_mechanism, provider_name, verification_ref_id, proof_metadata FROM parental_verification_logs WHERE fiduciary_id=? AND verified_at BETWEEN ? AND ?";
                break;
            default:
                throw new Exception("Unknown Export Subtype: " + subtype);
        }
        File outFile = new File(EXPORT_DIR + jobId + ".csv");
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PrintWriter pw = null;
        ResultSetMetaData meta = null;
        end =  getNextDate(end); // to make sure that the current

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setTimestamp(2, new Timestamp(start.getTime()));
            pstmt.setTimestamp(3, new Timestamp(end.getTime()));

            rs = pstmt.executeQuery();
            pw = new PrintWriter(new FileWriter(outFile));

            meta = rs.getMetaData();
            int cols = meta.getColumnCount();

            // Write Header
            for (int i = 1; i <= cols; i++) {
                pw.print(meta.getColumnName(i) + (i < cols ? "," : ""));
            }
            pw.println();

            // Write Rows
            while (rs.next()) {
                for (int i = 1; i <= cols; i++) {
                    String val = rs.getString(i);
                    pw.print((val == null ? "" : "\"" + val.replace("\"", "\"\"") + "\"") + (i < cols ? "," : ""));
                }
                pw.println();
            }
        }catch(Exception e) {
            e.printStackTrace();
        }finally
        {
            pool.cleanup(rs,pstmt,conn);
            if(pw!=null)pw.close();
        }
    }


    private void updateJobStatus(UUID jobId, String status, String info) {
        Connection conn = null;
        PoolDB pool = null;
        PreparedStatement pstmt = null;
        String sql = "UPDATE jobs SET status = ?, started_at = CASE WHEN ? = 'RUNNING' THEN NOW() ELSE started_at END, " +
                "completed_at = CASE WHEN ? IN ('COMPLETED', 'FAILED') THEN NOW() ELSE completed_at END, ";

        if ("FAILED".equals(status)) {
            sql += "error_message = ? WHERE id = ?";
        } else {
            sql += "output_file_path = ? WHERE id = ?";
        }

        try{
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, status);
            pstmt.setString(2, status);
            pstmt.setString(3, status);
            pstmt.setString(4, info);
            pstmt.setObject(5, jobId);
            pstmt.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }finally{
            pool.cleanup(null,pstmt,conn);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        running = false;
        if (executor != null) {
            executor.shutdownNow();
        }
    }
}
