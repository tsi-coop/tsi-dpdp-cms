package org.tsicoop.dpdpcms.ces;

import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.framework.BatchDB;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

/**
 * CESLauncher orchestrates the nightly compliance batch process.
 * It identifies principals requiring data purging or compliance notifications.
 */
public class CESLauncher {
    private static final String FULL_MODE = "FULL";
    private static final String INCREMENTAL_MODE = "INCREMENTAL";
    private static final int BATCH_SIZE = 100; // Fixed number of principals to fetch at a time


    /**
     * Entry point for enforcement logic.
     * @param mode "FULL" or "INCREMENTAL"
     */
    public void enforce(Properties config, String mode) {
        System.out.println("Starting CES in mode: " + mode + " at " + LocalDateTime.now());
        BatchDB batchdb = null;
        JSONObject principal = null;
        CESService cesService = null;

        try {
            batchdb = new BatchDB(config);
            cesService = new CESService(batchdb);
            // 1. Iterate through all active data principals in batches
            int offset = 0;
            boolean hasMore = true;

            while (hasMore) {
                List<JSONObject> principals = cesService.getPrincipalsBatch(BATCH_SIZE, offset);

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
                    System.out.println("Processed batch ending at offset: " + offset);
                }
            }

            System.out.println("CES execution completed successfully at " + LocalDateTime.now());
        } catch (Exception e) {
            throw new RuntimeException("Compliance Batch failed due to Database Error: " + e.getMessage(), e);
        }
    }

    public static void main(String[] args) {
        CESLauncher launcher = new CESLauncher();
        String runMode = (args.length > 0) ? args[0] : FULL_MODE;

        Properties config = new Properties();
        config.setProperty("framework.db.host","jdbc:postgresql://localhost:5433");
        config.setProperty("framework.db.name","tsi_dpdp_cms");
        config.setProperty("framework.db.user","postgres");
        config.setProperty("framework.db.password","India2050");

        try {
            launcher.enforce(config, runMode);
        } catch (Exception e) {
            System.err.println("CRITICAL FAILURE in Compliance Enforcement Service: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}