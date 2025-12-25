package org.tsicoop.dpdpcms.ces;

import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.framework.BatchDB;
import org.tsicoop.dpdpcms.framework.PoolDB;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
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
    private final CESService cesService = new CESService();

    /**
     * Entry point for enforcement logic.
     * @param mode "FULL" or "INCREMENTAL"
     */
    public void enforce(Properties config, String mode) {
        System.out.println("Starting CES in mode: " + mode + " at " + LocalDateTime.now());
        BatchDB batchdb = null;
        JSONObject principal = null;

        try {
            batchdb = new BatchDB(config);
            // 1. Iterate through all active data principals in batches
            int offset = 0;
            boolean hasMore = true;

            while (hasMore) {
                List<JSONObject> principals = cesService.getPrincipalsBatch(batchdb, BATCH_SIZE, offset);

                if (principals.isEmpty()) {
                    hasMore = false;
                } else {
                    Iterator<JSONObject> it = principals.iterator();
                    while(it.hasNext()){
                        principal = (JSONObject) it.next();
                        System.out.println(principal);
                        // Identify and execute necessary purge requests
                        cesService.processPrincipalPurge(batchdb, (String) principal.get("user_id"), (String) principal.get("purged_at"));
                    }
                    offset += BATCH_SIZE;
                    System.out.println("Processed batch ending at offset: " + offset);
                }
            }

            System.out.println("CES execution completed successfully at " + LocalDateTime.now());
        } catch (SQLException e) {
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