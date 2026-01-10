package org.tsicoop.dpdpcms.ces;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.framework.SystemConfig;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * CESContextListener initializes the Compliance Enforcement Service background worker.
 * It ensures that the lifecycle enforcement logic (purging, notifications)
 * runs automatically every 5 minutes while the server is active.
 */
@WebListener
public class CESContextListener implements ServletContextListener {

    private static final int BATCH_SIZE = 10; // Fixed number of principals to fetch at a time

    private ScheduledExecutorService scheduler;

    /**
     * Triggered when the web application is deployed/started.
     * Sets up the recurring execution of the CES batch.
     */
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("Initializing Compliance Enforcement background worker...");

        // Use a single-thread scheduled executor to ensure only one instance
        // of the batch runs at any given time.
        scheduler = Executors.newSingleThreadScheduledExecutor();

        // Schedule the task:
        // Initial delay: 5 minute (allows system startup to stabilize)
        // Period: 2 minutes (for testing purposes)
        scheduler.scheduleAtFixedRate(() -> {
            try {
                System.out.println("CES RUN: Starting automated incremental check...");
                this.enforce(SystemConfig.getAppConfig());

            } catch (Exception e) {
                System.err.println("CES RUN ERROR: Automated compliance batch failed: " + e.getMessage());
            }
        }, 2, 2, TimeUnit.MINUTES);
    }

    public void enforce(Properties config) {
        System.out.println("Starting CES at " + LocalDateTime.now());
        JSONObject principal = null;
        CESService cesService = null;

        try {
            cesService = new CESService();
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

    /**
     * Triggered when the web application is stopped.
     * Ensures graceful shutdown of the background worker.
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        System.out.println("TSI DPDP CMS: Shutting down Compliance Enforcement worker...");
        if (scheduler != null) {
            scheduler.shutdown();
            try {
                // Wait briefly for the current task to finish if it's in the middle of a purge
                if (!scheduler.awaitTermination(30, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
            }
        }
    }
}