package org.tsicoop.dpdpcms.ces;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.BatchDB;
import org.tsicoop.dpdpcms.framework.PoolDB;

import java.sql.*;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * CESService implements the compliance business logic.
 */
class CESService {

    private BatchDB batchdb = null;
    private Connection conn = null;

    public CESService(BatchDB batchdb){
        this.batchdb = batchdb;
        this.conn = batchdb.getConnection();
    }

    /**
     * Fetches a fixed number of active principal IDs using limit and offset.
     */
    public List<JSONObject> getPrincipalsBatch(   int limit,
                                                  int offset) throws SQLException {
        List<JSONObject> principals = new ArrayList<JSONObject>();
        String sql = "SELECT user_id,last_consent_mechanism,last_ces_run FROM data_principal ORDER BY user_id LIMIT ? OFFSET ?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        JSONObject principal = null;

        try{
            stmt = conn.prepareStatement(sql);
            stmt.setInt(1, limit);
            stmt.setInt(2, offset);
            rs = stmt.executeQuery();
            while (rs.next()) {
                principal = new JSONObject();
                principal.put("user_id", rs.getString("user_id"));
                principal.put("last_consent_mechanism", rs.getString("last_consent_mechanism"));
                principal.put("last_ces_run", rs.getString("last_ces_run"));
                principals.add(principal);
            }
        }finally {
            batchdb.close(rs);
            batchdb.close(stmt);
        }
        return principals;
    }

    /**
     * Logic to identify records where consent was withdrawn and retention period has passed.
     */
    public void processPrincipalPurge(String principalId, String lastCESRun, String lastConsentMechanism) throws Exception {
        System.out.println("Processing "+principalId);
       String mechanism = null;

        try {

            /**
             * Steps:
             * 1. For each data principal, check the recent consent mechanism (CONSENT_GIVEN or CONSENT_WITHDRAWN or ERASURE REQUEST).
             * 2. Ensure that the recent consent is received post the last_ces_run date for the data principal. If not, do nothing. Go to the next principal.
             * 3. If consent mechanism is CONSENT_GIVEN or CONSENT_WITHDRAWN, evaluate the consent_expiry based on retention policies.
             * 4. If the consent_expiry is X days away, initiate a notification to the data principal. The frontend system can request for renewal.
             * 5. If the consent_expiry is passed, identify the consent validators and issue a purge request. Notify the data principal about the purge.
             * 6. If the consent mechanism is ERASURE_REQUEST, identify the consent validators and issue a purge request. Notify the data principal about the purge.
             * 7. Update the data principal with the latest consent mechanism and the ces run timestamp
             */

            Timestamp tsFromInstant = Timestamp.from(Instant.now());

            JSONObject recent = getRecentConsent(principalId,lastCESRun);
            //System.out.println(recent);
            if(recent != null) {
                mechanism = (String) recent.get("mechanism");
                if (mechanism.equalsIgnoreCase("ERASURE_REQUEST")) {
                    handleErasure(recent, principalId, tsFromInstant);
                } else {
                    handleRetentionNotification(recent, principalId, tsFromInstant);
                }
            }
        }finally {
        }
    }

    private JSONObject getRecentConsent(String principalId, String lastCESRun) throws Exception{
        JSONObject recent = null;
        PreparedStatement checkStmt = null;
        ResultSet rs = null;
        String mechanism = null;
        String createdAt = null;
        Timestamp tsCreatedAt = null;
        Timestamp tsLastCESRun = null;
        JSONArray consents = null;

        String checkSql = "SELECT id, consent_mechanism, data_point_consents, created_at FROM consent_records WHERE user_id = ? order by created_at desc LIMIT 1";
        try{
            checkStmt = conn.prepareStatement(checkSql);
            checkStmt.setString(1, principalId);
            rs = checkStmt.executeQuery();
            if (rs.next()) {
                String recordId = rs.getString("id");
                mechanism = (String)  rs.getString("consent_mechanism");
                createdAt = (String)  rs.getString("created_at");
                consents = (JSONArray) new JSONParser().parse((String) rs.getString("data_point_consents"));
                if(lastCESRun != null){
                    tsCreatedAt = Timestamp.from((Instant) Instant.parse(createdAt));
                    tsLastCESRun = Timestamp.from((Instant) Instant.parse(lastCESRun));
                    if(tsCreatedAt.before(tsLastCESRun)){
                        System.out.println("Skipping Principal: " + principalId + " | Reason: No Recent Consent");
                        return recent;
                    }
                }
                recent = new JSONObject();
                recent.put("id",recordId);
                recent.put("mechanism",mechanism);
                recent.put("created_at",createdAt);
                recent.put("consents",consents);
            }
        }finally {
            batchdb.close(rs);
            batchdb.close(checkStmt);
        }
        return recent;
    }

    private void handleErasure(JSONObject recent, String principalId, Timestamp tsFromInstant){
        JSONObject consent = null;
        String purposeId = null;
        boolean granted = false;
        String expiry = null;
        Timestamp tsExpiry = null;
        boolean enforced = false;
        JSONArray consents = (JSONArray) recent.get("consents");
        Iterator<JSONObject> consentIt = consents.iterator();
        while(consentIt.hasNext()){
            consent = (JSONObject) consentIt.next();
            purposeId = (String) consent.get("data_point_id");
            granted = (boolean) consent.get("consent_granted");
            expiry = (String) consent.get("consent_expiry");
            //System.out.println("Printing: " + principalId + " | Purpose: " + purposeId + " | Granted: " + granted+ " | Expiry: " + expiry);
            if(expiry != null){
                tsExpiry = Timestamp.from((Instant) Instant.parse(expiry));
                if(tsExpiry.before(tsFromInstant)){
                    System.out.println("Enforcing Purge for Principal: " + principalId + " | Purpose: " + purposeId);
                    // Create Purge Request
                    // Create notifications
                    enforced = true;
                }
            }
        }
    }

    private void handleRetentionNotification(JSONObject recent, String principalId, Timestamp tsFromInstant){
        JSONObject consent = null;
        String purposeId = null;
        boolean granted = false;
        String expiry = null;
        Timestamp tsExpiry = null;
        Instant notifInstant = null;
        Timestamp tsNotif = null;
        Instant expiryinstant = null;
        JSONArray consents = (JSONArray) recent.get("consents");
        Iterator<JSONObject> consentIt = consents.iterator();
        while(consentIt.hasNext()){
            consent = (JSONObject) consentIt.next();
            purposeId = (String) consent.get("data_point_id");
            granted = (boolean) consent.get("consent_granted");
            expiry = (String) consent.get("consent_expiry");
            //System.out.println("Printing: " + principalId + " | Purpose: " + purposeId + " | Granted: " + granted+ " | Expiry: " + expiry);
            if(expiry != null){
                tsExpiry = Timestamp.from((Instant) Instant.parse(expiry));
                expiryinstant = tsExpiry.toInstant();
                notifInstant = expiryinstant.minus(5, ChronoUnit.DAYS);
                tsNotif = Timestamp.from(notifInstant);
                if(tsNotif.before(tsFromInstant) && tsFromInstant.before(tsExpiry)){
                    System.out.println("Sending retention notification to : " + principalId + " | Purpose: " + purposeId);
                    // Create notifications
                }
            }
        }
    }

    private void handleRetentionPurge(JSONObject recent, String principalId){
        JSONObject consent = null;
        String purposeId = null;
        boolean granted = false;
        String expiry = null;
        Timestamp tsExpiry = null;
        Timestamp tsFromInstant = Timestamp.from(Instant.now());
        JSONArray consents = (JSONArray) recent.get("consents");
        Iterator<JSONObject> consentIt = consents.iterator();
        while(consentIt.hasNext()){
            consent = (JSONObject) consentIt.next();
            purposeId = (String) consent.get("data_point_id");
            granted = (boolean) consent.get("consent_granted");
            expiry = (String) consent.get("consent_expiry");
            //System.out.println("Printing: " + principalId + " | Purpose: " + purposeId + " | Granted: " + granted+ " | Expiry: " + expiry);
            if(expiry != null){
                tsExpiry = Timestamp.from((Instant) Instant.parse(expiry));
                if(tsExpiry.before(tsFromInstant)){
                    System.out.println("Enforcing Purge for Principal: " + principalId + " | Purpose: " + purposeId);
                    // Create Purge Request
                    // Create notifications
                }
            }
        }

    }



    /**
     * Logic to generate notifications for compliance actions.
     */
    public void generateComplianceNotifications(BatchDB batchdb, String principalId) {
        String sql = "INSERT INTO notifications (user_id, type, message, created_at, status) " +
                        "VALUES (?, 'COMPLIANCE_ALERT', ?, NOW(), 'UNREAD')";
        PreparedStatement checkStmt = null;
        ResultSet rs = null;
        PreparedStatement insStmt = null;

        // Check if any purges were completed for this user today
        String checkPurgeSql = "SELECT COUNT(*) FROM consent_records WHERE user_id = ? AND DATE(purged_at) = CURRENT_DATE";

        try{
            Connection conn = batchdb.getConnection();
            checkStmt = conn.prepareStatement(checkPurgeSql);
            checkStmt.setString(1, principalId);
            rs = checkStmt.executeQuery();
            if (rs.next() && rs.getInt(1) > 0) {
                insStmt = conn.prepareStatement(sql);
                insStmt.setString(1, principalId);
                insStmt.setString(2, "Compliance confirmation: Data associated with your withdrawn consent has been erased as per DPDP guidelines.");
                insStmt.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("Error generating notifications for " + principalId + ": " + e.getMessage());
        } finally {
            batchdb.close(rs);
            batchdb.close(checkStmt);
            batchdb.close(insStmt);
        }
    }

    public LocalDateTime getLastCESRunTimestamp(BatchDB batchdb) throws SQLException {
        String sql = "SELECT metadata_value FROM system_metadata WHERE metadata_key = 'LAST_CES_RUN'";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try{
             Connection conn = batchdb.getConnection();
             stmt = conn.prepareStatement(sql);
             rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getTimestamp("metadata_value").toLocalDateTime();
            }
        }finally{
            batchdb.close(rs);
            batchdb.close(stmt);
        }
        // Default to 30 days ago if never run
        return LocalDateTime.now().minusDays(30);
    }

    public List<String> getPrincipalsUpdatedSince(BatchDB batchdb, LocalDateTime lastRun) throws SQLException {
        List<String> ids = new ArrayList<>();
        String sql = "SELECT user_id FROM data_principals WHERE last_updated_at > ?";
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try{
            Connection conn = batchdb.getConnection();
            stmt = conn.prepareStatement(sql);
            stmt.setTimestamp(1, Timestamp.valueOf(lastRun));
            rs = stmt.executeQuery();
            while (rs.next()) {
                ids.add(rs.getString("user_id"));
            }
        }finally {
            batchdb.close(rs);
            batchdb.close(stmt);
        }
        return ids;
    }

    public void updateLastCESRunTimestamp(BatchDB batchdb, LocalDateTime timestamp) throws SQLException {
        String sql = "UPDATE system_metadata SET metadata_value = ? WHERE metadata_key = 'LAST_CES_RUN'";
        String insertSql = "INSERT INTO system_metadata (metadata_key, metadata_value) VALUES ('LAST_CES_RUN', ?)";
        PreparedStatement stmt = null;
        PreparedStatement insStmt = null;
        try{
            Connection conn = batchdb.getConnection();
            stmt = conn.prepareStatement(sql);
            stmt.setTimestamp(1, Timestamp.valueOf(timestamp));
            if (stmt.executeUpdate() == 0) {
                // If row doesn't exist, insert it
                insStmt = conn.prepareStatement(insertSql);
                insStmt.setTimestamp(1, Timestamp.valueOf(timestamp));
                insStmt.executeUpdate();
            }
        }finally {
            batchdb.close(insStmt);
            batchdb.close(stmt);
        }
    }
}
