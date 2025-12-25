package org.tsicoop.dpdpcms.ces;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.BatchDB;
import org.tsicoop.dpdpcms.framework.PoolDB;

import java.sql.*;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * CESService implements the compliance business logic.
 */
class CESService {

    /**
     * Fetches a fixed number of active principal IDs using limit and offset.
     */
    public List<JSONObject> getPrincipalsBatch( BatchDB batchdb,
                                                    int limit,
                                                    int offset) throws SQLException {
        List<JSONObject> principals = new ArrayList<JSONObject>();
        String sql = "SELECT user_id,purged_at FROM data_principal ORDER BY user_id LIMIT ? OFFSET ?";
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        JSONObject principal = null;

        try{
            conn = batchdb.getConnection();
            stmt = conn.prepareStatement(sql);
            stmt.setInt(1, limit);
            stmt.setInt(2, offset);
            rs = stmt.executeQuery();
            while (rs.next()) {
                principal = new JSONObject();
                principal.put("user_id", rs.getString("user_id"));
                principal.put("purged_at", rs.getString("purged_at"));
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
    public void processPrincipalPurge(BatchDB batchdb, String principalId, String purgedAt) {
        String checkSql = "SELECT id, data_point_consents FROM consent_records WHERE user_id = ? order by created_at desc";
        String updateSql = "UPDATE consent_records SET purge_status = 'COMPLETED', purged_at = NOW() WHERE id = ?";
        PreparedStatement updStmt = null;
        ResultSet rs = null;
        PreparedStatement checkStmt = null;
        Connection conn = null;
        JSONArray consents = null;
        JSONObject consent = null;
        String purposeId = null;
        boolean granted = false;
        String expiry = null;
        Timestamp tsFromInstant = Timestamp.from(Instant.now());
        Timestamp tsExpiry = null;
        Timestamp tsPurgedAt = null;
        boolean enforced = false;

        try{
            conn = batchdb.getConnection();
            checkStmt = conn.prepareStatement(checkSql);
            checkStmt.setString(1, principalId);
            rs = checkStmt.executeQuery();
            if (rs.next()) {
                String recordId = rs.getString("id");
                consents = (JSONArray) new JSONParser().parse((String) rs.getString("data_point_consents"));
                System.out.println(consents.size());
                Iterator<JSONObject> it = consents.iterator();
                while(it.hasNext()){
                    consent = (JSONObject) it.next();
                    purposeId = (String) consent.get("data_point_id");
                    granted = (boolean) consent.get("consent_granted");
                    expiry = (String) consent.get("consent_expiry");
                    //System.out.println("Printing: " + principalId + " | Purpose: " + purposeId + " | Granted: " + granted+ " | Expiry: " + expiry);
                   if(expiry != null){
                       tsExpiry = Timestamp.from((Instant) Instant.parse(expiry));
                       if(purgedAt != null){
                           tsPurgedAt = Timestamp.from((Instant) Instant.parse(purgedAt));
                           if(tsExpiry.before(tsPurgedAt)){
                               System.out.println("Purge already enforced for Principal: " + principalId + " | Purpose: " + purposeId);
                               continue;
                           }
                       }

                       if(tsExpiry.before(tsFromInstant)){
                            System.out.println("Enforcing Purge for Principal: " + principalId + " | Purpose: " + purposeId);
                            // Create Purge Request
                            // Create notifications
                            enforced = true;
                        }
                    }
                }
                if(enforced) {
                    System.out.println("Updating purged at");
                    // Update purged_at
                    /*updStmt = conn.prepareStatement(updateSql);
                    updStmt.setString(1, recordId);
                    updStmt.executeUpdate();*/
                }
            }
        } catch (Exception e) {
            System.err.println("Error processing purge for " + principalId + ": " + e.getMessage());
        } finally {
            batchdb.close(updStmt);
            batchdb.close(rs);
            batchdb.close(checkStmt);
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
