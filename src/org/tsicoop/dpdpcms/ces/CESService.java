package org.tsicoop.dpdpcms.ces;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.PoolDB;
import org.tsicoop.dpdpcms.util.Constants;

import java.sql.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

/**
 * CESService implements the compliance business logic.
 */
class CESService {

    private PoolDB pool = null;
    private Connection conn = null;

    public CESService(){
    }

    /**
     * Fetches a fixed number of active principal IDs using limit and offset.
     */
    public List<JSONObject> getPrincipalsBatch(   int limit,
                                                  int offset) throws SQLException {
        List<JSONObject> principals = new ArrayList<JSONObject>();
        String sql = "SELECT fiduciary_id,user_id,last_consent_mechanism,last_ces_run FROM data_principal ORDER BY user_id LIMIT ? OFFSET ?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        JSONObject principal = null;

        try{
            pool = new PoolDB();
            conn = pool.getConnection();
            stmt = conn.prepareStatement(sql);
            stmt.setInt(1, limit);
            stmt.setInt(2, offset);
            rs = stmt.executeQuery();
            while (rs.next()) {
                principal = new JSONObject();
                principal.put("user_id", rs.getString("user_id"));
                principal.put("fiduciary_id", rs.getString("fiduciary_id"));
                principal.put("last_consent_mechanism", rs.getString("last_consent_mechanism"));
                principal.put("last_ces_run", rs.getTimestamp("last_ces_run"));
                principals.add(principal);
            }
        }finally {
            pool.cleanup(rs,stmt,conn);
        }
        return principals;
    }

    /**
     * Logic to identify records where consent was withdrawn and retention period has passed.
     */
    public void processPrincipal(String fiduciaryId, String principalId, Timestamp lastCESRun, String lastConsentMechanism) throws Exception {
        System.out.println("Processing "+principalId);
        String mechanism = null;

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
        if(recent != null) {
            mechanism = (String) recent.get("mechanism");
            if (mechanism.equalsIgnoreCase(Constants.ACTION_ERASURE_REQUEST)) {
                handleErasure(recent, principalId, fiduciaryId, tsFromInstant);
            } else {
                handleRetentionNotification(recent, principalId, fiduciaryId, tsFromInstant);
                handleRetentionPurge(recent, principalId, fiduciaryId, tsFromInstant);
            }
            updatePrincipalComplianceMetadata(fiduciaryId, principalId, mechanism, tsFromInstant);
        }
    }

    private JSONObject getRecentConsent(String principalId, Timestamp lastCESRun) throws Exception{
        JSONObject recent = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        String mechanism = null;
        Timestamp createdAt = null;
        JSONArray consents = null;

        String checkSql = "SELECT id, consent_mechanism, data_point_consents, created_at FROM consent_records WHERE user_id = ? order by created_at desc LIMIT 1";
        try{
            pool = new PoolDB();
            conn = pool.getConnection();
            stmt = conn.prepareStatement(checkSql);
            stmt.setString(1, principalId);
            rs = stmt.executeQuery();
            if (rs.next()) {
                String recordId = rs.getString("id");
                mechanism = (String)  rs.getString("consent_mechanism");
                createdAt = (Timestamp)  rs.getTimestamp("created_at");
                consents = (JSONArray) new JSONParser().parse((String) rs.getString("data_point_consents"));
                if(lastCESRun != null){
                    if(createdAt.before(lastCESRun)){
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
            pool.cleanup(rs,stmt,conn);
        }
        return recent;
    }

    private JSONObject logEventToDb(String userId, UUID fiduciaryId, String serviceType, UUID serviceId, String auditAction, String contextDetails) throws SQLException {
        String sql = "INSERT INTO audit_logs (id, fiduciary_id, timestamp, user_id, service_type, service_id, audit_action, context_details) " +
                "VALUES (uuid_generate_v4(), ?, NOW(), ?, ?, ?, ?, ?) RETURNING id";
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, userId);
            pstmt.setString(3, serviceType);
            pstmt.setObject(4, serviceId);
            pstmt.setString(5, auditAction);
            pstmt.setString(6, contextDetails);

            rs = pstmt.executeQuery();
            JSONObject result = new JSONObject();
            if (rs.next()) {
                result.put("success", true);
                result.put("id", rs.getObject("id").toString());
            }
            return result;
        } finally {
            pool.cleanup(rs,pstmt,conn);
        }
    }

    private void handleErasure(JSONObject recent, String principalId, String fiduciaryId, Timestamp tsFromInstant) throws Exception{
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
                    // Identify Apps (Data Processors)
                    List<JSONObject> appids = getAppIdsByPurpose(principalId, fiduciaryId, purposeId);
                    Iterator<JSONObject> appidIt = appids.iterator();
                    while(appidIt.hasNext()){
                        JSONObject appidJSON = (JSONObject) appidIt.next();
                        String appid = (String) appidJSON.get("app_id");
                        System.out.println("Enforcing Purge for Principal: " + principalId + " | App: "+ appid+" | Purpose: " + purposeId);
                        // Create Purge Request
                        insertPurgeRequest( principalId,
                                            fiduciaryId,
                                            appid,
                                            Constants.EVENT_PURGE_INITIATED);
                        // Send purge notification to data processor
                        insertNotification( "APP",
                                            appid,
                                            fiduciaryId,
                                            Constants.NOTIF_PURGE_INIT);
                        // log audit event
                        logEventToDb(principalId, UUID.fromString(fiduciaryId), "SYSTEM", null , "PURGE_INITIATION", "ERASURE_REQUEST"+"-"+appid+"-"+purposeId);
                    }
                }
            }
        }
    }

    private List<JSONObject> getAppIdsByPurpose(String userId, String fiduciaryId, String purposeId) throws SQLException {
        //System.out.println("userId:"+userId+" fiduciaryId:"+fiduciaryId+" purposeId:"+purposeId);
        List<JSONObject> appIds = new ArrayList<JSONObject>();
        String sql = "SELECT DISTINCT app_id FROM consent_validations WHERE user_id = ? AND fiduciary_id = ? AND purpose_id = ?";

        PreparedStatement stmt = null;
        ResultSet rs = null;
        JSONObject appIdObj = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, userId);
            stmt.setObject(2, UUID.fromString(fiduciaryId));
            stmt.setString(3, purposeId);

            rs = stmt.executeQuery();
            while (rs.next()) {
                appIdObj = new JSONObject();
                appIdObj.put("app_id", rs.getString("app_id"));
                appIds.add(appIdObj);
            }
        } catch (IllegalArgumentException e) {
            // Handle UUID parsing issues
            return appIds;
        } finally {
            pool.cleanup(rs,stmt,conn);
        }
        return appIds;
    }

    private void handleRetentionNotification(JSONObject recent, String principalId, String fiduciaryId, Timestamp tsFromInstant) throws SQLException{
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
                    // Create notification
                    // Send purge notification to data processor
                    insertNotification( "PRINCIPAL",
                                                    principalId,
                                                    fiduciaryId,
                                                    Constants.NOTIF_EXPIRY_REMINDER);
                }
            }
        }
    }

    private void handleRetentionPurge(JSONObject recent, String principalId, String fiduciaryId, Timestamp tsFromInstant) throws SQLException{
        JSONObject consent = null;
        String purposeId = null;
        boolean granted = false;
        String expiry = null;
        Timestamp tsExpiry = null;
        JSONArray consents = (JSONArray) recent.get("consents");
        Iterator<JSONObject> consentIt = consents.iterator();
        while(consentIt.hasNext()){
            consent = (JSONObject) consentIt.next();
            purposeId = (String) consent.get("data_point_id");
            granted = (boolean) consent.get("consent_granted");
            expiry = (String) consent.get("consent_expiry");
            System.out.println("Printing: " + principalId + " | Purpose: " + purposeId + " | Granted: " + granted+ " | Expiry: " + expiry);
            if(expiry != null){
                tsExpiry = Timestamp.from((Instant) Instant.parse(expiry));
                System.out.println("TS Expiry:"+tsExpiry+" Instant:"+tsFromInstant);
                if(tsExpiry.before(tsFromInstant)){
                    // Identify Apps (Data Processors)
                    List<JSONObject> appids = getAppIdsByPurpose(principalId, fiduciaryId, purposeId);
                    Iterator<JSONObject> appidIt = appids.iterator();
                    while(appidIt.hasNext()){
                        JSONObject appidJSON = (JSONObject) appidIt.next();
                        String appid = (String) appidJSON.get("app_id");
                        System.out.println("Enforcing Purge for Principal: " + principalId + " | App: "+ appid+" | Purpose: " + purposeId);
                        // Create Purge Request
                        insertPurgeRequest( principalId,
                                fiduciaryId,
                                appid, Constants.EVENT_PURGE_INITIATED);
                        // Send purge notification to data processor
                        insertNotification( "APP",
                                appid,
                                fiduciaryId,
                                Constants.NOTIF_PURGE_INIT);
                        // log audit event
                        logEventToDb(principalId, UUID.fromString(fiduciaryId), "SYSTEM", null , Constants.EVENT_PURGE_INITIATED, "RETENTION_EXPIRY"+"-"+appid+"-"+purposeId);
                    }
                }
            }
        }

    }

    /**
     * Inserts a new purge request record into the database based on the altered schema.
     * Uses your specific style with local PoolDB and try-finally cleanup.
     */
    public JSONObject insertPurgeRequest(String userId,
                                         String fiduciaryId,
                                         String appId,
                                         String triggerEvent) throws SQLException {
        JSONObject response = new JSONObject();
        String sql = "INSERT INTO purge_requests (user_id, fiduciary_id, app_id, trigger_event) " +
                "VALUES (?, ?, ?, ?) RETURNING id";

        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            stmt = conn.prepareStatement(sql);

            stmt.setString(1, userId);
            stmt.setObject(2, UUID.fromString(fiduciaryId));
            stmt.setObject(3, UUID.fromString(appId));
            stmt.setString(4, triggerEvent);

            rs = stmt.executeQuery();
            if (rs.next()) {
                response.put("success", true);
                response.put("id", rs.getObject("id").toString());
            }
        } finally {
            pool.cleanup(rs,stmt,conn);
        }
        return response;
    }

    /**
     * Inserts a new notification record into the database.
     * Follows the specific parameter-based style and try-finally cleanup.
     */
    public JSONObject insertNotification(String recipientType,
                                         String recipientId,
                                         String fiduciaryId,
                                         String notificationType) throws SQLException {
        JSONObject response = new JSONObject();
        String sql = "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type) " +
                "VALUES (?, ?, ?, ?) RETURNING id";

        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, recipientType);
            stmt.setString(2, recipientId);
            stmt.setObject(3, UUID.fromString(fiduciaryId));
            stmt.setString(4, notificationType);

            rs = stmt.executeQuery();
            if (rs.next()) {
                response.put("success", true);
                response.put("id", rs.getObject("id").toString());
            }
        } finally {
            pool.cleanup(rs,stmt,conn);
        }
        return response;
    }

    /**
     * Updates the last_consent_mechanism and sets last_ces_run to current time
     * in the data_principal table for a given user.
     */
    public JSONObject updatePrincipalComplianceMetadata(String fiduciaryId, String userId, String mechanism, Timestamp lastCESRun) throws SQLException {
        JSONObject response = new JSONObject();
        String sql = "UPDATE data_principal SET last_consent_mechanism = ?, last_ces_run=?::timestamp WHERE user_id = ? and fiduciary_id=?";

        PreparedStatement stmt = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, mechanism);
            stmt.setTimestamp(2, lastCESRun);
            stmt.setString(3, userId);
            stmt.setObject(4,UUID.fromString(fiduciaryId));
            int rowsAffected = stmt.executeUpdate();
            if (rowsAffected > 0) {
                response.put("success", true);
                response.put("message", "Data principal compliance metadata updated.");
            } else {
                response.put("success", false);
                response.put("message", "Principal not found.");
            }
        } finally {
            pool.cleanup(null,stmt,conn);
        }
        return response;
    }

}
