package org.tsicoop.dpdpcms.ces;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.PoolDB;
import org.tsicoop.dpdpcms.service.v1.Audit;
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
public class CESService {

    public CESService(){
    }

    /**
     * Fetches a fixed number of active principal IDs using limit and offset.
     */
    public List<JSONObject> getPrincipalsBatch( UUID fiduciaryId,
                                                String target,
                                                int limit,
                                                int offset) throws SQLException {
        List<JSONObject> principals = new ArrayList<JSONObject>();
        String sql = null;
        if(target == null || target.equalsIgnoreCase("FULL")) {
            sql = "SELECT fiduciary_id,user_id,last_consent_mechanism,last_ces_run FROM data_principal WHERE fiduciary_id=? ORDER BY user_id LIMIT ? OFFSET ?";
        }else{
            sql = "SELECT fiduciary_id,user_id,last_consent_mechanism,last_ces_run FROM data_principal WHERE fiduciary_id=? AND user_id='"+target+"' ORDER BY user_id LIMIT ? OFFSET ?";
        }
        PreparedStatement stmt = null;
        ResultSet rs = null;
        JSONObject principal = null;
        PoolDB pool = null;
        Connection conn = null;

        try{
            pool = new PoolDB();
            conn = pool.getConnection();
            stmt = conn.prepareStatement(sql);
            stmt.setObject(1, fiduciaryId);
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);
            rs = stmt.executeQuery();
            while (rs.next()) {
                principal = new JSONObject();
                principal.put("user_id", rs.getString("user_id"));
                principal.put("fiduciary_id", rs.getString("fiduciary_id"));
                principal.put("last_consent_mechanism", rs.getString("last_consent_mechanism"));
                principal.put("last_ces_run", rs.getTimestamp("last_ces_run")!=null?rs.getTimestamp("last_ces_run"):Timestamp.from(Instant.EPOCH));
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
        //System.out.println("Processing "+principalId);
        String mechanism = null;

        /**
         * Steps:
         * 1. For each data principal, check the recent consent mechanism (CONSENT_GIVEN or CONSENT_WITHDRAWN or ERASURE REQUEST).
         * 2. Retrieve that the recent consent for the data principal.
         * 3. If consent mechanism is CONSENT_GIVEN or CONSENT_WITHDRAWN, evaluate the consent_expiry based on retention policies.
         * 4. If the consent_expiry is X days away, initiate a notification to the data principal. The frontend system can request for renewal.
         * 5. If the consent_expiry is passed, identify the consent validators and issue a purge request. Notify the data principal about the purge.
         * 6. If the consent mechanism is ERASURE_REQUEST, identify the consent validators and issue a purge request. Notify the data principal about the purge.
         * 7. Update the data principal with the latest consent mechanism and the ces run timestamp
         */

        Timestamp newCESRun = Timestamp.from(Instant.now());
        JSONObject recent = getRecentConsent(principalId);
        if(recent == null) return;
        Timestamp createdAt = (Timestamp) recent.get("created_at");
        //System.out.println("Processing:"+principalId);
        mechanism = (String) recent.get("mechanism");
        if (mechanism.equalsIgnoreCase(Constants.ACTION_ERASURE_REQUEST)) {
            if(createdAt.after(lastCESRun)){
                handleErasure(recent, principalId, fiduciaryId, newCESRun);
                updatePrincipalComplianceMetadata(fiduciaryId, principalId, mechanism, newCESRun);
            }
        } else {
            handleRetentionNotification(recent, principalId, fiduciaryId, lastCESRun, newCESRun);
            handleRetentionPurge(recent, principalId, fiduciaryId, lastCESRun, newCESRun);
            updatePrincipalComplianceMetadata(fiduciaryId, principalId, mechanism, newCESRun);
        }
    }

    private JSONObject getRecentConsent(String principalId) throws Exception{
        //System.out.println("Inside getRecentConsent:"+principalId);
        JSONObject recent = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        String mechanism = null;
        Timestamp createdAt = null;
        JSONArray consents = null;
        PoolDB pool = null;
        Connection conn = null;

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
                recent = new JSONObject();
                recent.put("id",recordId);
                recent.put("mechanism",mechanism);
                recent.put("created_at",createdAt);
                recent.put("consents",consents);
            }
        }catch(Exception e){
            e.printStackTrace();
            System.out.println(e.getMessage());
        }finally{
            pool.cleanup(rs,stmt,conn);
        }
        return recent;
    }



    private void handleErasure(JSONObject recent, String principalId, String fiduciaryId, Timestamp newCESRun) throws Exception{
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
                if(tsExpiry.before(newCESRun)){
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
                                            Constants.PURGE_TRIGGER_ERASURE,
                                            Constants.EVENT_PURGE_INITIATED);
                        // Send purge notification to data processor
                        insertNotification( "APP",
                                            appid,
                                            fiduciaryId,
                                            Constants.NOTIF_PURGE_INIT);
                        // log audit event
                        new Audit().logEventToDb(principalId, UUID.fromString(fiduciaryId), "SYSTEM", null , "PURGE_INITIATION", "ERASURE_REQUEST"+"-"+appid+"-"+purposeId);
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
        PoolDB pool = null;
        Connection conn = null;

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

    private void handleRetentionNotification(JSONObject recent, String principalId, String fiduciaryId, Timestamp lastCESRun, Timestamp newCESRun) throws SQLException{
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
                if(tsNotif.after(lastCESRun) && tsNotif.before(newCESRun) && newCESRun.before(tsExpiry)){
                    //System.out.println("Sending retention notification to : " + principalId + " | Purpose: " + purposeId);
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

    private void handleRetentionPurge(JSONObject recent, String principalId, String fiduciaryId, Timestamp lastCESRun, Timestamp tsFromInstant) throws SQLException{
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
            //System.out.println("Printing: " + principalId + " | Purpose: " + purposeId + " | Granted: " + granted+ " | Expiry: " + expiry);
            if(expiry != null){
                tsExpiry = Timestamp.from((Instant) Instant.parse(expiry));
                //System.out.println("TS Expiry:"+tsExpiry+" Instant:"+tsFromInstant);
                if(tsExpiry.after(lastCESRun) && tsExpiry.before(tsFromInstant)){
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
                                Constants.PURGE_TRIGGER_EXPIRY,
                                Constants.EVENT_PURGE_INITIATED);
                        // Send purge notification to data processor
                        insertNotification( "APP",
                                appid,
                                fiduciaryId,
                                Constants.NOTIF_PURGE_INIT);
                        // log audit event
                        new Audit().logEventToDb(principalId, UUID.fromString(fiduciaryId), "SYSTEM", null , Constants.EVENT_PURGE_INITIATED, "RETENTION_EXPIRY"+"-"+appid+"-"+purposeId);
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
                                         String triggerEvent,
                                         String status) throws SQLException {
        JSONObject response = new JSONObject();
        String sql = "INSERT INTO purge_requests (user_id, fiduciary_id, app_id, trigger_event, status) " +
                "VALUES (?, ?, ?, ?, ?) RETURNING id";

        PreparedStatement stmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        Connection conn = null;
        String appName = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            stmt = conn.prepareStatement(sql);

            stmt.setString(1, userId);
            stmt.setObject(2, UUID.fromString(fiduciaryId));
            stmt.setObject(3, UUID.fromString(appId));
            stmt.setString(4, triggerEvent);
            stmt.setString(5, status);

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
        PoolDB pool = null;
        Connection conn = null;

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
        PoolDB pool = null;
        Connection conn = null;

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
