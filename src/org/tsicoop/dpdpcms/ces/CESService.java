package org.tsicoop.dpdpcms.ces;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.PoolDB;
import org.tsicoop.dpdpcms.framework.WebhookDispatcher;
import org.tsicoop.dpdpcms.service.v1.App;
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
        boolean targetFiltered = target != null && !target.equalsIgnoreCase("FULL");
        if (targetFiltered) {
            sql = "SELECT fiduciary_id,user_id,last_consent_mechanism,last_ces_run FROM data_principal WHERE fiduciary_id=? AND user_id=? LIMIT ? OFFSET ?";
        } else {
            sql = "SELECT fiduciary_id,user_id,last_consent_mechanism,last_ces_run FROM data_principal WHERE fiduciary_id=? ORDER BY user_id LIMIT ? OFFSET ?";
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
            if (targetFiltered) {
                stmt.setString(2, target);
                stmt.setInt(3, limit);
                stmt.setInt(4, offset);
            } else {
                stmt.setInt(2, limit);
                stmt.setInt(3, offset);
            }
            rs = stmt.executeQuery();
            while (rs.next()) {
                principal = new JSONObject();
                System.out.println("Processing:"+rs.getString("user_id"));
                principal.put("user_id", rs.getString("user_id"));
                principal.put("fiduciary_id", rs.getString("fiduciary_id"));
                principal.put("last_consent_mechanism", rs.getString("last_consent_mechanism"));
                principal.put("last_ces_run", rs.getTimestamp("last_ces_run")!=null?rs.getTimestamp("last_ces_run"):Timestamp.from(Instant.EPOCH));
                principals.add(principal);
            }
        }catch(Exception e){
            e.printStackTrace();
        }
        finally {
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
        JSONObject recent = getRecentConsent(principalId, fiduciaryId);
        if(recent == null) {
            System.out.println("[CES DEBUG] processPrincipal: no recent consent record found for principal=" + principalId + " -- skipping");
            return;
        }
        Timestamp createdAt = (Timestamp) recent.get("created_at");
        //System.out.println("Processing:"+principalId);
        mechanism = (String) recent.get("mechanism");
        System.out.println("[CES DEBUG] processPrincipal: principal=" + principalId
                + " mechanism=" + mechanism
                + " recordCreatedAt=" + createdAt
                + " lastCESRun=" + lastCESRun
                + " createdAtAfterLastCESRun=" + createdAt.after(lastCESRun));
        if (mechanism.equalsIgnoreCase(Constants.ACTION_ERASURE_REQUEST)) {
            if(createdAt.after(lastCESRun)){
                System.out.println("[CES DEBUG] processPrincipal: dispatching to handleErasure for principal=" + principalId);
                handleErasure(recent, principalId, fiduciaryId, newCESRun);
                updatePrincipalComplianceMetadata(fiduciaryId, principalId, mechanism, newCESRun);
            } else {
                System.out.println("[CES DEBUG] processPrincipal: ERASURE_REQUEST found but record createdAt=" + createdAt
                        + " is NOT after lastCESRun=" + lastCESRun + " -- handleErasure will NOT run for principal=" + principalId);
            }
        } else {
            handleRetentionNotification(recent, principalId, fiduciaryId, lastCESRun, newCESRun);
            handleRetentionPurge(recent, principalId, fiduciaryId, lastCESRun, newCESRun);
            updatePrincipalComplianceMetadata(fiduciaryId, principalId, mechanism, newCESRun);
        }
    }

    private JSONObject getRecentConsent(String principalId, String fiduciaryId) throws Exception{
        //System.out.println("Inside getRecentConsent:"+principalId);
        JSONObject recent = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        String mechanism = null;
        Timestamp createdAt = null;
        JSONArray consents = null;
        PoolDB pool = null;
        Connection conn = null;

        String checkSql = "SELECT id, consent_mechanism, data_point_consents, created_at FROM consent_records WHERE user_id = ? AND fiduciary_id = ? ORDER BY created_at DESC LIMIT 1";
        try{
            pool = new PoolDB();
            conn = pool.getConnection();
            stmt = conn.prepareStatement(checkSql);
            stmt.setString(1, principalId);
            stmt.setObject(2, UUID.fromString(fiduciaryId));
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
                System.out.println("[CES DEBUG] getRecentConsent: principal=" + principalId
                        + " recordId=" + recordId + " mechanism=" + mechanism
                        + " createdAt=" + createdAt + " consents=" + consents.toJSONString());
            } else {
                System.out.println("[CES DEBUG] getRecentConsent: NO consent_records row found for principal=" + principalId);
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
        JSONArray consents = (JSONArray) recent.get("consents");
        System.out.println("[CES DEBUG] handleErasure: principal=" + principalId + " fiduciary=" + fiduciaryId
                + " consentCount=" + consents.size() + " consents=" + consents.toJSONString());
        Iterator<JSONObject> consentIt = consents.iterator();
        while(consentIt.hasNext()){
            consent = (JSONObject) consentIt.next();
            purposeId = (String) consent.get("data_point_id");
            // An explicit erasure request must be enforced immediately for every purpose the
            // principal had consented to -- it must not wait for consent_expiry/retention to
            // lapse (that gating belongs to handleRetentionPurge).
            List<JSONObject> appids = getAppIdsByPurpose(principalId, fiduciaryId, purposeId);
            System.out.println("[CES DEBUG] handleErasure: principal=" + principalId + " purpose=" + purposeId
                    + " resolvedAppCount=" + appids.size() + " apps=" + appids);
            if (appids.isEmpty()) {
                System.out.println("[CES DEBUG] handleErasure: NO apps found in consent_validations for principal=" + principalId
                        + " fiduciary=" + fiduciaryId + " purpose=" + purposeId + " -- recording orphan compliance event so DPO is not blind to this");
                recordOrphanComplianceEvent(principalId, fiduciaryId, purposeId, Constants.PURGE_TRIGGER_ERASURE,
                        "Erasure request received but no linked data processor found for this purpose — manual review/erasure confirmation required.");
            }
            // Notify the Data Principal that purge has been initiated for this purpose,
            // once per purpose, regardless of whether a linked App was found.
            insertNotification("PRINCIPAL", principalId, fiduciaryId, Constants.NOTIF_PURGE_INIT);
            Iterator<JSONObject> appidIt = appids.iterator();
            while(appidIt.hasNext()){
                JSONObject appidJSON = (JSONObject) appidIt.next();
                String appid = (String) appidJSON.get("app_id");
                System.out.println("Enforcing Purge for Principal: " + principalId + " | App: "+ appid+" | Purpose: " + purposeId);
                // Create Purge Request
                JSONObject purgeResult = insertPurgeRequest( principalId,
                                    fiduciaryId,
                                    purposeId,
                                    appid,
                                    Constants.PURGE_TRIGGER_ERASURE,
                                    Constants.EVENT_PURGE_INITIATED);
                System.out.println("[CES DEBUG] handleErasure: insertPurgeRequest result=" + purgeResult
                        + " principal=" + principalId + " app=" + appid + " purpose=" + purposeId);
                // Send purge notification to data processor
                insertNotification( "APP",
                                    appid,
                                    fiduciaryId,
                                    Constants.NOTIF_PURGE_INIT);
                // log audit event
                JSONObject auditContext = new JSONObject();
                auditContext.put("principal", principalId);
                auditContext.put("trigger", Constants.PURGE_TRIGGER_ERASURE);
                auditContext.put("app", new App().getAppName(UUID.fromString(appid), UUID.fromString(fiduciaryId)));
                auditContext.put("purpose",purposeId);

                new Audit().logEventAsync(principalId, UUID.fromString(fiduciaryId), "SYSTEM", null , "PURGE_INITIATION", auditContext.toJSONString());
            }
        }
    }

    private List<JSONObject> getAppIdsByPurpose(String userId, String fiduciaryId, String purposeId) throws SQLException {
        //System.out.println("userId:"+userId+" fiduciaryId:"+fiduciaryId+" purposeId:"+purposeId);
        List<JSONObject> appIds = new ArrayList<JSONObject>();
        String sql = "SELECT DISTINCT app_id FROM consent_validations WHERE user_id = ? AND fiduciary_id = ? AND purpose_id = ? AND app_id IS NOT NULL";

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
            System.out.println("[CES DEBUG] getAppIdsByPurpose: SELECT DISTINCT app_id FROM consent_validations WHERE user_id='"
                    + userId + "' AND fiduciary_id='" + fiduciaryId + "' AND purpose_id='" + purposeId
                    + "' -> " + appIds.size() + " row(s)");
        } catch (IllegalArgumentException e) {
            System.out.println("[CES DEBUG] getAppIdsByPurpose: failed to parse fiduciaryId='" + fiduciaryId
                    + "' as UUID for userId=" + userId + " purposeId=" + purposeId + " -- " + e.getMessage());
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

    private JSONObject getRopaRetention(String fiduciaryId) {
        String sql = "SELECT retention_period_days, retention_start_event FROM ropa_entries WHERE fiduciary_id = ? AND status = 'active' ORDER BY updated_at DESC LIMIT 1";
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(fiduciaryId));
            rs = pstmt.executeQuery();
            if (rs.next() && rs.getObject("retention_period_days") != null) {
                JSONObject result = new JSONObject();
                result.put("retention_period_days", rs.getLong("retention_period_days"));
                result.put("retention_start_event", rs.getString("retention_start_event"));
                return result;
            }
        } catch (Exception e) {
            // non-blocking — fall back to JSONB expiry
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }

    private void handleRetentionPurge(JSONObject recent, String principalId, String fiduciaryId, Timestamp lastCESRun, Timestamp tsFromInstant) throws SQLException{
        Timestamp createdAt = (Timestamp) recent.get("created_at");

        // Prefer ROPA-derived retention for COLLECTION start event; fall back to JSONB consent_expiry
        JSONObject ropaRetention = getRopaRetention(fiduciaryId);
        Long ropaRetentionDays = null;
        boolean ropaCollection = false;
        if (ropaRetention != null) {
            ropaRetentionDays = (Long) ropaRetention.get("retention_period_days");
            ropaCollection = "COLLECTION".equals(ropaRetention.get("retention_start_event"));
        }

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
            if (ropaRetentionDays != null && ropaCollection) {
                tsExpiry = Timestamp.from(createdAt.toInstant().plus(ropaRetentionDays, ChronoUnit.DAYS));
            } else if (expiry != null) {
                tsExpiry = Timestamp.from(Instant.parse(expiry));
            } else {
                tsExpiry = null;
            }
            if(tsExpiry != null){
                //System.out.println("TS Expiry:"+tsExpiry+" Instant:"+tsFromInstant);
                if(tsExpiry.after(lastCESRun) && tsExpiry.before(tsFromInstant)){
                    // Identify Apps (Data Processors)
                    List<JSONObject> appids = getAppIdsByPurpose(principalId, fiduciaryId, purposeId);
                    if (appids.isEmpty()) {
                        System.out.println("[CES DEBUG] handleRetentionPurge: NO apps found in consent_validations for principal=" + principalId
                                + " fiduciary=" + fiduciaryId + " purpose=" + purposeId + " -- recording orphan compliance event so DPO is not blind to this");
                        recordOrphanComplianceEvent(principalId, fiduciaryId, purposeId, Constants.PURGE_TRIGGER_EXPIRY,
                                "Consent/retention period expired but no linked data processor found for this purpose — manual review/erasure confirmation required.");
                    }
                    // Notify the Data Principal that purge has been initiated for this purpose,
                    // once per purpose, regardless of whether a linked App was found.
                    insertNotification("PRINCIPAL", principalId, fiduciaryId, Constants.NOTIF_PURGE_INIT);
                    Iterator<JSONObject> appidIt = appids.iterator();
                    while(appidIt.hasNext()){
                        JSONObject appidJSON = (JSONObject) appidIt.next();
                        String appid = (String) appidJSON.get("app_id");
                        System.out.println("Enforcing Purge for Principal: " + principalId + " | App: "+ appid+" | Purpose: " + purposeId);
                        // Create Purge Request
                        insertPurgeRequest( principalId,
                                fiduciaryId,
                                purposeId,
                                appid,
                                Constants.PURGE_TRIGGER_EXPIRY,
                                Constants.EVENT_PURGE_INITIATED);
                        // Send purge notification to data processor
                        insertNotification( "APP",
                                appid,
                                fiduciaryId,
                                Constants.NOTIF_PURGE_INIT);
                        // log audit event
                        // log audit event
                        JSONObject auditContext = new JSONObject();
                        auditContext.put("principal", principalId);
                        auditContext.put("trigger", Constants.PURGE_TRIGGER_EXPIRY);
                        auditContext.put("app", new App().getAppName(UUID.fromString(appid), UUID.fromString(fiduciaryId)));
                        auditContext.put("purpose",purposeId);
                        new Audit().logEventAsync(principalId, UUID.fromString(fiduciaryId), "SYSTEM", null , Constants.EVENT_PURGE_INITIATED, auditContext.toJSONString());
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
                                         String purposeId,
                                         String appId,
                                         String triggerEvent,
                                         String status) throws SQLException {
        JSONObject response = new JSONObject();
        String sql = "INSERT INTO purge_requests (user_id, fiduciary_id, purpose_id, app_id, trigger_event, status) " +
                "VALUES (?, ?, ?, ?, ?, ?) RETURNING id";

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
            stmt.setString(3, purposeId);
            stmt.setObject(4, UUID.fromString(appId));
            stmt.setString(5, triggerEvent);
            stmt.setString(6, status);

            rs = stmt.executeQuery();
            if (rs.next()) {
                response.put("success", true);
                response.put("id", rs.getObject("id").toString());
                System.out.println("[CES DEBUG] insertPurgeRequest: INSERTED purge_requests id=" + response.get("id")
                        + " user_id=" + userId + " fiduciary_id=" + fiduciaryId + " purpose_id=" + purposeId
                        + " app_id=" + appId + " trigger_event=" + triggerEvent + " status=" + status);
            } else {
                System.out.println("[CES DEBUG] insertPurgeRequest: INSERT returned no row (no id) for user_id=" + userId
                        + " fiduciary_id=" + fiduciaryId + " purpose_id=" + purposeId + " app_id=" + appId);
            }
        } catch (SQLException e) {
            System.out.println("[CES DEBUG] insertPurgeRequest: SQLException while inserting purge_requests for user_id=" + userId
                    + " fiduciary_id=" + fiduciaryId + " purpose_id=" + purposeId + " app_id=" + appId
                    + " trigger_event=" + triggerEvent + " -- " + e.getMessage());
            e.printStackTrace();
            throw e;
        } catch (IllegalArgumentException e) {
            System.out.println("[CES DEBUG] insertPurgeRequest: invalid UUID -- fiduciary_id='" + fiduciaryId
                    + "' app_id='" + appId + "' user_id=" + userId + " purpose_id=" + purposeId + " -- " + e.getMessage());
            e.printStackTrace();
            throw e;
        } finally {
            pool.cleanup(rs,stmt,conn);
        }

        if (Boolean.TRUE.equals(response.get("success"))) {
            JSONObject payload = new JSONObject();
            payload.put("id", response.get("id"));
            payload.put("user_id", userId);
            payload.put("purpose_id", purposeId);
            payload.put("app_id", appId);
            payload.put("trigger_event", triggerEvent);
            payload.put("status", status);
            WebhookDispatcher.dispatch(fiduciaryId, "PURGE", "purge_request_created", payload);
        }
        return response;
    }

    /**
     * Records a visible compliance event for a purpose that has no linked data
     * processor (getAppIdsByPurpose returned an empty list). Without this, an
     * erasure request or a retention/consent expiry for such a purpose would
     * silently disappear -- there is no app to send a purge to, so no
     * purge_requests row and no DPO-visible trace would ever be created.
     * Inserts a purge_requests row with app_id = NULL so the DPO can see it
     * in the compliance console and confirm manual review/erasure.
     */
    private void recordOrphanComplianceEvent(String principalId,
                                              String fiduciaryId,
                                              String purposeId,
                                              String triggerEvent,
                                              String details) throws SQLException {
        String sql = "INSERT INTO purge_requests (user_id, fiduciary_id, purpose_id, app_id, trigger_event, status, details) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id";

        PreparedStatement stmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        Connection conn = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            stmt = conn.prepareStatement(sql);

            stmt.setString(1, principalId);
            stmt.setObject(2, UUID.fromString(fiduciaryId));
            stmt.setString(3, purposeId);
            stmt.setNull(4, Types.OTHER);
            stmt.setString(5, triggerEvent);
            stmt.setString(6, Constants.EVENT_PURGE_INITIATED);
            stmt.setString(7, details);

            rs = stmt.executeQuery();
            if (rs.next()) {
                System.out.println("[CES DEBUG] recordOrphanComplianceEvent: INSERTED purge_requests id=" + rs.getObject("id")
                        + " principal=" + principalId + " fiduciary=" + fiduciaryId + " purpose=" + purposeId
                        + " trigger_event=" + triggerEvent + " app_id=NULL");
            } else {
                System.out.println("[CES DEBUG] recordOrphanComplianceEvent: INSERT returned no row (no id) for principal=" + principalId
                        + " fiduciary=" + fiduciaryId + " purpose=" + purposeId);
            }
        } catch (SQLException e) {
            System.out.println("[CES DEBUG] recordOrphanComplianceEvent: SQLException while inserting orphan purge_requests for principal=" + principalId
                    + " fiduciary=" + fiduciaryId + " purpose=" + purposeId + " trigger_event=" + triggerEvent + " -- " + e.getMessage());
            e.printStackTrace();
            throw e;
        } finally {
            pool.cleanup(rs, stmt, conn);
        }

        JSONObject auditContext = new JSONObject();
        auditContext.put("principal", principalId);
        auditContext.put("trigger", triggerEvent);
        auditContext.put("app", "No Linked Processor");
        auditContext.put("purpose", purposeId);
        auditContext.put("details", details);
        new Audit().logEventAsync(principalId, UUID.fromString(fiduciaryId), "SYSTEM", null, Constants.EVENT_PURGE_INITIATED, auditContext.toJSONString());
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
                "VALUES (?, ?, ?, ?) RETURNING id, created_at";

        PreparedStatement stmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        Connection conn = null;
        String newId = null;
        String createdAt = null;

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
                newId = rs.getObject("id").toString();
                createdAt = rs.getTimestamp("created_at").toInstant().toString();
                response.put("id", newId);
            }
        } finally {
            pool.cleanup(rs,stmt,conn);
        }

        if (newId != null) {
            JSONObject payload = new JSONObject();
            payload.put("id", newId);
            payload.put("recipient_type", recipientType);
            payload.put("recipient_id", recipientId);
            payload.put("notification_type", notificationType);
            payload.put("created_at", createdAt);
            payload.put("messages", resolveNotificationMessages(fiduciaryId, notificationType));
            WebhookDispatcher.dispatch(fiduciaryId, "NOTIFICATION", "notification_created", payload);
        }
        return response;
    }

    /**
     * Looks up the DPO-configured message bundle for (fiduciaryId, notificationType),
     * same table/shape Notification.java's list_notifications JOIN already uses --
     * so the NOTIFICATION webhook payload is self-sufficient (no follow-up poll
     * needed just to get the configured message). Returns null if none configured.
     */
    private JSONObject resolveNotificationMessages(String fiduciaryId, String notificationType) {
        String sql = "SELECT messages FROM notification_message_templates WHERE fiduciary_id = ? AND notification_type = ?";
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(fiduciaryId));
            pstmt.setString(2, notificationType);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                return (JSONObject) new JSONParser().parse(rs.getString("messages"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, conn);
        }
        return null;
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
