package org.tsicoop.dpdpcms.util;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Central map of every operator-API function ("service.function") to what it requires:
 *   resource:level  a permission from {@link Permissions}
 *   AUTH            any authenticated operator with a known role (the service restricts further, e.g. self-service)
 *   NOAUTH          reachable before login (the filter already skips authentication for these)
 *   NONE            belongs to the public/client API; never an operator function
 * A function missing from this map is denied under enforcement. AccessControlTest fails if a service
 * gains a function that is not listed here.
 */
public final class AccessMap {
    private AccessMap() {}

    private static final Map<String, String> MAP;
    static {
        Map<String, String> m = new TreeMap<>();
        m.put("admindash.get_admin_metrics", "dashboard:manage");
        m.put("admindash.get_dpo_metrics", "dashboard:read");
        m.put("admindash.list_access_logs", "dashboard:manage");
        m.put("admindash.list_breach_deadlines", "dashboard:read");
        m.put("admindash.list_pending_grievances", "dashboard:read");
        m.put("apikey.generate_api_key", "apikeys:manage");
        m.put("apikey.get_api_key_details", "apikeys:manage");
        m.put("apikey.list_api_keys", "apikeys:manage");
        m.put("apikey.revoke_api_key", "apikeys:manage");
        m.put("apikey.update_api_key_status", "apikeys:manage");
        m.put("app.list_apps", "apps:read");
        m.put("app.get_app", "apps:read");
        m.put("app.create_app", "apps:manage");
        m.put("app.update_app", "apps:manage");
        m.put("app.delete_app", "apps:manage");
        m.put("audit.get_audit_chain_status", "audit:read");
        m.put("audit.get_audit_log", "audit:read");
        m.put("audit.list_audit_logs", "audit:read");
        m.put("audit.log_event", "audit:manage");
        m.put("audit.verify_audit_chain", "audit:read");
        m.put("breach.download_breach_report", "breaches:read");
        m.put("breach.get_breach", "breaches:read");
        m.put("breach.get_breach_settings", "breaches:read");
        m.put("breach.list_breaches", "breaches:read");
        m.put("breach.report_breach", "breaches:write");
        m.put("breach.set_breach_settings", "breaches:write");
        m.put("breach.update_breach_status", "breaches:write");
        m.put("compliance.assign_purge_request", "purges:manage");
        m.put("compliance.get_purge_request", "purges:read");
        m.put("compliance.initiate_purge_request", "purges:write");
        m.put("compliance.list_purge_requests", "purges:read");
        m.put("compliance.update_purge_status", "purges:write");
        m.put("consent.erasure_request", "consents:write");
        m.put("consent.get_active_consent", "consents:read");
        m.put("consent.get_withdrawal_implications", "consents:read");
        m.put("consent.get_consent_record_details", "consents:read");
        m.put("consent.link_user", "consents:write");
        m.put("consent.list_consent_history", "consents:read");
        m.put("consent.list_principals", "consents:read");
        m.put("consent.minor_guardian_audit", "consents:read");
        m.put("consent.record_consent", "consents:write");
        m.put("consent.record_parent_consent", "consents:write");
        m.put("consent.validate_consent", "consents:read");
        m.put("consent.withdraw_consent", "consents:write");
        m.put("fiduciary.create_fiduciary", "fiduciaries:manage");
        m.put("fiduciary.delete_fiduciary", "fiduciaries:manage");
        m.put("fiduciary.get_fiduciary", "fiduciaries:read");
        m.put("fiduciary.list_fiduciaries", "fiduciaries:read");
        m.put("fiduciary.update_fiduciary", "fiduciaries:manage");
        m.put("fiduciary.validate_fiduciary_domain", "fiduciaries:manage");
        m.put("grievance.assign_grievance", "grievances:manage");
        m.put("grievance.get_grievance", "grievances:read");
        m.put("grievance.list_grievances", "grievances:read");
        m.put("grievance.list_user_grievances", "grievances:read");
        m.put("grievance.submit_grievance", "grievances:write");
        m.put("grievance.submit_grievance_feedback", "grievances:write");
        m.put("grievance.upload_grievance_attachment", "grievances:write");
        m.put("grievance.get_grievance_attachment", "grievances:read");
        m.put("grievance.update_grievance_status", "grievances:write");
        m.put("job.create_job", "jobs:write");
        m.put("job.download_file", "jobs:read");
        m.put("job.list_jobs", "jobs:read");
        m.put("legal.generate_certificate", "certificates:write");
        m.put("legal.get_certificate", "certificates:read");
        m.put("legal.list_certificates", "certificates:read");
        m.put("notification.get_notification_messages", "settings:read");
        m.put("notification.get_rights_app_config", "settings:read");
        m.put("notification.get_webhook_delivery", "webhooks:read");
        m.put("notification.list_notifications", "AUTH");
        m.put("notification.list_webhook_configs", "settings:read");
        m.put("notification.list_webhook_deliveries", "webhooks:read");
        m.put("notification.mark_notification_read", "AUTH");
        m.put("notification.retry_webhook_delivery", "webhooks:write");
        m.put("notification.set_notification_message", "settings:write");
        m.put("notification.set_rights_app_config", "settings:write");
        m.put("notification.set_webhook_config", "settings:write");
        m.put("operator.create_user", "users:manage");
        m.put("operator.deactivate_user", "users:manage");
        m.put("operator.enrol_mfa", "NOAUTH");
        m.put("operator.generate_recovery_key", "AUTH");
        m.put("operator.get_user", "users:read");
        m.put("operator.list_users", "users:read");
        m.put("operator.login", "NOAUTH");
        m.put("operator.logout", "AUTH");
        m.put("operator.reset_password_via_recovery", "NOAUTH");
        m.put("operator.update_user", "AUTH");
        m.put("operator.verify_mfa", "NOAUTH");
        m.put("operator.verify_recovery_key", "NOAUTH");
        m.put("policy.create_policy", "policies:write");
        m.put("policy.delete_policy", "policies:write");
        m.put("policy.get_active_policy", "policies:read");
        m.put("policy.get_policy", "policies:read");
        m.put("policy.list_active_policies", "policies:read");
        m.put("policy.list_policies", "policies:read");
        m.put("policy.publish_policy", "policies:write");
        m.put("policy.update_policy", "policies:write");
        m.put("principal.list_active_fiduciaries", "NONE");
        m.put("principal.list_fiduciary_personas", "NONE");
        m.put("principal.principal_login", "NONE");
        m.put("principal.request_principal_otp", "NONE");
        m.put("purpose.close_purpose", "purposes:manage");
        m.put("purpose.list_closed_purposes", "purposes:read");
        m.put("purpose.list_purpose_lifecycle", "purposes:read");
        m.put("purpose.reopen_purpose", "purposes:manage");
        m.put("purpose.set_purpose_state", "purposes:manage");
        m.put("rights.assign_rights_request", "rights:manage");
        m.put("rights.create_nomination", "rights:write");
        m.put("rights.list_nominations", "rights:read");
        m.put("rights.revoke_nomination", "rights:write");
        m.put("rights.get_rights_request", "rights:read");
        m.put("rights.list_rights_requests", "rights:read");
        m.put("rights.list_user_rights_requests", "rights:read");
        m.put("rights.submit_rights_request", "rights:write");
        m.put("rights.update_rights_request_status", "rights:write");
        m.put("ropa.create_entry", "ropa:write");
        m.put("ropa.derive_from_policy", "ropa:write");
        m.put("ropa.export_ropa", "ropa:read");
        m.put("ropa.get_entry", "ropa:read");
        m.put("ropa.list_entries", "ropa:read");
        m.put("ropa.publish_entry", "ropa:write");
        m.put("ropa.retire_entry", "ropa:write");
        m.put("ropa.update_entry", "ropa:write");
        m.put("ropa.validate_completeness", "ropa:read");
        MAP = Collections.unmodifiableMap(m);
    }

    /** Requirement for service.function, or null if the function is not in the map. */
    public static String required(String service, String func) {
        if (service == null || func == null) return null;
        return MAP.get(service.toLowerCase() + "." + func.toLowerCase());
    }

    public static Set<String> keys() { return MAP.keySet(); }
}
