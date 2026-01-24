package org.tsicoop.dpdpcms.util;

public class Constants {

    // --- Lifecycle Phases ---
    public static final String PHASE_COLLECTION = "COLLECTION";
    public static final String PHASE_PROCESSING = "PROCESSING";
    public static final String PHASE_MAINTENANCE = "MAINTENANCE";
    public static final String PHASE_ERASURE = "ERASURE";

    // --- Action Types (Triggered by Apps or Users) ---
    public static final String ACTION_CONSENT_GIVEN = "CONSENT_GIVEN";
    public static final String ACTION_LINK_USER = "LINK_USER";
    public static final String ACTION_CONSENT_WITHDRAWN = "CONSENT_WITHDRAWN";
    public static final String ACTION_ERASURE_REQUEST = "ERASURE_REQUEST";

    public static final String ACTION_CONSENT_VALIDATION = "CONSENT_VALIDATION";
    public static final String ACTION_CORRECTION_REQUEST = "CORRECTION_REQUEST"; // Section 12 requirement
    public static final String ACTION_GRIEVANCE_SUBMITTED = "GRIEVANCE_SUBMITTED"; // Section 13 requirement

    // Consent Validation Status
    public static final String VALIDATION_SUCCESS = "VALIDATION_SUCCESS";
    public static final String VALIDATION_FAILED = "VALIDATION_FAILED";

    // --- Lifecycle Events (Triggered by CES / Internal System) ---
    public static final String EVENT_CESSATION = "CESSATION";
    public static final String EVENT_COLLECTION = "COLLECTION";
    public static final String EVENT_RETENTION_REACHED = "RETENTION_PERIOD_REACHED";
    public static final String EVENT_PURGE_INITIATED = "PURGE_INITIATED";
    public static final String EVENT_PURGE_IN_PROGRESS = "PURGE_IN_PROGRESS";
    public static final String EVENT_PURGE_COMPLETED = "PURGE_COMPLETED";
    public static final String EVENT_PURGE_FAILED = "PURGE_FAILED";
    public static final String EVENT_LEGAL_HOLD_APPLIED = "LEGAL_HOLD_APPLIED"; // Section 8(1) Exception

    // -- Purge Trigger Event

    public static final String PURGE_TRIGGER_ERASURE = "ErasureRequest";
    public static final String PURGE_TRIGGER_EXPIRY = "RetentionPolicyExpiry";

    // --- Notification Types ---
    public static final String NOTIF_EXPIRY_REMINDER = "EXPIRY_NOTIFICATION"; // Pre-expiry alert
    public static final String NOTIF_PURGE_INIT = "PURGE_INIT_NOTIFICATION";
    public static final String NOTIF_PURGE_CONFIRM = "PURGE_CONFIRM_NOTIFICATION"; // Post-erasure proof
    public static final String NOTIF_LEGAL_ONHOLD = "PURGE_ONHOLD_NOTIFICATION";
    public static final String NOTIF_WITHDRAWAL_ACK = "WITHDRAWAL_ACKNOWLEDGMENT";

    // --- Age Categories (Section 9) ---
    public static final String AGE_ADULT = "ADULT";
    public static final String AGE_MINOR = "MINOR";

    //-- Service Type
    public static final String SERVICE_TYPE_APP = "APP";
    public static final String SERVICE_TYPE_USER = "USER";

    public static final String SERVICE_TYPE_SYSTEM = "SYSTEM";

    // Grievance Status
    public static final String GRIEVANCE_NEW = "NEW";
    public static final String GRIEVANCE_IN_PROGRESS = "IN_PROGRESS";
    public static final String GRIEVANCE_RESOLVED = "RESOLVED";
    public static final String GRIEVANCE_ESCALATED = "ESCALATED";
}
