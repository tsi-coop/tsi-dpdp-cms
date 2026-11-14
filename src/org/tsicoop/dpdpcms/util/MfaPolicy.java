package org.tsicoop.dpdpcms.util;

/**
 * When is MFA mandatory? Enrolment and login challenges work in every mode; the "ADMIN, DPO and AUDITOR must
 * have MFA" rule is enforced in production, or anywhere MFA_ENFORCE=true (for testing it locally).
 * Production cannot be switched off with MFA_ENFORCE.
 */
public final class MfaPolicy {
    private MfaPolicy() {}

    public static boolean enforcing() {
        return enforcing(Env.isProduction(), System.getenv("MFA_ENFORCE"));
    }

    public static boolean enforcing(boolean production, String mfaEnforceFlag) {
        return production || (mfaEnforceFlag != null && mfaEnforceFlag.trim().equalsIgnoreCase("true"));
    }

    /** True if an operator with this role must have MFA enrolled before getting a working session. */
    public static boolean required(String role, boolean enforcing) {
        return enforcing && role != null && (role.equalsIgnoreCase("ADMIN") || role.equalsIgnoreCase("DPO") || role.equalsIgnoreCase("AUDITOR"));
    }

    public static boolean requiredFor(String role) {
        return required(role, enforcing());
    }
}
