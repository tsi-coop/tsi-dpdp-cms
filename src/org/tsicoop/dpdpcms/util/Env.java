package org.tsicoop.dpdpcms.util;

/**
 * The deployment environment, from TSI_DPDP_CMS_ENV: "production", "local" or "development".
 * Anything other than "production" (including unset) is treated as non-production, so the
 * production-only guards fail towards the safe side only when production is stated explicitly.
 */
public final class Env {

    public static final String VAR = "TSI_DPDP_CMS_ENV";

    private Env() {}

    public static String raw() {
        return System.getenv(VAR);
    }

    public static boolean isSet() {
        String v = raw();
        return v != null && !v.isBlank();
    }

    public static boolean isProduction() {
        return "production".equalsIgnoreCase(raw() == null ? null : raw().trim());
    }

    /** True for the values the application documents; anything else is probably a typo. */
    public static boolean isRecognized() {
        String v = raw() == null ? "" : raw().trim();
        return v.equalsIgnoreCase("production") || v.equalsIgnoreCase("local") || v.equalsIgnoreCase("development");
    }
}
