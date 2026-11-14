package org.tsicoop.dpdpcms.util;

import java.util.Locale;

/**
 * CONSENT_CAPTURE_MODE: "warn" (default) records a CONSENT_CAPTURE_WARNING audit event for submissions that
 * break the capture rules (incomplete purpose choices, a minor without a verified guardian log) and accepts
 * them; "strict" rejects them. Only the exact value "strict" rejects.
 */
public final class ConsentCaptureMode {
    private ConsentCaptureMode() {}
    public static final String VAR = "CONSENT_CAPTURE_MODE";
    public static boolean isStrict(String v) { return v != null && v.trim().toLowerCase(Locale.ROOT).equals("strict"); }
    public static boolean strict() { return isStrict(System.getenv(VAR)); }
}
