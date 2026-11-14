package org.tsicoop.dpdpcms.util;

import java.time.Instant;

public final class SessionPolicy {
    private SessionPolicy() {}

    /**
     * True if a token issued at {@code issuedAt} predates the operator's {@code tokens_valid_after}
     * cutoff (set on password change, deactivation, first MFA enrolment). JWT iat has one-second
     * resolution, so comparison is by whole seconds: a token issued in the same second as the
     * change (for example the one handed back right after enrolment) stays valid.
     */
    public static boolean issuedBeforeCutoff(Instant issuedAt, Instant cutoff) {
        if (cutoff == null || issuedAt == null) return false;
        return issuedAt.getEpochSecond() < cutoff.getEpochSecond();
    }
}
