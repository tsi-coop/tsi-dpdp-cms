package org.tsicoop.dpdpcms.util;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Reads the consent_expiry of a data point. The CMS writes full instants, but a value can also arrive as a date
 * alone or as a date-time with an offset or without one, and a parse failure must neither crash the request nor
 * make an expired consent look valid.
 */
public final class ExpiryDates {
    private ExpiryDates() {}

    /** @return the instant the consent ends, or null if blank or unreadable. A date alone ends at the start of the NEXT day (UTC). */
    public static Instant parse(String value) {
        if (value == null) return null;
        String v = value.trim();
        if (v.isEmpty()) return null;
        try { return Instant.parse(v); } catch (Exception ignored) { }
        try { return OffsetDateTime.parse(v).toInstant(); } catch (Exception ignored) { }
        try { return LocalDateTime.parse(v).toInstant(ZoneOffset.UTC); } catch (Exception ignored) { }
        try { return LocalDate.parse(v).plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC); } catch (Exception ignored) { }
        return null;
    }

    /** No expiry set: not expired. An expiry that cannot be read: expired (fail closed). */
    public static boolean isExpired(String value, Instant now) {
        if (value == null || value.isBlank()) return false;
        Instant at = parse(value);
        return at == null || now.isAfter(at);
    }
}
