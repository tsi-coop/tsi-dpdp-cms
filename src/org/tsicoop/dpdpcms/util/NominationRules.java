package org.tsicoop.dpdpcms.util;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Nominations (DPDP s.14): a data principal may nominate another individual to exercise their rights in the event
 * of their death or incapacity. The CMS records the nomination; whether and when the nominee may act is for the
 * fiduciary's DPO to verify, so nothing here grants the nominee access to anything.
 */
public final class NominationRules {
    private NominationRules() {}

    public static final int MAX_OPEN_PER_PRINCIPAL = 5;
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern PHONE = Pattern.compile("^[+0-9 ()\\-]+$");

    /** @return the problem, or null if the nomination is acceptable. Null dates mean "from now" / "until revoked". */
    public static String problem(String name, String contact, Instant validFrom, Instant validUntil, Instant now) {
        String n = name == null ? "" : name.trim();
        if (n.length() < 2 || n.length() > 100) return "the nominee's name must be 2 to 100 characters";
        String c = contact == null ? "" : contact.trim();
        if (c.isEmpty() || c.length() > 255) return "a contact (e-mail address or phone number) is required";
        if (c.contains("@")) {
            if (!EMAIL.matcher(c).matches()) return "the contact is not a valid e-mail address";
        } else {
            long digits = c.chars().filter(Character::isDigit).count();
            if (!PHONE.matcher(c).matches() || digits < 7 || digits > 15) return "the contact is not a valid e-mail address or phone number";
        }
        if (validFrom != null && validFrom.isBefore(now.minus(1, ChronoUnit.DAYS))) return "the start date cannot be in the past";
        if (validUntil != null) {
            Instant start = validFrom != null ? validFrom : now;
            if (!validUntil.isAfter(start) || !validUntil.isAfter(now)) return "the end date must be after the start date and in the future";
            if (validUntil.isAfter(now.plus(3650, ChronoUnit.DAYS))) return "a nomination can be valid for at most 10 years";
        }
        return null;
    }

    /** What the status is NOW: revoked and expired are final; otherwise the dates decide. */
    public static String effectiveStatus(String stored, Instant validFrom, Instant validUntil, Instant now) {
        String s = stored == null ? "" : stored.toUpperCase(Locale.ROOT);
        if (s.equals("REVOKED") || s.equals("EXPIRED")) return s;
        if (validUntil != null && now.isAfter(validUntil)) return "EXPIRED";
        if (validFrom != null && now.isBefore(validFrom)) return "PENDING";
        return "ACTIVE";
    }

    /** Staff see enough to recognise a contact, not the whole of it. */
    public static String maskContact(String contact) {
        if (contact == null) return null;
        String c = contact.trim();
        int at = c.indexOf('@');
        if (at > 0) return c.charAt(0) + "***" + c.substring(at);
        String digits = c.replaceAll("\\D", "");
        if (digits.length() <= 4) return "***";
        return "*".repeat(digits.length() - 4) + digits.substring(digits.length() - 4);
    }
}
