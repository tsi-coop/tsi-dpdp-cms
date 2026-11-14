package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class ExpiryDatesTest {
    @Test void fullInstantsAreParsed() {
        assertEquals(Instant.parse("2027-01-31T10:00:00Z"), ExpiryDates.parse("2027-01-31T10:00:00Z"));
        assertEquals(Instant.parse("2027-01-31T10:00:00.123Z"), ExpiryDates.parse("2027-01-31T10:00:00.123Z"));
    }

    @Test void offsetsAreHonoured() {
        assertEquals(Instant.parse("2027-01-31T04:30:00Z"), ExpiryDates.parse("2027-01-31T10:00:00+05:30"));
    }

    @Test void aDateAloneMeansThroughTheEndOfThatDay() {
        // valid on the 31st, expired from the start of the 1st (UTC)
        assertEquals(Instant.parse("2027-02-01T00:00:00Z"), ExpiryDates.parse("2027-01-31"));
        assertEquals(Instant.parse("2028-03-01T00:00:00Z"), ExpiryDates.parse("2028-02-29")); // leap day
    }

    @Test void aDateTimeWithoutAZoneIsTakenAsUtc() {
        assertEquals(Instant.parse("2027-01-31T10:00:00Z"), ExpiryDates.parse("2027-01-31T10:00:00"));
    }

    @Test void blankAndGarbageGiveNull() {
        assertNull(ExpiryDates.parse(null));
        assertNull(ExpiryDates.parse("   "));
        assertNull(ExpiryDates.parse("next tuesday"));
        assertNull(ExpiryDates.parse("2027-13-45"));
    }

    @Test void whitespaceIsTolerated() {
        assertEquals(Instant.parse("2027-02-01T00:00:00Z"), ExpiryDates.parse("  2027-01-31 "));
    }

    @Test void expiredMeansNotAfterTheInstant() {
        Instant now = Instant.parse("2027-01-31T12:00:00Z");
        assertTrue(ExpiryDates.isExpired("2027-01-30", now));
        assertFalse(ExpiryDates.isExpired("2027-01-31", now), "a date-only expiry lasts the whole day");
        assertTrue(ExpiryDates.isExpired("2027-01-31T11:59:59Z", now));
        assertFalse(ExpiryDates.isExpired("2027-01-31T12:00:01Z", now));
        assertFalse(ExpiryDates.isExpired(null, now), "no expiry set");
        assertTrue(ExpiryDates.isExpired("garbage", now), "an expiry that cannot be read is treated as expired, never as valid forever");
    }
}
