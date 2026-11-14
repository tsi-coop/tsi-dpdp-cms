package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class TotpTest {
    // RFC 6238 appendix B secret "12345678901234567890" (ASCII), base32-encoded
    private static final String RFC_SECRET = Totp.base32Encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    @Test
    void matchesRfc6238Vectors() {
        // RFC values are 8 digits; the 6-digit code is the last 6 of them.
        assertEquals("287082", Totp.code(RFC_SECRET, Totp.stepAt(59_000L)));
        assertEquals("081804", Totp.code(RFC_SECRET, Totp.stepAt(1111111109_000L)));
        assertEquals("353130", Totp.code(RFC_SECRET, Totp.stepAt(20000000000_000L)));
    }

    @Test
    void base32RoundTrips() {
        byte[] data = {1, 2, 3, (byte) 250, 99, 0, 7};
        assertArrayEquals(data, Totp.base32Decode(Totp.base32Encode(data)));
    }

    @Test
    void generatedSecretsAreUniqueAndUsable() {
        String a = Totp.generateSecret(), b = Totp.generateSecret();
        assertNotEquals(a, b);
        assertEquals(32, a.length());
        assertEquals(6, Totp.code(a, 1).length());
    }

    @Test
    void acceptsCurrentAndAdjacentStepsOnly() {
        long now = 1_000_000_000_000L;
        long step = Totp.stepAt(now);
        assertEquals(step, Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step), now, 0));
        assertEquals(step - 1, Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 1), now, 0));
        assertEquals(step + 1, Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step + 1), now, 0));
        assertEquals(-1, Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 2), now, 0));
        assertEquals(-1, Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step + 2), now, 0));
    }

    @Test
    void eachStepIsAcceptedOnlyOnce() {
        long now = 1_000_000_000_000L;
        long step = Totp.stepAt(now);
        String code = Totp.code(RFC_SECRET, step);
        long accepted = Totp.verify(RFC_SECRET, code, now, 0);
        assertEquals(step, accepted);
        assertEquals(-1, Totp.verify(RFC_SECRET, code, now, accepted)); // replay
        // an older (still in-window) step is also refused once a newer one was used
        assertEquals(-1, Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 1), now, accepted));
    }

    @Test
    void rejectsMalformedCodes() {
        long now = 1_000_000_000_000L;
        assertEquals(-1, Totp.verify(RFC_SECRET, null, now, 0));
        assertEquals(-1, Totp.verify(RFC_SECRET, "12345", now, 0));
        assertEquals(-1, Totp.verify(RFC_SECRET, "abcdef", now, 0));
        assertEquals(-1, Totp.verify(RFC_SECRET, "1234567", now, 0));
    }

    @Test
    void otpauthUriIsWellFormed() {
        String uri = Totp.otpauthUri("TSI DPDP CMS", "a@b.com", "ABC234");
        assertTrue(uri.startsWith("otpauth://totp/TSI%20DPDP%20CMS:a%40b.com?"));
        assertTrue(uri.contains("secret=ABC234"));
        assertTrue(uri.contains("issuer=TSI%20DPDP%20CMS"));
    }
}
