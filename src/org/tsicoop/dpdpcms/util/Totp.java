package org.tsicoop.dpdpcms.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/** RFC 6238 TOTP (HMAC-SHA1, 30 s step, 6 digits), compatible with Google/Microsoft Authenticator, Authy, etc. */
public final class Totp {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final long STEP_SECONDS = 30;
    private static final int DIGITS = 6;
    private static final int WINDOW = 1; // accept one step either side for clock drift
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {}

    public static String generateSecret() {
        byte[] b = new byte[20];
        RANDOM.nextBytes(b);
        return base32Encode(b);
    }

    public static long stepAt(long epochMillis) {
        return Math.floorDiv(epochMillis / 1000, STEP_SECONDS);
    }

    public static String code(String base32Secret, long step) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(base32Decode(base32Secret), "HmacSHA1"));
            byte[] msg = new byte[8];
            for (int i = 7, s = 0; i >= 0; i--, s += 8) msg[i] = (byte) (step >>> s);
            byte[] h = mac.doFinal(msg);
            int o = h[h.length - 1] & 0x0f;
            int bin = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
            int otp = bin % (int) Math.pow(10, DIGITS);
            return String.format("%0" + DIGITS + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns the accepted step, or -1. A step is accepted only if it is newer than
     * {@code lastAcceptedStep}, so every code works once and an older code cannot be replayed.
     */
    public static long verify(String base32Secret, String submitted, long nowMillis, long lastAcceptedStep) {
        if (submitted == null || !submitted.matches("\\d{" + DIGITS + "}")) return -1;
        long current = stepAt(nowMillis);
        long accepted = -1;
        for (long s = current - WINDOW; s <= current + WINDOW; s++) {
            // constant-time compare, and no early exit, so timing does not reveal which step matched
            boolean eq = MessageDigest.isEqual(code(base32Secret, s).getBytes(StandardCharsets.US_ASCII),
                    submitted.getBytes(StandardCharsets.US_ASCII));
            if (eq && s > lastAcceptedStep) accepted = s;
        }
        return accepted;
    }

    public static String otpauthUri(String issuer, String account, String secret) {
        return "otpauth://totp/" + enc(issuer) + ":" + enc(account)
                + "?secret=" + secret + "&issuer=" + enc(issuer) + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    public static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) { sb.append(ALPHABET.charAt((buffer >> (bits - 5)) & 31)); bits -= 5; }
        }
        if (bits > 0) sb.append(ALPHABET.charAt((buffer << (5 - bits)) & 31));
        return sb.toString();
    }

    public static byte[] base32Decode(String s) {
        String in = s.replace("=", "").replace(" ", "").toUpperCase();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int buffer = 0, bits = 0;
        for (char c : in.toCharArray()) {
            int v = ALPHABET.indexOf(c);
            if (v < 0) throw new IllegalArgumentException("Invalid base32 character");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) { out.write((buffer >> (bits - 8)) & 0xff); bits -= 8; }
        }
        return out.toByteArray();
    }
}
