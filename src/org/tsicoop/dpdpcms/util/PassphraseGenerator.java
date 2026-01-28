package org.tsicoop.dpdpcms.util;

import java.security.SecureRandom;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * PassphraseGenerator provides cryptographically secure, human-readable secrets.
 * Ideal for 2nd Factor Authentication (MFA) where connectivity for OTP is limited.
 */
public class PassphraseGenerator {

    private static final SecureRandom secureRandom = new SecureRandom();

    // A sample list of simple, distinct words.
    // In production, consider loading a standard EFF wordlist (7,776 words).
    private static final String[] WORD_LIST = {
            "alpha", "bravo", "cactus", "delta", "eagle", "forest", "galaxy", "harvest",
            "island", "jungle", "knight", "lemon", "mountain", "nebula", "ocean", "planet",
            "quartz", "river", "shadow", "tiger", "ultra", "valley", "winter", "xenon",
            "yellow", "zebra", "active", "bright", "clever", "daring", "eager", "fancy",
            "gentle", "happy", "iconic", "jolly", "kindly", "lucky", "mighty", "noble",
            "orange", "polite", "quiet", "rapid", "silver", "tough", "unique", "vibrant",
            "wisdom", "young", "anchor", "beacon", "castle", "desert", "engine", "fossil",
            "glider", "helmet", "impact", "jacket", "kettle", "legend", "mirror", "native",
            "orbit", "parade", "quiver", "rocket", "spirit", "tunnel", "update", "vessel",
            "wizard", "aspect", "beacon", "carbon", "device", "energy", "fusion", "ground",
            "hybrid", "indoor", "joyful", "kinetic", "linear", "matrix", "nature", "output",
            "pixel", "quantum", "remote", "sensor", "theory", "useful", "vector", "widget"
    };

    /**
     * Generates a 5-word hyphenated passphrase.
     * Example: "nebula-gentle-rocket-matrix-quartz"
     */
    public static String generate() {
        return generate(5, "-");
    }

    /**
     * Generates a customizable passphrase.
     * * @param wordCount Number of words to include.
     * @param delimiter The string to place between words.
     * @return A cryptographically secure passphrase string.
     */
    public static String generate(int wordCount, String delimiter) {
        if (wordCount <= 0) return "";

        return IntStream.range(0, wordCount)
                .mapToObj(i -> WORD_LIST[secureRandom.nextInt(WORD_LIST.length)])
                .collect(Collectors.joining(delimiter));
    }

    /**
     * Diagnostic Main Method
     */
    public static void main(String[] args) {
        System.out.println("Generated MFA Passphrase: " + generate());
        System.out.println("Generated 3-word key: " + generate(3, " "));
    }
}