package org.tsicoop.dpdpcms.framework;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class LookupHasher {

    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String TSI_LOOKUP_SALT = "TSI_LOOKUP_SALT";

    private final String globalLookupSalt;

    public LookupHasher() {
        // Read the global salt from the environment variable when the class is instantiated
        String salt = System.getenv(TSI_LOOKUP_SALT);
        // Crucial: Fail fast if the salt is not provided in production
        if (salt == null || salt.trim().isEmpty()) {
            throw new IllegalStateException("FATAL: Global lookup salt environment variable '" +
                    TSI_LOOKUP_SALT + "' not set or empty. " +
                    "This is required for deterministic ID hashing.");
        }
        this.globalLookupSalt = salt;
    }

    /**
     * Hashes the input data using a GLOBAL, fixed secret salt.
     * This hash is deterministic for the same input data and global salt.
     * Suitable for creating `hashed_id_number` which is used for direct lookup and duplicate checking.
     *
     * @param data The data to hash (e.g., Aadhaar number).
     * @return A Base64 encoded hash string.
     * @throws NoSuchAlgorithmException if SHA-256 algorithm is not available.
     */
    public String hashData(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] globalSaltBytes = globalLookupSalt.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Apply global salt before hashing the data
        digest.update(globalSaltBytes);
        byte[] hashedBytes = digest.digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    /**
     * Verifies a plaintext data against a stored hash that was generated using the GLOBAL salt.
     *
     * @param data The plaintext data.
     * @param storedHashBase64 The Base64 encoded hash to compare against.
     * @return true if the hashes match, false otherwise.
     */
    public boolean checkHash(String data, String storedHashBase64) {
        try {
            String computedHash = hashData(data); // Use the same global-salted hash method
            return computedHash.equals(storedHashBase64);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Hashing algorithm not available: " + e.getMessage());
            return false;
        }
    }
}
