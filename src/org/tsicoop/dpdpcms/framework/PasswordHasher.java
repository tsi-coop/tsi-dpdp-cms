package org.tsicoop.dpdpcms.framework;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordHasher {

    private static final int BCRYPT_LOG_ROUNDS = 12; // A common, secure value

    /**
     * Hashes a plaintext password using BCrypt.
     * @param plaintextPassword The password in plain text.
     * @return The hashed password.
     */
    public String hashPassword(String plaintextPassword) {
        // Generate a salt and hash the password
        String salt = BCrypt.gensalt(BCRYPT_LOG_ROUNDS);
        //String salt = System.getenv("TSI_AADHAR_VAULT_SALT");
        return BCrypt.hashpw(plaintextPassword, salt);
    }

    /**
     * Verifies a plaintext password against a stored hashed password.
     * @param plaintextPassword The password in plain text.
     * @param hashedPassword The hashed password stored in the database.
     * @return true if the password matches, false otherwise.
     */
    public boolean checkPassword(String plaintextPassword, String hashedPassword) {
        return BCrypt.checkpw(plaintextPassword, hashedPassword);
    }

    /**
     * Verifies a plain-text password against a BCrypt hashed password.
     *
     * @param plainTextPassword The password provided by the user (in plain text).
     * @param hashedPassword The stored BCrypt hashed password from the database.
     * @return true if the plain-text password matches the hash, false otherwise.
     */
    public boolean verifyPassword(String plainTextPassword, String hashedPassword) {
        if (plainTextPassword == null || hashedPassword == null) {
            // Handle null inputs gracefully, perhaps throw IllegalArgumentException or return false
            return false;
        }
        // BCrypt.checkpw(plain_password, hashed_password)
        // This method handles extracting the salt from the hashed password and comparing.
        return BCrypt.checkpw(plainTextPassword, hashedPassword);
    }
}