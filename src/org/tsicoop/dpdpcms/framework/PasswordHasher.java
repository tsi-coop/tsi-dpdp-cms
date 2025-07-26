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
}