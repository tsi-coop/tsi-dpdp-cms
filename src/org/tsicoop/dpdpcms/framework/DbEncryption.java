package org.tsicoop.dpdpcms.framework;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * Central access point for the DB_ENCRYPTION_KEY and reusable SQL fragments
 * for pgcrypto operations on PII columns (email, phone).
 *
 * Encryption scheme (matches 04_gaps.sql):
 *   Write  : encode(pgp_sym_encrypt(value, key), 'base64')  stored as TEXT
 *   Read   : pgp_sym_decrypt(decode(col, 'base64'), key)    returns TEXT
 *   Lookup : encode(hmac(lower(trim(value)), key, 'sha256'), 'hex')  stored in *_hmac column
 *
 * Requires the DB_ENCRYPTION_KEY environment variable to be set.
 */
public class DbEncryption {

    public static final String ENV_VAR = "DB_ENCRYPTION_KEY";

    private static final String key;

    static {
        String k = System.getenv(ENV_VAR);
        if (k == null || k.trim().isEmpty()) {
            throw new IllegalStateException(
                    ENV_VAR + " environment variable must be set. " +
                    "Run db/04_gaps.sql to migrate the schema before starting the application.");
        }
        key = k.trim();
    }

    private DbEncryption() {}

    /** The raw encryption/HMAC key. */
    public static String key() { return key; }

    // ------------------------------------------------------------------
    // SQL fragment constants — use these to build PreparedStatement SQL
    // ------------------------------------------------------------------

    /** Encrypts a bound parameter value. Consumes 2 bind slots: (value, key). */
    public static final String ENCRYPT =
            "encode(pgp_sym_encrypt(?, ?), 'base64')";

    /** Computes the deterministic HMAC for WHERE lookups. Consumes 2 bind slots: (value, key). */
    public static final String HMAC =
            "encode(hmac(lower(trim(?)), ?, 'sha256'), 'hex')";

    /**
     * Decrypts the named column inline in a SELECT.
     * Consumes 1 bind slot: (key) — positioned wherever the fragment appears in the query.
     *
     * Example:
     *   "SELECT " + DbEncryption.decryptCol("email_enc") + " AS email FROM operators WHERE id = ?"
     *   pstmt.setString(1, DbEncryption.key());   // decrypt key
     *   pstmt.setObject(2, id);                    // WHERE id
     */
    public static String decryptCol(String columnName) {
        return "pgp_sym_decrypt(decode(" + columnName + ", 'base64'), ?)";
    }

    // ------------------------------------------------------------------
    // PreparedStatement binding helpers
    // ------------------------------------------------------------------

    /** Binds (value, key) for ENCRYPT. Returns the next available param index. */
    public static int bindEncrypt(PreparedStatement ps, int idx, String value) throws SQLException {
        ps.setString(idx++, value);
        ps.setString(idx++, key);
        return idx;
    }

    /** Binds (value, key) for HMAC. Returns the next available param index. */
    public static int bindHmac(PreparedStatement ps, int idx, String value) throws SQLException {
        ps.setString(idx++, value);
        ps.setString(idx++, key);
        return idx;
    }

    /** Binds (key) for decryptCol. Returns the next available param index. */
    public static int bindKey(PreparedStatement ps, int idx) throws SQLException {
        ps.setString(idx++, key);
        return idx;
    }
}
