-- 04_gaps.sql
-- G-11 Option B: Column-level encryption of PII using pgcrypto
--
-- NOTE: G-25 (SLF4J structured logging) is a Java-only change — no SQL required.
--
-- ============================================================
-- PREREQUISITES — run before executing this script
-- ============================================================
--
--   Set the encryption key in your session (value must match DB_ENCRYPTION_KEY
--   environment variable that the Java application reads at runtime):
--
--       SET app.enc_key = '<value-of-DB_ENCRYPTION_KEY>';
--
--   To persist across sessions / connections:
--       ALTER DATABASE <dbname> SET app.enc_key = '<value-of-DB_ENCRYPTION_KEY>';
--
-- ============================================================
-- ENCRYPTION SCHEME
-- ============================================================
--
--   Write path : encode(pgp_sym_encrypt(plaintext, key), 'base64')  → TEXT column
--   Read path  : pgp_sym_decrypt(decode(ciphertext, 'base64'), key) → TEXT
--   Lookup path: encode(hmac(lower(trim(value)), key, 'sha256'), 'hex')
--                Stored in *_hmac column; used in WHERE clauses.
--
-- ============================================================
-- AFFECTED TABLES
-- ============================================================
--
--   operators   : email (NOT NULL, UNIQUE)
--   fiduciaries : email (nullable, UNIQUE), phone (nullable)
--   apps        : email (nullable), phone (nullable)
--
-- ============================================================
-- ROLLBACK
-- ============================================================
--
--   Plaintext values survive in *_plaintext columns throughout.
--   To rollback: rename *_plaintext columns back, drop new columns.

-- ============================================================
-- 0. Enable pgcrypto
-- ============================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ============================================================
-- TABLE: operators
--   email VARCHAR(255) NOT NULL UNIQUE
-- ============================================================

-- Step 1: Add encrypted value + deterministic HMAC columns
ALTER TABLE operators
    ADD COLUMN IF NOT EXISTS email_enc  TEXT,
    ADD COLUMN IF NOT EXISTS email_hmac TEXT;

-- Step 2: Populate from existing plaintext data
UPDATE operators
SET
    email_enc  = encode(pgp_sym_encrypt(email, current_setting('app.enc_key')), 'base64'),
    email_hmac = encode(hmac(lower(trim(email)), current_setting('app.enc_key'), 'sha256'), 'hex');

-- Step 3: Enforce NOT NULL on new columns (mirrors original email NOT NULL)
ALTER TABLE operators
    ALTER COLUMN email_enc  SET NOT NULL,
    ALTER COLUMN email_hmac SET NOT NULL;

-- Step 4: Move uniqueness to the HMAC column
--   Drop both the inline UNIQUE constraint and the explicit index
ALTER TABLE operators DROP CONSTRAINT IF EXISTS operators_email_key;
DROP INDEX  IF EXISTS idx_operators_email_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_operators_email_hmac ON operators (email_hmac);

-- Step 5: Rename plaintext column — forces Java queries to update
ALTER TABLE operators RENAME COLUMN email TO email_plaintext;


-- ============================================================
-- TABLE: fiduciaries
--   email VARCHAR(255) UNIQUE  (nullable)
--   phone VARCHAR(50)          (nullable)
-- ============================================================

-- Step 1: Add new columns
ALTER TABLE fiduciaries
    ADD COLUMN IF NOT EXISTS email_enc  TEXT,
    ADD COLUMN IF NOT EXISTS email_hmac TEXT,
    ADD COLUMN IF NOT EXISTS phone_enc  TEXT;

-- Step 2: Populate from existing plaintext data
UPDATE fiduciaries
SET
    email_enc  = CASE WHEN email IS NOT NULL
                      THEN encode(pgp_sym_encrypt(email, current_setting('app.enc_key')), 'base64')
                      ELSE NULL END,
    email_hmac = CASE WHEN email IS NOT NULL
                      THEN encode(hmac(lower(trim(email)), current_setting('app.enc_key'), 'sha256'), 'hex')
                      ELSE NULL END,
    phone_enc  = CASE WHEN phone IS NOT NULL
                      THEN encode(pgp_sym_encrypt(phone, current_setting('app.enc_key')), 'base64')
                      ELSE NULL END;

-- Step 3: Move uniqueness to the HMAC column (partial index — NULLs excluded)
ALTER TABLE fiduciaries DROP CONSTRAINT IF EXISTS fiduciaries_email_key;
DROP INDEX  IF EXISTS idx_fiduciaries_email_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_fiduciaries_email_hmac
    ON fiduciaries (email_hmac)
    WHERE email_hmac IS NOT NULL;

-- Step 4: Rename plaintext columns
ALTER TABLE fiduciaries RENAME COLUMN email TO email_plaintext;
ALTER TABLE fiduciaries RENAME COLUMN phone TO phone_plaintext;


-- ============================================================
-- TABLE: apps
--   email VARCHAR(255)  (nullable, no unique constraint)
--   phone VARCHAR(50)   (nullable, no unique constraint)
-- ============================================================

-- Step 1: Add new columns (no HMAC needed — no uniqueness requirement)
ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS email_enc TEXT,
    ADD COLUMN IF NOT EXISTS phone_enc TEXT;

-- Step 2: Populate from existing plaintext data
UPDATE apps
SET
    email_enc = CASE WHEN email IS NOT NULL
                     THEN encode(pgp_sym_encrypt(email, current_setting('app.enc_key')), 'base64')
                     ELSE NULL END,
    phone_enc = CASE WHEN phone IS NOT NULL
                     THEN encode(pgp_sym_encrypt(phone, current_setting('app.enc_key')), 'base64')
                     ELSE NULL END;

-- Step 3: Rename plaintext columns
ALTER TABLE apps RENAME COLUMN email TO email_plaintext;
ALTER TABLE apps RENAME COLUMN phone TO phone_plaintext;


-- ============================================================
-- Verification queries (run manually after migration)
-- ============================================================

-- Confirm all operators rows encrypted
-- SELECT count(*) AS total,
--        count(email_enc)  AS have_enc,
--        count(email_hmac) AS have_hmac
--   FROM operators;

-- Round-trip decrypt check for a known email
-- SELECT pgp_sym_decrypt(
--            decode(email_enc, 'base64'),
--            current_setting('app.enc_key')
--        ) AS decrypted_email
--   FROM operators
--  WHERE email_hmac = encode(
--            hmac(lower(trim('admin@example.com')), current_setting('app.enc_key'), 'sha256'),
--            'hex'
--        );

-- Confirm fiduciaries / apps migration
-- SELECT id, email_plaintext, email_enc IS NOT NULL AS encrypted FROM fiduciaries LIMIT 5;
-- SELECT id, email_plaintext, email_enc IS NOT NULL AS encrypted FROM apps LIMIT 5;
