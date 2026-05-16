# Security & Architecture Gaps
**TSI DPDP Consent Management System - v0.4**
Status: Under Review

---

## How to Read This Document

Each gap is assigned a severity, a source file, and a remediation note.
Severities: **CRITICAL** → **HIGH** → **MEDIUM** → **LOW**

---

## CRITICAL

### G-01 · JWT Secret Regenerated on Every Server Restart
**File:** `src/.../framework/JWTUtil.java:16`
The JWT signing key is generated in-memory at startup (`Keys.secretKeyFor(SignatureAlgorithm.HS256)`). Every server restart invalidates all active sessions - users are silently logged out. In a multi-instance deployment, instances cannot verify each other's tokens.
**Fix:** Load the signing key from an environment variable (`JWT_SECRET`) at startup, following the same pattern as `LookupHasher.java` which reads `TSI_LOOKUP_SALT` from env.

---

### G-02 · Session Persistence Not Implemented
**File:** `src/.../framework/JWTUtil.java`, `src/.../service/v1/Wallet.java:266`
There is no session store - all session state lives in-memory JWTs that are invalidated on restart (see G-01). A comment in `Wallet.java:266` explicitly notes that session/registry table validation "would be needed in production" but is not implemented. Operators must re-authenticate after every deployment.
**Fix:** Persist session tokens (or a token registry) in the PostgreSQL database. On startup, load and validate the JWT secret from a stable external source so existing tokens survive restarts.

---

### G-03 · Wallet Sync Token Validated by String Prefix Only
**File:** `src/.../service/v1/Wallet.java:267–269`
Token validation checks only whether the token string starts with `SECURE_JWT_TOKEN_`, `BRH_SYNC_TK_`, or `PCA_TOKEN_`. Any string with the correct prefix is accepted. There is no signature check, expiry check, or database lookup. The `userId` is also client-supplied and not cross-checked against the token payload.
**Fix:** Issue wallet sync tokens as signed JWTs using the same `JWTUtil` mechanism, or verify them against a tokens table in the database.

---

### G-04 · API Key Hashing Is a String Prefix, Not a Hash
**File:** `src/.../service/v1/ApiKey.java:201–204`, `src/.../framework/InputProcessor.java:199`
The "hash" function prepends `HASHED_` to the raw key (`"HASHED_" + rawKey`). A database breach exposes all API keys in plaintext. The code comment acknowledges this is a mock implementation.
**Fix:** Replace with `BCrypt.hashpw(rawKey, BCrypt.gensalt(12))` for storage and `BCrypt.checkpw(incoming, storedHash)` for validation - the same bcrypt pattern already used for operator passwords.

---

### G-05 · Privilege Escalation: Any Authenticated User Can Create an ADMIN Account
**File:** `src/.../service/v1/Operator.java:150–195`
The `create_user` action accepts a `role` field directly from the request body and inserts it without checking whether the calling operator has `ADMIN` role. Any authenticated operator can POST `"role": "ADMIN"` and create a super-admin account.
**Fix:** In `handleCreateUser()`, verify that the JWT role of the caller is `ADMIN` before allowing the `role` field to be set to `ADMIN`.

---

### G-06 · Job File Download Has No Authentication and Is Vulnerable to Path Traversal
**File:** `src/.../service/v1/Job.java:159–162, 187–189`
The `validate()` method unconditionally returns `true` (no auth check). The `job_id` parameter is concatenated directly into a file path (`EXPORT_DIR + jobId + ".csv"`) without validating that the resolved path stays inside `EXPORT_DIR`. An attacker can supply `job_id=../../../../etc/passwd` to read arbitrary files.
**Fix:** (1) Implement authentication in `validate()`. (2) Validate `job_id` against UUID format. (3) Use `file.getCanonicalPath().startsWith(EXPORT_DIR)` to block traversal.

---

### G-07 · SQL Injection in CESService (target Parameter)
**File:** `src/.../ces/CESService.java:39`
The `target` variable (user-supplied) is concatenated directly into a SQL string: `"... AND user_id='"+target+"' ..."`. A parameterized `?` placeholder should be used instead.
**Fix:** Replace string concatenation with `pstmt.setString()` for the `target` parameter.

---

### G-08 · SQL Injection in Job Service (jobType Parameter)
**File:** `src/.../service/v1/Job.java:126`
`jobType` from the request JSON is concatenated into the SQL query string. Same risk as G-07.
**Fix:** Use a parameterized `?` for `jobType` and validate it against an allowlist of known job types.

---

### G-09 · Audit Log Hash-Chaining Broken - Schema Missing Columns
**File:** `src/.../service/v1/Audit.java:157`, `db/01_init.sql:112–121`
`Audit.java` inserts `prev_log_hash` and `current_log_hash` into `audit_logs`, but the `audit_logs` table definition in `01_init.sql` does not include these columns. Every audit write fails at runtime with a silent SQL exception, meaning the tamper-evident audit trail is non-functional.
**Fix:** Add `prev_log_hash VARCHAR(512)` and `current_log_hash VARCHAR(512)` to the `audit_logs` schema in `01_init.sql` (or a new migration file).

---

## HIGH

### G-10 · XSS via Unsanitized innerHTML in Frontend
**Files:** `web/tour/dpdp-wallet.html:270,283,291,309`, `web/console/admin/dashboard.html`, `web/console/dpo/principals.html`, `web/console/dpo/reports.html`, `web/tour/user-dashboard.html`
API response values (names, IDs, statuses) are injected directly into `innerHTML` and into `onclick` attribute strings without HTML escaping. A malicious data value (e.g., a fiduciary name containing `"><script>`) would execute arbitrary JavaScript.
**Fix:** Replace `innerHTML` with `textContent` for plain text values, or use a sanitization helper. For `onclick` handlers, avoid inline event strings - use `addEventListener` with `data-*` attributes.

---

### G-11 · PII Stored in Plaintext in the Database
**File:** `db/01_init.sql:89,98,129,166,243–244`
`user_id`, `ip_address`, `email`, `phone`, `address`, `guardian_principal_id`, and `child_principal_id` are all stored as plaintext `VARCHAR` columns. A database breach exposes all personal data directly.
**Fix:** Apply column-level encryption for high-sensitivity fields (pgcrypto or application-level AES-256) or pseudonymise `user_id` via the existing `LookupHasher` mechanism.

---

### G-12 · No Rate Limiting on Login or Any Endpoint
**File:** `src/.../service/v1/Operator.java:87–148`, `src/.../framework/InterceptingFilter.java`
There is no failed-attempt counter, account lockout, or request throttling anywhere in the application. The login endpoint accepts unlimited password attempts.
**Fix:** Track failed login attempts per IP and per username in a short-lived in-memory or Redis store. Lock after 5 failed attempts for 15 minutes. Add `Retry-After` response headers.

---

### G-13 · HTTPS Not Enforced; CORS Wildcard Left Open
**File:** `src/.../framework/InterceptingFilter.java:106`
The filter does not redirect HTTP to HTTPS, does not set `Strict-Transport-Security`, and sets `Access-Control-Allow-Origin: *`. The code comment acknowledges `*` is a development setting but it has not been made environment-controlled.
**Fix:** (1) Enforce HTTPS redirect in the filter. (2) Add HSTS header. (3) Read `ALLOWED_ORIGINS` from an environment variable instead of hardcoding `*`.

---

### G-14 · No Token Revocation Mechanism
**File:** `src/.../framework/JWTUtil.java`
Once a JWT is issued, it cannot be invalidated before its 10-day expiry. There is no token blacklist, no revocation endpoint, and no way to force re-authentication after a credential change or suspected compromise.
**Fix:** Add a `revoked_tokens` table (token JTI + expiry). Check on every request. Alternatively, use short-lived access tokens (15–60 min) with a refresh token flow.

---

### G-15 · JWT Role Claim Not Re-Validated Against Database
**File:** `src/.../framework/InputProcessor.java:272–282`
The role used for access control is read from the JWT payload. If a user's role is changed in the database (e.g., demoted from ADMIN), their existing token continues to grant the old role for up to 10 days.
**Fix:** Cross-check the role against the `operators` table on sensitive operations, or reduce token expiry to a window where role staleness is acceptable.

---

### G-16 · Hardcoded Default Keystore Password
**File:** `production.env:15`, `docker-compose.yml:54`
`TSI_KEYSTORE_PASS=changeit` - the default Java keystore password - is committed in the repository. If the keystore file is exposed, the private key used for consent certificates can be extracted.
**Fix:** Remove the default value. Require an explicit secret (from a vault or deployment secret) on startup. Fail fast if the variable is unset or equals `changeit`.

---

### G-17 · Outdated Vulnerable Dependency: commons-validator 1.5.0
**File:** `pom.xml`
`commons-validator:1.5.0` (released 2012) is affected by CVE-2018-12221 (XML External Entity injection). `json-simple:1.1.1` is unmaintained.
**Fix:** Upgrade `commons-validator` to 1.8.0+. Replace `json-simple` with Jackson (already a project dependency).

---

## MEDIUM

### G-18 · Stack Traces Leaked in Error Responses
**Files:** `service/v1/Consent.java:410`, `service/v1/Operator.java:82`, `service/v1/Policy.java:233–242`, and others
`e.getMessage()` and `e.printStackTrace()` are passed to `OutputProcessor.errorResponse()` or printed to stderr. SQL errors can disclose table names, column names, or query structure.
**Fix:** Log full exceptions internally. Return only a generic error code and message to the client.

---

### G-19 · Database Connection Does Not Enforce SSL
**File:** `src/.../framework/PoolDB.java:33`
The JDBC URL is constructed without `?sslmode=require`. Whether the connection is encrypted depends solely on the PostgreSQL server's default configuration.
**Fix:** Append `?sslmode=require` to the JDBC URL.

---

### G-20 · Revoked API Keys Remain Valid While Cached
**File:** `src/.../framework/InputProcessor.java:184–209`
Validated API key results are cached in `apiClientCache` without a TTL or revocation hook. A key revoked in the database continues to work until the server restarts.
**Fix:** Add a TTL to cache entries (e.g., 60 seconds). Emit a cache invalidation event when a key is revoked via `ApiKey.java`.

---

### G-21 · Missing Security Headers
**File:** `src/.../framework/InterceptingFilter.java`
The following headers are absent: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`. These protect against clickjacking, MIME-sniffing, and inline script injection.
**Fix:** Add these headers in `InterceptingFilter.doFilter()` for all responses.

---

### G-22 · No CSRF Protection
**File:** `src/.../framework/InterceptingFilter.java`, `web/`
State-changing endpoints are not protected with CSRF tokens. Any authenticated user visiting a malicious page could have requests made on their behalf.
**Fix:** Implement the Synchroniser Token Pattern for non-API (cookie-based) sessions, or validate the `Origin` header against the allowed origin list.

---

### G-23 · User Update Endpoint Lacks Ownership Check
**File:** `src/.../service/v1/Operator.java:197–251`
`update_user` allows any DPO or admin to modify any other non-admin user's profile or password without verifying that they are the record owner or have delegated authority.
**Fix:** Enforce that a DPO can only update their own record unless they hold `ADMIN` role.

---

## LOW

### G-24 · JWT Validation Failures Not Audited
**File:** `src/.../framework/JWTUtil.java:49`
Token validation failures are caught with a generic `catch (Exception e)` that returns `false` silently. Failed validation attempts are not written to `audit_logs`, making it impossible to detect token replay or brute-force attempts.
**Fix:** Call `Audit.logEventAsync()` on validation failure, recording the raw token prefix and source IP.

---

### G-25 · Structured Logging Not Used; PII Risks in stderr
**Files:** Multiple service classes (`e.printStackTrace()` calls throughout)
All logging goes to `System.out` / `System.err`. There is no log level control, no structured format, and stack traces may include request context containing PII.
**Fix:** Replace with SLF4J + Logback. Apply MDC masking for user IDs and emails in log output.

---

## Summary

| ID | Title | Severity |
|----|-------|----------|
| G-01 | JWT secret regenerated on restart | CRITICAL |
| G-02 | Session persistence not implemented | CRITICAL |
| G-03 | Wallet sync token: prefix-only validation | CRITICAL |
| G-04 | API key hashing is a string prefix | CRITICAL |
| G-05 | Privilege escalation: any user can create ADMIN | CRITICAL |
| G-06 | Job download: no auth + path traversal | CRITICAL |
| G-07 | SQL injection in CESService | CRITICAL |
| G-08 | SQL injection in Job service | CRITICAL |
| G-09 | Audit log hash-chaining broken (missing DB columns) | CRITICAL |
| G-10 | XSS via innerHTML in frontend | HIGH |
| G-11 | PII stored in plaintext | HIGH |
| G-12 | No rate limiting on login | HIGH |
| G-13 | HTTPS not enforced; CORS wildcard | HIGH |
| G-14 | No token revocation mechanism | HIGH |
| G-15 | JWT role not re-validated against DB | HIGH |
| G-16 | Hardcoded default keystore password | HIGH |
| G-17 | Outdated commons-validator (CVE-2018-12221) | HIGH |
| G-18 | Stack traces leaked in error responses | MEDIUM |
| G-19 | Database connection missing SSL | MEDIUM |
| G-20 | Revoked API keys remain cached | MEDIUM |
| G-21 | Missing security headers (CSP, X-Frame, etc.) | MEDIUM |
| G-22 | No CSRF protection | MEDIUM |
| G-23 | User update lacks ownership check | MEDIUM |
| G-24 | JWT validation failures not audited | LOW |
| G-25 | Structured logging not used | LOW |
