# Security & Architecture Gaps — Implementation Plan
**TSI DPDP Consent Management System - v0.4**
Status: Planning

---

## Gap Status Assessment

### Fixed

| ID | Gap | Evidence |
|----|-----|---------|
| **G-09** | Audit log hash-chaining broken | `db/02_audit_ledger_schema.sql` adds `prev_log_hash` + `current_log_hash`; `Audit.java` references them correctly |

---

### Open — 24 of 25 gaps

#### CRITICAL (8 open)

| ID | Gap | File | Finding |
|----|-----|------|---------|
| G-01 | JWT secret regenerated on restart | `JWTUtil.java:16` | `Keys.secretKeyFor()` still in-memory — no env var read |
| G-02 | Session persistence not implemented | `JWTUtil.java`, `Wallet.java:266` | No session/token registry table in DB; comment unchanged |
| G-03 | Wallet sync token prefix-only validation | `Wallet.java:267` | `token.startsWith("SECURE_JWT_TOKEN_")` still the only check |
| G-04 | API key hashing is a string prefix | `ApiKey.java:204` | `return "HASHED_" + rawKey` unchanged |
| G-05 | Privilege escalation — any user can create ADMIN | `Operator.java:155` | `handleCreateUser` reads role from request body, never checks caller's JWT role |
| G-06 | Job download: no auth + path traversal | `Job.java:162,187` | `validate()` returns `true`; path is `EXPORT_DIR + jobId + ".csv"` with no UUID validation or canonical path check |
| G-07 | SQL injection in CESService | `CESService.java:39` | `AND user_id='"+target+"'` — string concatenation unchanged |
| G-08 | SQL injection in Job service | `Job.java:126` | `AND job_type='"+jobType+"'` — string concatenation unchanged |

#### HIGH (7 open)

| ID | Gap | File | Finding |
|----|-----|------|---------|
| G-10 | XSS via innerHTML | `dpdp-wallet.html:267,283,291,309` | Data values injected via `innerHTML` and inline `onclick` strings |
| G-11 | PII stored in plaintext | `db/01_init.sql` | No column-level encryption or pseudonymisation added |
| G-12 | No rate limiting on login | `InterceptingFilter.java` | No failed-attempt counter, lockout, or throttle |
| G-13 | HTTPS not enforced; CORS wildcard | `InterceptingFilter.java:106` | `Access-Control-Allow-Origin: *` hardcoded; no HSTS or HTTP redirect |
| G-14 | No token revocation | `JWTUtil.java` | No `revoked_tokens` table, no JTI claim, 10-day expiry unchanged |
| G-15 | JWT role not re-validated against DB | `InputProcessor.java:272–282` | Role read from JWT claim only — no DB cross-check |
| G-16 | Hardcoded default keystore password | `production.env:15` | `TSI_KEYSTORE_PASS=changeit` still committed |
| G-17 | Outdated commons-validator (CVE-2018-12221) | `pom.xml` | `commons-validator:1.5.0` and `json-simple:1.1.1` unchanged |

#### MEDIUM (6 open)

| ID | Gap | File | Finding |
|----|-----|------|---------|
| G-18 | Stack traces in error responses | `Consent.java`, `Operator.java`, `Policy.java` | `e.printStackTrace()` throughout; SQL errors reach stderr |
| G-19 | DB connection missing SSL | `PoolDB.java:33` | JDBC URL has no `?sslmode=require` |
| G-20 | Revoked API keys remain cached | `InputProcessor.java:184–209` | `apiClientCache` is a `ConcurrentHashMap` with no TTL or eviction |
| G-21 | Missing security headers | `InterceptingFilter.java` | No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` |
| G-22 | No CSRF protection | `InterceptingFilter.java`, `web/` | No CSRF token; no `Origin` header validation |
| G-23 | User update lacks ownership check | `Operator.java:202` | `handleUpdateUser` applies update for any caller — no check that DPO == target |

#### LOW (2 open)

| ID | Gap | File | Finding |
|----|-----|------|---------|
| G-24 | JWT validation failures not audited | `JWTUtil.java:49` | `catch(Exception e)` returns `false` silently — no audit log write |
| G-25 | Structured logging not used | All service classes | `System.err.println` / `e.printStackTrace()` throughout; no SLF4J |

---

## Remediation Plan

### Wave 1 — Quick Wins
*1–5 lines each. Zero risk of regression. Closes 7 gaps.*

| Gap | File | Change |
|-----|------|--------|
| **G-01** | `JWTUtil.java:16` | Read `JWT_SECRET` from `System.getenv()`; decode as HMAC key; fail-fast if unset |
| **G-07** | `CESService.java:39` | Replace `"...user_id='"+target+"'"` with `?` placeholder + `setString()` |
| **G-08** | `Job.java:126` | Replace `job_type='"+jobType+"'"` with `?` + `setString()`; add allowlist check |
| **G-16** | `production.env:15` | Remove default value; add startup guard in `SystemConfig` |
| **G-19** | `PoolDB.java:33` | Append `?sslmode=require` to JDBC URL |
| **G-21** | `InterceptingFilter.java` | Add `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy` in `doFilter()` |
| **G-13** | `InterceptingFilter.java:106` | Read `ALLOWED_ORIGINS` env var; replace hardcoded `*`; add `Strict-Transport-Security` header |

### Wave 2 — Moderate Fixes
*10–40 lines each. Service-layer logic only. No schema changes.*

| Gap | File | Change |
|-----|------|--------|
| **G-04** | `ApiKey.java:201–204`, `InputProcessor.java:199` | Replace `"HASHED_"+rawKey` with `BCrypt.hashpw` for storage; `BCrypt.checkpw` for validation |
| **G-05** | `Operator.java:155` | In `handleCreateUser()`, extract caller JWT role from request; reject ADMIN role assignment if caller is not ADMIN |
| **G-06** | `Job.java:159–162,187` | Validate `job_id` as UUID; add `getCanonicalPath().startsWith(EXPORT_DIR)` check; implement auth in `validate()` |
| **G-10** | `dpdp-wallet.html`, `dashboard.html`, `principals.html`, `reports.html`, `user-dashboard.html` | Replace `innerHTML` with `textContent` for data values; refactor `onclick` to `addEventListener` + `data-*` attributes |
| **G-15** | `InputProcessor.java:272` | After JWT decode, query `operators` table to verify role is still current for sensitive operations |
| **G-18** | All service classes | Replace `e.printStackTrace()` in `errorResponse()` calls with a generic message; log full exception internally |
| **G-20** | `InputProcessor.java:184` | Wrap cache entries with `CachedEntry(value, expiresAt)`; evict on TTL miss (60s TTL) |
| **G-23** | `Operator.java:202` | In `handleUpdateUser()`, block if caller role is DPO and `uid != loginUserId` |
| **G-24** | `JWTUtil.java:49` | In `catch` block, call `Audit.logEventAsync()` with token prefix and source IP |

### Wave 3 — Significant Effort
*New DB tables, token format changes, or framework additions. Coordinate as sprints.*

| Gap | Files | Change |
|-----|-------|--------|
| **G-02** | `db/` + `JWTUtil.java` | Add `token_registry` table; persist and validate on login; depends on G-01 stable secret |
| **G-03** | `Wallet.java:267` | Issue wallet sync tokens as signed JWTs via `JWTUtil`; or verify against `token_registry` table |
| **G-12** | `InterceptingFilter.java` | Per-IP / per-username failed-attempt counter using `ConcurrentHashMap` with expiry; `Retry-After` header on lockout |
| **G-14** | `db/` + `JWTUtil.java` + `InputProcessor.java` | Add `revoked_tokens(jti, expires_at)` table; embed JTI claim in token; check table on every authenticated request |
| **G-22** | `InterceptingFilter.java` + `web/` | `Origin` header allowlist validation for all state-changing requests |
| **G-11** | `db/01_init.sql` + service layer | Column-level encryption via `pgcrypto` for `email`, `phone`, `ip_address`; or pseudonymise `user_id` via `LookupHasher` |
| **G-17** | `pom.xml` + affected call sites | Bump `commons-validator` to `1.9.0`; migrate `json-simple` usages to `jackson-databind` (already a dependency) |
| **G-25** | `pom.xml` + all service classes | Add `slf4j-api` + `logback-classic`; replace all `System.err` / `e.printStackTrace()` |

---

## Sequencing Notes

- **G-01 is a prerequisite** for G-02, G-03, and G-14 — a stable JWT secret must exist before building a token registry or revocation mechanism.
- **Wave 1 first** — all changes are isolated and reversible; merge independently.
- **G-02 + G-03 + G-14** should be implemented together as a single "session hardening" sprint once Wave 1 is merged, since they share the `token_registry` table and JWT format.
- **G-11** (PII encryption) is the highest-risk Wave 3 item — requires a migration plan for existing plaintext rows and coordinated rollout.
- **G-17** (dependency upgrade) is low-risk but requires smoke-testing all validation call sites after the `commons-validator` bump.
