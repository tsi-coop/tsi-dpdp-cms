# Gaps and roadmap

Mirrors section 7 of the System Design document (`docs/design/TSI DPDP Consent Management System - System Design5.pdf`), software release v0.6. Change both together.

Ratings are a feature-level reading of what is built, not legal advice. Counsel should confirm provisions and commencement dates.

## 1. DPDP Act coverage gaps

Core consent management is rated good. Overall coverage is partial by design: much of the Act (securing the fiduciary's own systems, data accuracy, processor contracts, DPIA, audits, cross-border rules) is organisational, and the CMS supports it with records only.

| # | Provision | Gap | Planned step |
|---|---|---|---|
| 1 | s.5, s.6 Re-consent when a notice changes | The app decides what is material, but the CMS gives no help: `validate_consent` returns only granted, no signal that the active version is newer than the consent's, and the DPO cannot see principals on an older version. | Return consent and active policy versions with a `reconsent_needed` flag; DPO count of principals on older versions; mark a version as requiring re-consent; optional enforcement behind a setting, off by default. |
| 2 | s.7 Legitimate uses | Every purpose is treated as consent-based. No first-class record of processing under a legitimate use (for example employment), so consent may be collected where the law does not require it. | Register of legitimate-use purposes: no consent collected, still recorded and retained. |
| 3 | s.9(3) Children's restrictions | Tracking, behavioural monitoring and targeted advertising aimed at children are not flagged or blocked. Rule exemptions and guardians of persons with disabilities are not modelled. | A "behavioural or targeted" purpose flag; refuse or warn when a minor is granted one. |
| 4 | s.8(6) Breach report for the Board | Board deadline, intimation record and the Information and Action report PDFs (available while open, marked interim) are built. Remaining: nature, location, likely impact, mitigation and person responsible are free text in the description, not structured fields; one Board milestone is recorded, not initial intimation and detailed report separately. The CMS records the intimation; it does not submit it. | Structured breach fields; separate initial-intimation and detailed-report milestones. |
| 5 | s.8(7) Erasure and retention | No retention-policy editor; retention comes from the RoPA. Audit-record erasure is an open legal decision. | Retention-policy editor with an audit-log floor. |
| 6 | s.5 Notice content (Rule 3) | Withdrawal route and complaint-to-Board statement are free-form policy fields; the schema does not require them. Alert texts are English only. DPO contact display to principals unconfirmed. | Require the Rule 3 items in the policy schema; localise alerts; confirm contact display. |
| 7 | s.8(5) Safeguards, s.10, s.11, s.16 | Disk encryption, TLS and backups are deployment controls, not enforced. No anomaly detection beyond audited refusals and chain checks. DPIA and audit reports are not stored; DPO residence in India is not checked. The CMS holds the processing map, not the personal data, for access requests. No cross-border restriction list check. | Mostly organisational. Documented as supported by evidence, not discharged. |

## 2. Engineering and assurance gaps

Shipped in v0.6 and not listed: audit ledger, MFA, roles, tenant binding, consent evidence, rights, purpose lifecycle, purge binding and Board intimation.

| Area | Gap |
|---|---|
| Principal ID protection | Principal IDs are stored as plain text. v0.6 relies on opaque IDs plus disk, backup and TLS encryption. An opt-in design for encrypted, HMAC-looked-up IDs with masking and audited reveal was evaluated but is not built. `DB_ENCRYPTION_KEY` and `TSI_LOOKUP_SALT` cannot be rotated without re-encrypting. |
| Test harness and CI | JUnit tests exist, but no CI pipeline (build, test, Docker build on every push), and database tests skip without a database. |
| Outbound hardening | Webhook URLs are checked for private addresses, but there is no host allow-list, connection to the validated IP only, or redirect refusal. |
| Tenant isolation in depth | Tenant checks are in application code. Database row-level security, a central tenant class and a database check for non-ADMIN operators are not built. |
| Record immutability | `consent_records` is append-only by convention, not by database rule (the audit ledger is enforced). |
| Erasure correctness | Metadata scrub ordering, random re-key tokens, a purpose-scoped de-identify path, a legal-hold race and grievance-attachment deletion on whole-account erasure are listed for review. |
| Operator-initiated actions | A console withdrawal or erasure should need a grievance reference or written reason, audited as an operator action. |
| Alerts and health | No alerts service for bulk reads, repeated audit reads or failed logins; no `/healthz` or background-job heartbeat. |
| Web hardening | HSTS is set. Remaining: full output escaping review, CSV formula-injection defence, strict malformed-JSON rejection, a schema for every function. |
| Supply chain | No SBOM or dependency scan in CI; dependency versions not pinned beyond the POM. |
| Audit archive and continuity | No yearly partitioning or archive of the audit log, and no restore test that recomputes the audit chain. |
| Security assurance | No pen-test suite or external test report; ISMS control map, monitoring and review, outbound destinations, breach response runbook, purpose-validity review and DPO decision register are not written. Key management and log retention are. |
| Deferred | OIDC SSO, access report, API-key expiry sweep, persisted per-principal OTP lock-out for multi-instance use. |

## 3. Items in the original design that are not built

| Item | Status |
|---|---|
| Direct submission to the Data Protection Board (registration, client certificates, API) | Not built. The DPO records Board intimation and hands over the PDF reports. |
| Data Processor dashboard and processor registry with DPA tracking | Not built. Processors are Apps with API keys and a PURGE scope. |
| Custom role management | Four built-in roles; permissions are editable in the roles table. |
| SSO (OIDC), email-OTP second factor | SSO via integrators. TOTP is built and replaces email OTP. |
| DigiLocker / API Setu, verified guardian identity | Roadmap. The guardian flow records a reference only. |
| Interoperable portable consent artefact standard | Concept and demo wallet; standardisation is a proposal. |
| Console accessibility (WCAG-AA) | Done for the rights portal; console still open. |
| SDKs (Python first), packaged banner, GTM template, restricted public site key | Planned. A reference website integration ships in `examples/`. |
| PostgreSQL 17 / OpenJDK 21 images; scale beyond shared-database instances | Proposed. |

## 4. What the CMS cannot do, and does not claim

Secure the fiduciary's own systems; verify a parent's or a principal's identity; erase data inside processors' systems (it tracks the request and the processor's confirmation, and the count is a claim); produce the personal data for an access request; decide the lawful basis; submit anything to the Board; or make an organisation compliant. The CMS supports compliance and provides evidence.
