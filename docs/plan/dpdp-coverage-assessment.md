# DPDP Act functional coverage assessment (v0.6.0)

**What this is:** a feature-level check of what the tool does against the Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025.
**What it is not:** legal advice. Section and rule numbers are from my reading and must be checked against the notified texts and their
commencement dates by your counsel. Ratings are based on what is built in this repo at v0.6.0 (code and tests), not on a fresh audit of every screen.

**Rating:** **Good** = built, tested, does what the provision needs. **Partial** = some of it is built or it depends on how the implementer uses it.
**Gap** = not built. **Outside** = an organisational duty the tool can support with evidence but cannot discharge.

## Verdict

* **Core consent management: good.** Purpose-wise consent with evidence, versioned notices, withdrawal, erasure orchestration with processors,
  grievances, access/correction requests, nominations, children's guardian records, breach tracking, and a tamper-evident audit trail.
* **Overall coverage of the Act: partial, by design.** The tool is a consent management system. Much of the Act (security of the fiduciary's
  own systems, accuracy of data, processor contracts, DPIA, audits, cross-border rules) is the organisation's duty; the tool supports it with
  records but does not perform it.
* **The gaps that matter most** are listed in section 2: support for re-consent when a notice changes, legitimate-use processing,
  children's tracking restrictions, and a more complete breach report for the Board.

## 1. Coverage by provision

| Provision | What the law needs | What the tool does | Rating | Gap or action |
|---|---|---|---|---|
| s.5, Rule 3: notice | Itemised notice before consent: the data, the purpose, how to withdraw, how to exercise rights, how to complain to the Board | Versioned multilingual policy with purposes, data points, retention, `recipients_or_third_parties`, `cross_border_transfers`, contact, `grievance_redressal_info`, `data_principal_rights_summary`; DPO publish workflow | Partial | Confirm the policy schema requires every item Rule 3 lists (in particular the withdrawal route and the complaint-to-Board statement); today these are free-form fields |
| s.6(1)-(2): valid consent | Free, specific, informed, unconditional, unambiguous, limited to the stated purpose | Purpose-by-purpose true/false choices, mandatory purposes flagged, `CONSENT_CAPTURE_MODE` rejects unanswered purposes, policy version stamped on every record | Good | `warn` is the default; recommend `strict` once integrations are clean |
| s.6(3): language | Request in clear language; English or an Eighth Schedule language | Policy content is multilingual, `language_selected` is recorded | Partial | New alert and notification texts are English only |
| s.6(4)-(6): withdrawal | As easy as giving consent; consequences borne by the principal; processing stops | `withdraw_consent` (full and partial), portal, withdrawal-implications text shown first, purge requests sent to processors, confirmation tracked | Good | None |
| s.6(7), Rules 4 and Fourth Schedule: consent managers | Registration with the Board; accountable to the principal; keeps records of consents, notices and sharing for 7 years; data-blind; interoperable | Multi-tenant deployment, stores consents not personal data, open APIs, consent records and audit trail kept indefinitely | Partial | **A principal cannot see consents across fiduciaries**: the portal is per fiduciary. A consent manager extends the Rights app for that (a note to say so goes in the portal and the documentation). No registration or net-worth or conflict-of-interest workflow (organisational). The 7-year retention rule needs the audit archive decision (see `LOG_RETENTION.md`) |
| s.7: legitimate uses | Processing without consent for specified uses (voluntary provision, legal obligation, State function, medical emergency, **employment**, and others) | Purposes carry a `legal_basis` field used in withdrawal implications | **Gap** | No first-class record of "processed under legitimate use X, no consent needed". Matters for employees (`e-` principals), whose data is mostly processed on that basis: the tool would collect consent that the law does not require |
| s.8(3): accuracy | Complete, accurate, consistent data | Correction requests tracked with outcome | Outside | |
| s.8(5), Rule 6: security safeguards | Encryption or masking or tokens, access control, monitoring, backups, logs kept 1 year, contracts with processors | MFA, roles with tenant isolation, cross-tenant fixes, append-only audit ledger, opaque-ID guidance, key and log documents, required deployment controls | Partial | Disk encryption, TLS and backups are deployment controls, not enforced by the tool; no anomaly detection beyond shadow-mode and chain checks; processor contracts are organisational |
| s.8(6), Rule 7: breach | Intimate each affected principal without delay; intimate the Board, then a detailed report within 72 hours (nature, extent, timing, location, likely impact, mitigation, person responsible, remedial steps, notices given) | Breach register, principal notifications, notification and Board deadlines tracked, Board reference recorded, DPO alerts. **A downloadable PDF breach report** carries: fiduciary, incident id, severity, status, detected and reported times, both deadlines with the Board intimation date and reference, description, affected purpose, count of principals notified, the steps communicated to them, and resolution notes | Partial | The PDF is only available once the breach is CONTAINED or RESOLVED, but the Board's detailed report is due within 72 hours, when the breach may still be open. Nature, extent, location, likely impact, mitigation and person responsible are not separate fields (they go in the free-text description). One Board clock is tracked, not the initial intimation and the later detailed report separately. The tool records the intimation; it does not submit it |
| s.8(7), Rule 8: erasure and retention | Erase when the purpose is served or consent withdrawn, unless law requires retention; certain large platforms must warn the principal 48 hours before a time-limit erasure; processors must erase | Retention-driven purge engine, processor purge requests with confirmation, claimed record counts, legal holds, DE_IDENTIFY option, pre-expiry reminder to principals | Partial | The principal's reminder (5 days ahead) now covers both consent-expiry and RoPA-driven erasure, so it exceeds the 48 hours the Rule names; no retention-policy editor |
| s.8(9), Rule 9: contact | Publish the DPO or contact person's details | Contact fields in the policy and fiduciary settings | Partial | Confirm they are shown to principals in the portal |
| s.8(10), s.13, Rule 14: grievance | Redressal mechanism; reply within the published time (not more than 90 days) | Grievances with reference number, channel, DPO assignment, 30-day default deadline, escalation, attachments, feedback | Good | |
| s.9, Rule 10: children | Verifiable consent of a parent or guardian before processing a child's data | `record_parent_consent` with guardian verification log, minor flag set only by a recorded verification, Minor Consent Audit, rule that child and guardian differ | Good | The tool records the verification; it does not verify the parent's identity (the integrator does) |
| s.9(3): children, restrictions | No tracking, behavioural monitoring or targeted advertising aimed at children | Nothing | **Gap** | A purpose of that kind is not flagged, or blocked, when the principal is a minor. Also not modelled: the Rules' exemptions (for example health and education) and guardians of persons with disabilities (Rule 11) |
| s.10, Rule 13: significant data fiduciaries | DPO based in India, independent auditor, annual DPIA and audit, due diligence on software | DPO role, RoPA, audit trail and certificates as evidence, DPIA described in the implementation guide | Partial | DPIA and audit reports are not stored in the tool; whether the DPO is in India is not checked |
| s.11: right to information | A summary of the personal data processed and the processing, and the identities of fiduciaries and processors it was shared with | Access requests tracked, with a data map for the DPO (purposes, apps) | Partial | The tool holds the map of processing, not the personal data; the fiduciary produces the actual summary |
| s.12: correction and erasure | Correct, complete, update, erase on request | Correction requests tracked with outcome; erasure through the purge lifecycle | Good | The CMS does not edit the fiduciary's data (by design) |
| s.14: nomination | Right to nominate another person | Nominations (encrypted, masked for staff, expiring) | Good | Records only; the DPO verifies any claim |
| s.16, Rule 15: transfers outside India | Transfers allowed except to notified countries | Cross-border transfers declared in the policy and RoPA | Partial | No check against any restriction list; organisational |
| Records and evidence for the Board | Show consent, notices and actions when asked | Evidence certificates with signed audit trail, tamper-evident ledger, exports | Good | |
| Re-consent when the notice changes | Fresh consent when purposes or notice change materially | The fiduciary's app decides whether a change is material and asks again; consents keep the policy version they were given under, and `get_active_consent` returns it | Partial | The decision is the fiduciary's, but the CMS gives the app no help: `validate_consent` returns only `consent_granted`, there is no "the active version is newer than this consent's" signal, the DPO cannot see how many principals are on an older version, and a policy cannot be marked as needing re-consent. See section 2 |

## 2. The gaps that matter, in order

1. **Re-consent support** (s.5, s.6). The fiduciary's app decides when to ask; the CMS should make that easy. Small, additive steps: return the consent's `policy_version` and the current `active_policy_version` (and a `reconsent_needed` flag) from `get_active_consent` and `validate_consent`; show the DPO how many principals are on an older version; let the DPO mark a new version as requiring re-consent, with a note. Enforcement (treating consent on an older version as not granted) would change `validate_consent` behaviour, so it would be behind a setting, off by default.
2. **Legitimate uses** (s.7). Without it the tool treats every purpose as consent-based, which is wrong for much employee and State-linked processing. A register of legitimate-use purposes (no consent collected, still recorded and retained) is small and avoids collecting consent the law does not require.
3. **Consent managers** (s.6(7)). A consent manager extends the Rights app for a cross-fiduciary view; the product only needs a line in the portal and the documentation saying so, plus the 7-year record retention. Check the commencement date of the consent manager provisions.
4. **Children's restrictions** (s.9(3)). Add a "behavioural or targeted" flag on purposes and refuse or warn when a minor is granted one.
5. **Breach report for the Board** (Rule 7). A PDF exists. Allow it while the breach is still open (the detailed report is due within 72 hours), add separate fields for nature, extent, location, likely impact, mitigation and person responsible, and two Board milestones (initial intimation and detailed report).
6. **Erasure warning and retention policy** (Rule 8). Confirm the 48-hour warning; add a retention-policy editor with the audit-log floor.
7. **Provisions to verify before relying on them**: the policy items Rule 3 lists, DPO contact shown to principals, English-only alert texts.

## 3. What the tool cannot do, and should not claim

Secure the fiduciary's own systems, verify a parent's identity, verify a principal's identity for rights requests (the demo portal uses OTP),
erase data in the processors' systems (it tracks the request and the processor's confirmation, and the count is the processor's claim),
produce the personal data for an access request, decide the lawful basis, submit anything to the Board, or make an organisation compliant.
The documents should say "supports" and "provides evidence", never "makes you compliant".

## 4. How to use this

Treat sections 2 and 3 as the input to the next planning round. Before relying on any rating, have counsel confirm the provision and its
commencement date. The ratings can be re-run after each release; the regression cases in `tests/regression-test-cases.md` are the evidence for
the "Good" rows.
