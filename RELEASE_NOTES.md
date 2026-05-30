# Release Notes

### v0.4.3
**Policy Publish - Two-Step Wizard**
- **Single popup, no page hops:** Creating and activating a policy is now a two-step wizard entirely within the policy popup. Step 1 uploads the JSON and sets the policy ID; clicking "Next →" derives ROPA entries in the background and transitions directly to Step 2, with no separate Publish button and no redirect to the ROPA screen.
- **Inline ROPA review:** The derived ROPA entries appear in Step 2 of the same popup. DPOs can open each entry's detail view (with the DPDP completeness checklist) and publish it without leaving the modal. The policy becomes ACTIVE once all entries are published.
- **ROPA screen is now monitoring-only:** The ROPA Registry screen retains its full view, filter, and export (CSV/PDF) capabilities but no longer exposes a Publish action. All ROPA publishing now happens through the policy wizard, keeping the two workflows clearly separated.
- **Existing Under Review policies:** Policies already sitting in "Under Review" show a "Review ROPA" button that opens the popup directly at Step 2, so in-flight work is not disrupted.

---

### v0.4.2
**Policy Publishing & ROPA Usability**
- **Clearer publish flow:** The policy publish confirmation now accurately describes what happens - the policy enters ROPA review, not immediate activation - so DPOs are not surprised when the status shows "Under Review".
- **Next-step prompt after publish:** After submitting a policy for ROPA review, the DPO is offered a direct jump to the ROPA screen to validate and publish the auto-derived entries, removing the need to navigate there manually.
- **Review ROPA action on policy rows:** Policies sitting in "Under Review" now show a "Review ROPA" link in the actions column, making it easy to return to the ROPA screen on subsequent visits without hunting through the nav.

---

### v0.4.1
**Legal Module & Audit Reliability**
- **Fixed Consent Trace Missing:** Resolved a critical bug where the Legal Module evidence trail was empty due to mismatches between pseudonymised User IDs and query parameters.

---

### v0.4
This release focuses on compliance readiness and platform hardening.

**Records of Processing Activities (ROPA)**
- DPOs can now maintain a structured register of every data processing activity across all apps and fiduciaries, all in one place.
- ROPA entries are auto-populated from published consent policies so DPOs review and approve rather than write from scratch.
- A completeness checker flags missing fields (legal basis, retention period, data categories) before a regulator does.
- Full ROPA report can be exported as CSV/PDF in minutes, no manual assembly from multiple tables.
- Every ROPA entry is versioned and written into the tamper-evident audit trail.

**Security Hardening**
- JWT signing key is now loaded from an environment variable so active sessions survive server restarts.
- API keys are now stored using bcrypt hashing, the same approach used for operator passwords, instead of a plain-text prefix.
- Fixed a privilege escalation vulnerability where any authenticated user could create an ADMIN account.
- Fixed SQL injection risks in the compliance enforcement service and job service.
- Fixed a path traversal vulnerability in the job file download endpoint; the endpoint now requires authentication.
- Fixed the audit log hash-chaining that was silently failing due to a missing database column; the tamper-evident trail is now fully functional.
- Wallet sync tokens are now signature-verified; previously any string with the correct prefix was accepted.

---

### v0.3
This release added two new ways for Data Principals to interact with the system - through their voice and through a legally admissible evidence trail.

**Voice Consent Gateway** *(Sarvam AI integration)*
- Data Principals can now give or withdraw consent through a voice interface, no typing required.
- Uses Sarvam AI's text-to-speech and speech-to-text to read out the consent notice and capture a spoken affirmation in the user's own language.
- Designed for inclusion: reaches users who are not comfortable with forms or screens.

**Legal Evidence Module**
- Audit trails can now be crystallised into a cryptographically signed digital evidence artifact that meets the requirements of BSA Section 62 (court-admissible electronic records).
- DPOs can generate a certificate-backed evidence package for regulatory submissions or litigation without any manual paperwork.
- A sample evidence certificate is available in the repository for reference.

---

### v0.2
This release strengthened the trust framework, making consent verifiable by parents and audit trails admissible in court.

**Verifiable Parental Consent**
- Implements Section 9 of the DPDP Act: consent for Data Principals under 18 must be obtained from a verifiable guardian.
- Guardian identity is confirmed via OTP; the resulting consent artifact carries a cryptographic link to the parent's identity.
- Full end-to-end demo available in the interactive tour.

**Legal Module (early access)**
- Introduced the foundation for converting audit logs into non-repudiated, immutable digital evidence, expanded further in v0.3.

---

### v0.1
The first public release. Covered the full consent lifecycle from policy setup to enforcement and reporting.

**Admin Console**
- Onboard Data Fiduciaries and link their Apps through a single administrative interface.
- Manage operators, roles, and API keys with role-based access control (RBAC).
- Full audit log of all admin and DPO actions.

**Policy Management**
- Create, publish, archive, and version consent policies.
- Supports multilingual policies, the same policy can be served in multiple Indian languages.
- Validates purpose IDs for uniqueness within a fiduciary.

**Consent Collection (CES)**
- Consent notice is presented to the Data Principal with all required disclosures.
- Consent is captured and stored as a verifiable artifact.
- Works out of the box via an embeddable flow or API.

**Consent Verification**
- Real-time API for Data Processors to check whether a specific Principal has given consent for a specific purpose before processing.

**User Dashboard**
- Data Principals can view all their consent artifacts, withdraw consent, and submit grievances, all from one screen.
- Download a Portable Consent Artifact (PCA) for use with a DPDP Wallet.

**Compliance Enforcement Service**
- Automated jobs enforce retention periods: data is flagged and purged when the consent expires or is withdrawn.
- DPO can run compliance checks for individual Data Principals or across the full dataset.
- Visual compliance tracker in the DPO console.

**DPO Console**
- Comprehensive dashboard for the Data Protection Officer: manage policies, view principals, handle erasure requests, review grievances, and download audit reports.
- Supports erasure requests initiated by the DPO on behalf of a Principal.

**Password Recovery**
- Break-glass account recovery using secure Master Recovery Keys, no email dependency.

**Reports & Data Export**
- Export compliance reports and consent records as downloadable files; exports are persisted so they survive container restarts.

**Docker & Binary Install**
- Full Docker Compose setup for evaluators: one command to start.
- Binary release for direct server deployment without Docker.

---
