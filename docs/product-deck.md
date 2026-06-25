# TSI DPDP CMS End-Client Onboarding Deck

Format: breezy 10-minute presentation  
Presenter: implementation partner  
Audience: end-client leadership, DPO, legal, IT, product, and data teams  
Source inputs: `web/tour/index.html`, `README.md`, `RELEASE_NOTES.md` through v0.4.8

## Purpose

This deck is for partners to onboard end clients into a DPDP CMS evaluation or pilot. It helps the client understand:

- What business problem the system solves.
- What their team needs to prepare.
- What the partner will configure and demonstrate.
- What decisions are needed before pilot rollout.
- Which short demo videos can be used as follow-up material.

## 10-Minute Run Of Show

| Time | Slide | Client takeaway |
| --- | --- | --- |
| 0:00-0:45 | 1. Why We Are Here | DPDP compliance needs operating controls, not only documents. |
| 0:45-1:30 | 2. What You Get | A working consent, rights, enforcement, and evidence workflow. |
| 1:30-2:15 | 3. Who Is Involved | Legal, DPO, IT, product, and data owners need to align. |
| 2:15-3:15 | 4. The Client Journey | One consent can be followed from policy to proof. |
| 3:15-4:15 | 5. Configure First | Fiduciaries, apps, purposes, policies, and ROPA. |
| 4:15-5:15 | 6. Principal Experience | Rights portal, withdrawal, grievance, parental consent, and voice options. |
| 5:15-6:30 | 7. DPO Operating Model | DPO console, operator delegation, breach, reports, and legal evidence. |
| 6:30-7:45 | 8. Integration Path | APIs, webhooks, processor checks, and deployment model. |
| 7:45-8:45 | 9. Pilot Plan | What the partner and client do in the first pilot sprint. |
| 8:45-10:00 | 10. Decisions And Next Steps | Agree scope, owners, source systems, and success criteria. |

---

## Slide 1: Why We Are Here

### DPDP compliance has to run inside daily operations

**Client message:**  
The goal is to help your organization move from policy intent to operational proof.

**Talk track:**  
"This onboarding session is about how DPDP compliance becomes a working process. We will show how consent is captured, verified, withdrawn, enforced, and evidenced using TSI DPDP CMS."

**Partner cue:** Keep this about the client's operating risk, not the product feature list.

---

## Slide 2: What You Get

### A working compliance workflow your teams can evaluate

**Client outcomes:**
- A configurable DPDP consent and rights workflow.
- A DPO console for policy, ROPA, grievances, breach, compliance, audit, and reports.
- A rights portal where Data Principals can view consent, withdraw consent, and raise grievances.
- Consent verification APIs and webhooks for downstream systems.
- Evidence artifacts for audit, regulator, and legal response.

**Talk track:**  
"The pilot is not just a UI walkthrough. The objective is to map one real client use case into a working control flow."

---

## Slide 3: Who Is Involved

### The pilot works best when each owner is clear

**Client participants:**
- DPO or privacy lead: owns compliance workflow and sign-off.
- Legal or compliance: confirms notice language, legal basis, retention, and evidence expectations.
- Product or business owner: chooses the use case and principal journey.
- IT or platform team: supports deployment, identity, APIs, and webhooks.
- Data owner or processor owner: confirms processing purpose, retention, and erasure behavior.

**Talk track:**  
"The partner can configure the system, but the client must decide the real-world policy, purpose, retention, and operating ownership."

---

## Slide 4: The Client Journey

### Follow one consent from policy to proof

**Journey:**
- Define fiduciary, app, purpose, policy, and ROPA.
- Present notice and capture consent.
- Verify consent before processing.
- Let the principal view consent, withdraw consent, or raise a grievance.
- Trigger retention, erasure, purge, and audit workflows.
- Produce ROPA, breach, audit, or legal evidence records when needed.

**Talk track:**  
"For onboarding, we recommend choosing one practical use case and tracing it end to end. That keeps the pilot concrete."

---

## Slide 5: Configure First

### Start with the client's real processing map

**Inputs needed from the client:**
- Data Fiduciary name and branding preference.
- Apps or channels that collect consent.
- Data Principal identifiers used by the client.
- Purposes, data categories, retention periods, and processors.
- Draft notice or policy language.
- DPO, operator, and admin users.

**Relevant videos:**
- [Fiduciary Provisioning](https://youtu.be/216gZPlokuM)
- [ROPA Definition and Policy Creation](https://youtu.be/O_yhxu2o4Mc)
- [Partner White Labeling](https://youtu.be/DyU4GI_3-DY)

**Talk track:**  
"The first configuration workshop is about converting your processing map into system objects: fiduciaries, apps, purposes, policies, and ROPA entries."

---

## Slide 6: Principal Experience

### Show the client what their users will experience

**Capabilities to demonstrate:**
- Notice and consent capture.
- Rights dashboard for viewing consent artifacts.
- Withdrawal and grievance initiation.
- Verifiable parental consent for minors.
- Voice consent for assisted or inclusive journeys.

**Relevant videos:**
- [User Rights Management](https://youtu.be/nlthzXlBc1M)
- [Verifiable Parental Consent](https://youtu.be/kz4idKMBLXk)
- [Voice Consent Gateway](https://youtu.be/d6WuPd0mr9U)

**Talk track:**  
"This slide is where client product and service teams usually lean in. It shows what Data Principals will actually see and do."

---

## Slide 7: DPO Operating Model

### Turn compliance into assigned work

**Operating workflows:**
- DPO dashboard and navigation aligned to setup, operations, oversight, and administration.
- Operator delegation for assigned grievance and purge/compliance closure — operators are scoped to those closure items and cannot author policy, manage webhooks, or generate legal evidence certificates (DPO/Admin only). *New in v0.4.8*
- Grievance review, assignment, and resolution.
- Breach reporting, affected-principal notification, CSV upload, and PDF record generation. *New in v0.4.8*
- Nightly compliance enforcement jobs now self-heal: runs are claimed atomically across app instances and automatically catch up if a run was missed (e.g. the app was down at midnight). *New in v0.4.8*
- Audit, ROPA export, compliance reports, and legal evidence generation.

**Relevant videos:**
- [Compliance Management](https://youtu.be/TE27zu859_s)
- [Grievance Management](https://youtu.be/OGrfJgHgmJg)
- [Breach Notification](https://youtu.be/lHOAQSIrxh8)
- [Legal Module](https://youtu.be/neS4x46erHA)

**Talk track:**  
"For DPO teams, the important point is separation of control. DPOs own policy and oversight. Operators can be delegated closure work without receiving full administrative control."

---

## Slide 8: Integration Path

### Connect CMS to the client's systems

**Integration surfaces:**
- Consent verification API for processors before processing.
- Notification and Purge webhooks with per-fiduciary delivery URLs, HMAC-SHA256 signed, as an alternative to polling. *New in v0.4.8*
- Three new developer reference examples ship with this release: `NotificationListener.java` (polling client for the Notification API), `PurgeHandler.java` (interactive purge-acknowledgement client), and a consent-lifecycle script exercising capture, withdrawal, and erasure end-to-end. *New in v0.4.8*
- Docker Compose evaluation and binary deployment path.
- Rights portal login settings: Dummy, Email OTP, or Mobile OTP, each with a configurable delivery webhook and message, plus an optional PCA QR toggle. *New in v0.4.8*

**Relevant video:**
- [System Integration](https://youtu.be/P6kY9aBc_gM)

**Talk track:**  
"The integration workshop should identify where consent is collected, where processing decisions happen, and which systems must receive purge or notification events."

---

## Slide 9: Pilot Plan

### A simple first sprint for the client and partner

**Week-one pilot flow:**
- Choose one fiduciary use case and one app/channel.
- Configure one policy with a small set of purposes.
- Create the ROPA entries and review required fields.
- Run consent capture, verification, withdrawal, grievance, and breach scenarios.
- Connect one downstream API or webhook path.
- Export audit, ROPA, and evidence artifacts for review.

**Talk track:**  
"A good pilot is narrow but complete. One use case taken end to end is more useful than many disconnected screens."

---

## Slide 10: Decisions And Next Steps

### What the client needs to decide before rollout

**Decision checklist:**
- Which fiduciary, app, and principal journey should be piloted first?
- Who signs off on purposes, notices, legal basis, and retention?
- Which identity method should the rights portal use?
- Which processors or downstream systems need consent verification?
- Which notification, purge, grievance, breach, and evidence workflows are in scope?
- What success criteria will decide whether to move from pilot to implementation?

**Close:**  
"The next step is a focused onboarding workshop: pick one use case, collect the configuration inputs, and run one consent from policy to proof."

---

## Future Directions

These are useful strategic conversations, but they should not be presented as required scope for the first client onboarding pilot.

- Portable Consent Artifacts and DPDP Wallet: future direction for portable privacy and user-managed consent artifacts.
- Standardized Erasure Protocol: future direction for consistent erasure request handling across fiduciaries, processors, and downstream systems.

Reference material:
- DPDP Wallet / PCA proposal: https://techadvisory.substack.com/p/dpdpa-solving-consent-fatigue-via
- Standardized Erasure Interface proposal: https://techadvisory.substack.com/p/the-need-for-standardized-erasure

---

## Partner Appendix: Full Tour Video Index

- Fiduciary Provisioning: https://youtu.be/216gZPlokuM
- ROPA Definition and Policy Creation: https://youtu.be/O_yhxu2o4Mc
- User Rights Management: https://youtu.be/nlthzXlBc1M
- Compliance Management: https://youtu.be/TE27zu859_s
- Grievance Management: https://youtu.be/OGrfJgHgmJg
- Breach Notification: https://youtu.be/lHOAQSIrxh8
- Legal Module: https://youtu.be/neS4x46erHA
- System Integration: https://youtu.be/P6kY9aBc_gM
- Verifiable Parental Consent: https://youtu.be/kz4idKMBLXk
- Password Recovery: https://youtu.be/LYouy1cqiGE
- Voice Consent Gateway: https://youtu.be/d6WuPd0mr9U
- Partner White Labeling: https://youtu.be/DyU4GI_3-DY

## Partner Appendix: Release Themes To Mention If Asked

- v0.4.8: Operator delegation, breach CSV upload, rights portal settings, HMAC webhooks, reliable nightly enforcement jobs.
- v0.4.5: Partner white labeling through `BRAND_NAME`.
- v0.4: ROPA, security hardening, tamper-evident audit trail.
- v0.3: Voice consent and legal evidence.
- v0.2: Verifiable parental consent.
- v0.1: Consent lifecycle baseline.
