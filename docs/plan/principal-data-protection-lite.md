# Item 7 (revised): principal data protection = opaque IDs + encryption at rest and in transit

**Status:** built (P1-P3). The startup SSL warning was dropped: production already forces `sslmode=require` in `PoolDB`. The full encrypted/hashed-column design stays in `principal-data-protection-evaluation.md` as an
opt-in hardening release for fiduciaries that need it.

## 1. The approach in one paragraph
The CMS does not need to know who a person is, only which record belongs to them. Implementers build on their own apps and call the API, so
they choose the principal ID. **They send an opaque ID** (for example `c-98a7b6c5`), never an email address or phone number. The CMS then
holds no directly identifying value; the ID is still personal data because the fiduciary can link it to a person, so the deployment
**encrypts it at rest (disk/volume, including backups) and in transit (TLS)**. No change to the data layer.

## 2. What we do

### P1. Guidance (S, 0.5 day)
* Integration guide, tour, webhook guide, API docs: **do not use email addresses or phone numbers as the principal ID; send an opaque ID from
  your own system.** Say why: the ID is stored in consent records, the audit trail and webhook payloads and cannot be changed later.
* OTP webhook guide: the payload carries `user_id` only; map the opaque ID to a contact address inside your own OTP endpoint.

### P2. Demo portal and DPO settings wording (S, 0.5 day)
* Rights portal login: one neutral label "Data Principal ID", text input for every OTP mode (no `type="email"` / `type="tel"`), opaque
  placeholder (`e.g. c-98a7b6c5`), OTP hint "sent through your organisation's OTP service", and a short note: "Use the ID your
  application sends to the CMS. Avoid email addresses and phone numbers as IDs." Implementers can test the whole lifecycle with opaque IDs.
* **Evaluation banner (visible on the login page and after login):** "This portal is for implementers to evaluate the consent lifecycle. It
  is not meant to be used by data principals. In a real deployment, principals use your own application, which calls the CMS API."
* DPO settings next to the OTP mode: same warning; option labels describe how the code is delivered, not what the ID is.
* Not enforced in code: any ID is still accepted.

### P3. Required deployment controls and documents (S, 1 day)
* `docs/security/KEY_MANAGEMENT.md`: what `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT`, `JWT_SECRET` protect, what losing each means, backup, what
  cannot be rotated without re-encrypting, an owner for each.
* `docs/security/LOG_RETENTION.md`: retention floors (365-day delivery logs; audit ledger append-only; 7-year floor when archiving is added).
  Existing audit rows keep whatever ID was sent.
* Deployment checklist with **required** controls, each with an owner and evidence (who confirmed, when):
  disk/volume encryption on the database server, replicas and backups; TLS to the CMS and to the database; encrypted backups; restricted
  database access; a restore rehearsal.
* Startup warning if the database connection is not using SSL outside local mode (verify first whether production already requires it).
* Residual-exposure statement: IDs sit in plain text in the database and audit log and rely on those infrastructure controls.

### Optional, not in this release: encrypt guardian proof and claimed IP (1.5 to 2.5 days)
Parental verification reference/OTP data and an integrator-claimed IP are personal data whatever the ID style. Column encryption (`db/27`,
re-runnable, rollback by decrypting) can be added now or in the hardening release.

## 3. Effort
| Piece | Days |
|---|---|
| P1 guidance | 0.5 |
| P2 portal and settings wording | 0.5 |
| P3 documents, checklist, SSL warning | 1 |
| **Total** | **about 2** (3.5 to 4.5 with the optional column encryption) |

## 4. Not in this release
Console masking, masked exports, audit pseudonymisation, hashed or encrypted ID columns, reveal service, re-key tool. These need a rewrite
of the data layer and stay in the opt-in hardening release (see the evaluation document).

## 5. Acceptance
* The guides state clearly: do not use email/phone as principal ID; use opaque IDs.
* The portal logs in with an opaque ID in every OTP mode; no console or API behaviour changes.
* The deployment checklist names disk encryption, TLS and encrypted backups as required, with an owner and evidence field.
* Full suite passes in every mode from a clean build.
