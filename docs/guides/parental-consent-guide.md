# Parental Consent (Children's Data) Guide

**Document Version:** 1.0
**Applies to:** TSI DPDP CMS v0.5.4+ (the audit view is new in v0.5.4; the recording calls are older)
**Audience:** Developers building consent collection for services children use; DPOs and auditors reviewing it.

---

## 1. Overview

Section 9 of the DPDP Act requires the verifiable consent of a parent or lawful guardian before a child's personal data is processed, and restricts tracking, behavioural monitoring and targeted advertising aimed at children. The age that makes someone a child and what counts as "verifiable" are set by the Act and its Rules - check them for your service. This guide covers only what the CMS does.

**Responsibility is split on purpose:**

| Who | Does |
|---|---|
| **Your application** | Decides who is a minor, collects and verifies the guardian's consent (OTP, KYC provider, digital-ID credential, ...), and tells the CMS about it. |
| **The CMS** | Records the guardian verification, links it to the child's consent, keeps the principal's minor flag, and gives the DPO and auditors a view of where the link is missing. |
| **The DPO / auditor** | Reviews the audit view and follows up gaps with the application owner. |

The CMS does **not** verify anyone's age or identity, does **not** refuse a consent that has no guardian reference, and does **not** enforce the Act's restrictions on tracking or advertising to children. It records what the application sends and makes gaps visible.

### Is an OTP enough for "verifiable" consent?

Usually not on its own. An OTP proves that someone controls a phone number or email address. It does not prove that the person is an adult, or that they are this child's parent or guardian: a child can enter their own number or borrow a parent's phone. Section 9 and the DPDP Rules expect the fiduciary to show due diligence that the person giving consent is an identifiable adult, so check the current Rules for what your service must do (and take legal advice). In order of strength:

1. **A government-backed digital-identity token (for example a DigiLocker token).** This is the most appropriate mechanism, because it ties the consent to an identified adult. The CMS does not talk to DigiLocker: it has to be integrated in your client application, which runs the check and then records the result in the CMS (see [Recording a DigiLocker token instead of an OTP](#recording-a-digilocker-token-instead-of-an-otp)).
2. **A guardian you have already verified**, for example a parent whose adult identity you checked at enrolment, linked to the child's account.
3. **OTP combined with 1 or 2.** The OTP then only confirms that the person present is the one you verified.
4. **OTP alone.** Weak. Use it only where the risk is low, and expect to have to defend it.

The CMS records whichever mechanism you used (`verification_mechanism`, `provider`, `reference`), so the audit shows how each guardian was verified. It does not judge whether that mechanism is good enough.

### Recording a DigiLocker token instead of an OTP

Your application runs the DigiLocker flow itself. Once the guardian has been verified as an adult, record it with the same `record_parent_consent` call used for an OTP (see [section 2](#2-the-flow-in-your-application)), changing only the verification fields:

```json
{
  "_func": "record_parent_consent",
  "child_principal_id": "learner@example.com",
  "guardian_principal_id": "+919990001111",
  "verification_mechanism": "DIGILOCKER_TOKEN",
  "provider_name": "DIGILOCKER",
  "verification_ref_id": "<the token reference DigiLocker returned>",
  "proof_metadata": { "adult_verified": true, "verified_at": "2026-10-27T10:00:00Z" }
}
```

- **`verification_mechanism`:** any short text up to 50 characters. Use one value consistently (here `DIGILOCKER_TOKEN`) so the audit and the Parent Consent export can tell DigiLocker-verified guardians from OTP ones.
- **`verification_ref_id`:** the reference or identifier for the DigiLocker token, so the check can be traced back to DigiLocker later. Do not store access tokens, passwords, or the identity documents themselves.
- **`proof_metadata`:** the outcome and when it happened, nothing more. Keep Aadhaar numbers and document contents out of it.
- **The rest of the flow is the same:** `link_user` with `MINOR`, then `record_consent` with the `verification_log_id`.

## 2. The flow in your application

Three calls, in this order, for a child:

**1. Record the guardian verification** (`record_parent_consent`, WRITE scope):

```json
{
  "_func": "record_parent_consent",
  "child_principal_id": "learner@example.com",
  "guardian_principal_id": "+919990001111",
  "verification_mechanism": "INTERNAL_OTP",
  "provider_name": "ACME_AUTH",
  "verification_ref_id": "otp_tx_8f3a21",
  "proof_metadata": { "guardian_name": "A Parent", "timestamp": "2026-10-27T10:00:00Z" }
}
```

`child_principal_id`, `guardian_principal_id` and `verification_mechanism` are required; without them the call returns `400 Parental Consent Failed`. Success is `201` with a `verification_log_id`. Put your provider's transaction reference in `verification_ref_id`. `proof_metadata` is stored exactly as sent and is copied into the audit trail, so keep it to references and hashes - not identity documents or raw ID numbers.

**2. Flag the principal as a minor** (`link_user`):

```json
{
  "_func": "link_user",
  "anonymous_user_id": "anon_12345",
  "authenticated_user_id": "learner@example.com",
  "age_category": "MINOR",
  "guardian_id": "+919990001111",
  "verification_status": "VERIFIED"
}
```

This sets the principal's `age_category`, `guardian_id` and `verification_status`, and also merges the anonymous session's consent history into the authenticated id (see the [System Integration Guide](system-integration-guide.md)).

**3. Record the consent with the reference** (`record_consent`), for the child's principal id, every time consent is recorded:

```json
{
  "_func": "record_consent",
  "user_id": "learner@example.com",
  "policy_id": "learner_policy",
  "verification_log_id": "<the id from step 1>",
  "data_point_consents": [ ... ]
}
```

The CMS does not expire a verification: later consents from the same child can reuse the same `verification_log_id`. Decide your own re-verification policy.

Withdrawal and erasure need no guardian reference in the CMS.

**Worked example:** `web/tour/parent-consent.html` (the education demo) performs exactly this sequence. Its guardian OTP is a placeholder that accepts `123456` in the browser - it demonstrates the flow and is **not** verification. Policy purposes may carry `"requires_parental_consent": true`; the demo uses it to decide what to show, and the CMS itself does not act on it.

## 3. What the CMS stores

- A `parental_verification_logs` row per verification: child, guardian, mechanism, provider, reference, proof metadata, fiduciary and time. Export it from **Reports -> Parent Consent Log**.
- On the principal (`data_principal`): `age_category`, `guardian_id`, `verification_status`.
- On each consent record: the `verification_log_id` you sent.
- An audit-trail event for the verification.

## 4. Auditing guardian references

**DPO Console -> Principals -> Minor Consent Audit** summarises, for every principal flagged `MINOR`, whether each consent record carries a guardian reference that belongs to that child. **Reports -> Minor Guardian Audit** exports every such consent as CSV (problems first) for the date range you pick - choose a wide range for "everything". The DPO, admins and operators of the fiduciary can view the panel.

| Finding | Meaning | Usual cause |
|---|---|---|
| OK | A reference is present, its log is for this child and this fiduciary, and its guardian matches the principal's `guardian_id` | - |
| Missing reference | The consent has no `verification_log_id` | The application did not send it, or flagged the principal as a minor after the consent was recorded |
| Reference mismatch | The reference points to a log for another child, another fiduciary, or another guardian | Wrong log id passed, or the guardian on file changed |

A finding is something to review with the application owner, not an automatic violation. Recorded consents cannot be edited; to correct a gap, fix the integration and collect fresh consent with the reference.

## 5. Limits worth knowing

- **Only principals flagged `MINOR` are covered.** `ADULT` is the default, so a child the application never flags is invisible to the audit.
- **The flag belongs to your application.** `link_user` can change it at any time, including back to `ADULT`. When a child comes of age, do that deliberately.
- **Order matters.** Consent recorded before the principal is flagged shows as "Missing reference".
- **"Verified" means "your application says so".** The CMS checks that the reference exists and is consistent, not that the guardian was genuinely verified. Running the DigiLocker check is up to your application (see [Is an OTP enough?](#is-an-otp-enough-for-verifiable-consent)).

## 6. Integrator checklist

- [ ] Decide how your service identifies a minor and when guardian consent is collected.
- [ ] Call `record_parent_consent`, then `link_user` with `MINOR`, then `record_consent` with the `verification_log_id`.
- [ ] Send the `verification_log_id` on every consent recorded for that child.
- [ ] Keep identity documents out of `proof_metadata`.
- [ ] After go-live, ask the DPO to check the Minor Consent Audit panel and resolve any findings.

## 7. Related

- [System Integration Guide](system-integration-guide.md) - the full consent-recording calls
- [Implementation Guide](implementation-guide.md) - the audit view and exports for DPOs
- [OpenAPI spec](../api/openapi.yaml) - `record_parent_consent`, `link_user`, `record_consent`
- [Regression test cases](../test-cases/regression-test-cases.md) - TC-RTS-12 (the flow) and TC-DPO-16a (the audit)
