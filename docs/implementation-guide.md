# TSI DPDP CMS Implementation Guide

**Document Version:** 1.0  
**Target Compliance:** Digital Personal Data Protection (DPDP) Act, 2023 (India)

---

## 1. Introduction & Architecture Overview

The TSI DPDP Consent Management System (CMS) is a **runtime enforcement engine**, not a database or storage layer. It acts as the operational gatekeeper that decides whether a business application may legally collect, query, share, or delete personal data based on active user consent and regulatory rules.

Because the engine operates purely at the execution layer, it has no inherent context about what data exists across the enterprise, who owns it, or why it is captured. That context is supplied through a structured configuration process owned by the compliance and engineering teams:

1. The **Data Protection Officer (DPO)** or Data Steward discovers and documents requirements in a plain-text Record of Processing Activities (`.txt` RoPA) blueprint.
2. The **Engineering Team** translates that blueprint into a validated, production-ready configuration schema (`.json`) for runtime enforcement.

---

## 2. Phase 1: Data Discovery & RoPA Cataloging

### Step 1: The App-by-App Questionnaire

The DPO/Data Steward distributes the questionnaire below to every engineering lead, product manager, and business-unit owner. A separate form is completed for every distinct application or standalone microservice that touches customer or employee data.

```
+-----------------------------+   Completes Questionnaire   +-----------------------------+
|  Product / Engineering Lead | --------------------------> |  Data Protection Officer    |
|  (Audits App Code & Schema) |                             |    (Reviews Compliance)     |
+-----------------------------+                             +-----------------------------+
```

---

#### DPDP Privacy Governance: Application Data Discovery Questionnaire

*Instructions: Complete one form per application, microservice, or distinct processing activity under your technical ownership. These inputs establish the corporate compliance baseline.*

**Part 1: Administrative & System Metadata**

| Field | Response |
|---|---|
| 1.1 Application / System Name | __________ |
| 1.2 Sector / Corporate Domain Unit | __________ |
| 1.3 Product Owner / Lead Engineer | __________ |
| 1.4 Primary Business Function (e.g. User Authentication, Loan Disbursal, Patient Registration) | __________ |

**Part 2: Personal Data Inventory (Data Categories)**

Check all data types this application collects, processes, or stores. For every item checked, map the exact database table and column name(s).

| Data Category | Processed? (Y/N) | Database Table & Column Name(s) |
|---|---|---|
| Primary Identity (Legal Name, Father's Name, Passport-size Photo) | | |
| Government Identifiers (Aadhaar, PAN Card, Voter ID) | | |
| Contact Tokens (Mobile, Email, Secondary Numbers) | | |
| Financial / Transaction (Bank Account No, IFSC, Credit Score, Income) | | |
| Location Markers (Live GPS, IP Address) | | |
| Device Artifacts (IMEI, Device ID, OS Version) | | |

**Part 3: Purpose Mapping & Legal Grounding**

- 3.1 Primary processing purposes (e.g. "KYC & Identity Verification", "Credit Assessment & Scoring", "Promotional Offers"): __________
- 3.2 Is this processing mandatory to deliver the core service?
  - [ ] Yes (denial/erasure breaks the application or terminates the service)
  - [ ] No (optional, promotional, or secondary feature)
- 3.3 Legal basis under the DPDP Act?
  - [ ] Explicit Customer Consent (Section 6)
  - [ ] Specified Legitimate Uses incl. Employment (Section 7)
  - [ ] Statutory / Regulatory Obligation (e.g. RBI Master Directions, PMLA)

**Part 4: Data Flow & Third-Party Sharing (Egress)**

- 4.1 Does this application transmit personal data to external APIs, vendors, cloud providers, or sub-processors? [ ] Yes [ ] No
- 4.2 If Yes, list authorized processors:

| Vendor | Country | Data Shared | Purpose |
|---|---|---|---|
| | | | |
| | | | |

**Part 5: Data Retention & Deletion Lifecycle**

*Complete 5.1 and 5.2 separately for each processing purpose declared in Part 3 - retention may differ per purpose (e.g. statutory financial records vs. consent-based marketing).*

- 5.1 When does operational necessity for holding the data expire (the trigger event)?
  - [ ] Immediately after the transaction concludes
  - [ ] On formal closure / termination of the account or user relationship
  - [ ] Other: __________
- 5.2 Is there a statutory minimum retention period?
  - [ ] No statutory minimum (delete on purpose fulfillment)
  - [ ] Yes: retain ____ [Days / Months / Years] post-trigger due to: __________

---

### Step 2: Drafting the DPO's Master RoPA Baseline (`.txt`)

Once questionnaires are collected and verified, the DPO synthesizes them into an immutable plain-text RoPA registry - the corporate Record of Processing Activities and the framework engineers must implement.

> **Note on format:** The example below shows an illustrative initial-draft RoPA. The reference files under `examples/ropa/` in this repository have been evolved to include a `LEGAL BASIS BY PURPOSE` section and `RETENTION BY PURPOSE` section, replacing the earlier single-value retention and activity-level legal basis fields.

```
========================================================================
ROPA REQUIREMENTS DOCUMENT
Activity : varam_borrower_v1
Sector   : Finance / Microlending
Standard : Digital Personal Data Protection Act, 2023 (India)
========================================================================

DESCRIPTION
------------------------------------------------------------------------
ROPA requirements for Varam Microcredit's borrower consent policy.
Covers KYC, credit assessment, loan servicing, and promotional
communications.

COMPLIANCE LIFECYCLE
------------------------------------------------------------------------
  1. DPO defined requirements in this template
  2. Engineer configured policy (varam_borrower_v1)
  3. System auto-derived ROPA draft on publish
  4. DPO verified draft against this template
  5. DPO published (dpo_id auto-recorded)

PROCESSING ACTIVITY
------------------------------------------------------------------------
  Activity Name : varam_borrower_v1
  Legal Basis   : CONSENT
  Purpose       :
    - KYC & Identity Verification
    - Credit Assessment & Scoring
    - Loan Disbursement & Collections
    - Promotional Offers & New Products

DATA SUBJECT CATEGORIES
------------------------------------------------------------------------
  - customer

DATA CATEGORIES  (15 total)
------------------------------------------------------------------------
  full_name              pan_card             masked_aadhaar
  photo                  voter_id             income_details
  bank_statements        existing_loan_info   employment_status
  bank_account_no        ifsc_code            current_location
  contact_number         mobile_number        email_address

SECURITY MEASURES
------------------------------------------------------------------------
AES-256 encryption at rest, TLS 1.3 in transit, CERSAI-compliant data
vaulting, role-based access with MFA.

DATA PROCESSORS  (4 declared)
------------------------------------------------------------------------
  Name      Country   Role                          Contact
  --------- --------- ----------------------------- ---------------------------
  AWS       IN        Cloud Hosting & Storage       aws-india-dpa@amazon.com
  CIBIL     IN        Credit Bureau Enquiry         compliance@cibil.com
  CERSAI    IN        Central Registry Verification helpdesk@cersai.org.in
  Twilio    US        OTP & SMS Delivery            privacy@twilio.com

PURPOSE-PROCESSOR MAPPING
------------------------------------------------------------------------
  Purpose                    Authorised Processors
  -------------------------- ------------------------------
  purpose_kyc_identity       CERSAI
  purpose_credit_scoring     CIBIL
  purpose_loan_servicing     (unrestricted)
  purpose_marketing_offers   Twilio

CROSS-BORDER TRANSFERS
------------------------------------------------------------------------
  Destination   Safeguard                            Processor
  ------------- ------------------------------------ ------------
  US            Standard Contractual Clauses (SCC)   Twilio

RETENTION  (per purpose)
------------------------------------------------------------------------
  Purpose                    Period              Start Event
  -------------------------- ------------------- ------------
  purpose_kyc_identity       2555 days (~7 yrs)  CESSATION
  purpose_credit_scoring     2555 days (~7 yrs)  CESSATION
  purpose_loan_servicing     2555 days (~7 yrs)  CESSATION
  purpose_marketing_offers   730 days  (~2 yrs)  COLLECTION

  Note: KYC, credit and loan-servicing data are financial records held
  for the 7-year statutory period after account cessation. Marketing is
  consent-based: deleted on consent withdrawal, with a 2-year backstop
  from collection (it is NOT tied to loan cessation).

LINKED CONSENT POLICY
------------------------------------------------------------------------
  - varam_borrower_v1

========================================================================
NOTE: This document records the DPO's ROPA requirements before system
configuration. Once the consent policy is published, the system auto-
derives a ROPA draft, which the DPO verifies against this document
before publishing the ROPA entry.
========================================================================
```

> **Reconciliation status (current reference files):** The compiled `varam_borrower_v1.json` includes all four purposes and per-purpose retention that matches this baseline. The activity-level `Legal Basis` field and per-purpose legal bases have been reconciled in the current reference files - the RoPA now carries a `LEGAL BASIS BY PURPOSE` section, and the JSON assigns the correct statutory/contractual/consent bases per purpose. The DPO's verification step (lifecycle item 4) should confirm that the published JSON matches the signed RoPA before the ROPA entry is published.

---

## 3. Phase 2: Technical Mapping & JSON Compilation

### Step 1: Map the Data Flow

Before compiling the schema, the engineering team establishes how personal data actually moves through each application, so the policy reflects real behaviour rather than assumptions. For every application, document three boundaries:

- **Ingress (capture)** - identify which endpoints collect personal data, and confirm a consent check is invoked before any data is processed or stored. No data category should be captured without a matching purpose in the policy.
- **Storage (at rest)** - record where each data category is persisted, and confirm that sensitive identifiers (e.g. PAN, Aadhaar) are encrypted or vaulted rather than held in plain tables.
- **Egress (departure)** - list which external processors receive data, what is sent, and under what safeguard. Every egress destination must correspond to a declared processor in the policy, and any cross-border flow to a recorded transfer safeguard.

The deliverable from this step is a plain mapping - data category → purpose → storage location → recipients - which is exactly what the schema in Step 2 encodes.

### Step 2: Schema Translation (Compiling `varam_borrower_v1.json`)

The engineering team converts the DPO's text blueprint into a structured JSON file with strict data types, localized language pairs, integer retention values, and the validation schema required by the CMS parser.

> **Retention unit note:** The illustrative JSON below uses `"DAYS"` with explicit day counts for precision (e.g. `2555` for 7 years). The actual reference files in `examples/policy/` use `"YEARS"` and `"MONTHS"` with integer values for readability. Both representations are valid; choose the unit that best suits your compliance tooling.

```json
{
  "en": {
    "title": "Varam Microcredit - Data & Privacy Policy",
    "introduction": "At Varam Microcredit, we are committed to the secure and transparent processing of your personal and financial data. This policy outlines how we handle your information to provide micro-finance services, in strict compliance with the Digital Personal Data Protection Act (DPDP), 2023.",
    "general_purpose_description": "We process data for KYC Verification, Credit Assessment, Loan Disbursement, Recovery Management, and Regulatory Reporting.",
    "data_processing_purposes": [
      {
        "id": "purpose_kyc_identity",
        "name": "KYC & Identity Verification",
        "description": "To verify your identity and prevent fraud using government-issued identifiers. This is a mandatory regulatory requirement for financial services.",
        "legal_basis": "Statutory Obligation (PMLA & DPDP Act)",
        "data_categories_involved": ["full_name", "pan_card", "masked_aadhaar", "photo", "voter_id"],
        "recipients_or_third_parties": ["CERSAI"],
        "retention_policy": "Statutory retention of 7 years (2555 days) after account closure, per RBI/PMLA norms.",
        "retention_duration_value": 2555,
        "retention_duration_unit": "DAYS",
        "retention_start_event": "CESSATION",
        "is_mandatory_for_service": true,
        "is_sensitive": true
      },
      {
        "id": "purpose_credit_scoring",
        "name": "Credit Assessment & Scoring",
        "description": "To evaluate your creditworthiness and determine loan eligibility based on financial history.",
        "legal_basis": "Contractual Necessity (DPDP Act, Section 7(b))",
        "data_categories_involved": ["income_details", "bank_statements", "existing_loan_info", "employment_status"],
        "recipients_or_third_parties": ["CIBIL"],
        "retention_policy": "Retained for 7 years (2555 days) after account closure for audit and regulatory record-keeping.",
        "retention_duration_value": 2555,
        "retention_duration_unit": "DAYS",
        "retention_start_event": "CESSATION",
        "is_mandatory_for_service": true,
        "is_sensitive": false
      },
      {
        "id": "purpose_loan_servicing",
        "name": "Loan Disbursement & Collections",
        "description": "To transfer funds to your bank account and manage the repayment cycle, including field visits if required.",
        "legal_basis": "Contractual Necessity",
        "data_categories_involved": ["bank_account_no", "ifsc_code", "current_location", "contact_number"],
        "recipients_or_third_parties": [],
        "retention_policy": "Retained for 7 years (2555 days) after loan closure for financial record-keeping.",
        "retention_duration_value": 2555,
        "retention_duration_unit": "DAYS",
        "retention_start_event": "CESSATION",
        "is_mandatory_for_service": true,
        "is_sensitive": false
      },
      {
        "id": "purpose_marketing_offers",
        "name": "Promotional Offers & New Products",
        "description": "To inform you about new loan products, insurance top-ups, and financial literacy programs.",
        "legal_basis": "Consent (DPDP Act, Section 6(1)(a))",
        "data_categories_involved": ["mobile_number", "email_address"],
        "recipients_or_third_parties": ["Twilio"],
        "retention_policy": "Deleted on consent withdrawal; 2-year (730-day) backstop from collection. Not tied to loan cessation.",
        "retention_duration_value": 730,
        "retention_duration_unit": "DAYS",
        "retention_start_event": "COLLECTION",
        "is_mandatory_for_service": false,
        "is_sensitive": false
      }
    ],
    "data_categories_details": [
      { "id": "full_name",          "name": "Full Name",                   "description": "Legal name as on government-issued ID, used for KYC and loan documentation." },
      { "id": "pan_card",           "name": "PAN Number",                  "description": "Used for credit bureau checks and income verification." },
      { "id": "masked_aadhaar",     "name": "Masked Aadhaar",              "description": "Identity proof with Aadhaar number partially hidden for security." },
      { "id": "photo",              "name": "Photograph",                  "description": "Passport-size photo captured during field KYC for account records." },
      { "id": "voter_id",           "name": "Voter ID",                    "description": "Alternative government-issued identity proof." },
      { "id": "income_details",     "name": "Income Details",              "description": "Salary slips or income certificates used for creditworthiness assessment." },
      { "id": "bank_statements",    "name": "Bank Statements",             "description": "Last 3-6 months of transaction history for credit evaluation." },
      { "id": "existing_loan_info", "name": "Existing Loan Information",   "description": "Active loans and repayment history sourced from credit bureaus." },
      { "id": "employment_status",  "name": "Employment Status",           "description": "Current occupation and employer details for repayment capacity assessment." },
      { "id": "bank_account_no",    "name": "Bank Account Details",        "description": "Account number and IFSC required for automated loan disbursement." },
      { "id": "ifsc_code",          "name": "IFSC Code",                   "description": "Bank branch identifier required for NEFT/RTGS disbursement." },
      { "id": "current_location",   "name": "Current Location",            "description": "Residential address for field visit coordination and loan delivery." },
      { "id": "contact_number",     "name": "Contact Number",              "description": "Mobile number for EMI reminders and collections communication." },
      { "id": "mobile_number",      "name": "Mobile Number",               "description": "Primary contact used for OTP and promotional communications." },
      { "id": "email_address",      "name": "Email Address",               "description": "Secondary channel for loan account statements and offer notifications." }
    ],
    "data_subject_categories": ["customer"],
    "security_measures": "AES-256 encryption at rest, TLS 1.3 in transit, CERSAI-compliant data vaulting, role-based access with MFA.",
    "processors": [
      { "name": "AWS",    "country": "IN", "role": "Cloud Hosting & Storage",        "contact": "aws-india-dpa@amazon.com" },
      { "name": "CIBIL",  "country": "IN", "role": "Credit Bureau Enquiry",          "contact": "compliance@cibil.com" },
      { "name": "CERSAI", "country": "IN", "role": "Central Registry Verification",  "contact": "helpdesk@cersai.org.in" },
      { "name": "Twilio", "country": "US", "role": "OTP & SMS Delivery",             "contact": "privacy@twilio.com" }
    ],
    "cross_border_transfers": [
      { "destination_country": "US", "safeguard": "Standard Contractual Clauses (SCC)", "processor": "Twilio" }
    ],
    "data_principal_rights_summary": "Under the DPDP Act 2023, you have the right to access your loan data, correct inaccuracies, withdraw consent for marketing, and request data erasure after all statutory and financial obligations are met.",
    "grievance_redressal_info": "For concerns, contact our Nodal Officer / DPO at: Email: compliance@varamcredit.in | Phone: +91 44 2233 4455 | Address: 10, Artha Towers, Mount Road, Chennai, Tamil Nadu.",
    "buttons": {
      "accept_all": "I Agree to Terms & Continue",
      "reject_all_non_essential": "Decline Optional Processing",
      "manage_preferences": "Customize My Privacy",
      "save_preferences": "Confirm Choices"
    },
    "links": {
      "full_privacy_policy_text": "Detailed Fintech Privacy Policy",
      "full_privacy_policy_url": "https://varamcredit.in/privacy",
      "terms_of_service_text": "Loan Agreement Terms",
      "terms_of_service_url": "https://varamcredit.in/terms"
    },
    "important_note": "Financial data and KYC documents are protected with banking-grade encryption. Core data required for loan processing and statutory reporting cannot be withdrawn while a loan is active."
  }
}
```

> **Legal basis note:** The `"Contractual Necessity (DPDP Act, Section 7(b))"` label used for credit scoring and loan servicing above should be reviewed with counsel - the DPDP Act recognizes only consent (S.6) and a closed list of legitimate uses (S.7), with no contractual-necessity ground, and S.7(b) concerns State processing rather than lending contracts.

> **Reconciliation status (current reference files):** All 15 data categories map to a purpose, and per-purpose retention matches the RoPA baseline. The legal basis fields have been reconciled in the reference files - the JSON in `examples/policy/finance/varam_borrower_v1.json` assigns the correct statutory/contractual/consent basis per purpose, and the corresponding RoPA carries a `LEGAL BASIS BY PURPOSE` table.

---

## 4. Phase 3: Pre-Production Risk Operations

### Step 1: Document-Based DPIAs

Product owners and engineers complete a Data Protection Impact Assessment (DPIA) for any change that introduces new endpoints or captures additional data fields.

```
+--------------------------------------------------------------------------+
|               DATA PROTECTION IMPACT ASSESSMENT (DPIA)                   |
|  Document Ref: DPIA-2026-VARAM_BORROWER_V1                               |
+--------------------------------------------------------------------------+

1. SYSTEM COMPLIANCE REVIEW:
   [x] All 15 captured data fields have explicit text matches in the active
       data classification sheet.
   [x] No data items are collected without a directly associated
       operational purpose.

2. LEAKAGE & ENCRYPTION CONTROLS AUDIT:
   - Data elements exposed via internal log aggregators? (No)
   - Dynamic masking on backend administrative portals? (Yes)
   - Raw identifiers transmitted over unencrypted HTTP? (No)

3. TRANS-BORDER GEOGRAPHY COMPLIANCE:
   - Any vendor routing customer payloads outside India? (Yes)
   - Vendor Context: Twilio SMS API processes in the US.
   - Statutory Control: SCCs signed, verified, and archived in the
     corporate compliance repository.

4. SYSTEM AUTHORIZATION DISPOSITION:
   [x] APPROVED   [ ] CONDITIONAL   [ ] REJECTED

   DPO Signature: Amit Sharma                          Date: June 2, 2026
```

> **Note:** DPIA item 1 asserts every field maps to a purpose. With `purpose_loan_servicing` present, all 15 categories are mapped in `varam_borrower_v1.json`, so this assertion holds.

### Step 2: Manual Vendor Privacy Verification

With no vendor dashboard, the DPO runs email-driven compliance reviews for third-party processors:

- **Mandatory DPA signatures** - before an external API is integrated, legal must sign a Data Processing Agreement (DPA) with provisions matching the DPDP Act.
- **Access security verification** - the vendor must declare its security posture (e.g. ISO 27001 or SOC 2 Type II audit certificates).
- **Repository logging** - contracts are filed in a secure corporate directory as legal proof of compliance in the event of a Data Protection Board (DPB) audit.

---

## 5. Phase 4: Production Deployment & Lifecycle Execution

### 1. Policy Creation and Publishing via the DPO Console

The finalized JSON schema is loaded into the system through the DPO Console UI. API-based policy creation and publishing are not currently supported.

**Step A - Create (DRAFT):** Log in to the DPO Console, navigate to **Policies**, and use the policy editor to paste or upload the compiled JSON content. The system saves the entry in `DRAFT` status pending review.

**Step B - Publish (DRAFT → ACTIVE):** After the DPO verifies the draft against the signed RoPA baseline (compliance lifecycle item 4), they click **Publish** in the console. A fiduciary can have multiple policies active simultaneously (e.g. a customer policy, a vendor policy, an employee policy). However, only one version of any given policy can be `ACTIVE` at a time; attempting to publish a new version while a previous version is still active will be rejected with a conflict error. The active version must be retired before a new one can be published.

### 2. UI Notice Synchronization

Once published, client applications pull the active configuration on login and render UIs dynamically. Multi-lingual text, checkboxes, privacy-policy URLs, and preference settings match the DPO's verified baseline without front-end code changes.

### 3. Executing the Standardized Deletion Interface

Triggered by a user erasure request or by the retention clock crossing its boundary (e.g. 2555 days post-CESSATION):

```
        (Data Retention Clock Expiry / User Erase Request)
                            |
                            v
              [Data Steward Logs Request Matrix]
                            |
                            v
          [Invokes Standardized Erasure Interface]
                            |
            +---------------+----------------+
            v                                v
   [Database Command (SQL)]        [API Command (Webhook)]
                            |
                            v
              [Generates Immutable Compliance Log]
```

1. **Verification check** - the Data Steward confirms no active loans or outstanding financial obligations override the erasure request.
2. **Interface invocation** - the steward runs the erasure interface, which executes the internal purge:

```sql
DELETE FROM secure_kyc_vault WHERE user_id = 98412;
DELETE FROM users WHERE id = 98412;
```

3. **Downstream purge** - the CMS fires outbound webhooks to registered processors (e.g. Twilio, external collections) ordering them to purge all references to the user ID.
4. **Audit log** - the CMS writes a cryptographically signed, immutable confirmation to the compliance ledger as court-ready proof that erasure was fulfilled.

---

## 6. Operational Responsibilities Summary

| Operational Capability | Team Responsibility |
|---|---|
| Data Discovery | Distribute questionnaires to engineering leads; consolidate manually. |
| RoPA Mapping | Maintain a `.txt` specification, mapped to code traces by hand. |
| DPIA & Risk Ops | Complete DPIA templates; route to DPO for sign-off. |
| Policy Upload | Format and validate the JSON policy file; create and publish via the DPO Console. |
| Source Validation | Inject `X-API-Key` and `X-API-Secret` into request headers for API calls (consent verification, erasure, etc.). |
| Data Retention | Periodically review the RoPA master list; run scripted erasure APIs. |
