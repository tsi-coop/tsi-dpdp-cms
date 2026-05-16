# Records of Processing Activities (ROPA)
**TSI DPDP Consent Management System - Design & Implementation Plan**
Version: 0.4 | Status: Planned

---

## 1. What is ROPA?

A Record of Processing Activities (ROPA) is a formal, structured register that a Data Fiduciary is required to maintain, documenting every activity in which personal data is processed.

ROPA answers six core questions for each processing activity:

| # | Question | Example |
|---|----------|---------|
| 1 | **What** data is processed? | Mobile number, Aadhaar hash, location |
| 2 | **Whose** data? | Customers, minors, employees |
| 3 | **Why** is it processed? | KYC verification, marketing, fraud detection |
| 4 | **Who** processes it? | Internal app, third-party sub-processor |
| 5 | **How long** is it kept? | 3 years from account closure |
| 6 | **With what safeguards?** | AES-256 at rest, TLS in transit, access logs |

Under the **Digital Personal Data Protection Act 2023 (India)**, Section 8 imposes accountability obligations on Data Fiduciaries. While the Act does not use the term "ROPA" explicitly, it requires fiduciaries to:

- Process data only for a **specified, clear, and lawful purpose** (Section 6)
- Maintain and publish a clear **privacy notice** disclosing processing activities (Section 5)
- **Demonstrate compliance** and produce records when called upon by the Data Protection Board of India (Section 8(9))
- Ensure personal data is **erased upon withdrawal of consent or fulfilment of purpose** (Section 8(7))

A ROPA is the operational instrument that makes all of the above demonstrable and auditable.

---

## 2. Why Do We Need ROPA?

### 2.1 Regulatory Obligation

Data Fiduciaries operating under the DPDP Act 2023 must be able to produce evidence of lawful, purposeful, and time-bound processing at any time. The Data Protection Board of India can initiate an inquiry and demand records (Section 28). Non-compliance attracts penalties of up to **₹250 crore** (Schedule, Item 3).

Without a ROPA, a fiduciary cannot:
- Prove that every processing activity has a documented legal basis
- Show that consent was obtained for the specific purposes recorded
- Demonstrate that retention limits were enforced systematically

### 2.2 Operational Need

The current CMS stores consent policies, apps, and consent records in separate silos. There is no consolidated view of all processing activities across an organisation's apps. This means:

- DPOs cannot answer a Data Principal's right-to-information request accurately without manually querying multiple tables
- Retention enforcement (CES) reads app-level fields that are not governed or versioned
- There is no completeness check - gaps in required declarations go unnoticed until an audit

ROPA addresses all three gaps in a single module.

### 2.3 Significant Data Fiduciary (SDF) Path

The DPDP Act designates certain fiduciaries as **Significant Data Fiduciaries** (Section 10) based on volume, sensitivity, or risk. SDFs face heightened obligations including mandatory Data Protection Impact Assessments (DPIAs). A well-maintained ROPA is a prerequisite for the SDF designation process and for passing any DPIA exercise.

### 2.4 Customer and Partner Trust

Enterprise clients - banks, hospitals, fintechs, insurers - perform vendor due diligence that includes reviewing the CMS platform's own compliance posture. A ROPA export demonstrates that the platform is compliance-grade, not just a consent-click tool. This is a direct trust signal for procurement and sales.

---

## 3. Business Outcomes

### 3.1 Regulatory Audit Readiness
- DPO can export a complete, signed ROPA report (CSV/PDF) in minutes - no manual assembly from disparate tables
- Every ROPA entry is timestamped, versioned, and written into the tamper-evident audit trail
- Board inquiry response time reduces from weeks to hours

### 3.2 Reduced Legal Risk
- Every processing activity has a documented legal basis - eliminates "we didn't know we needed consent" failures
- Retention periods managed from one authoritative source - CES purge jobs read ROPA instead of unversioned app fields
- Cross-border transfer declarations surface data localisation risks before they become violations

### 3.3 DPO Efficiency
- Draft ROPA entries are auto-populated from published consent policies - DPOs review and publish rather than write from scratch
- Completeness checker flags missing required fields before a regulator does
- Single dashboard view of all processing activities, filterable by legal basis, status, app, and data category

### 3.4 Platform Differentiation
- ROPA is a feature gap in most competing CMS products in the Indian market
- Positions the platform as an end-to-end DPDP compliance tool, not just a consent SDK
- Enables a future DPDP compliance score / maturity report per fiduciary - a premium reporting feature

---

## 4. Implementation Steps

### Step 1 - Database Migration
**New file:** `db/02_ropa.sql`

```sql
CREATE TABLE ropa_entries (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fiduciary_id            UUID NOT NULL REFERENCES fiduciaries(id),
    app_id                  UUID REFERENCES apps(id),
    activity_name           TEXT NOT NULL,
    purpose                 TEXT NOT NULL,
    legal_basis             VARCHAR(30) NOT NULL
                                CHECK (legal_basis IN ('consent','legal_obligation',
                                                       'vital_interest','legitimate_use')),
    data_categories         JSONB NOT NULL DEFAULT '[]',
    data_subject_categories JSONB NOT NULL DEFAULT '[]',
    retention_period_days   INTEGER,
    retention_start_event   VARCHAR(20)
                                CHECK (retention_start_event IN ('COLLECTION','CESSATION')),
    processors              JSONB DEFAULT '[]',
    cross_border_transfers  JSONB DEFAULT '[]',
    security_measures       TEXT,
    dpo_id                  UUID REFERENCES operators(id),
    linked_policy_ids       JSONB DEFAULT '[]',
    status                  VARCHAR(20) NOT NULL DEFAULT 'draft'
                                CHECK (status IN ('draft','active','under_review','retired')),
    version                 INTEGER NOT NULL DEFAULT 1,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ropa_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ropa_entry_id   UUID NOT NULL REFERENCES ropa_entries(id),
    version         INTEGER NOT NULL,
    snapshot        JSONB NOT NULL,
    changed_by      UUID REFERENCES operators(id),
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Link consent records to their governing ROPA entry
ALTER TABLE consent_records
    ADD COLUMN ropa_entry_id UUID REFERENCES ropa_entries(id);
```

---

### Step 2 - Service Layer
**New file:** `src/org/tsicoop/dpdpcms/service/v1/Ropa.java`

Follow the `post()` / `validate()` dispatch pattern used by `Consent.java` and `Policy.java`.

| Action | Description |
|--------|-------------|
| `create_entry` | Insert draft entry; write initial snapshot to `ropa_history` |
| `update_entry` | Snapshot current state to `ropa_history`, increment version, apply update |
| `publish_entry` | Transition `draft` → `active`; write to `audit_logs` |
| `retire_entry` | Transition `active` → `retired`; no deletion allowed |
| `list_entries` | Filter by `fiduciary_id`, `status`, `app_id`, `legal_basis` |
| `get_entry` | Return single entry with full version history |
| `validate_completeness` | Return list of missing required fields against DPDP checklist |
| `export_ropa` | Generate CSV rows for all active entries of a fiduciary |
| `derive_from_policy` | Trigger `RopaDeriver` to pre-populate a draft from a published consent policy |

**New utility:** `src/org/tsicoop/dpdpcms/util/RopaDeriver.java`

Reads `consent_policies.policy_content` JSONB, extracts `data_categories_details[]`, `data_processing_purposes[]`, and `retention_start_event`. Reads `apps.processing_purposes` for processor info. Creates a draft `ropa_entry` linked to the policy.

**New utility:** `src/org/tsicoop/dpdpcms/util/RopaValidator.java`

Validates a ROPA entry against the completeness checklist (see Step 6).

---

### Step 3 - API Routes
Wire into the existing servlet filter (`web/WEB-INF/web.xml`). Access restricted to `DPO` and `ADMIN` roles, following the role-check pattern in `Operator.java`.

```
POST   /api/v1/ropa/entries                create_entry
GET    /api/v1/ropa/entries                list_entries
GET    /api/v1/ropa/entries/{id}           get_entry
PUT    /api/v1/ropa/entries/{id}           update_entry
POST   /api/v1/ropa/entries/{id}/publish   publish_entry
POST   /api/v1/ropa/entries/{id}/retire    retire_entry
GET    /api/v1/ropa/entries/{id}/validate  validate_completeness
GET    /api/v1/ropa/export                 export_ropa (?format=csv)
POST   /api/v1/ropa/derive                 derive_from_policy
```

---

### Step 4 - Integration with Existing Modules

| Module | File | Change |
|--------|------|--------|
| Policy publish | `service/v1/Policy.java` | After status → `ACTIVE`, call `RopaDeriver.deriveFromPolicy()` to create a draft ROPA entry |
| Consent record | `service/v1/Consent.java` | In `recordConsentToDb()`, resolve and write `ropa_entry_id` into `consent_records` |
| CES retention | `ces/CESService.java` | Read `retention_period_days` + `retention_start_event` from `ropa_entries` (replaces unversioned app field) |
| Audit log | `service/v1/Audit.java` | Add `ROPA` as a valid `service_type` in `logEventAsync()` |
| Dashboard | `service/v1/AdminDash.java` | Add metrics: count of ROPA entries by status, % entries with all required fields complete |

---

### Step 5 - Frontend
**New files:** `web/ropa-registry.html`, `web/ropa-registry.js`

| Component | Description |
|-----------|-------------|
| ROPA entries table | Status badges, filter bar (app, legal basis, status) |
| Entry form | Create/edit all fields; read-only when status is `active` or `retired` |
| Completeness panel | Visual checklist of missing required fields per entry |
| History timeline | Version-by-version view of who changed what and when |
| Export button | Triggers `GET /api/v1/ropa/export?format=csv` |
| Derive from Policy | Dropdown to select a published policy; calls `POST /api/v1/ropa/derive` |

---

### Step 6 - Completeness Validation Checklist
`RopaValidator.java` checks each active entry against DPDP Act accountability obligations:

- [ ] `activity_name` - non-empty
- [ ] `purpose` - non-empty
- [ ] `legal_basis` - set (not null)
- [ ] `data_categories` - at least one entry
- [ ] `data_subject_categories` - at least one entry
- [ ] `retention_period_days` - greater than zero
- [ ] `retention_start_event` - set
- [ ] `dpo_id` - assigned
- [ ] `security_measures` - non-empty
- [ ] `cross_border_transfers` - if non-empty, each transfer must have `destination_country` and `safeguard`

Returns structured validation errors so the UI renders an actionable completeness checklist.

---

## 5. Roles and Access Control

| Role | Permissions |
|------|-------------|
| ADMIN | Full CRUD on all fiduciary ROPA entries; publish; retire |
| DPO | CRUD on their fiduciary's entries; publish; retire |
| AUDITOR | Read-only - entries and history |
| OPERATOR (app-level) | No access |

---

## 6. Files to Create / Modify

### New Files
| File | Purpose |
|------|---------|
| `db/02_ropa.sql` | DB migration - `ropa_entries`, `ropa_history`, FK on `consent_records` |
| `src/.../service/v1/Ropa.java` | Service class - all ROPA actions |
| `src/.../util/RopaDeriver.java` | Auto-populate draft from consent policy |
| `src/.../util/RopaValidator.java` | Completeness checker |
| `web/ropa-registry.html` | ROPA registry UI |
| `web/ropa-registry.js` | Frontend logic |

### Modified Files
| File | Change |
|------|--------|
| `service/v1/Policy.java` | Call `RopaDeriver` on policy publish |
| `service/v1/Consent.java` | Write `ropa_entry_id` on `record_consent` |
| `ces/CESService.java` | Read retention from `ropa_entries` |
| `service/v1/AdminDash.java` | Add ROPA metrics to dashboard |
| `service/v1/Audit.java` | Register `ROPA` as a `service_type` |
| `web/WEB-INF/web.xml` | Wire new ROPA API routes |

---

## 7. Verification

| Test | Expected Result |
|------|----------------|
| `POST /api/v1/ropa/entries` with DPO token | 201 Created; entry appears in list |
| `POST /api/v1/ropa/derive` with existing `policy_id` | Draft entry pre-filled from policy JSONB |
| `POST .../publish` | Status → `active`; `audit_logs` entry written with `service_type=ROPA` |
| `GET .../validate` on incomplete entry | Returns list of missing required fields |
| `GET /api/v1/ropa/export?format=csv` | Downloadable CSV with all active entries |
| Publish a consent policy | Draft ROPA entry auto-created via `RopaDeriver` |
| CES purge run after consent withdrawal | Reads `retention_period_days` from `ropa_entries`, not app field |
| AUDITOR token on `PUT /api/v1/ropa/entries/{id}` | 403 Forbidden |
