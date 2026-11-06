# Plan: Access (s.11) and Correction (s.12) Requests

**Status:** Proposed. Open decisions in section 10; the legal points in section 9 need counsel before the SLA defaults are set.
**Supersedes:** item 5 of the partner-feedback list ("access/correction, parked").
**Principle:** the collecting app owns the data and the CMS is the record-keeper. Keep the change as small as the need allows.

## 1. Where we are

How each right is handled today (verified against the code):

| Right | Handling today |
|---|---|
| Withdrawal | `withdraw_consent` inserts an immutable `consent_records` row (`CONSENT_WITHDRAWN`); the principal is notified and audited; apps see it via `validate_consent`. |
| Erasure | `erasure_request` inserts an `ERASURE_REQUEST` record; the CES batch (`CESService.handleErasure`) creates a `purge_requests` row per app found in `consent_validations`; apps poll or get a webhook and confirm; the DPO tracks it under Compliance. Orphan cases (no linked app) are flagged. |
| Grievance (s.13) | `grievances` table and DPO console. A complaint, resolved by the DPO. |
| **Access, correction** | **No flow.** The rights app form offers them as grievance types (`DATA_ACCESS_REQUEST`, "Data Portability Request"; `CORRECTION_REQUEST`). They are stored as plain grievances with a 30-day due date and nothing else happens. |

Two problems follow from this:

1. Access and correction are rights to be **fulfilled**, not complaints to be **resolved**. Mixing them into `grievances` mixes their reports, deadlines and lifecycle. A grievance should be what a user raises when any right, including these, is not honoured.
2. **Stray erasure option.** The grievance form also offers "Right to Erasure (Deletion)" (`web/rights/dashboard.html:817`). It stores a grievance with a 7-day due date and triggers no erasure or purge. A user who picks it instead of the erasure button on the consent card believes they asked for deletion, and nothing is enforced.

## 2. Scope

**In scope**
- A `rights_requests` table for ACCESS and CORRECTION requests, one table with a `type` column (the two share one lifecycle).
- API for the principal (submit, list, get) and for the DPO (list, get, assign, update status).
- Rights app: a "My Rights" request section.
- DPO console: a rights requests page with a read-only data-map panel for the user.
- Notifications, audit events, regression test cases, guide and release notes.
- Rework the rights app grievance form so it only raises complaints (section 6.1), which removes the stray erasure option.

**Out of scope** (see section 8)
- Correction fan-out to apps, generated access export, per-app access fulfilment, before/after correction values, moving existing grievances.

## 3. Design

### 3.1 Access: tracking only

The CMS holds consent metadata, not the fiduciary's business data. For an access request the DPO gathers the data from the business systems and delivers it **outside the CMS**, through the fiduciary's own secure channel. The CMS records the request, the deadline, who handled it, and a delivery note. The data is never stored in the CMS or attached to the request.

To help the DPO make the response complete, the request page shows a **read-only data-map panel** for that user (for both ACCESS and CORRECTION requests):
- apps and processors that validated consent for the user (`consent_validations`),
- purposes and data points consented to (latest `consent_records`),
- the ROPA entry for each purpose (what is processed, why, retention).

This is a query and a table. It gives the DPO a checklist of systems to cover and needs no export or new API beyond the get call.

### 3.2 Correction: description only, tracking only

The user describes what is wrong ("my date of birth is recorded incorrectly") in free text. **No old or new values pass through the CMS.**

- The DPO reviews the request and marks it FULFILLED or REJECTED, with a note.
- The DPO tells the affected apps through the fiduciary's usual channels, and records in the outcome note that this was done. The same data-map panel as for access (3.1) lists the apps that hold the user's data, found via `consent_validations`, so the DPO has a checklist rather than having to work it out.
- The CMS sends nothing to apps. Automatic fan-out is deferred (section 8).

### 3.3 Grievance stays a grievance

A grievance is a complaint about any right (for example "my access request was ignored"). On a rejected or overdue request the rights app offers "Raise a grievance about this request". Optionally the grievance carries a reference to the request (section 8).

## 4. Data model

New migration `db/18_rights_requests.sql`:

```sql
CREATE TABLE IF NOT EXISTS rights_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL,
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    type VARCHAR(20) NOT NULL,                 -- ACCESS, CORRECTION
    description TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'NEW', -- NEW, IN_PROGRESS, FULFILLED, REJECTED
    due_date TIMESTAMP WITH TIME ZONE,
    assigned_dpo_user_id UUID REFERENCES operators(id),
    outcome_note TEXT,                         -- delivery note (ACCESS) or outcome / reason (CORRECTION)
    submission_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolution_timestamp TIMESTAMP WITH TIME ZONE,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rights_requests_fid_ts ON rights_requests (fiduciary_id, submission_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_rights_requests_fid_user ON rights_requests (fiduciary_id, user_id, submission_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_rights_requests_pending ON rights_requests (status, due_date ASC);
```

Additive and idempotent; no change to existing tables. Follow the repo's migration conventions (`db/` numbering, upgrade note in the release notes).

## 5. API

Mirror `Grievance.java`: RPC style, `_func`-dispatched, same role checks (operators see only assigned requests, DPOs only their own fiduciary, principals only their own `user_id`). A new service class `RightsRequest` unless the pattern argues for adding to `Consent`.

| `_func` | Caller | Scope | Notes |
|---|---|---|---|
| `submit_rights_request` | principal or app | WRITE | `type` (ACCESS or CORRECTION), `description`. Sets `due_date` from a per-type SLA. |
| `get_rights_request` | principal, DPO | READ | Principal: own only. DPO: includes the data-map panel. |
| `list_user_rights_requests` | principal, app | READ | |
| `list_rights_requests` | DPO console | | Filters: type, status, overdue. |
| `assign_rights_request` | DPO | | Same rules as `assign_grievance`. |
| `update_rights_request_status` | DPO | | `status`, `outcome_note`. Tracking only; sends nothing to apps. |

Also update `docs/api/openapi.yaml`, `docs/api/index.html` and the System Integration Guide for the client-reachable functions.

Constants (`Constants.java`): add `RIGHTS_ACCESS`, `RIGHTS_CORRECTION`, status values, SLA days (`ACCESS_SLA_DAYS`, `CORRECTION_SLA_DAYS`, set after section 9), notification types `RIGHTS_REQUEST_SUBMITTED_NOTIFICATION`, `RIGHTS_REQUEST_FULFILLED_NOTIFICATION`, `RIGHTS_REQUEST_REJECTED_NOTIFICATION`. `ACTION_CORRECTION_REQUEST` already exists; reuse it for the submit audit event if it fits.

## 6. UI

**Rights app (`web/rights/dashboard.html`)**
- New "My Rights" section: "Request a copy of my data" and "Request a correction", a short description box, a list of past requests with status and deadline.
- On REJECTED or overdue rows: "Raise a grievance about this request", which opens the grievance form.
- Label ACCESS as "Request a copy of my data", not "Data Portability".
- Grievance form: see 6.1.

### 6.1 Grievance form cleanup (ships with this release)

Today the dropdown (`web/rights/dashboard.html:816-819`) mixes complaints with requests: "General Inquiry" (`GENERAL_COMPLAINT`), "Right to Erasure" (`ERASURE_REQUEST`, triggers nothing), "Data Portability Request" (`DATA_ACCESS_REQUEST`) and "Correction Request" (`CORRECTION_REQUEST`). The form, tab and button are all titled "Request". It ships **together with** `rights_requests`, so users never lose the ability to ask for access or correction.

The form becomes complaint-only, with a one-line helper above the dropdown:

> *Use this form to raise a complaint. To withdraw consent or request erasure, use your Consent history. To request a copy of your data or a correction, use My Rights.*

| Label | Stored value |
|---|---|
| My consent or withdrawal was not honoured | `CONSENT_COMPLAINT` |
| My erasure request was not completed | `ERASURE_COMPLAINT` |
| My request for a copy of my data was not fulfilled | `ACCESS_COMPLAINT` |
| My correction request was not fulfilled | `CORRECTION_COMPLAINT` |
| Misuse of my personal data | `DATA_MISUSE_COMPLAINT` |
| Other complaint | `GENERAL_COMPLAINT` |

Also rename: form "Raise a Complaint", button "+ New Complaint", tab "Grievances".

Related changes:
- **SLA special case.** Remove the `ERASURE_REQUEST` 7-day branch and `ERASURE_SLA_DAYS` from `Grievance.calculateDueDate`; an erasure complaint is not an erasure request, so all complaints use the default. Existing rows keep their due dates.
- **Docs and examples** that use the old values: `web/tour/json/submit_grievance.json` (`ERASURE_REQUEST`), the `type` description and 7-day note in `docs/api/openapi.yaml`, and a check of the guides. The grievance lifecycle script uses `GENERAL_COMPLAINT`, which stays valid.
- **Existing rows** typed `ERASURE_REQUEST`, `DATA_ACCESS_REQUEST` or `CORRECTION_REQUEST` are left as they are; the DPO console prints the type with underscores replaced, so they still display. Same as decision 2 in section 10.
- **Server validation.** The server keeps storing any `type` string, so integrators posting other values do not break. The documented list is the contract.
- **DPO console.** `grievances.html` shows the type as text, so the new labels need no code change. A type filter is optional.

### 6.2 DPO console
- New page `web/console/dpo/rights-requests.html`, modelled on `grievances.html` and added to the nav: list with type, status and overdue filters; detail dialog with assign, status update, outcome note; data-map panel.
- Dashboard: overdue rights requests alongside overdue grievances, visibility only, no push (consistent with the DPO notification decision).
- Reports: add "Rights Requests" as an export option next to the existing Grievance Log.

## 7. Notifications, audit, compliance

- **Principal notifications:** submitted, fulfilled, rejected (in-app, plus webhook category `NOTIFICATION` as other notifications do).
- **Audit events:** `RIGHTS_REQUEST_SUBMITTED`, `RIGHTS_REQUEST_ASSIGNED`, `RIGHTS_REQUEST_STATUS_UPDATED` (with outcome note), on the existing audit ledger.
- **Legal evidence:** consider including rights requests in the per-principal evidence certificate; decide after the base feature.

## 8. Deliberately not in this release

- **Generated access export** (consent history, processors, ROPA as a file). Add if DPOs ask; the data-map panel covers the checklist need.
- **Correction fan-out to apps.** On a fulfilled correction, notify the apps found via `consent_validations` over the v0.5.4 webhook delivery table (retry, tracking, manual retry) plus an in-app notification, with an orphan compliance event when no app is linked, as erasure does. The event would carry the request id and user id only, no values. Add if partners find the DPO's manual step painful; the data-map panel and `rights_requests` need no redesign for it.
- **Per-app access fulfilment** (fan-out like purge, each app confirming delivery). Same machinery as correction fan-out, can be added later without redesign.
- **Before/after correction values.** The CMS does not carry personal data values.
- **Migrating existing `DATA_ACCESS_REQUEST` / `CORRECTION_REQUEST` grievances.** They remain as grievances; the DPO console keeps showing them. A one-off copy is possible later if wanted.
- **Linking grievances to requests** (`related_request_ref` on `grievances`). One nullable column; add when a DPO needs the trace.
- **Moving erasure or withdrawal.** They already have purpose-built flows.
- **Server-side validation of grievance `type`.** Stays lenient (6.1).

## 9. Legal points to confirm with counsel before release

1. The required content of an access response under s.11 (summary of personal data and processing, identities of those it was shared with, and so on). This decides whether the data-map panel is enough or the generated export is needed.
2. Response timelines under the current Rules for access and correction. **Do not set `ACCESS_SLA_DAYS` or `CORRECTION_SLA_DAYS` until this is checked.**
3. Whether the OTP login of the rights app satisfies identity verification of the requester.
4. Whether a corrected record needs any CMS-side retention of the request itself, and for how long.

## 10. Open decisions

Answered in discussion: one table for both types (not two), a separate table from grievances, option A (tracking) for access, description-only for correction, complaint-only grievance form shipped with this release. Still open:

1. SLA days for access and correction (section 9, item 2).
2. Existing `DATA_ACCESS_REQUEST` / `CORRECTION_REQUEST` grievances: leave as grievances (proposed) or migrate.
3. Grievance form cleanup (6.1): **agreed**, ships in this release with `rights_requests`, not earlier. Confirm no partner relies on the old type values or the 7-day erasure SLA before removing it.
4. New service class vs adding to `Consent`: proposed new class.
5. Include rights requests in the legal evidence certificate: proposed later.

## 11. Delivery plan

| Step | Work | Size |
|---|---|---|
| 1 | `db/18` migration, constants, `RightsRequest` service (submit, get, list, assign, update status), audit and notifications | M |
| 2 | Rights app "My Rights" section; grievance form rework (6.1), SLA branch removal, docs and example updates | S |
| 3 | DPO console page, data-map panel, dashboard overdue count, report export | M |
| 4 | OpenAPI and guide updates, regression test cases, release notes, upgrade steps | S |

Steps 1 to 3 deliver tracking for both types and are the release; step 4 completes it. Correction fan-out is a later addition (section 8).

## 12. Test cases to add

Add to `docs/test-cases/regression-test-cases.md`:
- Principal submits ACCESS and CORRECTION; due date set per SLA; cannot read another user's request.
- DPO sees only own fiduciary's requests; operator sees only assigned ones; non-DPO cannot update status.
- Status transitions: NEW to IN_PROGRESS to FULFILLED / REJECTED; invalid transitions refused; outcome note required on REJECTED.
- Fulfilling a CORRECTION sends nothing to apps (no webhook, no app notification); the principal is still notified.
- No old or new values are stored or transmitted.
- Data-map panel lists the right apps, purposes and ROPA entries for the user, on both ACCESS and CORRECTION requests.
- Grievance form offers only the six complaint options, shows the helper text, and the form, button and tab are titled as complaints; "Raise a grievance about this request" opens the form.
- Complaint types use the default SLA (no 7-day branch); old rows keep their due dates and still display in the DPO console.
- `submit_grievance` still accepts an arbitrary `type` string.
- Overdue requests show on the DPO dashboard; no push notification is sent.
- Migration is idempotent on an existing database.
