# Access and correction requests (v0.6, part A of "Data Principal rights")

Migration `db/23_rights_requests.sql`. New service `Rights` (`/api/v1/rights`). Design: `docs/plan/access-and-correction-requests.md`.

## What it is

* **Access (s.11)** and **correction (s.12)** are rights to be **fulfilled**, so they live in `rights_requests`, not in
  `grievances` (a grievance is a complaint, for example "my access request was ignored").
* The CMS **tracks** the request, deadline, handler and outcome. It holds **no personal data values**: the DPO delivers an
  access copy through the fiduciary's own secure channel and notes how; a correction is described in words, and the DPO
  tells the affected apps. Nothing is sent to apps.
* Reference `RR-<year>-<6 digits>`; auto-assigned to the fiduciary's DPO; statuses `NEW -> IN_PROGRESS -> FULFILLED | REJECTED`
  (final states cannot change; closing needs an outcome note of 10+ characters).

## Deadlines are not assumed

`ACCESS_SLA_DAYS` and `CORRECTION_SLA_DAYS` set the deadlines. **Leave them unset until counsel has confirmed the timelines
under the Rules**: with no value a request has no deadline and is never "overdue" (the portal shows "Not set").

## API (`/api/v1/client/rights` for principals and API keys, `/api/v1/rights` for the console)

| `_func` | Who | Notes |
|---|---|---|
| `submit_rights_request` | principal, API key (names `user_id`), DPO/ADMIN on the principal's behalf | `type` ACCESS or CORRECTION, `description` |
| `get_rights_request` | the principal (own), DPO, assigned OPERATOR | the DPO's view includes `data_map` |
| `list_user_rights_requests` | principal, API key | a principal sees only their own |
| `list_rights_requests` | DPO, OPERATOR (assigned only) | filters `type`, `status`, `overdue` |
| `assign_rights_request` | DPO, ADMIN | assignee must be an active operator of the same fiduciary |
| `update_rights_request_status` | DPO, ADMIN, assigned OPERATOR | forward-only; notifies the principal on FULFILLED / REJECTED |

The fiduciary is taken from the caller's credential, never from the request body. New permission `rights:read|write|manage`
(DPO `manage`, OPERATOR `write`, AUDITOR reads through `*:read`); the migration adds it to existing databases.

## What it looks like

**Rights portal** (`web/rights/dashboard.html`)
* New tab **My Rights**: "Request a copy of my data" and "Request a correction" buttons, a short form, and a list with
  reference, type, submitted, deadline, status and outcome. A rejected or overdue row offers **Raise a complaint about this
  request**, which opens the grievance form with the right category and a subject that quotes the reference.
* The old **Requests & Grievances** tab is now **Grievances** and complaint-only (six complaint categories; no more bare
  "Right to Erasure", "Data Portability" or "Correction" options). It shows the grievance **reference number**, an optional
  **attachment**, and a **feedback** control once a grievance is resolved or closed.

**DPO console** (`web/console/dpo/rights-requests.html`, "Rights Requests" in the menu)
* List with type, status and overdue filters; a detail dialog with assignment, outcome and a read-only **data map**: the apps and
  processors that checked consent for the principal, the purposes in their latest consent, and the ROPA entries for those
  purposes.

## Also in this change

* Grievances no longer have a 7-day branch for the type `ERASURE_REQUEST`; every complaint has the default period.
* Notification types `RIGHTS_REQUEST_SUBMITTED / ASSIGNED / FULFILLED / REJECTED`, in English only for now (other languages fall
  back to English until translated); the first three can be edited under Settings.

## Not done yet

* DPO dashboard overdue count and a "Rights Requests" report export.
* OpenAPI entries and the System Integration Guide for the new functions (only the grievance `type` text was corrected).
* Correction fan-out to apps (deliberately out of scope in the plan).
