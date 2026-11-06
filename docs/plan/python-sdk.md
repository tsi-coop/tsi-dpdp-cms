# Plan: Python SDK (`tsi-dpdp`)

**Status:** Proposed. Working name; open decisions in section 12.
**Based on:** `docs/api/openapi.yaml`, the webhook and polling guides, and [`integrations-roadmap.md`](integrations-roadmap.md).

## 1. Shape of the problem

- **The API is RPC-style.** Every call is a `POST` to one of five paths (`/policy`, `/consent`, `/grievance`, `/notification`, `/compliance`). The `_func` field in the body selects the operation. That covers 19 client functions, scoped READ, WRITE or PURGE.
- **Generated clients will be poor.** The spec itself warns that tooling struggles with the `oneOf` on `_func`. Hand-write a thin client and keep the models typed.
- **Three kinds of caller.**
  - Backend services that record or validate consent. They authenticate with `X-API-Key` and `X-API-Secret`.
  - Webhook and polling consumers for notifications and purge. Purge is API-key only.
  - Rights-portal flows that use a principal JWT. These are less common for a Python team, so they go in Phase 3.
- **The SDK is server-side only.** The secret must never reach a browser. The package docs say so up front.

## 2. Principles

1. **Python teams should have little to learn.** Use `httpx`, `pydantic` v2, and type hints throughout. Sync and async clients share one core.
2. **Hide `_func`.** Expose methods like `client.consent.validate(...)`, not `post("/consent", {"_func": ...})`.
3. **Fail closed by default.** If the CMS is unreachable, `validate()` raises or returns "not consented". It never silently returns `True`.
4. **Make the safe thing the easy thing.** The SDK ships a webhook verifier that checks the signature on the raw body and de-duplicates on `delivery_id`, and a purge-handler loop. These are the parts partners get wrong.
5. **A thin core with optional extras.** `pip install tsi-dpdp` brings only `httpx` and `pydantic`. Framework adapters are extras: `tsi-dpdp[fastapi]`, `[django]`, `[flask]`.

## 3. Package layout

```
tsi_dpdp/
  __init__.py          # Client, AsyncClient, errors
  client.py            # transport, auth, retries, error mapping
  config.py            # from_env(): CMS_BASE_URL, CMS_API_KEY, CMS_API_SECRET
  resources/
    policy.py          # list_active, get, get_active
    consent.py         # record, record_parent, get_active, history, details,
                       # link_user, validate, withdraw, request_erasure
    grievance.py       # submit, get, list_for_user
    notification.py    # list, mark_read
    compliance.py      # list_purge_requests, update_purge_status
  models/              # pydantic: Policy, DataPointConsent, ConsentRecord, ...
  errors.py
  webhooks.py          # verify(), parse_event(), typed events
  workers.py           # PurgeWorker, NotificationPoller
  ext/                 # fastapi.py, django.py, flask.py
  testing.py           # FakeCMS / pytest plugin
  py.typed
```

## 4. Core API

```python
from tsi_dpdp import Client

cms = Client.from_env()          # or Client(base_url=..., api_key=..., api_secret=...)

policy = cms.policy.get_active(fiduciary_id="f1", jurisdiction="IN")

rec = cms.consent.record(
    user_id="u_123",             # your stable account id, not email
    policy_id=policy.id,
    data_point_consents={"marketing_email": True, "analytics": False},
)

# The enforcement point. Gate sends and processing on this.
if cms.consent.validate(user_id="u_123", purpose_id="marketing_email"):
    send_campaign()

cms.consent.withdraw(user_id="u_123", purpose_ids=["marketing_email"])
cms.consent.link_user(anonymous_user_id="anon_x", authenticated_user_id="u_123")
```

`AsyncClient` has the same surface (`await acms.consent.validate(...)`). Generate the sync client from the async one, or share a request-building and response-parsing layer, so the two never drift.

**Return types.**
- Reads return pydantic models. `validate()` returns a small `Validation` object that is truthy when consent is valid.
- `Validation` also carries `reason` and `policy_version`, so callers can log why a check failed.

## 5. Transport and reliability

- **Auth:** the client injects `X-API-Key` and `X-API-Secret`. It redacts both from logs and `repr`.
- **Timeouts:** 10 seconds by default, configurable.
- **Retries:** exponential backoff with jitter on connection errors, 502, 503 and 504. By default retry only idempotent operations (all reads, `validate`, `link_user`). Writes like `record` and `submit_grievance` are not retried (see open decision 2).
- **Connection pooling:** one `httpx.Client` per `Client`. Support context-manager use.
- **Observability:** standard `logging` under the `tsi_dpdp` logger. Optional OpenTelemetry spans if the package is installed.
- **Caching:** an opt-in short-TTL cache for `policy.get_active` only. Never cache `validate`, because withdrawal must take effect immediately.

## 6. Errors

The OpenAPI file documents two 400 shapes, 401, 403, 404, 5xx, and a few function-specific cases. The SDK maps them as follows.

```
TsiError
 ├─ ConnectionError / TimeoutError
 ├─ AuthError (401: bad key, or missing scope)
 ├─ PermissionError (403: for example principal JWT sub mismatch)
 ├─ NotFoundError (404)
 ├─ ValidationError (400: .fields lists the offending fields, both envelope shapes)
 └─ ServerError (5xx)
```

Every error carries `status`, `func`, and the server message. The raw response is available for debugging. The SDK also corrects the two known cases where the server's 400 message names the wrong field, so users aren't misled.

## 7. Inbound: webhooks and polling

The CMS signs the raw body with HMAC-SHA256 in `X-TSI-Signature`. Delivery is at-least-once, so receivers must verify and de-duplicate.

```python
from tsi_dpdp.webhooks import WebhookReceiver

hooks = WebhookReceiver(secret=os.environ["WEBHOOK_SECRET"], dedupe=RedisDedupe(r))

@hooks.on("notification_created")
def handle(evt):                      # evt is a typed model
    if evt.data.notification_type == "WITHDRAWAL_ACKNOWLEDGMENT":
        crm.suppress(evt.data.user_id)
```

- **Verification:** `verify()` is constant-time and works on raw bytes.
- **De-duplication:** a `DedupeStore` protocol with in-memory, Redis and SQLAlchemy implementations.
- **Adapters:** the extras mount the receiver as a FastAPI router, a Django view, or a Flask blueprint. They answer 2xx immediately and hand the work off.
- **Polling safety net:** `NotificationPoller` and `PurgeWorker` run a reconcile loop with `list_notifications` or `list_purge_requests`. Polling is the source of truth and webhooks only add latency.
- **Purge:** `PurgeWorker(handler=my_purge_fn)` polls, calls your function, then calls `update_purge_status`. It supports the legal-hold and cancel statuses.

## 8. Framework helpers

```python
# FastAPI
from tsi_dpdp.ext.fastapi import require_consent

@app.post("/send-offer")
def send(user=Depends(current_user), _=Depends(require_consent("marketing_email"))): ...
```

- **`require_consent(purpose)`:** a dependency or decorator that returns 403 when consent is missing. It fails closed.
- **Consent proxy router:** a ready-made version of `examples/integration/website-consent/proxy/server.py`. It whitelists fields and takes the `user_id` from your session, never from the browser. It accepts only `anon_*` ids from anonymous visitors. Call `link_user` once at login.

This helper serves any Python backend that fronts the banner. A TypeScript SDK would give the same for Next.js and similar (roadmap 4.3 and example 5.3).

## 9. Testing support

- **`tsi_dpdp.testing.FakeCMS`:** an in-memory implementation of the same interface, exposed as a pytest fixture. Teams can unit-test consent gates without a running CMS.
- **Conformance scenarios (language-neutral):** the scenarios are plain data files (JSON or YAML), not Python tests, so every later SDK reuses them with a small runner. Python is the first runner. They run against a docker-compose CMS using the existing lifecycle scripts (consent, grievance, purge) and cover the awkward cases (409 on a stale policy version, 401 for a missing scope, an unlinked `anon_` id). See roadmap 4.2.
- **Behaviour notes:** a short document of the choices the spec does not capture (no write retries, 409 handling, error mapping, the `/compliance` authorization gap), written during Phase 1 and followed by later SDKs.
- **Drift guard:** a CI check (reusable for other SDKs) compares the function list in `openapi.yaml` against the SDK's methods and fails if they diverge.

## 10. Packaging and versioning

- Python 3.9 or later, `py.typed`, wheels on PyPI, Apache-2.0 to match the repo.
- The SDK uses its own semver. A compatibility table maps SDK versions to supported CMS versions, because the server is at 0.5.x and the API is declared `1.0.0`.
- Location: a new `sdk/python/` directory in this repo to start with. Move it out if partners need an independent release cadence. This ties into the roadmap's open question about who owns SDKs and where they live (roadmap section 8).
- Docs: a Python quickstart guide in `docs/guides/`, plus a generated API reference.

## 11. Phasing

| Phase | Scope | Size |
|---|---|---|
| 1 | Sync and async client, consent, policy and grievance resources, errors, retries, `FakeCMS`, **language-neutral conformance scenarios and behaviour notes** | M |
| 2 | Webhook receiver, `NotificationPoller`, `PurgeWorker`, FastAPI, Django and Flask extras, consent proxy router | M |
| 3 | Principal JWT support (rights flows), OpenTelemetry, caching, CLI (`tsi-dpdp validate ...`) | S |

## 12. Open decisions

1. **Depend on pydantic?** Recommended: yes, v2 only. It gives typed models and validation, at the cost of one dependency. A dataclass-only core is possible if zero dependencies beyond `httpx` is preferred.
2. **Idempotency on writes.** Retrying `record_consent` could create duplicate records. Either the SDK never retries writes, or the server gains an idempotency key. Recommended: no write retries for v1, a server change later.
3. **Site key (roadmap 3.1).** If it ships, a small restricted-client variant (`get_policy` and constrained `record_consent`) would belong in this SDK. Defer until that decision is made.
4. **Repo home and ownership.** In-repo `sdk/python/` is the simplest start.
5. **Authorization gap in `/compliance`.** The spec notes that any PURGE-scoped key can update any purge request, as far as the source verifies. The SDK cannot fix that, so the docs should say so.
