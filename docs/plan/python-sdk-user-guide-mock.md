# Python SDK User Guide (MOCK)

> **This is a mock.** The SDK does not exist yet. This guide shows what the developer experience would be if the design in [`python-sdk.md`](python-sdk.md) is built as written. Package name, method names and signatures are proposals. Use it to review the design from a user's point of view, and replace it with the real guide once Phase 1 ships.

**Applies to:** `tsi-dpdp` 0.1 (proposed), TSI DPDP CMS v0.5.4+
**Python:** 3.9 or later

---

## 1. Overview

`tsi-dpdp` is a server-side Python client for the TSI DPDP CMS client API. It lets your backend:

- fetch the published consent policy,
- record, validate, withdraw and link consent,
- submit and look up grievances,
- receive notifications by webhook or polling,
- handle purge requests.

**Run it only on your server.** It uses your App API key and secret, which must never reach a browser or mobile app. For web front ends, use the consent proxy in section 9.

## 2. Install

```bash
pip install tsi-dpdp                 # core: httpx + pydantic
pip install "tsi-dpdp[fastapi]"      # adds FastAPI helpers
pip install "tsi-dpdp[django]"       # adds Django views
pip install "tsi-dpdp[flask]"        # adds Flask blueprint
```

## 3. Quick start: record and check consent in 5 steps

**Step 1: Get credentials.** An ADMIN console user creates an App and issues an API key and secret. Give the key `READ` and `WRITE` scopes. Add `PURGE` only for the service that handles purge requests.

**Step 2: Set the environment.**

```bash
export CMS_BASE_URL=https://cms.example.com
export CMS_API_KEY=...
export CMS_API_SECRET=...
```

**Step 3: Create a client.**

```python
from tsi_dpdp import Client

cms = Client.from_env()
```

**Step 4: Record consent.**

```python
policy = cms.policy.get_active(fiduciary_id="f1", jurisdiction="IN")

record = cms.consent.record(
    user_id="u_123",
    policy_id=policy.id,
    data_point_consents={"marketing_email": True, "analytics": False},
)
print(record.record_id)
```

**Step 5: Check before you act.**

```python
if cms.consent.validate(user_id="u_123", purpose_id="marketing_email"):
    send_campaign("u_123")
```

That is the whole core loop: record consent where you collect it, validate where you use the data.

## 4. Concepts you need

| Term | Meaning |
|---|---|
| **Fiduciary** | The organisation that owns the data. Your API key resolves to one fiduciary, so you rarely pass its id. |
| **Policy** | The published, multilingual notice. Each has an id and a version. |
| **Purpose / data point** | One thing a user can consent to, for example `marketing_email`. |
| **`user_id`** | Your stable account id. Use your database id, **not the email address**, and use the same id everywhere. |
| **Anonymous id** | `anon_<token>` for visitors who are not logged in. Link it to the account at login (section 6). |

## 5. Configuration

```python
from tsi_dpdp import Client

cms = Client(
    base_url="https://cms.example.com",
    api_key="...",
    api_secret="...",
    timeout=10.0,          # seconds, default 10
    max_retries=2,         # reads only; see section 11
)
```

- `Client.from_env()` reads `CMS_BASE_URL`, `CMS_API_KEY`, `CMS_API_SECRET`.
- Use `with Client.from_env() as cms:` to close the connection pool cleanly.
- The key and secret are masked in `repr()` and logs.

### Async

`AsyncClient` has the same methods. Add `await`.

```python
from tsi_dpdp import AsyncClient

async with AsyncClient.from_env() as cms:
    ok = await cms.consent.validate(user_id="u_123", purpose_id="marketing_email")
```

## 6. Consent

### Record

```python
cms.consent.record(
    user_id="u_123",
    policy_id="pol_42",
    data_point_consents={"marketing_email": True, "sms": False},
)
```

### Validate

```python
result = cms.consent.validate(user_id="u_123", purpose_id="marketing_email")

if result:                      # truthy when consent is valid
    ...
else:
    log.info("blocked: %s (policy v%s)", result.reason, result.policy_version)
```

`validate` **fails closed**. If the CMS cannot be reached, it raises `ConnectionError` or `TimeoutError`. It never returns a false "yes". Decide in your code what happens on an exception, and make the default "do not send".

### Withdraw and erase

```python
cms.consent.withdraw(user_id="u_123", purpose_ids=["marketing_email"])
cms.consent.request_erasure(user_id="u_123")
```

### Read

```python
cms.consent.get_active(user_id="u_123")
cms.consent.history(user_id="u_123")
cms.consent.details(record_id="rec_9")
```

### Link an anonymous visitor to an account

Call this once at login, with the anon id your front end sent and the account id from your session.

```python
cms.consent.link_user(anonymous_user_id="anon_x8Kq2...", authenticated_user_id="u_123")
```

### Parental consent

```python
cms.consent.record_parent(...)   # see the Parental Consent Guide for the fields
```

## 7. Policy

```python
cms.policy.list_active(fiduciary_id="f1")
cms.policy.get(policy_id="pol_42")
cms.policy.get_active(fiduciary_id="f1", jurisdiction="IN")
```

Policy lookups are the only calls you may cache. Pass `cache_ttl=60` to `Client` to enable a short cache for `get_active`. Consent checks are never cached.

## 8. Grievances

```python
g = cms.grievance.submit(
    user_id="u_123",
    fiduciary_id="f1",
    type="ACCESS",
    subject="Copy of my data",
    description="Please send a copy of the data you hold about me.",
)

cms.grievance.get(grievance_id=g.id)
cms.grievance.list_for_user(fiduciary_id="f1", user_id="u_123")
```

## 9. Web sites and apps: the consent proxy

Browsers must not hold the secret. Mount the ready-made proxy in your backend instead. It exposes two narrow endpoints and takes the user id from **your** session, never from the browser.

```python
from fastapi import FastAPI
from tsi_dpdp.ext.fastapi import consent_router

app = FastAPI()
app.include_router(
    consent_router(
        cms,
        policy_id="pol_42",
        session_user=lambda request: request.state.user_id,  # your auth; None if anonymous
    ),
    prefix="/consent-api",
)
```

What it does:

- `GET /consent-api/policy` returns the configured policy.
- `POST /consent-api/consent` records consent. Only whitelisted fields pass through.
- Logged-in visitor: `user_id` comes from your session. If the browser also sent its `anon_` id, the proxy links it to the account.
- Anonymous visitor: the browser id is accepted only if it matches `anon_<token>`.

### Gate an endpoint on consent

```python
from fastapi import Depends
from tsi_dpdp.ext.fastapi import require_consent

@app.post("/send-offer")
def send_offer(
    user=Depends(current_user),
    _=Depends(require_consent("marketing_email")),   # 403 if not consented
):
    ...
```

Django and Flask equivalents live in `tsi_dpdp.ext.django` and `tsi_dpdp.ext.flask`.

## 10. Receiving events

The CMS pushes events by webhook (at-least-once, with retries) and also supports polling. **Polling is the source of truth.** Use webhooks for speed and polling as a safety net.

### Webhooks

```python
import os
from fastapi import FastAPI
from tsi_dpdp.webhooks import WebhookReceiver
from tsi_dpdp.webhooks.dedupe import RedisDedupe
from tsi_dpdp.ext.fastapi import webhook_router

hooks = WebhookReceiver(
    secret=os.environ["WEBHOOK_SECRET"],
    dedupe=RedisDedupe(redis_client),       # in-memory store is for development only
)

@hooks.on("notification_created")
def on_notification(evt):
    if evt.data.notification_type == "WITHDRAWAL_ACKNOWLEDGMENT":
        crm.suppress(evt.data.user_id)

app = FastAPI()
app.include_router(webhook_router(hooks), prefix="/hooks/tsi")
```

The receiver does the three things every receiver must do:

1. Verifies the HMAC-SHA256 signature on the **raw body** (constant-time).
2. De-duplicates on `delivery_id`, because retries re-send the same event.
3. Answers `2xx` immediately and runs your handler after. The CMS waits at most 10 seconds.

A bad signature returns `401`. Register the URL and the same secret in the DPO console under Settings, Webhooks. The CMS accepts only public `https://` URLs.

### Polling notifications

```python
from tsi_dpdp.workers import NotificationPoller

poller = NotificationPoller(cms, interval=60)

@poller.on_notification
def handle(n):
    ...

poller.run()          # blocks; use poller.run_async() under asyncio
```

### Purge requests

Requires an API key with the `PURGE` scope. Principal tokens are rejected.

```python
from tsi_dpdp.workers import PurgeWorker

def purge(request) -> str:
    delete_everything_for(request.user_id)
    return "COMPLETED"          # or "ON_HOLD" for a legal hold

PurgeWorker(cms, fiduciary_id="f1", handler=purge, interval=300).run()
```

The worker polls `list_purge_requests`, calls your handler, then calls `update_purge_status` with the result. If your handler raises, the request is left unchanged and retried on the next poll.

## 11. Errors and retries

```python
from tsi_dpdp.errors import AuthError, ValidationError, NotFoundError, TsiError

try:
    cms.consent.record(...)
except ValidationError as e:
    print(e.fields)          # which fields were rejected
except AuthError:
    ...                      # bad key, or key lacks the needed scope
except TsiError as e:
    log.error("%s %s %s", e.status, e.func, e)
```

| Exception | When |
|---|---|
| `ConnectionError`, `TimeoutError` | Network problem or no reply in time |
| `AuthError` | 401: invalid key or secret, or missing scope |
| `PermissionError` | 403: for example a principal token's subject does not match `user_id` |
| `NotFoundError` | 404 |
| `ValidationError` | 400: missing or invalid fields (`.fields` lists them) |
| `ServerError` | 5xx |

**Retries:** reads, `validate` and `link_user` are retried with backoff on connection errors and 502/503/504. **Writes such as `record` and `submit` are not retried**, to avoid duplicate records. If you retry them yourself, check `consent.history` first.

## 12. Testing your code

Use the built-in fake. No running CMS needed.

```python
# conftest.py
pytest_plugins = ["tsi_dpdp.testing"]
```

```python
def test_blocks_send_without_consent(fake_cms):
    fake_cms.consent.record(user_id="u1", policy_id="p", data_point_consents={"marketing_email": False})
    assert not fake_cms.consent.validate(user_id="u1", purpose_id="marketing_email")

def test_withdrawal_takes_effect(fake_cms):
    fake_cms.consent.record(user_id="u1", policy_id="p", data_point_consents={"marketing_email": True})
    fake_cms.consent.withdraw(user_id="u1", purpose_ids=["marketing_email"])
    assert not fake_cms.consent.validate(user_id="u1", purpose_id="marketing_email")
```

Inject `fake_cms` wherever your code takes a client. For end-to-end checks, point a real `Client` at a local CMS from the [Local Development Guide](../guides/local-development-guide.md).

## 13. Rules that keep you compliant

- Keep the API key and secret on the server. Never in front-end code, mobile apps or logs.
- The server decides the `user_id`. The browser may only supply an `anon_` id.
- Use your stable account id, not email, and use the same id in `record` and `validate`.
- **Fail closed.** If you cannot confirm consent, do not send or process.
- Re-prompt users when the policy version changes.
- Make withdrawal as easy as granting.
- Do not cache `validate` results.

## 14. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `AuthError` on every call | Wrong key or secret, or wrong `CMS_BASE_URL` |
| `AuthError` only on purge calls | Key lacks the `PURGE` scope |
| `PermissionError` with a principal token | `user_id` does not match the token's subject |
| `ValidationError` with an odd field name | A few server messages name the wrong field; check `.fields` against the method signature |
| Webhook returns `401` | Secret mismatch, or you verified a re-serialised body instead of the raw bytes |
| Webhook shows Retrying in the console | Your endpoint is slow or non-2xx; the CMS waits at most 10 seconds |
| Webhook never arrives locally | The CMS rejects `localhost`, private addresses and plain `http://`; use a public `https://` URL or a tunnel |
| Same event handled twice | Using the in-memory dedupe store across several processes; use Redis or SQL |

## 15. What is not in this mock

- The exact fields of every model. They will follow `docs/api/openapi.yaml`.
- Principal-token flows for rights-portal features (planned for Phase 3).
- A generated API reference.
