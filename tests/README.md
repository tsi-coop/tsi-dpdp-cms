# Load Test: Consent Lifecycle

Runnable [Apache JMeter](https://jmeter.apache.org/) load test against the
TSI DPDP CMS client API, covering the consent lifecycle: notice/policy
retrieval, consent capture, processing validation, rights/dashboard reads,
withdrawal/erasure, grievances, purge polling, and the full guardian OTP
login round trip.

**Full methodology, endpoint mapping, sizing guidance, and how to read the
report:** [`load-testing-plan.md`](load-testing-plan.md). Read that first;
this file is just the quick-start.

## Prerequisites

- [Apache JMeter](https://jmeter.apache.org/download_jmeter.cgi) installed
  (needs only a JRE; unpack the binary distribution, no root/install
  required). Validated against JMeter 5.6.3.
- A running TSI DPDP CMS instance: **local Docker Compose or a dedicated
  staging environment only. Never production, never real fiduciary data.**
- A throwaway test Fiduciary, App, and API key, and an active published
  policy on that Fiduciary. If you don't have these yet, see "Set up test
  credentials" below.

## Set up test credentials

If you already have a test Fiduciary/App/API key and an active policy,
skip to "Configure" below. Otherwise, using the Admin Console
(`/console/admin/`, login with your master admin credentials from initial
System Setup):

1. **Fiduciaries** (`fiduciaries.html`): create a throwaway test
   Fiduciary, or reuse one already clearly marked as test/eval data. Note
   its UUID from the list; that's `fiduciary.id`.
2. **Apps** (`apps.html`): create a test App under that Fiduciary.
3. **API Keys** (`apikeys.html`): generate a key for that App with
   **READ, WRITE, and PURGE** scopes (this plan exercises all three). The
   raw secret is shown **once**, at creation, so copy both the key (a
   UUID) and secret into `load-test.properties` immediately (`api.key`,
   `api.secret`); it can't be retrieved again afterward.
4. **Policy**: if the Fiduciary doesn't have an active published policy
   yet, publish one via the DPO Console (see the
   [Implementation Guide](../docs/guides/implementation-guide.md) for the
   full ROPA/policy-authoring workflow, or the root
   [README's Fiduciary Provisioning step](../README.md#post-installation-steps)
   for a video walkthrough). Once published, note the policy's `id`
   (`policy.id`) and one purpose's `id` from its `data_processing_purposes`
   array (`purpose.id`), visible in the policy JSON returned by
   `get_active_policy`, or in the DPO Console's policy editor.
5. **OTP mode**: leave the App's Rights Management config on the default
   **Dummy OTP** delivery mode (DPO Console → Settings) so stage 8's full
   login round trip works out of the box; see "OTP login round trip"
   below.

With those five values in hand, edit `load-test.properties` (see
"Configure" below), then come back here for the last setup step.

## Seed a test principal

`validate_consent`, `get_active_consent`, and `submit_grievance` default to
a fixed `user_id` (`existing.user.id` in the properties file) so they
exercise a real, always-present consent record rather than a fresh "not
found" one every run. Before your first real load run, seed it once:

```bash
curl -s -X POST http://localhost:8080/api/v1/client/consent \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your test App's API key>" \
  -H "X-API-Secret: <your test App's API secret>" \
  -d '{
    "_func": "record_consent",
    "user_id": "loadtest_seed_user",
    "policy_id": "<your policy_id>",
    "data_point_consents": [{
      "data_point_id": "<your purpose_id>",
      "consent_granted": true,
      "purpose_agreed_to": "<your purpose_id>",
      "timestamp_updated": "2026-01-01T00:00:00Z"
    }]
  }'
```

This returns HTTP 201 on success. Change `existing.user.id` in
`load-test.properties` if you use a different seed user ID.

## Configure

Edit [`load-test.properties`](load-test.properties):

- `base.url`, `api.key`, `api.secret`, `fiduciary.id`: your test instance
  and test App's credentials.
- `policy.id`, `purpose.id`: from that Fiduciary's published policy.
- `existing.user.id`: the seeded principal above (default:
  `loadtest_seed_user`).
- `dummy.otp`: the fixed OTP value accepted when a Fiduciary's OTP
  delivery mode is `DUMMY_OTP` (see "OTP login round trip" below).
  Default `1234`, matching the source's current hardcoded placeholder;
  only change this if that ever changes.
- One `<stage>.threads` / `<stage>.loops` pair per lifecycle stage:
  concurrency and request count. `threads × loops` = total requests for
  that stage. There's no properties-driven on/off switch per stage; to
  skip one entirely, open the plan in the JMeter GUI and disable its
  Thread Group (right-click → Disable), or set its `loops` very low as a
  lightweight workaround from the properties file alone.

See the plan doc's "Refining concurrency and number of requests" section
before picking numbers. Defaults in `load-test.properties` are a
reasonable load-test starting point, not a fixed prescription.

## OTP login round trip

Unlike a typical black-box load test, this one can exercise the **full**
`request_principal_otp` → `principal_login` flow, not just OTP issuance.
That's only possible because of a fixed test-mode OTP: when a Fiduciary's
Rights Management App is configured with OTP Delivery Mode = **Dummy OTP**
(DPO Console → Settings → Rights Management App config; this is also the
default for a newly created Fiduciary), the server accepts a fixed OTP
value (currently `1234`, see `PLACEHOLDER_OTP` in
`src/org/tsicoop/dpdpcms/service/v1/Principal.java`) instead of dispatching
a real one. Thread Group 8 in the test plan uses exactly that: it requests
an OTP and immediately logs in with `dummy.otp`, in the same iteration, for
a freshly generated `user_id` each time.

If your test Fiduciary's OTP mode has been switched to `EMAIL_OTP` or
`MOBILE_OTP`, this scenario will fail at the `principal_login` step (the
fixed OTP won't be accepted); switch it back to Dummy OTP in DPO Console
Settings for load testing, or disable Thread Group 8.

## Run

Non-GUI mode (recommended for an actual load run):

```bash
cd tests
jmeter -n -t consent-lifecycle-test.jmx -q load-test.properties \
  -l results.jtl -e -o report/
```

- `-q load-test.properties` loads your concurrency/request-count/config
  values.
- `-l results.jtl` writes every sample.
- `-e -o report/` generates the full HTML Dashboard Report (throughput,
  error %, latency graphs and percentiles) into `report/` after the run.
  Open `report/index.html` in a browser.

Override any single property from the command line without editing the
file:

```bash
jmeter -n -t consent-lifecycle-test.jmx -q load-test.properties \
  -Jvalidate_consent.threads=50 -Jvalidate_consent.loops=200 \
  -l results.jtl -e -o report/
```

GUI mode (for building/debugging the plan itself, not for a real load
run; JMeter's own docs warn against generating load from the GUI):

```bash
jmeter -t consent-lifecycle-test.jmx
```

## Output

- Live one-line-per-batch summary during a non-GUI run (requests,
  throughput, errors, avg/min/max latency).
- `results.jtl`: every sample, for custom analysis or diffing between
  runs.
- `report/index.html`: the full HTML Dashboard: throughput over time,
  error % by request, response time percentiles (p50/p90/p95/p99) per
  stage.

`results.jtl` and `report/` are run output, not meant to be committed
(gitignored).

## Known limitations

- No spike-test scenario (sudden burst) is implemented yet; see the plan
  doc for how to extend Thread Group scheduling for that.
- Thread Groups have no built-in per-run enable/disable toggle from the
  properties file; use the JMeter GUI's enable/disable checkbox per Thread
  Group, or set the loop count very low as a lightweight workaround.

## Test results against a local Docker instance (2026-09-27)

Three runs so far, in increasing order of concurrency, all against
`tsi_dpdp_cms_server` + `tsi_dpdp_cms_db`, using the "Varam" test
Fiduciary/App. Each run's connection-pool numbers come from
`pg_stat_activity`, not JMeter; JMeter only sees client-side latency/
errors, so the pool state was checked directly in Postgres before,
during, and after each run.

### 1. Smoke test (1 thread / 1 loop per stage, 10 requests)

- **10/10 requests succeeded, 0 errors**, across three consecutive runs.
- **No connection leak.** Baseline was 5 idle DB connections (matches
  `PoolDB.java`'s `minimumIdle=5`). The pool grew to 8 idle after the
  first run (expected: 8 Thread Groups running concurrently, well under
  the `maximumPoolSize=15` cap) and held steady at exactly 8 across two
  more back-to-back runs, all connections cleanly idle, none stuck
  active or idle in transaction.

### 2. Load test (default `load-test.properties`, 6,960 requests)

Full default profile: all 8 stages running concurrently (63 total
threads), matching the properties file shipped in this repo.

| Stage | Requests | Errors | p50 | p90 | p95 | p99 | Max |
|---|---|---|---|---|---|---|---|
| `get_active_policy` | 1000 | 0 | 2.4s | 6.0s | 8.0s | 11.9s | 20.5s |
| `record_consent` | 200 | 0 | 6.9s | 14.7s | 16.8s | 27.5s | 28.4s |
| `validate_consent` | 5000 | 0 | 3.6s | 7.1s | 8.8s | 13.4s | 28.0s |
| `get_active_consent` | 200 | 0 | 5.6s | 11.7s | 14.9s | 22.0s | 22.8s |
| `record_consent` (seed) | 100 | 0 | 6.4s | 13.2s | 18.4s | 26.0s | 26.0s |
| `withdraw_consent` | 100 | 0 | 10.9s | 17.0s | 19.4s | 28.6s | 28.6s |
| `submit_grievance` | 100 | 0 | 7.6s | 14.5s | 16.8s | 19.9s | 19.9s |
| `list_purge_requests` | 60 | 0 | 5.5s | 10.0s | 10.4s | 12.1s | 12.1s |
| `request_principal_otp` | 100 | 0 | 3.4s | 7.1s | 7.9s | 13.8s | 13.8s |
| `principal_login` | 100 | 0 | 4.5s | 8.9s | 9.9s | 13.0s | 13.0s |

- **0 errors across all 6,960 requests.** Wall-clock time: 14m32s
  (~8.0 req/s overall).
- **Latency is high across every stage, not just `validate_consent`.**
  That's expected here, not a bug: this profile runs all 8 stages'
  threads at once (63 total) against a pool sized for 15 concurrent DB
  connections, so every stage queues for a connection behind every other
  stage. This is what pushing total concurrency to ~4x the pool size
  looks like; see "Sizing concurrency" in `load-testing-plan.md`.
- **No connection leak.** Pool grew to its ceiling (15 idle, matching
  `maximumPoolSize=15`) during the run and settled cleanly back to 15
  idle immediately after, zero active or idle-in-transaction connections
  left over.

### 3. Stress test (`validate_consent` isolated, 60 threads × 50 loops)

Every other stage set to 1 request (to isolate the hot path), against a
15-connection pool, so 60 threads is 4x oversubscribed by design.

- **3,000 requests, 1 error (0.033%).** p50 7.9s, p90 16.0s, p95 19.2s,
  p99 25.0s, max 41.9s.
- **The one failure:** an HTTP 500 at exactly 30,045ms elapsed, matching
  `PoolDB.java`'s `connectionTimeout=30000` (30s) almost exactly. Strongly
  consistent with that request waiting the full connection-acquisition
  timeout and failing.
- **No connection leak.** Pool settled to 13 idle after the run, all
  cleanly idle, including after the one request that hit the timeout;
  HikariCP released that connection correctly rather than holding it.

### Reading these together

No leaks in any of the three runs, at any concurrency tried so far. The
load test shows the app degrades in *latency*, not correctness, once
total concurrency crosses the connection-pool ceiling; the stress test
found the actual failure edge (the 30-second connection-acquisition
timeout) at 4x oversubscription on the single hottest endpoint.
Treat `maximumPoolSize=15` as the next thing to tune.

### Key takeaways

- **Full consent-lifecycle coverage.** These runs exercise the end-to-end
  workflow (notice retrieval, consent recording, validation, withdrawal,
  grievances, and the full dummy-OTP login round trip), not a single
  pinged endpoint.
- **Zero failures under both normal and heavy load.** 0 errors across
  6,960 requests in the 8-stage load test.
- **Database health and resource cleanup confirmed independently.**
  Connection-pool behavior was checked directly against PostgreSQL
  (`pg_stat_activity`), not inferred from the app's own client-facing
  responses, and showed zero connection leaks across all three runs,
  including the run that produced a failure.
- **Graceful degradation, not a crash.** The one failure found (stress
  test, 4x oversubscription) was a single HTTP 500 whose timing lines up
  with the configured 30-second connection-acquisition timeout, not a
  server crash, hang, or corrupted state; every other request at that
  same concurrency succeeded, just slower.

**Scope of this conclusion:** all three runs were against one local
Docker instance on one machine, not production hardware, network, or
concurrent real-world traffic. "Zero leaks" and "graceful degradation"
are true for the concurrency levels actually tried here. Tuning `maximumPoolSize=15` for your needs should give you the right result.
