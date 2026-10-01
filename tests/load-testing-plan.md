# Load Testing Plan: Consent Lifecycle

**Purpose:** Give a repeatable, tunable way to measure throughput, error
rate, and latency across the real consent-lifecycle API stages, and to
verify that rate-limiting fixes actually hold under concurrent load, not
just a single-request test.

This plan also works as a general production-readiness check, independent
of any specific fix it's used to verify.

**Where to run this:** local Docker Compose or a dedicated staging
instance only. **Never production**, and never against real fiduciary
data. Provision a throwaway test Fiduciary + App (with its own API
key/secret) before running any of this.

---

## 1. Endpoints covered, mapped to the actual consent lifecycle

Pulled directly from `docs/guides/system-integration-guide.md` and the
service source, not invented:

| Stage | `_func` | Endpoint | Scope | Notes |
|---|---|---|---|---|
| 1. Notice / Policy retrieval | `get_active_policy` | `POST /api/v1/client/policy` | READ | Called on every notice render; high frequency |
| 2. Consent capture | `record_consent` | `POST /api/v1/client/consent` | WRITE | One write per grant/update |
| 3. Processing validation | `validate_consent` | `POST /api/v1/client/consent` | READ | **Hottest path.** Called before every processing action by every integrated App, not just once at collection time |
| 4. Rights / dashboard | `get_active_consent` | `POST /api/v1/client/consent` | READ | Principal-facing dashboard reads |
| 5. Withdrawal / erasure | `record_consent` (seed), `withdraw_consent` | `POST /api/v1/client/consent` | WRITE | Seeds a fresh consent record then withdraws it, so the withdrawal path always has something real to act on |
| 6. Grievances | `submit_grievance` | `POST /api/v1/client/grievance` | WRITE | Returns HTTP 201 on success (confirmed in `Grievance.java`), not 200 |
| 7. Purge lifecycle (async) | `list_purge_requests` | `POST /api/v1/client/compliance` | PURGE | Batch-driven; polling load is steady-background, not request-driven |
| 8. Guardian/OTP login (Section 9) | `request_principal_otp`, `principal_login` | `POST /api/v1/public/principal` | **None** | **No API key/secret required for either call** (confirmed from source, `Principal.java`, and by running this plan against a live instance: `/client/principal` returns 403 for these functions, `/public/principal` is the correct path per `InterceptingFilter.PUBLIC_ALLOWED_FUNCS`). This pair is the endpoint the rate-limiting gap flags as unrated-limited; load-testing it is the direct verification path for that fix |

**On the fixed OTP that makes stage 8's full round trip possible:** when a
Fiduciary's Rights Management App has OTP Delivery Mode set to **Dummy
OTP** in DPO Console → Settings (the default for a newly created
Fiduciary), the server accepts a fixed placeholder value instead of
dispatching a real OTP over SMS/email/voice. That value is `1234`,
hardcoded as `PLACEHOLDER_OTP` in
`src/org/tsicoop/dpdpcms/service/v1/Principal.java`. Because that value is fixed and known, the test plan can
script the **full** `request_principal_otp` → `principal_login` flow, not
just issuance, something a real OTP delivery flow normally rules out for
automated load testing.

If your test Fiduciary's OTP mode has been switched to `EMAIL_OTP` or
`MOBILE_OTP`, stage 8 will fail at `principal_login` (the fixed OTP won't
be accepted there); switch it back to Dummy OTP for load testing, or
disable that stage.

**Excluded:** `POST /api/v1/bootstrap/setup`, a documented one-time setup
action (see `docs/security-fixes/2.md`), not a repeatable target.

---

## 2. Tooling

**Apache JMeter** (Apache-2.0), matching this project's own license. 

What JMeter provides, mapped to this doc's requirements:
- Concurrency and request count per stage, set via a `.properties` file
  or `-J` command-line overrides, with no code edits needed to change load
  shape (see §4).
- Throughput, error rate, and latency percentiles (p50/p90/p95/p99) via
  the built-in HTML Dashboard Report (`-e -o report/` on the command
  line), and every individual sample in a `.jtl` file for custom analysis.
- Runs standalone from a downloaded binary distribution; only needs a JRE,
  no root/install required.

Install: download the binary `.tgz`/`.zip` from
[jmeter.apache.org](https://jmeter.apache.org/download_jmeter.cgi),
unpack, run `bin/jmeter`. This plan was built and validated against
JMeter 5.6.3.

---

## 3. Refining "concurrency and number of requests": industry-standard framing

A single flat "N users, M requests" number isn't how load testing is
normally scoped. Refined into the standard test-type taxonomy, applied to
this system's actual constraints:

| Test type | Purpose | Suggested shape here |
|---|---|---|
| **Smoke** | Sanity check the plan and environment work at all | 1 thread, 1 loop per stage |
| **Load** | Model expected real-world peak, sustained | See §4 defaults below |
| **Stress** | Find the breaking point | Ramp `validate_consent` threads up in steps (e.g. 20, 50, 100, 200) until error rate or p95 latency crosses threshold |
| **Soak / endurance** | Catch leaks and resource exhaustion (connection pool, memory) that only show up over time | Moderate threads (e.g. 10) with a very high loop count, run for hours, on `validate_consent` |
| **Spike** | Sudden burst, e.g. simulating the bulk CSV breach-notification path | Not built into v1 plan; needs JMeter's Ultimate Thread Group or Synchronizing Timer to shape a sudden burst. Noted as a follow-on, not implemented here to avoid overbuilding beyond what was asked |

**Run smoke, then load, then stress, then soak, in that order.** Don't
jump straight to a large concurrency number; each earlier stage validates
the plan and environment are sound before you trust a bigger number's
results.

### Sizing concurrency against a real constraint, not a round number

`PoolDB.java` sets `HikariCP` `maximumPoolSize = 15`, `minimumIdle = 5`.
That's the actual ceiling on concurrent DB-bound work today, and it's a
better anchor than an arbitrary guess:

- **Load test baseline:** keep write-heavy stages (`record_consent`,
  `withdraw_consent`) at or under about 5 to 10 concurrent threads. Each
  holds a DB connection for the call's duration, and you want to measure
  normal behavior, not induced queuing.
- **`validate_consent` specifically:** since it's the hottest path in
  production (called before every processing action, per App, potentially
  many times per principal), it's the one stage worth deliberately pushing
  *past* the pool size (e.g. 20 to 30 threads against a 15-connection
  pool) in the load test itself, not just in the stress test, so you see
  queuing/latency behavior at realistic peak, not just at comfortable
  concurrency.
- **Stress test:** push `validate_consent` well beyond the pool size
  (100+) specifically to find where the error rate or p95 latency breaks
  down. That threshold is the actual capacity number worth recording, not
  whatever thread count you started with.

### Traffic mix, not equal weighting

Production traffic is not evenly split across `_func` calls;
`validate_consent` dominates because it's called per processing action, not
once per user. Suggested default mix for the load test (a planning guide;
not enforced by the test plan itself):

| Stage | Suggested share |
|---|---|
| `validate_consent` | ~50% |
| `get_active_policy` (notice) | ~15% |
| `record_consent` (capture) | ~10% |
| Rights/dashboard reads | ~10% |
| Withdrawal/erasure | ~5% |
| Grievance | ~5% |
| Purge polling | ~5% |

### Thresholds (industry-typical defaults)

- **Error rate:** under 1% for a load test. Separate *business* errors
  (e.g. "no consent found" returned as a normal 200 with a false/empty
  result) from *system* errors (5xx, timeouts, connection resets) before
  judging this; the plan's Response Assertions check HTTP status only, not
  the business payload.
- **Latency:** p95 under 500ms, p99 under 1000ms as a starting bar for
  `validate_consent` specifically, since it's on a synchronous
  authorization path for the calling App. Loosen for less time-sensitive
  stages (grievance submission, purge polling). Read these off the HTML
  Dashboard Report's response time percentile table per label.
- **Throughput:** state your actual expected peak requests/sec if you know
  it (from real fiduciary traffic estimates); otherwise treat the load
  test's measured throughput at target latency as the number to record and
  compare against next time, not a pass/fail gate on day one.

---

## 4. Configuring concurrency and request counts

Edit [`load-test.properties`](load-test.properties), the file that
answers "where do I define concurrency and number of requests":

```properties
base.url=http://localhost:8080

api.key=REPLACE_WITH_TEST_APP_API_KEY
api.secret=REPLACE_WITH_TEST_APP_API_SECRET
fiduciary.id=REPLACE_WITH_TEST_FIDUCIARY_UUID

policy.id=REPLACE_WITH_ACTIVE_POLICY_ID
purpose.id=REPLACE_WITH_PURPOSE_ID
user.id.prefix=loadtest_user_
existing.user.id=loadtest_seed_user

dummy.otp=1234
ramp.up.seconds=5

policy_notice.threads=10
policy_notice.loops=100

consent_capture.threads=5
consent_capture.loops=40

validate_consent.threads=25
validate_consent.loops=200

rights_dashboard.threads=5
rights_dashboard.loops=40

withdrawal_erasure.threads=5
withdrawal_erasure.loops=20

grievance.threads=5
grievance.loops=20

purge_polling.threads=3
purge_polling.loops=20

otp_login.threads=5
otp_login.loops=20
```

Each stage's total requests = `threads × loops`. Two ways to change load:

- **Edit the properties file** for a persistent change.
- **Override on the command line** with `-Jstagename.threads=N
  -Jstagename.loops=M` for a one-off run, without touching the file (see
  §5).

For a soak test (sustained duration rather than a fixed request count),
there's no direct properties-file equivalent in this plan today; open the
plan in the JMeter GUI and change that stage's Thread Group to use a
Scheduler with a duration, or set an intentionally very high `loops` value
and stop the run manually/via a `-X` duration flag.

**Before running `validate_consent`, `rights_dashboard`, or `grievance`
for real, seed `existing.user.id` once** so those reads hit a real record
instead of "not found" every time; see the `curl` command in
[`README.md`](README.md#prerequisites).

---

## 5. Running it

Non-GUI mode (the only mode suitable for generating real load; JMeter's
own documentation recommends against load-generation from the GUI):

```bash
cd tests
jmeter -n -t consent-lifecycle-test.jmx -q load-test.properties \
  -l results.jtl -e -o report/
```

Override specific values without editing the properties file:

```bash
jmeter -n -t consent-lifecycle-test.jmx -q load-test.properties \
  -Jvalidate_consent.threads=50 -Jvalidate_consent.loops=200 \
  -l results.jtl -e -o report/
```

Output:
- Live one-line-per-batch summary during the run (requests, throughput,
  errors, latency).
- `results.jtl`: every sample, for diffing between runs or custom
  analysis.
- `report/index.html`: the full HTML Dashboard Report, throughput over
  time, error % by request label, and response time percentiles
  (p50/p90/p95/p99) per stage.

See [`README.md`](README.md) for prerequisites and the seed-user step
before your first real run.

---

## 6. Known limitations of this v1

- Spike testing (sudden burst) isn't implemented; the breach-notification
  bulk-CSV path (`report_breach` / Job Manager) is the natural spike-test
  candidate if this gets extended later, using JMeter's Ultimate Thread
  Group or a Synchronizing Timer.
- No JVM/GC or connection-pool-saturation metrics are captured from the
  server side; this only measures client-observed latency/errors. If
  HikariCP pool exhaustion is suspected as the cause of a latency cliff
  during a run, corroborate with server logs/`jstat`, since the pool
  doesn't expose a metrics endpoint today. Not currently tracked as its
  own gap, but worth flagging if this comes up again during a run.
- There's no properties-driven per-stage on/off switch (see §4); skipping
  a stage means editing the plan in the JMeter GUI or setting its loop
  count very low as a workaround.
