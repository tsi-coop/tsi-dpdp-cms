# Plan: Developer Integrations Roadmap

**Status:** Proposed. Revised 2026-11-04 to a developer-first direction; discuss with implementation partners.
**Note:** Statements about third-party platforms (APIs, app-store rules, consent features) come from general knowledge and must be verified against current vendor documentation before building.

## 1. Direction

We cater to developers. We provide:

1. **Official SDKs** for generic languages (Python first, others when a real requirement arrives).
2. **Enablers** that any integration needs (a packaged banner, possibly a restricted site key, reference server snippets).
3. **Small, standalone examples** under `examples/integration/` that show one integration pattern end to end (for example [`gtm-consent`](google-tag-manager-template.md)).

We do **not** build or maintain product integrations (WordPress plugin, Shopify app, Zoho or Salesforce connectors and the like). Developers and implementation partners build those on the SDKs and examples, because they know the product and own its release cycle.

## 2. Where we are

A working reference exists for the website case: [`examples/integration/website-consent`](../../examples/integration/website-consent/) (banner, preference center, privacy notice, proxy holding the API credentials, anonymous-to-account linking).

Every integration, whoever builds it, solves the same four problems:

| # | Problem | Answer |
|---|---|---|
| 1 | Keep API key/secret off the client | A server-side component (app backend, proxy) or a restricted public key (see 3.1) |
| 2 | Show the policy and capture consent | Banner/preference center, or native UI on mobile |
| 3 | Decide the user id and link anonymous to account | Server decides; `link_user` at login |
| 4 | Enforce the decision | Gate scripts/tags on the site, or validate consent downstream (`validate_consent`) |

## 3. Enablers (build once, reused by SDKs and examples)

### 3.1 Restricted public site key (CMS change; decision needed)

Today a browser cannot call the CMS directly, because the secret would be public and CORS does not allow `X-API-Secret`. Sites with no backend (static sites, tag managers, hosted site builders) cannot host our proxy.

Option: a new key type, "site key", that is origin-locked (allowed domains), limited to `get_policy` and a constrained `record_consent`, rate-limited, and unable to read anything. Needs a server design and security review (abuse of anonymous writes, origin spoofing). If accepted it removes the per-site proxy for most backend-less builds. **Open decision for the maintainers.** This is the only enabler that changes the core.

### 3.2 Packaged banner

Publish `consent-banner.js` as a versioned, minified file plus an npm package, with documented data attributes and events. Add `window.DPDPConsentConfig`, an exposed `ready()`, a return-visit signal, nonce/custom-header support and an optional anon-id cookie. The first three are required by the [GTM example](google-tag-manager-template.md).

### 3.3 Reference server snippets

The ~100-line proxy in other languages (Node/Express, PHP, Java; Python exists) so any backend can copy it. Once the Python SDK ships, its consent proxy router replaces the Python snippet.

## 4. Official SDKs

### 4.1 Approach

- **Hand-written, thin clients**, one language at a time. The surface is small (five paths, 19 `_func` operations), and the `oneOf` on `_func` makes generators awkward. If the surface grows a lot, generate only the models.
- **Python first**, as in the [Python SDK plan](python-sdk.md).
- **Add a language when a real requirement shows up.** Do not publish a language calendar. The roadmap commits to the suite below, not to dates.
- **Community SDKs welcome** (Go, C# and others) if they pass the conformance suite. We list them; we do not maintain them.
- **Stable contract:** additive API changes only within a version. Each SDK has its own semver and a compatibility table against CMS versions.

### 4.2 Language-neutral pieces (built during the Python phase, reused by every SDK)

| Piece | What it is |
|---|---|
| **Conformance scenarios** | Plain data files (JSON or YAML) describing each scenario: calls to make and the status codes and fields expected. They cover consent, policy, grievance and purge, plus the awkward cases (409 on a stale policy version, 401 for a missing scope, an unlinked `anon_` id). Run against a docker-compose CMS using the existing lifecycle scripts. Each SDK writes only a small runner. |
| **Behaviour notes** | A short document of choices the spec does not capture: no automatic retries on writes, how to treat 409, error-to-exception mapping, the known `/compliance` authorization gap. A new SDK follows this instead of reverse-engineering the Python one. |
| **Drift guard** | A CI check comparing the function list in `docs/api/openapi.yaml` with each SDK's methods. |

### 4.3 Adding a language (template)

Client, models, scenario runner, drift check, quickstart guide, release pipeline. The first working version is the runner passing the scenarios. Candidates when asked: TypeScript (also serves server helpers for Next.js and similar), Java, Go, C#.

### 4.4 Decide before the second language

- **Write idempotency.** Retrying `record_consent` can duplicate records. Recommended: no write retries in v1, and a server-side idempotency key later (a core change, so a separate decision).
- **Layout.** Proposed convention: `sdk/<language>/` in this repo (`sdk/python/` first). Move out if partners need an independent release cadence.

## 5. Examples (small, standalone)

Each is a folder under `examples/integration/` that runs on its own, with no dependency on another example folder. Each ships a README, a test checklist and, where it copies shared files (banner, proxy), a drift check against the source.

| # | Example | Status | Notes |
|---|---|---|---|
| 5.1 | `website-consent`: banner, preference center, notice, proxy | Exists | The reference for everything else |
| 5.2 | `gtm-consent`: Google Tag Manager template and Consent Mode v2 | Planned: [detailed plan](google-tag-manager-template.md) | Needs 3.2; works with a proxy URL, site key later |
| 5.3 | Next.js / React: provider, `useConsent(purpose)`, route-handler proxy | Candidate | Most useful once a TypeScript SDK exists |
| 5.4 | Enforcement consumer: webhook plus polling reconcile loop that suppresses sends on withdrawal | Candidate | Generic, so it serves every CRM and marketing tool. Prefer one such example over a connector per vendor |
| 5.5 | Login hook recipe: carry `anon_` id, call `link_user` with the stable subject id | Candidate | Short recipe, not a product |

## 6. Cross-cutting rules for every SDK and example

- API key/secret server-side only; one App key per fiduciary with only the scopes needed (READ + WRITE for collection).
- The server decides the user id; the browser only supplies an `anon_` id.
- Use a stable account id (platform user id, not email) and the same id elsewhere in `validate_consent`.
- Fail closed: if the policy cannot load, gated scripts stay blocked and the site keeps working.
- Banner re-prompts on policy version change; withdrawal is as easy as granting.
- Each SDK and example ships: a guide, a versioned artifact, a test checklist and a changelog.
- No per-fiduciary visual theming beyond what the banner's own settings give (the CMS's identity stays consistent across deployments).

## 7. Suggested sequencing

1. Python SDK phase 1, together with the conformance scenarios and behaviour notes (4.2).
2. Packaged banner (3.2), and a decision on the site key (3.1).
3. GTM example (5.2), standalone.
4. Python SDK phases 2 and 3 (webhook receiver, workers, framework helpers, consent proxy router).
5. A second SDK (probably TypeScript) when a requirement arrives, then the Next.js example (5.3).
6. Other examples (5.4 and 5.5) on request.

## 8. Open questions

- Which languages do current implementation partners actually need after Python? Please rank.
- Do we build the site key (3.1)? It unlocks backend-less sites but changes the CMS security model.
- Do we add a server-side idempotency key for writes (4.4)?
- Repo layout: `sdk/<language>/` in this repo, or separate repos for independent release cadence?
- Support model and versioning policy for community SDKs we list.
