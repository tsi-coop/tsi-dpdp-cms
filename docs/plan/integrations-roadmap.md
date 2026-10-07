# Plan: Platform Integrations Roadmap

**Status:** Proposed. Priorities are a first proposal for discussion with implementation partners.
**Note:** Statements about third-party platforms (APIs, app-store rules, consent features) come from general knowledge and must be verified against current vendor documentation before building.

## 1. Where we are

A working reference exists for the website case: [`examples/integration/website-consent`](../../examples/integration/website-consent/) (banner, preference center, privacy notice, proxy holding the API credentials, anonymous-to-account linking). The [WordPress plugin plan](wordpress-plugin.md) is the first platform adapter.

Every integration below solves the same four problems:

| # | Problem | Answer |
|---|---|---|
| 1 | Keep API key/secret off the client | A server-side component (plugin, app backend) or a restricted public key (see 2.1) |
| 2 | Show the policy and capture consent | Banner/preference center, or native UI on mobile |
| 3 | Decide the user id and link anonymous to account | Server decides; `link_user` at login |
| 4 | Enforce the decision | Gate scripts/tags on the site, or validate consent downstream (`validate_consent`) |

## 2. Enablers (build once, reused by many integrations)

### 2.1 Restricted public site key (CMS change; decision needed)

Today a browser cannot call the CMS directly, because the secret would be public and CORS does not allow `X-API-Secret`. Platforms with no backend (Wix, Squarespace, Webflow, Shopify theme embeds, plain static sites) cannot host our proxy.

Option: a new key type, "site key", that is origin-locked (allowed domains), limited to `get_policy` and a constrained `record_consent`, rate-limited, and unable to read anything. Needs a server design and security review (abuse of anonymous writes, origin spoofing). If accepted it removes the per-platform proxy for most no-code builders. **Open decision for the maintainers.**

### 2.2 Packaged banner

Publish `consent-banner.js` as a versioned, minified file plus an npm package, with documented data attributes and events. Add nonce/custom-header support and the optional anon-id cookie (both needed by WordPress).

### 2.3 Tag-manager template

A Google Tag Manager community template that loads the banner and maps purposes to Google Consent Mode v2 signals (`analytics_storage`, `ad_storage`, `ad_user_data`, `ad_personalization`).

### 2.4 Reference server snippets

The ~100-line proxy in other languages (Node/Express, PHP, Java, Python exists) so non-WordPress backends can copy it.

## 3. Integration list and priority

| Priority | Integration | Type | Needs 2.1? | Why |
|---|---|---|---|---|
| P0 | **WordPress** | Plugin | No | Largest CMS share; partners' typical client site. See [plan](wordpress-plugin.md). |
| P0 | **WooCommerce** | Extension of the WP plugin | No | Checkout, account and marketing consent on the most common open-source store. |
| P0 | **Shopify** | Embedded app + theme extension | Partly | Dominant hosted store builder; storefront has its own Customer Privacy API to bridge. |
| P1 | **Google Tag Manager** | Community template | Yes (or proxy URL) | One install path for sites that already run GTM; Consent Mode v2. |
| P1 | **React / Next.js** | npm package + server helper | No | Most custom sites and web apps. |
| P1 | **Mobile: Android, iOS, Flutter, React Native** | SDKs / reference apps | No (server-mediated) | Native apps need native UI; same API. |
| P1 | **Zoho (CRM, Commerce)** | Extension / Deluge functions | n/a | Large installed base in India; consent sync and enforcement. |
| P2 | **No-code builders: Wix, Squarespace, Webflow** | Embed snippet | Yes | Small sites; only workable with a public site key. |
| P2 | **Magento / Adobe Commerce, BigCommerce** | Module / app | No | Mid-market commerce. |
| P2 | **Drupal, Joomla** | Module | No | Government and institutional sites. |
| P2 | **Salesforce, HubSpot** | Connected app / consent sync | n/a | Enterprise CRM and marketing; keep CRM opt-in flags in step with CMS consent. |
| P2 | **Marketing and engagement tools** (MoEngage, WebEngage, CleverTap, Mailchimp, Segment) | Webhook/polling consumers | n/a | Downstream enforcement: suppress sends and syncs on withdrawal. |
| P3 | **Identity providers** (Keycloak, Auth0, Okta) | Login hook | n/a | Reliable `link_user` at sign-in for apps using a central IdP. |

P0 to P3 is a proposed order; re-rank with partner demand.

## 4. Plan per integration

Each follows the same template: goal, approach, scope, risks, effort (S under 1 week, M 1 to 3 weeks, L over 3 weeks, for one engineer, excluding review and partner pilots).

### 4.1 WooCommerce (P0, M, on top of WordPress)
- **Goal:** capture and record consent at the points a store really collects data.
- **Approach:** hooks inside the WordPress plugin: checkout (marketing opt-in checkbox mapped to a purpose id), account registration, and order-time `validate_consent` before sending marketing email.
- **Scope:** purpose mapping UI; record consent with the WP user id, or the guest anon id for guest checkout (link at account creation); optional erasure request wiring from WooCommerce's privacy tools.
- **Risks:** guest checkout and caching; Woo's own privacy-export/erase hooks overlap with CMS rights flows. Decide which is authoritative.

### 4.2 Shopify (P0, L)
- **Goal:** banner on the storefront, consent recorded in the CMS, checkout marketing consent respected.
- **Approach:** an app with a backend (holds the key/secret per merchant, performs the proxy role, reached from the storefront via Shopify's app proxy) and a theme app extension that injects the banner. Bridge decisions to Shopify's Customer Privacy API so Shopify-side tracking honours them.
- **Scope:** OAuth install flow, per-shop settings, `shop customer ID` as the account id, uninstall cleanup.
- **Risks:** Shopify app review and its privacy/compliance requirements (including mandatory data-request and erasure webhooks), hosting a multi-merchant backend (we become a processor of merchant credentials). May be better delivered as a partner-run app than by us.

### 4.3 Google Tag Manager template (P1, S to M)
- **Goal:** one-step install and Consent Mode v2 signalling.
- **Approach:** community template that injects the banner and sets default-denied consent state, updating it on `dpdp:consent`; purpose-to-signal mapping in the template fields.
- **Risks:** template gallery review; needs the proxy URL or site key (2.1) because GTM has no backend.

### 4.4 React / Next.js (P1, M)
- **Goal:** first-class component and hooks for modern front ends.
- **Approach:** npm package with a `<ConsentProvider>`, `useConsent(purpose)`, and a server helper (Next.js route handlers) implementing the proxy rules and session-based user id.
- **Risks:** SSR/hydration of the banner; framework-specific session handling, so ship Next.js first and others later.

### 4.5 Mobile SDKs (P1, L)
- **Goal:** native consent UI and a thin client that works with the same policy.
- **Approach:** the app's backend holds the credentials and exposes the two proxy endpoints; the SDK renders native UI from the policy and posts to that backend. Android first or Flutter first depending on partner demand; Flutter/React Native reduces duplication.
- **Scope:** policy fetch and caching, offline queueing of consent changes, persistent anonymous id, account linking, re-prompt on policy version change.
- **Risks:** secure storage of the anonymous id; offline ordering of consent events; app store privacy labels are separate and still manual.

### 4.6 Zoho CRM / Commerce (P1, M)
- **Goal:** keep Zoho's consent fields in step with the CMS and block marketing sends without consent.
- **Approach:** Deluge functions calling `validate_consent`; a webhook/polling consumer that updates Zoho records on consent or withdrawal ([webhook guide](../guides/webhook-integration-guide.md), [polling guide](../guides/polling-integration-guide.md)).
- **Risks:** which Zoho object is the source of truth; rate limits.

### 4.7 No-code builders: Wix, Squarespace, Webflow (P2, S each, after 2.1)
- **Approach:** a copy-paste embed snippet using the site key; a short guide per builder covering where to paste it and how to tag third-party scripts.
- **Risks:** each builder limits custom script placement and script gating (some inject their own analytics outside our control). Document what cannot be gated.

### 4.8 Magento, BigCommerce, Drupal, Joomla (P2, M each)
- Same pattern as WordPress: a module whose server side is the proxy, using the platform's session for the user id and its login event for `link_user`. Start only when a partner asks.

### 4.9 Salesforce, HubSpot (P2, M to L)
- **Approach:** a consent-sync app: push CMS decisions into the platform's consent/opt-in fields, and call `validate_consent` from automation before sends. Webhook consumer with polling reconciliation.
- **Risks:** field mapping differs per customer; two sources of truth.

### 4.10 Marketing and engagement tools (P2, S to M each)
- Prefer one generic "enforcement consumer" reference (webhook + polling, reconcile loop) with a short recipe per tool, rather than a connector per vendor.

### 4.11 Identity providers (P3, S to M)
- A post-login hook recipe per IdP that calls `link_user` with the anonymous id (carried in a cookie) and the stable subject id.

## 5. Cross-cutting rules for every integration

- API key/secret server-side only; one App key per fiduciary with only the scopes needed (READ + WRITE for collection).
- The server decides the user id; the browser only supplies an `anon_` id.
- Use a stable account id (platform user id, not email) and the same id elsewhere in `validate_consent`.
- Fail closed: if the policy cannot load, gated scripts stay blocked and the site keeps working.
- Banner re-prompts on policy version change; withdrawal is as easy as granting.
- Each integration ships: a guide, a versioned artifact, a test checklist and a changelog.
- No per-fiduciary visual theming beyond what the platform's own settings already give (the CMS's identity stays consistent across deployments).

## 6. Suggested sequencing

1. Enablers 2.2 (packaged banner) and a decision on 2.1 (site key).
2. WordPress, then WooCommerce.
3. In parallel with partner pilots: GTM template and Next.js package.
4. Shopify and mobile once a partner commits to a pilot.
5. P2/P3 items on demand.

## 7. Open questions

- Which platforms do your current implementation partners' clients actually use? Please rank.
- Do we build the site key (2.1)? It unlocks most no-code platforms but changes the CMS security model.
- Do we ship each artifact ourselves or let partners own and publish platform-specific apps (Shopify especially)?
- Support model and versioning policy for partner-distributed artifacts.
