# Website Consent Banner Integration Guide

**Document Version:** 1.1
**Audience:** Web developers adding a DPDP cookie / consent banner and privacy notice to a public website.

---

## What this guide gets you

A consent banner on your website, backed by TSI DPDP CMS:

- a **banner** with Accept all / Reject non-essential / Manage preferences,
- a **preference center** where each non-mandatory purpose can be switched on or off,
- a **privacy notice** page generated from the same policy,
- **script gating**, so analytics and marketing tags do not run until the visitor consents.

Every choice is saved in the CMS as an auditable consent record, tied to the policy the visitor saw.

The guide has two parts:

- **[Part 1: Try the demo](#part-1-try-the-demo)** (about 30 minutes). Run the ready-made example on your machine and see it all working.
- **[Part 2: Add it to your own site](#part-2-add-it-to-your-own-site)**. The same pieces, in your stack.

Do the **checkpoint** at the end of each step before moving on.

> **Not a cookie scanner.** Consent here is per *processing purpose* in your policy (for example "Analytics" or "Marketing"), not per individual cookie. You describe your cookie use as purposes in the policy, then tag the scripts that serve each purpose.

### How it fits together

```
Browser (consent-banner.js)  ──►  Your backend (proxy)  ──►  TSI DPDP CMS
   no credentials                 holds X-API-Key/Secret      /api/v1/client/policy
                                  whitelists requests         /api/v1/client/consent
```

**Never put the API key and secret in page JavaScript.** Anything in the browser is public, and the secret grants whatever permissions the key has. Your backend makes the CMS calls, and the browser only ever calls your two endpoints. (The CMS also does not allow `X-API-Secret` on cross-origin browser requests.)

The reference example lives in [`examples/integration/website-consent/`](../../examples/integration/website-consent/).

---

## Part 1: Try the demo

### Step 1: Have a running CMS

You need the CMS running and an admin account created. If you do not have that yet, follow the [Local Development Guide](local-development-guide.md), or the [README](../../README.md#installation) for the quick route. The rest of this guide assumes it is at `http://localhost:8080`.

> **Checkpoint:** you can sign in to the console at <http://localhost:8080/console/>.

### Step 2: Publish the sample website policy

The example ships a ready-made policy for a typical corporate website, in English and Hindi.

| File | What it is |
|---|---|
| [`examples/policy/website/website_visitor_v1.json`](../../examples/policy/website/website_visitor_v1.json) | The consent policy to load in the DPO console |
| [`examples/ropa/website/website_visitor_v1.txt`](../../examples/ropa/website/website_visitor_v1.txt) | The DPO's RoPA requirements blueprint for the same policy |

It defines these purposes:

| Purpose id | Basis | Mandatory | Typical use |
|---|---|---|---|
| `purpose_site_essential` | Legitimate Use | yes | Essential cookies, logs, security |
| `purpose_contact_enquiry` | Consent | no | Contact / support form |
| `purpose_newsletter` | Consent | no | Newsletter subscription |
| `purpose_analytics` | Consent | no | Analytics cookies |
| `purpose_marketing` | Consent | no | Advertising pixels and cookies |

1. In the DPO console, open **Policies** and create a new policy. Give it a **Policy ID** (for example `WEBSITE_VISITOR`), a **Version** (for example `1.0`) and a jurisdiction, and upload `website_visitor_v1.json`.
2. Follow the usual flow to publish: the RoPA draft is derived from the policy, the DPO checks it against the `.txt` blueprint, and then you publish. The [Implementation Guide](implementation-guide.md) (section 5) walks through this.

Write down the **Policy ID**. You need it in Step 4.

> **Checkpoint:** the policy shows as **Active** on the Policies page.

### Step 3: Create an API key for the website

1. Sign in as an **ADMIN** and use **Apps -> Add New App** to add the website, then go to **API Keys**.
2. Generate a key with the **READ** and **WRITE** scopes.
3. **Copy the API Key and the API Secret now.** The console shows them once and never again.

> **Checkpoint:** you have a key (a UUID) and a secret saved somewhere safe.

### Step 4: Start the demo server

The demo includes a small server that holds the key and secret and serves the page. It uses only Python 3, with nothing to install.

```bash
cd examples/integration/website-consent
CMS_BASE_URL=http://localhost:8080 \
CMS_API_KEY=<your-key> CMS_API_SECRET=<your-secret> \
POLICY_ID=<your-policy-id> \
python3 proxy/server.py
```

Leave it running. You should see `Serving demo on http://127.0.0.1:8090`.

> **Checkpoint:** in a second terminal, `curl http://localhost:8090/consent-api/policy` prints your policy as JSON. If you get an error about the key or secret, re-check Step 3.

### Step 5: Use the banner

1. Open <http://localhost:8090> in a **private/incognito window** (so no earlier choice is remembered).
2. The banner appears. Click **Manage preferences**, switch **Analytics** on, and save.
3. The demo page has a gated script tied to `purpose_analytics`. It runs only now that analytics is granted.
4. Open **Cookie settings** (the link on the page), switch Analytics off, and save.
5. Open <http://localhost:8090/privacy.html>. This is the privacy notice, rendered live from the published policy.

> **Checkpoint:** the banner showed on the first visit and not after you chose. In the DPO console (**Principals** page), a visitor with an id starting `anon_` now has consent records for the purposes you toggled.

### Step 6 (optional): Try the sign-in flow

Accept cookies. The demo page shows the visitor's anonymous id and a **Sign in** button. Sign in with any email in the popup. The id changes to the account id, and the page lists the calls the server made: `record_consent` as the anonymous id, `link_user` from the anonymous id to the account, and `record_consent` as the account. This is how consent given before login carries over to the account (see Part 2, Step 7).

The sign-in is fake and is switched on only while the server listens on `127.0.0.1`. Never enable it (`DEMO_LOGIN`) in production.

> **Checkpoint:** after signing in, the visitor's earlier consent records are linked to the account.

You have now seen the whole flow. Next, put it into your own site.

---

## Part 2: Add it to your own site

### Step 1: Define your purposes and publish the policy

Start from the sample policy in Part 1 and replace the illustrative parts: organisation name, `example.com` URLs, DPO contact, processors, retention periods and safeguards. Remove purposes you do not need, along with the matching processors and data categories. Each purpose needs a stable `id`, `name`, `description` and `is_mandatory_for_service`. Publish it as in Part 1, Step 2.

Two rules matter:

- The purpose ids on your pages (in Step 4) must match the published policy **exactly**.
- Use `purpose_site_essential` (the mandatory one) only for processing that is genuinely necessary. The banner cannot switch mandatory purposes off, so never put analytics or ads under it.

> These are illustrative templates, not legal advice. The legal bases (notably Legitimate Use for essential cookies), retention periods, processors and Hindi text need review by your DPO or counsel before use.

> **Checkpoint:** your policy is Active, and you have a list of the purpose ids your scripts will use.

### Step 2: Build two endpoints in your backend

Create an API key as in Part 1, Step 3. Then add exactly two endpoints on **your own origin**. `examples/integration/website-consent/proxy/server.py` does all of this in about 100 lines of standard-library Python. Port it to your stack.

**Endpoint 1: `GET /consent-api/policy`**

Call the CMS and return its response unchanged:

```
POST {CMS}/api/v1/client/policy      (X-API-Key / X-API-Secret)
{ "_func": "get_policy", "policy_id": "<POLICY_ID>" }
```

Alternatively use `get_active_policy` with `fiduciary_id` and `jurisdiction`, so the banner always shows the currently active policy (see the [System Integration Guide](system-integration-guide.md)). You can cache the response for a few minutes.

**Endpoint 2: `POST /consent-api/consent`**

Accept the widget's JSON and forward a **whitelisted** `record_consent`:

```
POST {CMS}/api/v1/client/consent
{ "_func": "record_consent", "policy_id": "<POLICY_ID>", "user_id": "...",
  "language_selected": "en", "consent_mechanism": "...",
  "data_point_consents": [ { "data_point_id", "consent_granted",
                             "purpose_agreed_to", "timestamp_updated" } ] }
```

Your endpoint must:

- Hard-code `_func` and `policy_id`. Never take them from the browser.
- **Decide the user id yourself** (Step 7). Use the logged-in account from your session if there is one. Otherwise accept the browser's id only if it matches `^anon_[A-Za-z0-9_-]{8,64}$`, and reject anything else. This stops anyone writing consent records against someone else's account id.
- Copy only known fields, validate their types, and cap the body size (the example uses 32 KB).
- Rate-limit per IP, because this endpoint is public.

> **IP address caveat.** The CMS records the *caller's* address, which is your backend's, not the visitor's. The visitor's IP is not passed through, so do not rely on it in the evidence record.

> **Checkpoint:** `curl` your policy endpoint and get the policy JSON. POST a consent with `"user_id": "someone@example.com"` and get a `400`. POST one with `"user_id": "anon_abcdefgh1234"` and get a `200`.

### Step 3: Add the widget to your pages

Copy `consent-banner.js` to your static assets and include it on every page:

```html
<script src="/assets/consent-banner.js" defer
        data-policy-url="/consent-api/policy"
        data-consent-url="/consent-api/consent"
        data-privacy-url="/privacy"></script>
```

| Attribute | Default | Meaning |
|---|---|---|
| `data-policy-url` | required | Your policy endpoint |
| `data-consent-url` | required | Your consent endpoint |
| `data-storage-key` | `dpdp_consent` | localStorage key prefix |
| `data-expiry-days` | `365` | Re-ask after this many days |
| `data-position` | `bottom` | `bottom`, `bottom-left`, `bottom-right` |
| `data-color` | `#006A67` | Accent colour |
| `data-privacy-url` | none | Adds a "full privacy policy" link in the preference center |

Good to know:

- Language follows `<html lang>`, then the browser language, then `en`.
- The banner **re-appears when the policy version changes**, so consent always matches the notice shown.
- The demo banner records consent **fire-and-forget**: the visitor's choice applies in the browser immediately. The CMS records each consent against the policy's *active* version and answers `409` if the version the banner sent is no longer active (for example, the DPO published a new version while the page was open). The demo does not show that response, so that one choice is not recorded centrally, and the visitor sees the new notice on their next page load. **A production integration should treat any non-OK response as "re-fetch the policy and ask again".**
- If the policy cannot be loaded, the banner does not show and gated scripts stay blocked (it fails closed). The rest of the site is unaffected.
- Mandatory purposes show as "Always on" and cannot be switched off.
- All policy text is HTML-escaped before it is shown.

> **Checkpoint:** open a page in a private window. The banner appears.

### Step 4: Gate your third-party scripts

Change `type` to `text/plain` and add the purpose id from your policy. The script runs only after that purpose is granted (immediately on page load, if consent already exists):

```html
<script type="text/plain" data-consent-category="purpose_analytics"
        src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>
```

A script that has already run cannot be un-run. After a **withdrawal**, reload the page, or react to the change and stop the vendor SDK yourself:

```js
DPDPConsent.onChange(function (prefs) {
  if (!prefs.purpose_analytics) { /* opt out of your analytics SDK, or reload */ }
});
// or: document.addEventListener('dpdp:consent', e => e.detail)
```

> **Checkpoint:** on a first visit, the Network tab shows no request to the analytics vendor. After accepting, it does.

### Step 5: Add a "Cookie settings" link (required)

Withdrawing consent must be as easy as giving it. Add a permanent link, for example in the footer. Any element with `data-dpdp-open` opens the preference center:

```html
<a href="#" data-dpdp-open>Cookie settings</a>
```

> **Checkpoint:** clicking the link opens the preference center with the saved toggles.

### Step 6: Add the privacy notice page

Render the full notice (purposes, legal basis, data used, recipients, retention) from the same published policy, so the page cannot drift from what visitors agree to:

```html
<div id="notice"></div>
<script src="/assets/consent-banner.js" defer data-policy-url="..." data-consent-url="..."></script>
<script>
  window.addEventListener('load', () => DPDPConsent.renderNotice(document.getElementById('notice')));
</script>
```

This is a structured, policy-derived notice. It does not replace the narrative your DPO may need (grievance officer contact, cross-border transfers, children's data). Add that text around the container.

> **Checkpoint:** the page lists every purpose in your policy.

### Step 7: Handle anonymous and logged-in visitors

The widget always sends a random `anon_<uuid>` id, kept in the browser's localStorage. It is pseudonymous, not anonymous: it is a persistent identifier for that browser, so describe it as a cookie identifier in your notice. The widget never sends an account id. **Your backend decides who the visitor is:**

| Visitor | `user_id` recorded | How |
|---|---|---|
| Not logged in | the browser's `anon_...` id | accepted only if it matches the `anon_` pattern |
| Logged in | the account id from **your session** | the browser's value is ignored |

**Linking at sign-in.** Your login handler should pass the browser's `anon_` id (for example, as a parameter to your login call). Your backend then calls `link_user` (`anonymous_user_id` to `authenticated_user_id`; see the [System Integration Guide](system-integration-guide.md)) once per pair, so consent given before login carries over to the account. As a fallback, a consent request from a logged-in visitor that still carries an unlinked `anon_` id triggers the same link.

**What to replace in the example.** In `proxy/server.py`, the function `session_user(handler)` must be **replaced** with a lookup into your real session store, or a verified signed cookie or JWT. It must return the account id from something the browser cannot forge. The demo version only reads an in-memory table filled by `/demo/login?user=<id>`, which exists only with the `DEMO_LOGIN` switch.

The account id you pass must be the same identifier your other systems use with the CMS (for example when they call `validate_consent`), or the history will not line up.

> **Checkpoint:** after login, new records use the account id, and earlier anonymous history is linked to it.

### Step 8: Run the full test checklist

Before launch, go through every item:

- [ ] First visit: the banner shows and no gated script has run (Network tab).
- [ ] Accept all: gated scripts run, and a consent record appears in the CMS.
- [ ] Reject non-essential: only mandatory purposes are granted, and gated scripts stay blocked.
- [ ] Reload: no banner, and the previous choice applies.
- [ ] "Cookie settings" opens the center with the saved toggles, and saving records new consent.
- [ ] Publish a new policy version: the banner re-appears.
- [ ] Stop the CMS: the site still works, the banner is hidden, and gated scripts stay blocked.
- [ ] Keyboard only: Tab reaches every control, and Esc closes the preference center.
- [ ] Page source and network traces contain no API key or secret.
- [ ] A forged `user_id` (for example an email address) from a logged-out browser is rejected with `400`.
- [ ] After login, new records use the account id, and earlier anonymous history is linked to it.

---

## Limitations

- No automatic cookie discovery or per-cookie declarations.
- Consent state is per browser (localStorage). There is no cross-device sync until the visitor logs in and you link identities.
- Withdrawal is recorded in the CMS, but it cannot stop scripts already running in the browser.
- Button labels come from the policy's optional `buttons` object (`accept_all`, `reject_all_non_essential`, `manage_preferences`), otherwise English defaults. "Save my choices", "Close" and "Details" are fixed English.

## Common problems

| Problem | Likely cause and fix |
|---|---|
| The banner never appears | The policy endpoint failed (the banner fails closed). Open `/consent-api/policy` in the browser and check the response. |
| `401` from either endpoint | Wrong key or secret in your backend, or the key lacks the needed scope (READ for the policy, WRITE for consent). A missing scope shows up as `401`, not `403`. Create a new key with both READ and WRITE. |
| Gated script never runs | The `data-consent-category` does not match a purpose id in the published policy exactly. |
| `409` on consent | The policy version changed while the page was open. Re-fetch the policy and ask again. |
| Consent saved but not linked after login | Your login handler is not passing the `anon_` id to your backend. |
