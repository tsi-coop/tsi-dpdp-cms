# Website Consent Banner Integration Guide

**Document Version:** 1.0
**Audience:** Web developers adding a DPDP cookie / consent banner and privacy notice to a public website.

---

## 1. Overview

TSI DPDP CMS records consent against a published **policy** (purposes, data
categories, legal basis, retention, recipients). This guide shows how to put that
policy in front of website visitors as:

- a **consent banner** (Accept all / Reject non-essential / Manage preferences),
- a **preference center** where each non-mandatory purpose can be toggled,
- a **privacy notice** page generated from the same policy,
- **script gating**, so analytics/marketing tags don't run until consented.

Every choice is written to the CMS as an auditable consent record
(`record_consent`), tied to the policy the visitor saw.

A ready-to-run reference lives in [`examples/website-consent/`](../../examples/website-consent/).

> **Not a cookie scanner.** Consent here is per *processing purpose* in your
> policy, not per individual cookie. Model your cookie use as purposes
> (e.g. "Analytics", "Marketing") in the policy and tag the scripts that serve them.

## 2. Architecture

```
Browser (consent-banner.js)  ──►  Your backend (proxy)  ──►  TSI DPDP CMS
   no credentials                 holds X-API-Key/Secret      /api/v1/client/policy
                                  whitelists requests         /api/v1/client/consent
```

**Do not put the API key/secret in page JavaScript.** Anything in the browser is
public, and the secret grants whatever scopes the key has. The CMS's CORS headers
also don't allow `X-API-Secret` on cross-origin browser requests. Your backend
makes the CMS calls; the browser only ever calls your two endpoints.

## 3. Prerequisites

1. A **published policy** for your fiduciary (see the [Implementation Guide](implementation-guide.md)).
   For a standard website, start from the sample in section 4 below.
   Each purpose needs a stable `id`, `name`, `description` and `is_mandatory_for_service`.
2. An **App API key** with `READ` and `WRITE` scopes, created by an ADMIN in the console.
3. The policy id to display (`POLICY_ID`).

## 4. Sample website policy and RoPA

Starter files for a typical corporate website:

| File | What it is |
|---|---|
| [`examples/policy/website/website_visitor_v1.json`](../../examples/policy/website/website_visitor_v1.json) | Consent policy (English + Hindi) to load in the DPO console |
| [`examples/ropa/website/website_visitor_v1.txt`](../../examples/ropa/website/website_visitor_v1.txt) | The DPO's RoPA requirements blueprint for the same policy |

Purposes defined:

| Purpose id | Basis | Mandatory | Typical use |
|---|---|---|---|
| `purpose_site_essential` | Legitimate Use | yes | Essential cookies, logs, security |
| `purpose_contact_enquiry` | Consent | no | Contact / support form |
| `purpose_newsletter` | Consent | no | Newsletter subscription |
| `purpose_analytics` | Consent | no | Analytics cookies |
| `purpose_marketing` | Consent | no | Advertising pixels and cookies |

How to use them:

1. Copy both files, then replace the illustrative parts: organisation name, `example.com`
   URLs, DPO contact, processors, retention periods and safeguards. Remove purposes you
   don't need (and the matching processors and data categories).
2. Follow the usual flow from the [Implementation Guide](implementation-guide.md): DPO reviews
   the RoPA blueprint, an engineer loads the policy JSON, publishing derives the RoPA draft,
   and the DPO verifies it against the `.txt` before publishing.
3. Tag your scripts with the purpose ids, e.g.
   `<script type="text/plain" data-consent-category="purpose_analytics" ...>`. The ids in your
   page must match the ids in the published policy exactly.
4. Add `purpose_site_essential` only for processing that is genuinely necessary; the widget
   cannot switch mandatory purposes off, so don't put analytics or ads under it.

> These are illustrative templates, not legal advice. The legal bases (notably Legitimate Use
> for essential cookies), retention periods, processors and Hindi text need review by your DPO
> or counsel before use.

## 5. Backend endpoints

Expose exactly two endpoints on your own origin.

### `GET /consent-api/policy`

Call the CMS and return its response unchanged:

```
POST {CMS}/api/v1/client/policy      (X-API-Key / X-API-Secret)
{ "_func": "get_policy", "policy_id": "<POLICY_ID>" }
```

Alternatively use `get_active_policy` with `fiduciary_id` + `jurisdiction` so the
banner always shows the currently active policy (see the
[System Integration Guide](system-integration-guide.md)). You can cache this for a few minutes.

### `POST /consent-api/consent`

Accept the widget's JSON and forward a **whitelisted** `record_consent`:

```
POST {CMS}/api/v1/client/consent
{ "_func": "record_consent", "policy_id": "<POLICY_ID>", "user_id": "...",
  "language_selected": "en", "consent_mechanism": "...",
  "data_point_consents": [ { "data_point_id", "consent_granted",
                             "purpose_agreed_to", "timestamp_updated" } ] }
```

Your proxy should:

- Hard-code `_func` and `policy_id`; never take them from the browser.
- **Decide the user id yourself** (see section 10): use the logged-in account from your
  session if there is one; otherwise accept the browser's id only if it matches
  `^anon_[A-Za-z0-9_-]{8,64}$`. Reject anything else, so nobody can write consent
  records against someone else's account id.
- Copy only known fields, validate types, and cap body size (the example uses 32 KB).
- Rate-limit per IP, since this endpoint is public.

`examples/website-consent/proxy/server.py` does all of this in about 100 lines of
standard-library Python; port it to your stack.

> **IP address caveat.** The CMS records the *caller's* address
> (`req.getRemoteAddr()`), which will be your proxy's, not the visitor's. The
> visitor IP is not currently passed through, so don't rely on it in the evidence record.

## 6. Add the widget to your pages

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

Behaviour worth knowing:

- Language follows `<html lang>`, then the browser language, falling back to `en`.
- The banner **re-appears when the policy version changes**, so consent matches the notice shown.
- If the policy can't be loaded, the banner doesn't show and gated scripts stay
  blocked (fail closed); the rest of the site is unaffected.
- Mandatory purposes are shown as "Always on" and can't be switched off.
- All policy text is HTML-escaped before rendering.

## 7. Gate third-party scripts

Set `type="text/plain"` and add the purpose id from your policy. The script runs
only after that purpose is granted (immediately on page load if consent already exists):

```html
<script type="text/plain" data-consent-category="purpose_analytics"
        src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>
```

A script that already ran can't be un-run. After a **withdrawal**, reload the page or
react to the change and stop the vendor SDK yourself:

```js
DPDPConsent.onChange(function (prefs) {
  if (!prefs.purpose_analytics) { /* opt out of your analytics SDK, or reload */ }
});
// or: document.addEventListener('dpdp:consent', e => e.detail)
```

## 8. "Cookie settings" link (required)

Withdrawing consent must be as easy as giving it. Add a persistent link, e.g. in the
footer. Any element with `data-dpdp-open` opens the preference center:

```html
<a href="#" data-dpdp-open>Cookie settings</a>
```

## 9. Privacy notice page

Render the full notice (purposes, legal basis, data used, recipients, retention) from
the same published policy, so the page can't drift from what visitors consent to:

```html
<div id="notice"></div>
<script src="/assets/consent-banner.js" defer data-policy-url="..." data-consent-url="..."></script>
<script>
  window.addEventListener('load', () => DPDPConsent.renderNotice(document.getElementById('notice')));
</script>
```

This is a structured, policy-derived notice. It doesn't replace the narrative your DPO
may need (grievance officer contact, cross-border transfers, children's data); add that
text around the container.

## 10. User identity: anonymous and logged-in visitors

The widget always sends a random `anon_<uuid>` id (kept in localStorage). It is
pseudonymous, not anonymous: it is a persistent identifier for that browser, so
describe it as a cookie identifier in your notice. The widget never sends an account id;
the **proxy decides** who the visitor is:

| Visitor | `user_id` recorded | How |
|---|---|---|
| Not logged in | the browser's `anon_...` id | accepted only if it matches the `anon_` pattern |
| Logged in | the account id from **your session** | the browser's value is ignored |

Link at sign-in: your login handler should pass the browser's `anon_` id (for example as a
parameter to your login call) and the proxy calls `link_user`
(`anonymous_user_id` -> `authenticated_user_id`; see the
[System Integration Guide](system-integration-guide.md)) once per pair, so consent given
before login carries over to the account. As a fallback, a consent request from a logged-in
visitor that still carries an unlinked `anon_` id triggers the same link.

In `proxy/server.py` this is the `session_user(handler)` function. **Replace it** with a
lookup into your real session store or a verified signed cookie/JWT: it must return the
account id from something the browser cannot forge. The demo version reads an in-memory
table filled by `/demo/login?user=<id>`, which only exists with
the proxy's `DEMO_LOGIN` switch (on by default only while it listens on `127.0.0.1`), and the
example page has a mock sign-in popup that shows the whole sequence:
`record_consent` as the anonymous id, `link_user` anonymous id -> account, then
`record_consent` as the account. Never enable `DEMO_LOGIN` outside local testing.

The account id you pass must be the same identifier your other systems use with the CMS
(for example when calling `validate_consent`), or the history won't line up.

## 11. Testing checklist

- [ ] First visit: banner shows; no gated script has run (Network tab).
- [ ] Accept all: gated script runs; consent record appears in the CMS.
- [ ] Reject non-essential: only mandatory purposes granted; gated scripts stay blocked.
- [ ] Reload: no banner, previous choice applied.
- [ ] "Cookie settings" opens the center with saved toggles; saving records new consent.
- [ ] Publish a new policy version: banner re-appears.
- [ ] Stop the CMS: site still works, banner hidden, gated scripts blocked.
- [ ] Keyboard only: Tab reaches all controls; Esc closes the preference center.
- [ ] Page source and network traces contain no API key/secret.
- [ ] A forged `user_id` (e.g. an email address) from a logged-out browser is rejected with 400.
- [ ] After login, new records use the account id, and earlier anonymous history is linked to it.

## 12. Limitations

- No automatic cookie discovery or per-cookie declarations.
- Consent state is per browser (localStorage); no cross-device sync until the visitor
  logs in and you link identities.
- Withdrawal is recorded in the CMS, but cannot stop scripts already running in the browser.
- Button labels come from the policy's optional `buttons` object (`accept_all`,
  `reject_all_non_essential`, `manage_preferences`), otherwise English defaults.
  "Save my choices", "Close" and "Details" are fixed English.
