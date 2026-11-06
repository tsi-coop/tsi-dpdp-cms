# Plan: Google Tag Manager Community Template

**Status:** Proposed. Detail for [integrations roadmap](integrations-roadmap.md) example 5.2 (effort S to M).
**Note:** Statements about Google Tag Manager, Consent Mode v2 and the Community Template Gallery come from general knowledge and must be verified against current Google documentation before building. Section 9 lists what to check.

## 1. Goal

A site that already runs GTM can install DPDP consent in one step, with no code changes to the page:

1. The template injects the consent banner.
2. Before the visitor decides, Google consent state is **default-denied**.
3. When the visitor decides, the template **updates** Google consent state from the visitor's per-purpose choices.
4. Google tags (GA4, Ads, Floodlight) and other tags that honour Consent Mode then behave correctly without per-tag work.

Consent is still recorded in the CMS exactly as in the [Website Consent Banner Integration Guide](../guides/website-consent-banner-integration-guide.md); GTM only carries the banner and mirrors the decision into Google's consent signals.

## 2. Constraints that shape the design

| Constraint | Consequence |
|---|---|
| GTM has no backend, and the browser must never hold the API key/secret. | The template needs either a **proxy URL** (the site's own two endpoints, as in the integration guide) or a **site key** (roadmap 3.1, not built yet). |
| Template sandbox JavaScript is restricted. `injectScript` loads a URL but cannot set `data-*` attributes, and `consent-banner.js` reads its config from its own `<script>` tag attributes (`document.currentScript`). | The banner must accept config another way. **This is a required banner change** (section 4). |
| The banner fires `dpdp:consent` only when the visitor saves a choice. On a return visit with a stored decision it does **not** fire; it only activates gated scripts. | The template cannot rely on the event alone. It must also read `DPDPConsent.getPreferences()` once the banner is ready, or returning visitors stay at "denied". |
| The banner loads asynchronously and fails closed if the policy cannot be fetched. | Default-denied must be set **before** the banner loads, and stay denied on failure. |
| `consent-banner.js` gates only `<script type="text/plain" data-consent-category=...>` tags. GTM-managed tags are not those. | In GTM, gating is done by GTM's own consent checks (tag consent settings), not by the banner's script gating. |

## 3. How it works

```
Page load
  GTM container (Consent Initialization trigger)
    └─ DPDP template, tag 1: setDefaultConsentState (all denied, except what the site chooses)
  GTM container (later trigger, e.g. Initialization or Page View)
    └─ DPDP template, tag 2: injectScript(banner) with config
         banner fetches policy via proxy / site key
           ├─ stored decision for current policy version → read prefs, updateConsentState
           └─ no decision → show banner
                 visitor saves → dpdp:consent → updateConsentState
```

Two parts in one template, selected by a mode field:

- **Default mode** (fires on the Consent Initialization trigger, before any other tag): `setDefaultConsentState` with every Google signal `denied`, plus `wait_for_update` (for example 500 ms) so tags that fire on page load wait briefly for a stored decision.
- **Banner mode** (fires on All Pages or Initialization): loads the banner, then wires consent updates (section 5).

Keeping them as two tag instances of one template is the usual GTM pattern. It lets the default fire on Consent Initialization while the banner loads later.

## 4. Required change to `consent-banner.js`

The change is made in the GTM example's own copy of the banner (section 10). Make the same change in `website-consent/consent-banner.js` at the same time, because roadmap enabler 3.2 (packaged banner) and the SDK-based examples need it too, and the two copies should stay identical (drift check, section 10).

Add a config fallback, used when there is no usable script tag:

```js
window.DPDPConsentConfig = {
  policyUrl: '/consent-api/policy',
  consentUrl: '/consent-api/consent',
  privacyUrl: '/privacy',
  storageKey: 'dpdp_consent',
  expiryDays: 365,
  position: 'bottom',
  color: '#006A67'
};
```

Rule: a `data-*` attribute wins if present, otherwise `window.DPDPConsentConfig`, otherwise the existing default. Existing installs are unaffected.

Two more small additions are needed for GTM, and are useful elsewhere:

- `DPDPConsent.ready()`: returns a promise resolved once the policy is loaded and any stored decision is read (the existing internal `ready` promise, exposed). Rejects or never resolves if the policy fails, which the template treats as "stay denied".
- Also fire `dpdp:consent` (or a sibling `dpdp:ready`) with the stored preferences on a return visit, so listeners get one uniform signal. If this is done, the template needs only the event. Until then the template calls `getPreferences()` after `ready()`.

## 5. Purpose-to-signal mapping

Google Consent Mode v2 has four signals the template sets: `ad_storage`, `analytics_storage`, `ad_user_data`, `ad_personalization`. The template optionally also exposes `functionality_storage`, `personalization_storage` and `security_storage`.

The visitor's choices are per **policy purpose id** (for example `purpose_analytics`), so the mapping is a field in the template:

| Template field | Type | Example |
|---|---|---|
| `analytics_storage` granted when purposes | list of purpose ids | `purpose_analytics` |
| `ad_storage` granted when purposes | list of purpose ids | `purpose_marketing` |
| `ad_user_data` granted when purposes | list of purpose ids | `purpose_marketing` |
| `ad_personalization` granted when purposes | list of purpose ids | `purpose_marketing` |
| (optional) `functionality_storage`, `personalization_storage`, `security_storage` | list of purpose ids | `purpose_site_essential` |

Rules:

- A signal is `granted` only if **all** purposes listed for it are granted. An empty list means the signal stays `denied`. (Choosing "all" over "any" is the safe default; make it a template option if partners ask.)
- Mandatory purposes appear in the preferences as `true`, so mapping `security_storage` to `purpose_site_essential` yields `granted`, which is correct.
- The mapping is by the **exact purpose id**, so it must match the published policy, as with script gating. A typo leaves the signal denied (fails closed).
- A sensible default mapping for the sample website policy ships pre-filled: analytics to `purpose_analytics`; the three ad signals to `purpose_marketing`.

The template calls `updateConsentState` with the computed object on every decision, including a withdrawal (granted to denied).

## 6. Template fields

| Field | Required | Notes |
|---|---|---|
| Mode | yes | Default state / Banner |
| Policy URL | yes (banner) | The proxy `GET /consent-api/policy`, or the site-key endpoint |
| Consent URL | yes (banner) | The proxy `POST /consent-api/consent`, or the site-key endpoint |
| Site key | later | Replaces the two URLs once roadmap 3.1 exists |
| Privacy notice URL | no | Link in the preference center |
| Banner script URL | yes | Defaults to the versioned, hosted banner file (enabler 3.2). Must be allow-listed in the template permissions. |
| Position, accent colour, expiry days, storage key | no | Pass through to the banner config |
| Purpose-to-signal mapping | yes | Section 5 |
| `wait_for_update` ms | no | Default 500 |
| Region-specific defaults | no | Optional rows: region codes and their default state |

Template permissions (declared in the template, shown to the GTM user at install): inject script from the banner host; access consent state for the listed signals (write); read `window.DPDPConsent`, `window.DPDPConsentConfig`; listen to `dpdp:consent`.

## 7. What the user does

1. Publish the policy and run the two endpoints (integration guide, Part 2, Steps 1 and 2). This is the same prerequisite as every other integration.
2. In GTM, add the DPDP template from the gallery.
3. Create the two tags: **DPDP Consent Defaults** on the Consent Initialization trigger, and **DPDP Consent Banner** on All Pages.
4. In GTM, for each Google or third-party tag, set the tag's **consent settings**: require `analytics_storage` for GA4, the ad signals for Ads/Floodlight, and so on. Tags that natively honour Consent Mode (Google tags) adapt on their own.
5. Add a "Cookie settings" link (`data-dpdp-open`) to the site. GTM can do this with a Custom HTML tag, but a footer link in the page is simpler and does not depend on GTM loading.
6. Test with GTM Preview (section 8).

## 8. Testing

- [ ] **Consent Initialization:** in GTM Preview, the Defaults tag fires before every other tag, and the consent panel shows all signals `denied`.
- [ ] **First visit:** banner appears, GA4 sends cookieless pings only (or nothing, if the tag requires consent), and no marketing cookies are set.
- [ ] **Accept all:** consent panel shows the mapped signals `granted`, GA4 and Ads tags fire with cookies, and a consent record appears in the CMS.
- [ ] **Reject non-essential:** signals stay `denied` except those mapped to mandatory purposes.
- [ ] **Partial:** analytics only: `analytics_storage` granted, the three ad signals denied.
- [ ] **Return visit:** no banner, and signals are `granted` from stored prefs without waiting for a click (the gap noted in section 2).
- [ ] **Withdrawal:** via "Cookie settings", signals go back to `denied` and `dpdp:consent` fires. Remember that already-running third-party scripts need a reload to fully stop.
- [ ] **New policy version:** banner re-appears and signals reset to denied until the visitor decides.
- [ ] **CMS or proxy down:** banner does not show, signals stay `denied`, site works.
- [ ] **No credentials:** container JSON and network traces contain no API key or secret.
- [ ] **Ad blocker / GTM blocked:** site works, no tags fire. Consent cannot be collected, which is acceptable (fails closed).

## 9. Risks and open questions

| Risk | Detail and mitigation |
|---|---|
| **Needs 3.1 or a proxy URL** | Without a backend there is nowhere to hold credentials. Ship v1 as "bring your proxy URL" (works today); add the site key field when 3.1 lands. Make clear in the install guide that GTM alone is not enough. |
| **Gallery review** | The Community Template Gallery has review and policy requirements and takes time. Fallback: publish the `.tpl` file in the repo for manual import, so partners are not blocked. Check current submission rules, naming limits and permission restrictions. |
| **Sandbox limits** | The template sandbox is restricted (no arbitrary globals, limited APIs). Verify that `listenToDomEvent`-style access to a custom document event, reading `window.DPDPConsent` through `copyFromWindow`, and polling or callback for `ready()` are all allowed. If custom document events cannot be listened to, fall back to a small function the banner calls (`window.dataLayer.push({event:'dpdp_consent', ...})`) and trigger on that. **This is the first thing to prototype.** |
| **Return-visit gap** | Section 2. Solved by `ready()` plus reading preferences, or by the banner firing the event on load. Test explicitly. |
| **Mapping drift** | Purpose ids typed into GTM can drift from the policy. Mitigate with a "test mapping" note in the install guide and, later, a CLI or console check that compares mapping to the policy's purposes. |
| **Consent Mode is not enforcement** | Consent Mode tells Google tags what to do. It does not block tags that ignore it. Non-Google tags must use GTM's tag-level consent settings or a trigger on the `dpdp_consent` dataLayer event. State this plainly in the guide. |
| **GTM as a processor** | GTM and any tag it loads run with the visitor's data. The privacy notice should mention tag-management and listed vendors. A DPO matter, not code, but the install guide should flag it. |
| **Banner hosted by us** | If the template loads the banner from a CDN we run, that host sees visitor IPs and is a processor. Prefer letting the site self-host the file, with the URL as a field; document the choice. |
| **Policy-language and labels** | Unchanged from the banner (button labels from the policy `buttons` object). Nothing GTM-specific. |
| **Region defaults** | Consent Mode supports per-region defaults. DPDP applies to India, so a single global default-denied is simplest. Offer region rows only if a partner needs them. |

## 10. The example module (standalone)

The work ships as its own example, `examples/integration/gtm-consent/`, **standalone**: it does not depend on `website-consent`, and you can read, run and copy it on its own.

```
examples/integration/gtm-consent/
  README.md                   prerequisites, setup, mapping, test checklist (sections 7 and 8)
  consent-banner.js           copy of the website-consent banner, plus DPDPConsentConfig and ready() (section 4)
  proxy/server.py             copy of the reference proxy, trimmed to what GTM needs (no demo login)
  template/dpdp-consent.tpl   the GTM template: fields, sandboxed JS, permissions, in-template tests
  container/sample-container.json   importable container: Defaults tag, Banner tag, triggers, a GA4 tag with consent settings
  site/index.html             demo page with the GTM snippet and a "Cookie settings" link
  check-drift.sh              diffs the shared files against website-consent (below)
```

**To run it:** publish the policy and create a key (integration guide, Part 1, Steps 2 and 3), start `proxy/server.py`, import the template and container into your own GTM test container, set its container ID in `site/index.html`, and open the page.

**Why standalone:** each example is one thing you can pick up and run, with no ordering or version dependency between folders. The README for this example does not tell you to start another example first.

**The cost is duplication.** There are two copies of the banner and the proxy, and the proxy holds security checks (`anon_` id validation, hard-coded `_func` and `policy_id`, body size cap, rate limit). Controls:

1. **Stamp the copies.** A header comment in each copied file records the source and version ("copied from `website-consent` at v0.5.4"). Any fix to one gets applied to the other.
2. **Drift check.** `check-drift.sh` compares the shared parts of the two copies and reports differences. The banner should match exactly apart from changes both copies carry. The proxy should match on the checks listed above. Run it before a release; wire it into CI if one exists.
3. **Keep the proxy copy minimal.** Only the policy and consent endpoints, with the same validation. No demo login, no `link_user` demo flow.

If the duplication becomes a burden, the later fix is to extract the banner and proxy into one shared package that both examples consume. That is a larger refactor and is not justified for this work.

**Release artifact.** `template/dpdp-consent.tpl` is a single file, so it can be handed to partners for manual import, and later submitted to the gallery, without extracting anything else.

## 11. Scope and effort

**In scope (S to M, one engineer):**

1. Banner changes in both copies: `window.DPDPConsentConfig`, exposed `ready()`, return-visit signal (shared with 3.2). About 1 to 2 days.
2. Template `.tpl` with Defaults and Banner modes, field set, mapping, permissions, and in-template tests (GTM's template test runner). About 3 to 5 days.
3. The example module: proxy copy, sample container, demo page, README, drift check. About 2 to 3 days.
4. Section for GTM in the [Website Consent Banner Integration Guide](../guides/website-consent-banner-integration-guide.md) that points to the example. About 0.5 day.
5. Gallery submission and the manual-import fallback. Calendar time depends on Google's review.

**Not in scope:**

- Site key (3.1). Tracked separately.
- Server-side GTM.
- Cookie scanning or automatic tag discovery.
- Auto-blocking third-party tags that do not honour Consent Mode.
- Extracting a shared banner/proxy package.

## 12. Suggested order

1. Prototype the sandbox questions in section 9 (events, `copyFromWindow`, `ready()`) in a throwaway GTM container. If custom events cannot be heard, adopt the `dataLayer` push approach before writing more.
2. Create the example folder with the copied banner and proxy, and apply the banner changes (section 4) to both copies.
3. Build the template and container, and run the section 8 checklist in GTM Preview against the demo page.
4. Add the drift check and the integration guide section.
5. Distribute the `.tpl` to partners, then submit to the gallery.
6. Add the site-key field when 3.1 is decided.

## 13. Decisions needed

1. **Banner change now or later?** The template cannot work without `DPDPConsentConfig` (section 4). Recommended: do it now, in both banner copies, as part of 3.2.
2. **Ship v1 with proxy URL only, or wait for the site key?** Recommended: ship with proxy URL only; most GTM-using partners already have a backend.
3. **Granting rule:** "all mapped purposes" (recommended) or "any".
4. **Who hosts the banner file:** the site (recommended) or a shared CDN of ours.
5. **Standalone example (section 10):** confirmed direction is a self-contained `gtm-consent` folder with stamped copies and a drift check, rather than a subfolder of `website-consent`. Review before building.
