# Plan: WordPress Plugin (TSI DPDP Consent)

**Status:** Proposed. Nothing built yet.
**Distribution:** Implementation partners, via a versioned zip on GitHub Releases. Not listed on wordpress.org.
**Builds on:** the standalone banner in [`examples/integration/website-consent`](../../examples/integration/website-consent/) and the [Website Consent Banner Integration Guide](../guides/website-consent-banner-integration-guide.md).

## 1. Why a plugin, not just a guide

The banner needs a backend that holds the App API key/secret, whitelists requests and decides the user id. In WordPress that is PHP. A guide alone makes every partner rebuild the same code for every client site. A plugin gives partners a repeatable, versioned deliverable.

wordpress.org is skipped deliberately: partners get the zip from us, so we avoid the listing review and its support expectations and keep control of which version is in the field.

## 2. Architecture

```
Visitor's browser ── consent-banner.js ──► WP REST routes (the plugin) ──► TSI DPDP CMS
                                            holds API key/secret            /api/v1/client/policy
                                            decides user id                 /api/v1/client/consent
```

The API key/secret never reach page JavaScript.

## 3. Deliverables

```
examples/integration/wordpress/tsi-dpdp-consent/
  tsi-dpdp-consent.php        bootstrap, hooks, enqueue
  includes/settings.php       settings page
  includes/rest.php           /policy and /consent routes
  includes/cms-client.php     wp_remote_post wrapper
  includes/shortcodes.php
  assets/consent-banner.js    copied from examples/integration/website-consent
  readme.txt, CHANGELOG.md
docs/guides/wordpress-integration-guide.md      partner-facing guide
```

## 4. Scope

| Area | Behaviour |
|---|---|
| Settings (Settings > DPDP Consent, `manage_options`) | CMS base URL, API key, API secret, policy ID, banner position/colour, privacy page URL. Secret may instead be a `wp-config.php` constant (preferred; the options table is plaintext). |
| `GET /wp-json/tsi-dpdp/v1/policy` | Calls `get_policy`; caches in a transient for about 5 minutes. |
| `POST /wp-json/tsi-dpdp/v1/consent` | Hard-codes `_func` and `policy_id`; whitelists fields; enforces `^anon_[A-Za-z0-9_-]{8,64}$`; caps body size; rate-limits per IP. |
| Identity | Logged in: `get_current_user_id()` (the WP user ID, not the email, which can change). Otherwise the `anon_` id. |
| Linking | `link_user` on `wp_login` (needs the anon id server-side, see 5.2), with the consent-time link as fallback. |
| Banner | `wp_enqueue_script`; data attributes added via the `script_loader_tag` filter. |
| Shortcodes | `[tsi_dpdp_privacy_notice]`, `[tsi_dpdp_cookie_settings]`. |
| Script gating | `script_loader_tag` rewrites chosen handles to `type="text/plain" data-consent-category="purpose_..."`; handle-to-purpose map in settings. |
| Language | Widget reads `<html lang>`, which WordPress sets from the site locale. |

## 5. Decisions and required widget changes

1. **REST route with a nonce**, not `admin-ajax`: the current WordPress convention. REST treats a request as logged-out unless it carries `X-WP-Nonce`, so the widget needs a way to send that header (for example a `data-nonce` attribute or a `data-headers` option).
2. **First-party cookie for the anon id.** The widget keeps it only in localStorage, so PHP cannot read it at login. Add an opt-in write of the same value to a cookie (`SameSite=Lax`). Document it in the privacy notice as a cookie identifier.
3. **Caching.** Page caches (WP Rocket, LiteSpeed, etc.) can serve a stale nonce. Fetch the nonce at runtime, or exclude the endpoints from caching.
4. **Visitor IP.** The CMS records the caller's address (the web server, not the visitor). Known limitation; see the website guide.

## 6. Security checklist

- Capability check and nonce on the settings page; sanitise and escape everything.
- No secret in HTML, JS, logs or error messages.
- Public routes: body-size cap, strict validation, rate limit, no echoing of CMS error bodies.
- `uninstall.php` removes options and transients.

## 7. Testing

- Local WordPress (Docker `wordpress` image) plus a mock or real CMS.
- Matrix: logged-out and logged-in; with and without a page-cache plugin; with an analytics plugin (Site Kit or similar).
- Behaviour to prove: banner shows; gated scripts blocked until consent; accept/reject/withdraw recorded; login links the anon id; policy version bump re-prompts; CMS down leaves the site working.
- Known gap to document: scripts injected by other plugins (Site Kit, GTM4WP, Meta Pixel plugins) are not covered by handle-based gating without per-plugin work.

## 8. Partner guide outline (`wordpress-integration-guide.md`)

Install and configure; one App API key per fiduciary with READ + WRITE only; gating other plugins' scripts; caching exclusions; rollout and acceptance checklist; troubleshooting; upgrade procedure.

## 9. Milestones

1. Widget changes (nonce header, anon-id cookie) and tests in `examples/integration/website-consent`.
2. Plugin skeleton: settings, CMS client, REST routes, enqueue.
3. Shortcodes, gating, login linking.
4. Test matrix, fixes, `CHANGELOG`, version 0.1.0 zip.
5. Partner guide and README entry.

## 10. Open questions

- Which partners and client sites can pilot it, and on which caching/analytics plugins?
- Do we want multisite support in 0.1?
- Support model: who answers partner questions about the plugin?
