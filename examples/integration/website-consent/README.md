# Website Consent Banner (standalone example)

A drop-in cookie / consent banner, preference center and privacy-notice renderer
for any website, backed by TSI DPDP CMS. No framework, no build step.

| File | Purpose |
|---|---|
| `consent-banner.js` | The widget. Shadow-DOM UI, script gating, public JS API. |
| `proxy/server.py` | Tiny stdlib proxy that holds the API key/secret server-side. Replace with a few lines in your own backend for production. |
| `index.html` | Demo page with the banner, a gated script and a "Cookie settings" link. |
| `privacy.html` | Demo of a privacy notice page rendered live from the published policy. |

## Run the demo

```bash
# Needs a published policy and an App API key with READ + WRITE scopes.
CMS_BASE_URL=http://localhost:8080 \
CMS_API_KEY=<uuid> CMS_API_SECRET=<secret> \
POLICY_ID=<published policy id> \
python3 proxy/server.py
# open http://localhost:8090
```

To try the sign-in flow: accept cookies, and the page shows the anonymous user id with a
**Sign in** button. Sign in with any email in the popup and the id changes to the account id; the
page also lists the `link_user` and `record_consent` calls the proxy made. The sign-in is a fake
session and is on by default only because the proxy listens on `127.0.0.1`. If you set `HOST` to
anything else it turns off unless you set `DEMO_LOGIN=1`. Never enable it in production. See guide
section 10.

The demo's gated script is tied to `purpose_analytics`, which matches the sample policy
`examples/policy/website/website_visitor_v1.json` (RoPA: `examples/ropa/website/website_visitor_v1.txt`).
Use another policy by changing `data-consent-category` in `index.html`.

Full details, security notes and production guidance:
[Website Consent Banner Integration Guide](../../../docs/guides/website-consent-banner-integration-guide.md).
