#!/usr/bin/env python3
"""
Minimal consent proxy + static file server for the website-consent example.

Why this exists: the CMS client API needs X-API-Key / X-API-Secret. Those must
never be shipped to a browser. This server holds them (from environment
variables) and exposes only two narrow endpoints to the page:

    GET  /consent-api/policy    -> CMS get_policy for the configured POLICY_ID
    POST /consent-api/consent   -> CMS record_consent (fields whitelisted)

Pure Python standard library. For production, port the same ~40 lines of logic
into your own backend (Node, Java, PHP, ...) - see the integration guide.

Env:
    CMS_BASE_URL   e.g. http://localhost:8080          (required)
    CMS_API_KEY    App API key (needs READ + WRITE)    (required)
    CMS_API_SECRET App API secret                      (required)
    POLICY_ID      published policy to render          (required)
    PORT           default 8090
    HOST           default 127.0.0.1 (localhost only)
    DEMO_LOGIN     mock sign-in (/demo/login, /demo/logout, /demo/whoami) = fake sessions for
                   trying the account-linking flow. On by default on localhost, off on any other
                   HOST unless set to 1. NEVER enable in production.

User identity rules for POST /consent-api/consent:
    * Logged-in visitor  -> user_id comes from YOUR session, never from the browser.
                            If the browser also sent its anon_ id, it is linked to the account.
    * Anonymous visitor  -> browser id accepted only if it looks like "anon_<token>".
"""
import json, os, re, secrets, sys, urllib.parse, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CMS = os.environ.get("CMS_BASE_URL", "").rstrip("/")
KEY, SECRET, POLICY_ID = (os.environ.get(k, "") for k in ("CMS_API_KEY", "CMS_API_SECRET", "POLICY_ID"))
PORT = int(os.environ.get("PORT", "8090"))
HOST = os.environ.get("HOST", "127.0.0.1")
WEB_ROOT = Path(__file__).resolve().parent.parent
STATIC = {"/": "index.html", "/index.html": "index.html", "/privacy.html": "privacy.html",
          "/consent-banner.js": "consent-banner.js"}
MAX_BODY = 32 * 1024
ANON_ID = re.compile(r"^anon_[A-Za-z0-9_-]{8,64}$")
# Mock sign-in is on by default only while listening on localhost. If you bind
# elsewhere (HOST=0.0.0.0) it stays off unless you explicitly set DEMO_LOGIN=1.
DEMO_LOGIN = os.environ.get("DEMO_LOGIN", "1" if HOST in ("127.0.0.1", "localhost", "::1") else "0") == "1"
DEMO_SESSIONS = {}   # session token -> user id (demo only)
LINKED = set()       # (anon, user) pairs already linked, to avoid repeat calls
DEMO_LOG = []        # recent identity events, shown by the demo page (demo only)


def demo_log(kind, **kw):
    if DEMO_LOGIN:
        DEMO_LOG.append(dict(kind=kind, **kw))
        del DEMO_LOG[:-20]


def link_once(anon, account):
    """Merge an anonymous consent history onto an account (CMS link_user), once per pair."""
    if not ANON_ID.match(anon) or (anon, account) in LINKED:
        return
    st, _ = call_cms("/api/v1/client/consent", {
        "_func": "link_user", "anonymous_user_id": anon, "authenticated_user_id": account})
    if st < 300:
        LINKED.add((anon, account))
        demo_log("link", anon_id=anon, user_id=account)


def session_user(handler):
    """Return the authenticated user's id from YOUR session, or None.

    REPLACE THIS with a lookup into your real session/JWT. It must come from
    something the browser cannot forge (server-side session, signed cookie).
    The demo uses an in-memory table filled by /demo/login.
    """
    for part in handler.headers.get("Cookie", "").split(";"):
        name, _, val = part.strip().partition("=")
        if name == "demo_sid":
            return DEMO_SESSIONS.get(val)
    return None


def call_cms(path, payload):
    req = urllib.request.Request(
        CMS + path, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": KEY, "X-API-Secret": SECRET})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception:
        return 502, b'{"error":"CMS unreachable"}'


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if DEMO_LOGIN and path == "/demo/login":
            m = re.search(r"user=([^&]+)", self.path)
            user = urllib.parse.unquote(m.group(1)) if m else ""
            if not user or len(user) > 128:
                return self._send(400, b'{"error":"user required"}')
            sid = secrets.token_urlsafe(24)
            DEMO_SESSIONS[sid] = user
            m2 = re.search(r"anon=([^&]+)", self.path)
            if m2:
                link_once(urllib.parse.unquote(m2.group(1)), user)  # what your login handler should do
            body = json.dumps({"user": user}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", f"demo_sid={sid}; Path=/; HttpOnly; SameSite=Lax")
            self.end_headers()
            self.wfile.write(body)
            return
        if DEMO_LOGIN and path == "/demo/whoami":
            return self._send(200, json.dumps({"user": session_user(self), "events": DEMO_LOG}).encode())
        if DEMO_LOGIN and path == "/demo/logout":
            body = b'{"user":null}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "demo_sid=; Path=/; Max-Age=0")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/consent-api/policy":
            code, body = call_cms("/api/v1/client/policy", {"_func": "get_policy", "policy_id": POLICY_ID})
            return self._send(code, body)
        if path in STATIC:
            f = WEB_ROOT / STATIC[path]
            if f.is_file():
                ctype = "text/javascript" if f.suffix == ".js" else "text/html; charset=utf-8"
                return self._send(200, f.read_bytes(), ctype)
        self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path.split("?")[0] != "/consent-api/consent":
            return self._send(404, b'{"error":"not found"}')
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0 or n > MAX_BODY:
                raise ValueError
            body = json.loads(self.rfile.read(n))
            points = body["data_point_consents"]
            browser_id = str(body["user_id"])
            if not isinstance(points, list):
                raise ValueError
        except Exception:
            return self._send(400, b'{"error":"bad request"}')

        # Identity: the server decides who this is, not the browser.
        account = session_user(self)
        if account:
            user_id = account
            link_once(browser_id, account)
        elif ANON_ID.match(browser_id):
            user_id = browser_id
        else:
            return self._send(400, b'{"error":"invalid user id"}')

        # Whitelist: the browser cannot choose _func, policy, or anything else.
        payload = {
            "_func": "record_consent",
            "policy_id": POLICY_ID,
            "user_id": user_id,
            "policy_version": str(body.get("policy_version", "")),
            "timestamp": str(body.get("timestamp", "")),
            "language_selected": str(body.get("language_selected", "en")),
            "consent_mechanism": str(body.get("consent_mechanism", "")),
            "user_agent": self.headers.get("User-Agent", ""),
            "data_point_consents": [
                {"data_point_id": str(p["data_point_id"]), "consent_granted": bool(p["consent_granted"]),
                 "purpose_agreed_to": str(p.get("purpose_agreed_to", "")),
                 "timestamp_updated": str(p.get("timestamp_updated", ""))}
                for p in points if isinstance(p, dict) and "data_point_id" in p],
        }
        code, out = call_cms("/api/v1/client/consent", payload)
        if code < 300:
            demo_log("consent", user_id=user_id, anon_id=browser_id if ANON_ID.match(browser_id) else None,
                     granted=[p["data_point_id"] for p in payload["data_point_consents"] if p["consent_granted"]])
        self._send(code, out)


if __name__ == "__main__":
    missing = [k for k, v in (("CMS_BASE_URL", CMS), ("CMS_API_KEY", KEY), ("CMS_API_SECRET", SECRET), ("POLICY_ID", POLICY_ID)) if not v]
    if missing:
        sys.exit("Missing env vars: " + ", ".join(missing))
    print(f"Serving demo on http://{HOST}:{PORT}  (CMS: {CMS})")
    if DEMO_LOGIN:
        print("Mock sign-in is ON (fake sessions). Do not expose this server publicly.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
