/**
 * TSI DPDP CMS - Standalone Website Consent Banner
 *
 * Drop-in cookie/consent banner + preference center + privacy notice renderer.
 * No dependencies, no build step. UI lives in a Shadow DOM so it cannot clash
 * with your site's CSS.
 *
 * It never holds CMS credentials. It talks to two URLs on YOUR OWN backend
 * (see proxy/server.py), which add the X-API-Key / X-API-Secret headers.
 *
 * Usage:
 *   <script src="consent-banner.js" defer
 *           data-policy-url="/consent-api/policy"
 *           data-consent-url="/consent-api/consent"></script>
 *
 * Optional data- attributes:
 *   data-storage-key   localStorage key prefix        (default "dpdp_consent")
 *   data-expiry-days   re-ask after N days            (default 365)
 *   data-position      "bottom" | "bottom-left" | "bottom-right" (default "bottom")
 *   data-color         accent colour                  (default "#006A67")
 *   data-privacy-url   link to your full privacy page (optional)
 *
 * Gate third-party scripts until consent for a purpose is given:
 *   <script type="text/plain" data-consent-category="purpose_analytics" src="..."></script>
 *
 * Public API (window.DPDPConsent):
 *   open()                 open the preference center
 *   getPreferences()       { purposeId: boolean } or null if no decision yet
 *   hasConsent(purposeId)  boolean
 *   onChange(fn)           fn(preferences) on every save; also fires DOM event "dpdp:consent"
 *   renderNotice(element)  render the full privacy notice into an element
 *
 * Any element with a data-dpdp-open attribute opens the preference center
 * (use it for a "Cookie settings" footer link, which DPDP requires be available
 * so users can change or withdraw consent as easily as they gave it).
 */
(function () {
  'use strict';

  var script = document.currentScript;
  var cfg = {
    policyUrl: attr('data-policy-url'),
    consentUrl: attr('data-consent-url'),
    storageKey: attr('data-storage-key') || 'dpdp_consent',
    expiryDays: parseInt(attr('data-expiry-days'), 10) || 365,
    position: attr('data-position') || 'bottom',
    color: attr('data-color') || '#006A67',
    privacyUrl: attr('data-privacy-url')
  };
  function attr(n) { return script ? script.getAttribute(n) : null; }

  var state = { policy: null, content: null, lang: 'en', prefs: null, listeners: [] };
  var host, root;

  // ---------- helpers ----------
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function anonId() {
    var k = cfg.storageKey + '_anon_id', id = lsGet(k);
    if (!id) {
      id = 'anon_' + (window.crypto && crypto.randomUUID ? crypto.randomUUID() : Date.now() + '_' + Math.random().toString(36).slice(2));
      lsSet(k, id);
    }
    return id;
  }
  function parseMaybeJson(v) {
    if (typeof v === 'string') { try { return JSON.parse(v); } catch (e) { return null; } }
    return v;
  }
  function pickLang(map) {
    var want = (document.documentElement.lang || navigator.language || 'en').toLowerCase();
    var have = Object.keys(map);
    if (have.indexOf(want) > -1) return want;
    var base = want.split('-')[0];
    if (have.indexOf(base) > -1) return base;
    return have.indexOf('en') > -1 ? 'en' : have[0];
  }
  function purposes() { return (state.content && state.content.data_processing_purposes) || []; }
  function label(key, fallback) { return (state.content && state.content.buttons && state.content.buttons[key]) || fallback; }

  // ---------- stored decision ----------
  function readStored() {
    try {
      var d = JSON.parse(lsGet(cfg.storageKey) || 'null');
      if (!d || !d.preferences) return null;
      var exp = new Date(d.timestamp); exp.setDate(exp.getDate() + cfg.expiryDays);
      if (new Date() > exp) return null;
      return d;
    } catch (e) { return null; }
  }

  // ---------- CMS I/O (via your backend) ----------
  function fetchPolicy() {
    return fetch(cfg.policyUrl, { headers: { Accept: 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('policy ' + r.status); return r.json(); })
      .then(function (j) { return j.data || j; });
  }
  function recordConsent(prefs, mechanism) {
    var now = new Date().toISOString();
    var body = {
      user_id: anonId(), // server replaces this with the account id when the visitor is logged in
      policy_version: state.policy.version || '',
      timestamp: now,
      language_selected: state.lang,
      consent_mechanism: mechanism,
      user_agent: navigator.userAgent,
      data_point_consents: purposes().map(function (p) {
        return { data_point_id: p.id, consent_granted: !!prefs[p.id], purpose_agreed_to: p.name, timestamp_updated: now };
      })
    };
    return fetch(cfg.consentUrl, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(function (r) { return r.ok; }).catch(function () { return false; });
  }

  // ---------- consent actions ----------
  function save(prefs, mechanism) {
    state.prefs = prefs;
    lsSet(cfg.storageKey, JSON.stringify({
      preferences: prefs, timestamp: new Date().toISOString(), mechanism: mechanism,
      policyId: state.policy.policy_id, policyVersion: state.policy.version || ''
    }));
    recordConsent(prefs, mechanism); // fire-and-forget; local decision applies immediately
    activateScripts(prefs);
    hideAll();
    state.listeners.forEach(function (fn) { try { fn(prefs); } catch (e) {} });
    document.dispatchEvent(new CustomEvent('dpdp:consent', { detail: prefs }));
  }
  function acceptAll() {
    var p = {}; purposes().forEach(function (x) { p[x.id] = true; }); save(p, 'accept_all_banner');
  }
  function rejectNonEssential() {
    var p = {}; purposes().forEach(function (x) { p[x.id] = !!x.is_mandatory_for_service; }); save(p, 'reject_all_banner');
  }
  function savePrefs() {
    var p = {};
    purposes().forEach(function (x) {
      var el = root.getElementById('t-' + x.id);
      p[x.id] = x.is_mandatory_for_service ? true : !!(el && el.checked);
    });
    save(p, 'preference_center_save');
  }
  function activateScripts(prefs) {
    var nodes = document.querySelectorAll('script[type="text/plain"][data-consent-category]');
    Array.prototype.forEach.call(nodes, function (old) {
      if (!prefs[old.getAttribute('data-consent-category')]) return;
      var s = document.createElement('script');
      Array.prototype.forEach.call(old.attributes, function (a) {
        if (a.name !== 'type' && a.name !== 'data-consent-category') s.setAttribute(a.name, a.value);
      });
      s.text = old.text;
      old.parentNode.replaceChild(s, old);
    });
  }

  // ---------- UI ----------
  var CSS = [
    ':host{all:initial}',
    '*{box-sizing:border-box;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}',
    '.bar{position:fixed;z-index:2147483000;background:#fff;color:#222;border:1px solid #ddd;border-radius:10px;box-shadow:0 6px 28px rgba(0,0,0,.18);padding:16px 18px;max-width:560px;font-size:14px;line-height:1.5;display:none}',
    '.bar.bottom{left:50%;transform:translateX(-50%);bottom:16px;width:calc(100% - 32px);max-width:760px}',
    '.bar.bottom-left{left:16px;bottom:16px;width:calc(100% - 32px)}',
    '.bar.bottom-right{right:16px;bottom:16px;width:calc(100% - 32px)}',
    '.bar h2{margin:0 0 6px;font-size:15px}',
    '.bar p{margin:0}',
    '.row{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}',
    'button{font:inherit;cursor:pointer;border-radius:6px;padding:8px 14px;border:1px solid var(--c);background:var(--c);color:#fff}',
    'button.sec{background:#fff;color:var(--c)}',
    'button.link{border:0;background:none;color:var(--c);text-decoration:underline;padding:8px 4px}',
    'button:focus-visible,summary:focus-visible,input:focus-visible,a:focus-visible{outline:3px solid #f59e0b;outline-offset:2px}',
    '.ov{position:fixed;inset:0;z-index:2147483001;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:16px}',
    '.modal{background:#fff;color:#222;border-radius:12px;max-width:640px;width:100%;max-height:90vh;overflow:auto;padding:20px 22px;font-size:14px;line-height:1.5}',
    '.modal h2{margin:0 0 6px;color:var(--c)}',
    '.card{border:1px solid #e5e5e5;border-radius:8px;padding:12px 14px;margin:10px 0;background:#fafafa}',
    '.card .top{display:flex;justify-content:space-between;align-items:center;gap:12px}',
    '.badge{font-size:11px;font-weight:700;color:#15803d;white-space:nowrap}',
    '.card p{margin:6px 0 0;color:#555;font-size:13px}',
    'details{margin-top:6px;font-size:12.5px;color:#444}',
    'summary{cursor:pointer;color:var(--c)}',
    'dl{margin:6px 0 0;display:grid;grid-template-columns:max-content 1fr;gap:2px 10px}',
    'dt{font-weight:600}dd{margin:0}',
    'input[type=checkbox]{width:20px;height:20px;accent-color:var(--c);cursor:pointer}',
    '.foot{display:flex;justify-content:flex-end;gap:8px;margin-top:14px}'
  ].join('');

  function build() {
    host = document.createElement('div');
    host.setAttribute('data-dpdp-consent', '');
    root = host.attachShadow({ mode: 'open' });
    root.innerHTML =
      '<style>' + CSS + '</style><div style="display:contents;--c:' + esc(cfg.color) + '">' +
      '<div class="bar ' + esc(cfg.position) + '" id="bar" role="dialog" aria-label="Cookie and data consent"></div>' +
      '<div class="ov" id="ov"><div class="modal" id="modal" role="dialog" aria-modal="true" aria-labelledby="mt"></div></div></div>';
    document.body.appendChild(host);
    root.getElementById('ov').addEventListener('click', function (e) { if (e.target.id === 'ov') closePrefs(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closePrefs(); });
  }

  function renderBar() {
    var c = state.content, bar = root.getElementById('bar');
    bar.innerHTML =
      '<h2>' + esc(c.title || 'Your privacy') + '</h2>' +
      '<p>' + esc(c.general_purpose_description || 'We process your data to provide our services.') + '</p>' +
      '<div class="row">' +
      '<button id="acc">' + esc(label('accept_all', 'Accept all')) + '</button>' +
      '<button id="rej" class="sec">' + esc(label('reject_all_non_essential', 'Reject non-essential')) + '</button>' +
      '<button id="mng" class="link">' + esc(label('manage_preferences', 'Manage preferences')) + '</button>' +
      '</div>';
    root.getElementById('acc').onclick = acceptAll;
    root.getElementById('rej').onclick = rejectNonEssential;
    root.getElementById('mng').onclick = openPrefs;
  }

  function purposeDetails(p) {
    var rows = [];
    if (p.legal_basis) rows.push(['Legal basis', p.legal_basis]);
    if (p.data_categories_involved && p.data_categories_involved.length) rows.push(['Data used', p.data_categories_involved.join(', ')]);
    if (p.recipients_or_third_parties && p.recipients_or_third_parties.length) rows.push(['Shared with', p.recipients_or_third_parties.join(', ')]);
    if (p.retention_policy) rows.push(['Retention', p.retention_policy]);
    if (!rows.length) return '';
    return '<details><summary>Details</summary><dl>' +
      rows.map(function (r) { return '<dt>' + esc(r[0]) + '</dt><dd>' + esc(r[1]) + '</dd>'; }).join('') + '</dl></details>';
  }

  function renderPrefs() {
    var c = state.content, cur = state.prefs || {}, html = '';
    html += '<h2 id="mt">' + esc(c.title || 'Privacy preferences') + '</h2>';
    if (c.introduction) html += '<p>' + esc(c.introduction) + '</p>';
    purposes().forEach(function (p) {
      var on = cur[p.id] !== undefined ? cur[p.id] : !!p.is_mandatory_for_service;
      html += '<div class="card"><div class="top"><strong>' + esc(p.name) + '</strong>' +
        (p.is_mandatory_for_service
          ? '<span class="badge">ALWAYS ON</span>'
          : '<input type="checkbox" id="t-' + esc(p.id) + '" aria-label="' + esc(p.name) + '"' + (on ? ' checked' : '') + '>') +
        '</div><p>' + esc(p.description) + '</p>' + purposeDetails(p) + '</div>';
    });
    if (cfg.privacyUrl) html += '<p><a href="' + esc(cfg.privacyUrl) + '" style="color:var(--c)">Read the full privacy policy</a></p>';
    html += '<div class="foot"><button class="sec" id="cl">Close</button><button id="sv">Save my choices</button></div>';
    var m = root.getElementById('modal');
    m.innerHTML = html;
    root.getElementById('sv').onclick = savePrefs;
    root.getElementById('cl').onclick = closePrefs;
  }

  function openPrefs() {
    if (!state.content) return;
    renderPrefs();
    root.getElementById('bar').style.display = 'none';
    root.getElementById('ov').style.display = 'flex';
    var f = root.getElementById('sv'); if (f) f.focus();
  }
  function closePrefs() {
    if (!root) return;
    root.getElementById('ov').style.display = 'none';
    if (!state.prefs) root.getElementById('bar').style.display = 'block';
  }
  function hideAll() {
    root.getElementById('bar').style.display = 'none';
    root.getElementById('ov').style.display = 'none';
  }

  // Full privacy notice, rendered into the host page (e.g. your /privacy page)
  function renderNotice(el) {
    function draw() {
      var c = state.content, h = '<h1>' + esc(c.title || 'Privacy Notice') + '</h1>';
      if (c.introduction) h += '<p>' + esc(c.introduction) + '</p>';
      h += '<p>' + esc(c.general_purpose_description || '') + '</p>';
      purposes().forEach(function (p) {
        h += '<h2>' + esc(p.name) + (p.is_mandatory_for_service ? ' (required)' : '') + '</h2><p>' + esc(p.description) + '</p><ul>';
        if (p.legal_basis) h += '<li><strong>Legal basis:</strong> ' + esc(p.legal_basis) + '</li>';
        if (p.data_categories_involved && p.data_categories_involved.length) h += '<li><strong>Data used:</strong> ' + esc(p.data_categories_involved.join(', ')) + '</li>';
        if (p.recipients_or_third_parties && p.recipients_or_third_parties.length) h += '<li><strong>Shared with:</strong> ' + esc(p.recipients_or_third_parties.join(', ')) + '</li>';
        if (p.retention_policy) h += '<li><strong>Retention:</strong> ' + esc(p.retention_policy) + '</li>';
        h += '</ul>';
      });
      h += '<p><a href="#" data-dpdp-open>Change or withdraw your consent</a></p>';
      el.innerHTML = h;
    }
    if (state.content) draw(); else ready.then(draw);
  }

  // ---------- init ----------
  var ready = new Promise(function (resolve) { state._resolve = resolve; });

  function init() {
    if (!cfg.policyUrl || !cfg.consentUrl) { console.error('DPDP consent: data-policy-url and data-consent-url are required'); return; }
    document.addEventListener('click', function (e) {
      var t = e.target.closest && e.target.closest('[data-dpdp-open]');
      if (t) { e.preventDefault(); openPrefs(); }
    });
    fetchPolicy().then(function (policy) {
      state.policy = policy;
      var map = parseMaybeJson(policy.policy_content || policy);
      if (!map || typeof map !== 'object') throw new Error('unreadable policy content');
      state.lang = pickLang(map);
      state.content = map[state.lang];
      state._resolve();
      build();
      var stored = readStored();
      var current = stored && String(stored.policyVersion) === String(policy.version || '');
      if (current) { state.prefs = stored.preferences; activateScripts(state.prefs); }
      else { renderBar(); root.getElementById('bar').style.display = 'block'; }
    }).catch(function (err) {
      // Fail closed: gated scripts stay blocked, site keeps working.
      console.warn('DPDP consent: banner unavailable -', err.message);
    });
  }

  window.DPDPConsent = {
    open: openPrefs,
    getPreferences: function () { return state.prefs; },
    hasConsent: function (id) { return !!(state.prefs && state.prefs[id]); },
    onChange: function (fn) { state.listeners.push(fn); },
    renderNotice: renderNotice
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
