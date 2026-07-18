/**
 * TSI DPDP CMS — Data Principal Self-Service Portal
 * Shared session management and API utilities.
 * All session state is stored in sessionStorage (auto-clears on tab close).
 */

const PORTAL_BASE_URL = window.location.origin;

const SESSION_KEYS = {
    token:          'pp_token',
    userId:         'pp_user_id',
    fiduciaryId:    'pp_fiduciary_id',
    fiduciaryName:  'pp_fiduciary_name',
    policies:       'pp_policies',  // JSON array of { policy_id, version, jurisdiction, title, personas }
    pcaQrEnabled:   'pp_pca_qr_enabled',
    persona:        'pp_persona',   // the persona (e.g. "employee") the principal declared pre-login
    syncToken:      'pp_sync_token' // long-lived wallet sync token, issued at login regardless of consent history
};

function getSession() {
    const token = sessionStorage.getItem(SESSION_KEYS.token);
    if (!token) return null;
    return {
        token:         token,
        userId:        sessionStorage.getItem(SESSION_KEYS.userId),
        fiduciaryId:   sessionStorage.getItem(SESSION_KEYS.fiduciaryId),
        fiduciaryName: sessionStorage.getItem(SESSION_KEYS.fiduciaryName),
        policies:      getSessionPolicies(),
        pcaQrEnabled:  sessionStorage.getItem(SESSION_KEYS.pcaQrEnabled) !== 'false',
        persona:       sessionStorage.getItem(SESSION_KEYS.persona) || null,
        syncToken:     sessionStorage.getItem(SESSION_KEYS.syncToken) || null
    };
}

function saveSession(data) {
    const policies = filterPoliciesByPersona(data.policies || [], data.persona);
    sessionStorage.setItem(SESSION_KEYS.token,         data.token          || '');
    sessionStorage.setItem(SESSION_KEYS.userId,        data.user_id        || '');
    sessionStorage.setItem(SESSION_KEYS.fiduciaryId,   data.fiduciary_id   || '');
    sessionStorage.setItem(SESSION_KEYS.fiduciaryName, data.fiduciary_name || '');
    sessionStorage.setItem(SESSION_KEYS.policies,      JSON.stringify(policies));
    sessionStorage.setItem(SESSION_KEYS.pcaQrEnabled,  String(data.pca_qr_enabled !== false));
    sessionStorage.setItem(SESSION_KEYS.persona,       data.persona || '');
    sessionStorage.setItem(SESSION_KEYS.syncToken,     data.sync_token || '');
}

/**
 * Scopes the policies shown in the portal to the ones tagged for the declared persona
 * (e.g. an Employee shouldn't see a Customer-only policy). Falls back to the full list
 * when there's no persona, or when none of the policies carry a matching tag -- a DPO's
 * data_subject_categories tagging may be incomplete, and hiding every policy would be
 * worse than showing an unfiltered list.
 */
function filterPoliciesByPersona(policies, persona) {
    if (!persona) return policies;
    const p = persona.toLowerCase();
    const matched = policies.filter(pol => (pol.personas || []).some(c => (c || '').toLowerCase() === p));
    return matched.length > 0 ? matched : policies;
}

function getSessionPolicies() {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEYS.policies) || '[]'); }
    catch { return []; }
}

function getPolicyTitle(policyId) {
    const policies = getSessionPolicies();
    const match = policies.find(p => p.policy_id === policyId);
    return match ? match.title : policyId;
}

function getPersonaLabel(personaId) {
    if (!personaId) return '';
    return personaId.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function clearSession() {
    Object.values(SESSION_KEYS).forEach(k => sessionStorage.removeItem(k));
}

function requireAuth() {
    const session = getSession();
    if (!session) {
        window.location.href = 'index.html';
        return null;
    }
    return session;
}

async function apiCall(path, func, bodyExtra) {
    const session = getSession();
    const headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    };
    if (session) {
        headers['Authorization'] = 'Bearer ' + session.token;
    }
    const body = JSON.stringify({ _func: func, ...bodyExtra });
    try {
        const res = await fetch(PORTAL_BASE_URL + path, { method: 'POST', headers, body });
        if (res.status === 401) {
            clearSession();
            window.location.href = 'index.html';
            return null;
        }
        return await res.json();
    } catch (e) {
        console.error('Portal API error:', e);
        return null;
    }
}

async function publicApiCall(path, func, bodyExtra) {
    const headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    };
    const body = JSON.stringify({ _func: func, ...bodyExtra });
    const res = await fetch(PORTAL_BASE_URL + path, { method: 'POST', headers, body });
    return await res.json();
}

function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

function formatTimestamp(iso) {
    return iso ? new Date(iso).toLocaleString() : 'N/A';
}

function getStatusBadge(status) {
    const s = (status || '').toUpperCase();
    const colors = {
        'ACTIVE':             'background:#f0fdf4;color:#15803d;border-color:#bbf7d0',
        'CONSENT_GIVEN':      'background:#f0fdf4;color:#15803d;border-color:#bbf7d0',
        'RESOLVED':           'background:#f0fdf4;color:#15803d;border-color:#bbf7d0',
        'IN_PROGRESS':        'background:#fefce8;color:#a16207;border-color:#fde68a',
        'PENDING_DPO_REVIEW': 'background:#fefce8;color:#a16207;border-color:#fde68a',
        'WITHDRAWN':            'background:#fef2f2;color:#b91c1c;border-color:#fecaca',
        'CONSENT_WITHDRAWN':    'background:#fef2f2;color:#b91c1c;border-color:#fecaca',
        'PARTIALLY WITHDRAWN':  'background:#fefce8;color:#a16207;border-color:#fde68a',
        'ERASURE_REQUEST':      'background:#fef2f2;color:#b91c1c;border-color:#fecaca'
    };
    const style = colors[s] || 'background:#f8fafc;color:#475569;border-color:#e2e8f0';
    return `<span style="font-size:0.65rem;padding:2px 8px;border-radius:9999px;text-transform:uppercase;font-weight:800;border:1px solid;${style}">${esc(s.replace(/_/g, ' '))}</span>`;
}

function resolvePolicyContent(data) {
    let content = data.policy_content || data;
    if (typeof content === 'string') {
        try { content = JSON.parse(content); } catch (e) {}
    }
    return content;
}

function getPreferredLanguage(policyMap) {
    const lang = (document.documentElement.lang || navigator.language || 'en').toLowerCase();
    const available = Object.keys(policyMap);
    if (available.includes(lang)) return lang;
    const base = lang.split('-')[0];
    if (available.includes(base)) return base;
    return available.includes('en') ? 'en' : available[0];
}
