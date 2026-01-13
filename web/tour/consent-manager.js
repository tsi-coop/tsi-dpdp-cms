/**
 * TSI DPDP Consent Manager
 * Version: 1.3 (Identity Consolidation Update)
 * Features: Robust JSON parsing, Tour Link interception, and Interactive Link User flow.
 */

// --- Configuration & Constants ---
const CONSENT_LOCAL_STORAGE_KEY = `${config.tsi_dpdp_cms_localstoragekey}`;
const CONSENT_EXPIRY_DAYS = parseInt(`${config.tsi_dpdp_cms_consentexpiry}`);
const API_BASE_URL = `${config.tsi_dpdp_cms_apibaseurl}`;
const POLICY_API_ENDPOINT = `${API_BASE_URL}/api/v1/client/policy`;
const CONSENT_API_ENDPOINT = `${API_BASE_URL}/api/v1/client/consent`;

let API_KEY = null;
let API_SECRET = null;
let POLICY_ID = null;
let currentPolicy = null;
let currentLanguageContent = null;
let consentCategoriesConfig = {};

// --- DOM Elements ---
const cookieBanner = document.getElementById('cookie-consent-banner');
const preferenceCenterOverlay = document.getElementById('preference-center-overlay');
const preferenceCenterContent = preferenceCenterOverlay ? preferenceCenterOverlay.querySelector('.preference-center-content') : null;

// --- Helper Functions ---

/**
 * Display a custom modal that appears above all other UI elements.
 */
function displayCustomModal(title, bodyHtml, actionButtonHtml = '') {
    const existing = document.getElementById('custom-message-modal-overlay');
    if (existing) existing.remove();

    let modalHtml = `
        <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 3000;" id="custom-message-modal-overlay">
            <div style="background-color: white; padding: 25px; border-radius: 8px; max-width: 500px; width: 90%; max-height: 90vh; overflow-y: auto; font-family: Arial, sans-serif; color: #333; position: relative;">
                <button style="position: absolute; top: 10px; right: 10px; background: none; border: none; font-size: 1.5em; cursor: pointer; color: #888;" onclick="document.getElementById('custom-message-modal-overlay').remove();">&times;</button>
                <h2 style="color:#006A67; margin-top:0;">${title}</h2>
                <div style="font-size: 0.95em; margin-top: 15px; line-height: 1.5;">${bodyHtml}</div>
                <div style="margin-top:20px;">${actionButtonHtml}</div>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}

/**
 * Logic to initiate the Link User popup and API call.
 */
function initiateLinkPrincipalFlow() {
    const anonymousUserId = localStorage.getItem('tsi_dpdp_cms_anon_id');
    const existingPrincipal = localStorage.getItem('tsi_dpdp_cms_principal_id');

    if (existingPrincipal) {
        displayCustomModal("Account Already Linked", `This session is already associated with Data Principal: <strong>${existingPrincipal}</strong>. No further linking required.`);
        return;
    }

    const bodyHtml = `
        <p>Consolidate your anonymous choices with your official account to manage your data rights across devices.</p>
        <div style="margin-top:15px; text-align: left;">
            <label style="display:block; font-size:0.8em; font-weight:bold; margin-bottom:5px; color:#555;">Full Name</label>
            <input type="text" id="link-user-name" style="width:100%; padding:10px; border:1px solid #ccc; border-radius:6px; margin-bottom:15px; box-sizing: border-box;" placeholder="Enter your name">

            <label style="display:block; font-size:0.8em; font-weight:bold; margin-bottom:5px; color:#555;">Email Address (Authenticated ID)</label>
            <input type="email" id="link-user-email" style="width:100%; padding:10px; border:1px solid #ccc; border-radius:6px; box-sizing: border-box;" placeholder="email@example.com">
            <p style="font-size: 0.75em; color: #888; margin-top: 8px;">Your current ID: <strong>${anonymousUserId || 'Pending'}</strong></p>
        </div>
    `;

    const actionHtml = `
        <button id="submit-link-btn" style="background:#006A67; color:white; border:none; padding:12px 20px; border-radius:6px; cursor:pointer; width:100%; font-weight:bold; font-size: 1em;">Submit & Link Account</button>
    `;

    displayCustomModal("Link Data Principal", bodyHtml, actionHtml);

    document.getElementById('submit-link-btn').onclick = async () => {
        const name = document.getElementById('link-user-name').value.trim();
        const email = document.getElementById('link-user-email').value.trim();

        if (!name || !email) {
            alert("Please provide both name and email.");
            return;
        }

        const btn = document.getElementById('submit-link-btn');
        btn.disabled = true;
        btn.textContent = "Processing Identity...";

        try {
            const payload = {
                "_func": "link_user",
                "anonymous_user_id": anonymousUserId,
                "authenticated_user_id": email,
                "meta": { "name": name, "source": "tour_demo" }
            };

            const response = await fetch(CONSENT_API_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json; charset=UTF-8',
                    'X-API-Key': API_KEY,
                    'X-API-Secret': API_SECRET
                },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                // Persist the linked identity
                localStorage.setItem('tsi_dpdp_cms_principal_id', email);
                displayCustomModal("Identity Linked!", `<div style="text-align:center;">
                    <p>Successfully linked <strong>${anonymousUserId}</strong> to <strong>${email}</strong>.</p>
                    <p style="color: #28a745; font-weight:bold; margin-top:10px;">Audit trail updated for compliance.</p>
                </div>`);
            } else {
                throw new Error("API Rejected request");
            }
        } catch (e) {
            console.error("Linking error:", e);
            alert("Linking failed. Ensure the CMS backend is reachable.");
            btn.disabled = false;
            btn.textContent = "Submit & Link Account";
        }
    };
}

/**
 * Detects if the policy_content is a string (JDBC JSONB leak) or Object and resolves it.
 */
function resolvePolicyContent(data) {
    let content = data.policy_content || data;
    if (typeof content === 'string') {
        try {
            content = JSON.parse(content);
        } catch (e) {
            console.error("Critical: Policy content is an invalid JSON string.", e);
        }
    }
    return content;
}

/**
 * Detects user language and falls back to English or first available.
 */
function getPreferredLanguage(policyMap) {
    const lang = (document.documentElement.lang || navigator.language || 'en').toLowerCase();
    const availableLangs = Object.keys(policyMap);
    if (availableLangs.includes(lang)) return lang;
    const baseLang = lang.split('-')[0];
    if (availableLangs.includes(baseLang)) return baseLang;
    return availableLangs.includes('en') ? 'en' : availableLangs[0];
}

async function fetchConsentPolicy() {
    try {
        const response = await fetch(`${POLICY_API_ENDPOINT}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'X-API-Key': API_KEY,
                'X-API-Secret': API_SECRET
            },
            body: JSON.stringify({ "_func": "get_policy", "policy_id": POLICY_ID })
        });
        if (!response.ok) return null;
        const data = await response.json();
        return data.data || data;
    } catch (error) {
        console.error("Policy API unreachable", error);
        return null;
    }
}

function getConsentState() {
    try {
        const stored = localStorage.getItem(CONSENT_LOCAL_STORAGE_KEY);
        if (stored) {
            const data = JSON.parse(stored);
            const expiryDate = new Date(data.timestamp);
            expiryDate.setDate(expiryDate.getDate() + CONSENT_EXPIRY_DAYS);
            if (new Date() < expiryDate) return data.preferences;
        }
    } catch (e) {}
    return null;
}

async function saveConsentState(preferences, mechanism) {
    const consentData = {
        preferences: preferences,
        timestamp: new Date().toISOString(),
        mechanism: mechanism,
        policyVersion: currentPolicy.version || "1.0",
        policyId: currentPolicy.policy_id || POLICY_ID
    };
    localStorage.setItem(CONSENT_LOCAL_STORAGE_KEY, JSON.stringify(consentData));
    await invokeBackendConsentAPI(preferences, mechanism);
    applyConsent(preferences);
    if (cookieBanner) cookieBanner.style.display = 'none';
}

async function invokeBackendConsentAPI(preferences, mechanism) {
    const userId = localStorage.getItem('tsi_dpdp_cms_principal_id') || localStorage.getItem('tsi_dpdp_cms_anon_id') || `anon_${Date.now()}`;
    localStorage.setItem('tsi_dpdp_cms_anon_id', userId);

    const payload = {
        _func: 'record_consent',
        user_id: userId,
        fiduciary_id: currentPolicy.fiduciary_id || localStorage.getItem('fiduciary_id'),
        policy_id: currentPolicy.policy_id || POLICY_ID,
        policy_version: currentPolicy.version || "1.0",
        timestamp: new Date().toISOString(),
        consent_mechanism: mechanism,
        data_point_consents: Object.keys(preferences).map(id => ({
            data_point_id: id,
            consent_granted: preferences[id],
            timestamp_updated: new Date().toISOString()
        }))
    };

    try {
        await fetch(CONSENT_API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY, 'X-API-Secret': API_SECRET },
            body: JSON.stringify(payload)
        });
    } catch (e) {}
}

function applyConsent(preferences) {
    document.querySelectorAll('script[type="text/plain"][data-consent-category]').forEach(script => {
        const cat = script.dataset.consentCategory;
        if (preferences[cat] && script.type !== 'text/javascript') {
            const news = document.createElement('script');
            Array.from(script.attributes).forEach(a => { if (a.name !== 'type') news.setAttribute(a.name, a.value); });
            news.text = script.text;
            if (script.src) news.src = script.src;
            script.parentNode.replaceChild(news, script);
            console.log(`Compliance: Activated script for purpose [${cat}]`);
        }
    });
}

// --- Dynamic UI Rendering ---

function renderCookieBanner() {
    if (!currentLanguageContent || !cookieBanner) return;
    const btn = currentLanguageContent.buttons || {};
    cookieBanner.innerHTML = `
        <p style="margin:0;">${currentLanguageContent.general_purpose_description || 'We process data to provide better services.'}.</p>
        <div style="display:flex; gap:10px; margin-top:10px;">
            <button id="accept-all-btn" style="background:#006A67; color:white; border:none; padding:8px 15px; border-radius:5px; cursor:pointer;">${btn.accept_all || 'Accept All'}</button>
            <button id="reject-all-btn" style="background:#666; color:white; border:none; padding:8px 15px; border-radius:5px; cursor:pointer;">${btn.reject_all_non_essential || 'Reject Non-Essential'}</button>
            <button id="manage-prefs-btn" style="background:transparent; border:1px solid #ccc; color:white; padding:8px 15px; border-radius:5px; cursor:pointer;">${btn.manage_preferences || 'Preferences'}</button>
        </div>
    `;
    document.getElementById('accept-all-btn').onclick = handleAcceptAll;
    document.getElementById('reject-all-btn').onclick = handleRejectAll;
    document.getElementById('manage-prefs-btn').onclick = handleManagePreferences;
    cookieBanner.style.display = 'flex';
}

function renderPreferenceCenter() {
    if (!currentLanguageContent || !preferenceCenterContent) return;
    let html = `
        <div style="display:flex; justify-content:flex-end;"><button onclick="closePreferenceCenter()" style="border:none; background:none; font-size:1.5rem; cursor:pointer; color:#888;">&times;</button></div>
        <h2 style="color:#006A67;">${currentLanguageContent.title}</h2>
        <div style="margin-top:20px;">
    `;
    (currentLanguageContent.data_processing_purposes || []).forEach(p => {
        html += `
            <div style="padding:15px; border:1px solid #eee; border-radius:8px; margin-bottom:10px; background:#f9f9f9;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <strong style="color:#333;">${p.name}</strong>
                    ${p.is_mandatory_for_service ? '<span style="color:green; font-size:0.7rem; font-weight:bold;">MANDATORY</span>' : `
                        <input type="checkbox" id="toggle-${p.id}" style="width:20px; height:20px; cursor:pointer;">
                    `}
                </div>
                <p style="font-size:0.8em; color:#666; margin-top:5px;">${p.description}</p>
            </div>
        `;
    });
    html += `</div><div style="text-align:right; margin-top:20px;"><button id="save-prefs-btn" style="background:#006A67; color:white; border:none; padding:12px 25px; border-radius:4px; cursor:pointer; font-weight:bold;">Save My Choices</button></div>`;
    preferenceCenterContent.innerHTML = html;
    document.getElementById('save-prefs-btn').onclick = handleSavePreferences;
}

// --- Event Handlers & Tour Logic ---

function handleAcceptAll() {
    const prefs = {};
    currentLanguageContent.data_processing_purposes.forEach(p => prefs[p.id] = true);
    saveConsentState(prefs, 'accept_all_banner');
}

function handleRejectAll() {
    const prefs = {};
    currentLanguageContent.data_processing_purposes.forEach(p => prefs[p.id] = p.is_mandatory_for_service);
    saveConsentState(prefs, 'reject_all_banner');
}

function handleManagePreferences() {
    const prefs = getConsentState() || {};
    (currentLanguageContent.data_processing_purposes || []).forEach(p => {
        const el = document.getElementById(`toggle-${p.id}`);
        if (el) el.checked = prefs[p.id] !== undefined ? prefs[p.id] : p.is_mandatory_for_service;
    });
    preferenceCenterOverlay.style.display = 'flex';
    if (cookieBanner) cookieBanner.style.display = 'none';
}

function handleSavePreferences() {
    const prefs = {};
    currentLanguageContent.data_processing_purposes.forEach(p => {
        const el = document.getElementById(`toggle-${p.id}`);
        prefs[p.id] = el ? el.checked : p.is_mandatory_for_service;
    });
    saveConsentState(prefs, 'save_preferences_center');
    preferenceCenterOverlay.style.display = 'none';
}

function closePreferenceCenter() { preferenceCenterOverlay.style.display = 'none'; }

// --- Tour Module Interactions ---

function displayCurrentPreferencesAsJson() {
    const stored = localStorage.getItem(CONSENT_LOCAL_STORAGE_KEY);
    const body = stored ? `<pre style="background:#f4f4f4; padding:10px; border-radius:4px; font-size:0.8em; overflow-x:auto;">${JSON.stringify(JSON.parse(stored), null, 2)}</pre>` : '<p>No consent record found yet. Please interact with the banner first.</p>';
    displayCustomModal("Auditable Consent Artifact", body);
}

// --- Initialization ---

async function initConsentManager() {
    API_KEY = config.tsi_dpdp_cms_apikey;
    API_SECRET = config.tsi_dpdp_cms_apisecret;
    POLICY_ID = config.tsi_dpdp_cms_policyid;

    currentPolicy = await fetchConsentPolicy();
    if (!currentPolicy) {
        console.warn("Consent Manager: Waiting for valid policy connection...");
        return;
    }

    const map = resolvePolicyContent(currentPolicy);
    const lang = getPreferredLanguage(map);
    currentLanguageContent = map[lang];

    renderCookieBanner();
    renderPreferenceCenter();

    // setupLink Helper: Prevents default navigation for tour elements
    const setupLink = (id, fn) => {
        const el = document.getElementById(id);
        if (el) el.onclick = (e) => { e.preventDefault(); fn(); };
    };

    setupLink('view-preferences', displayCurrentPreferencesAsJson);

    setupLink('validate-add-post', () => {
        const state = getConsentState();
        if (state && state.purpose_community_engagement) {
            displayCustomModal("Access Granted!", "Your consent for 'Community Engagement' is active. You are eligible to add a post.");
        } else {
            displayCustomModal("Access Denied", "This feature requires 'Community Engagement' consent.", `<button onclick="handleManagePreferences()" style="background:#006A67; color:white; border:none; padding:10px 20px; border-radius:4px; cursor:pointer;">Update Preferences</button>`);
        }
    });

    setupLink('validate-provider-zone', () => {
        const state = getConsentState();
        if (state && state.purpose_solution_service_training_showcase) {
            displayCustomModal("Access Granted!", "Verified: 'Solutions & Services Showcase' consent is active. Proceeding to Provider Zone.");
        } else {
            displayCustomModal("Access Denied", "Provider Zone requires 'Solutions & Services Showcase' consent.", `<button onclick="handleManagePreferences()" style="background:#006A67; color:white; border:none; padding:10px 20px; border-radius:4px; cursor:pointer;">Manage Preferences</button>`);
        }
    });

    // Updated handler to call the interactive Link Principal flow
    setupLink('link-principal', initiateLinkPrincipalFlow);

    setupLink('open-cookie-settings', handleManagePreferences);
    setupLink('view-profile', () => displayCustomModal("Authenticated Profile", "This view simulates the dashboard of a linked Data Principal as required by Section 11 of the DPDP Act."));

    // Apply existing consent if found
    const current = getConsentState();
    if (current) {
        applyConsent(current);
        if (cookieBanner) cookieBanner.style.display = 'none';
    }
}