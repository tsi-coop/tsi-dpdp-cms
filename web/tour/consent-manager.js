// consent-manager.js

// --- Configuration & Constants ---
const configEl = document.getElementById("config-data");
const config = JSON.parse(configEl.textContent);
const CONSENT_LOCAL_STORAGE_KEY = `${config.tsi_dpdp_cms_localstoragekey}`;
const CONSENT_EXPIRY_DAYS = `${config.tsi_dpdp_cms_consentexpiry}`;
const API_BASE_URL = `${config.tsi_dpdp_cms_apibaseurl}`;
const API_KEY = `${config.tsi_dpdp_cms_apikey}`;
const API_SECRET = `${config.tsi_dpdp_cms_apisecret}`;
const POLICY_ID = `${config.tsi_dpdp_cms_policyid}`;
const POLICY_API_ENDPOINT = `${API_BASE_URL}`+'/api/v1/client/policy';

let currentPolicy = null; // Stores the fetched policy JSON
let currentLanguageContent = null; // Stores content for the detected language
let consentCategoriesConfig = {}; // Map of purpose_id to its policy config (name, desc, mandatory etc.)

// --- DOM Elements ---
const cookieBanner = document.getElementById('cookie-consent-banner');
const preferenceCenterOverlay = document.getElementById('preference-center-overlay');
const preferenceCenterContent = preferenceCenterOverlay.querySelector('.preference-center-content');
const savePreferencesBtn = document.getElementById('save-preferences');
const openCookieSettingsLink = document.getElementById('open-cookie-settings');
const viewPreferencesLink = document.getElementById('view-preferences'); // New: Link for viewing preferences
const addPostLink = document.getElementById('validate-add-post'); // New: Link for Add Post functionality
const providerZoneLink = document.getElementById('validate-provider-zone'); // New: Link for Provider Zone functionality
const linkPrincipalLink = document.getElementById('link-principal'); // New: Link for Link Principal functionality

// --- Generic Modal Display Function (MOVED TO TOP OF HELPERS) ---
function displayCustomModal(title, bodyHtml, actionButtonHtml = '') {
    // Remove any existing custom modal before displaying a new one
    const existingModal = document.getElementById('custom-message-modal-overlay');
    if (existingModal) {
        existingModal.remove();
    }

    let modalHtml = `
        <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 1003;" id="custom-message-modal-overlay">
            <div style="background-color: white; padding: 20px; border-radius: 8px; max-width: 500px; width: 90%; max-height: 90vh; overflow-y: auto; font-family: Arial, sans-serif; color: #333;">
                <button style="float: right; background: none; border: none; font-size: 1.5em; cursor: pointer; color: #555;" onclick="document.getElementById('custom-message-modal-overlay').remove();">&times;</button>
                <h2>${title}</h2>
                <p style="font-size: 1em; text-align: center; margin-top: 15px;">${bodyHtml}</p>
                ${actionButtonHtml}
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}
// --- END Generic Modal Display Function ---

// --- Helper Functions ---

/**
 * Detects user's preferred language from browser or default to English.
 * @returns {string} Language code (e.g., 'en', 'ta', 'hi').
 */
function getPreferredLanguage() {
    const lang = document.documentElement.lang || navigator.language || navigator.userLanguage;
    const availableLangs = Object.keys(currentPolicy.policy_content);

    // Check for exact match or base language match
    if (availableLangs.includes(lang.toLowerCase())) return lang.toLowerCase();
    if (availableLangs.includes(lang.split('-')[0].toLowerCase())) return lang.split('-')[0].toLowerCase();

    // Default to English if no match, or first available language
    return availableLangs.includes('en') ? 'en' : availableLangs[0];
}

/**
 * Fetches the active consent policy from the backend.
 * @returns {Promise<Object>} The policy JSON.
 */
async function fetchConsentPolicy() {
    /*
    try {
        const response = await fetch(POLICY_API_ENDPOINT);
        console.log(response);
        if (!response.ok) {
            throw new Error(`Failed to fetch policy: ${response.statusText}`);
        }
        return await response.json();
    } catch (error) {
        console.error("Error fetching consent policy:", error);
        // Fallback: Use a very basic, hardcoded policy or show an error
        return null; // Handle this gracefully in initConsentManager
    }
    */

    // Request payload matches curl example
    const payload = {
        "_func": "get_policy",
        "policy_id": POLICY_ID
    };

    try {
        const response = await fetch(`${POLICY_API_ENDPOINT}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY,
                'X-API-Secret': API_SECRET
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const err = await response.text();
            throw new Error(`Policy fetch failed: ${response.status} - ${err}`);
        }
        const data = await response.json();
        // Assume data structure matches your Policy JSON format.
        // If backend wraps it in {data: ...}, use data.data
        return data.data || data;
    } catch (error) {
        console.error("Error fetching policy:", error);
        alert("Failed to fetch policy. Please check your API credentials or backend status.");
        return null;
    }
}

/**
 * Gets consent state from local storage.
 * @returns {Object|null} Current consent preferences or null if not found/expired.
 */
function getConsentState() {
    try {
        const stored = localStorage.getItem(CONSENT_LOCAL_STORAGE_KEY);
        if (stored) {
            const consentData = JSON.parse(stored);
            const now = new Date();
            const expiryDate = new Date(consentData.timestamp);
            expiryDate.setDate(expiryDate.getDate() + CONSENT_EXPIRY_DAYS);

            if (now < expiryDate && consentData.policyVersion === currentPolicy.version) {
                return consentData.preferences;
            } else {
                console.log('Consent expired or policy version changed. Re-prompting.');
                localStorage.removeItem(CONSENT_LOCAL_STORAGE_KEY); // Clear expired/old consent
                return null;
            }
        }
    } catch (e) {
        console.error("Failed to parse consent from local storage:", e);
        localStorage.removeItem(CONSENT_LOCAL_STORAGE_KEY); // Clear corrupt data
    }
    return null;
}

/**
 * Saves consent state to local storage and invokes backend.
 * @param {Object} preferences - Object like {purpose_id: true/false, ...}
 * @param {string} mechanism - How consent was given (e.g., 'accept_all_banner', 'save_preferences_center')
 */
async function saveConsentState(preferences, mechanism) {
    const consentData = {
        preferences: preferences,
        timestamp: new Date().toISOString(),
        mechanism: mechanism,
        policyVersion: currentPolicy.version,
        policyId: currentPolicy.policy_id
    };
    localStorage.setItem(CONSENT_LOCAL_STORAGE_KEY, JSON.stringify(consentData));
    console.log('Consent saved to local storage:', preferences);

    // Invoke backend API to store consent log
    await invokeBackendConsentAPI(preferences, mechanism);

    applyConsent(preferences); // Apply the changes to the scripts
    cookieBanner.style.display = 'none'; // Hide banner
}

/**
 * Makes an API call to the backend to log the consent decision.
 * @param {Object} preferences - The user's chosen preferences.
 * @param {string} mechanism - The method by which consent was given.
 */
async function invokeBackendConsentAPI(preferences, mechanism) {
    // This user ID should come from your actual user authentication system
    // For a non-logged-in user, you might use a cookie ID or generate a temporary one.
    const userId = localStorage.getItem('tsi_coop_user_id') || `anon_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    localStorage.setItem('tsi_coop_user_id', userId); // Persist anon ID if generated

    const consentPayload = {
        _func:'record_consent',
        user_id: userId,
        fiduciary_id: currentPolicy.fiduciary_id, // Ensure your policy JSON has Fiduciary ID
        policy_id: currentPolicy.policy_id,
        policy_version: currentPolicy.version,
        timestamp: new Date().toISOString(),
        jurisdiction: currentPolicy.jurisdiction || 'IN',
        language_selected: currentLanguageContent.langCode || 'en',
        consent_status_general: Object.values(preferences).every(p => p === true) ? 'granted_all' : (Object.values(preferences).every(p => p === false || (consentCategoriesConfig[Object.keys(preferences).find(key => preferences[key])].is_mandatory_for_service)) ? 'denied_non_essential' : 'custom'),
        consent_mechanism: mechanism,
        ip_address: '0.0.0.0',
        user_agent: navigator.userAgent,
        data_point_consents: Object.keys(preferences).map(purposeId => ({
            data_point_id: purposeId, // Using purposeId as data_point_id
            consent_granted: preferences[purposeId],
            purpose_agreed_to: currentLanguageContent.data_processing_purposes.find(p => p.id === purposeId)?.name || purposeId, // Link to actual purpose name
            timestamp_updated: new Date().toISOString()
        })),
        is_active_consent: true // Always true for the latest consent submitted
    };
    console.log(consentPayload);
    try {
        const response = await fetch(`http://localhost:8080/api/v1/client/consent`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // Add API Key or Authorization header if your backend requires it
                // 'X-API-KEY': 'YOUR_TSI_API_KEY'
            },
            body: JSON.stringify(consentPayload)
        });
        if (response.ok) {
            console.log('Consent log successfully sent to backend!');
        } else {
            const errorData = await response.json();
            console.error('Failed to send consent log to backend:', response.status, errorData);
        }
    } catch (error) {
        console.error('Network error while sending consent log to backend:', error);
    }
}

/**
 * Activates or deactivates scripts based on consent preferences.
 * This function iterates through scripts with data-consent-category and enables/disables them.
 * @param {Object} preferences - The current consent preferences (purposeId: boolean).
 */
function applyConsent(preferences) {
    document.querySelectorAll('script[type="text/plain"][data-consent-category]').forEach(scriptTag => {
        const category = scriptTag.dataset.consentCategory;
        if (preferences[category]) {
            // Check if it's already active (type="text/javascript") to avoid re-execution
            if (scriptTag.type !== 'text/javascript') {
                scriptTag.type = 'text/javascript'; // Change type to activate
                const newScript = document.createElement('script');
                Array.from(scriptTag.attributes).forEach(attr => {
                    if (attr.name !== 'type') {
                        newScript.setAttribute(attr.name, attr.value);
                    }
                });
                newScript.text = scriptTag.text;
                if (scriptTag.src) {
                    newScript.src = scriptTag.src;
                    newScript.onload = () => console.log(`External script for ${category} loaded.`);
                    newScript.onerror = (e) => console.error(`Failed to load external script for ${category}:`, e);
                }
                scriptTag.parentNode.replaceChild(newScript, scriptTag);
                console.log(`Script for purpose "${category}" activated.`);
            }
        } else {
            // Keep it inactive (type="text/plain")
            console.log(`Script for purpose "${category}" remains inactive.`);
        }
    });
}

/**
 * Dynamically renders the cookie banner content from the fetched policy.
 */
function renderCookieBanner() {
    if (!currentLanguageContent || !cookieBanner) return;

    cookieBanner.innerHTML = `
        <p>${currentLanguageContent.general_purpose_description}.</p>
        <br/><br/>
        <div class="button-group">
            <button id="accept-all-cookies">${currentLanguageContent.buttons.accept_all}</button>
            <button id="reject-all-cookies">${currentLanguageContent.buttons.reject_all_non_essential}</button>
            <button id="manage-preferences">${currentLanguageContent.buttons.manage_preferences}</button>
        </div>
    `;

    // Re-attach event listeners as innerHTML overwrites them
    document.getElementById('accept-all-cookies').addEventListener('click', handleAcceptAll);
    document.getElementById('reject-all-cookies').addEventListener('click', handleRejectAll);
    document.getElementById('manage-preferences').addEventListener('click', handleManagePreferences);
}

/**
 * Dynamically renders the preference center content from the fetched policy.
 */
function renderPreferenceCenter() {
    if (!currentLanguageContent || !preferenceCenterContent) return;

    let categoriesHtml = `
        <div style="width:100%;display:flex;flex-direction:row;justify-content:flex-end;">
                <button style="top: 15px; right: 15px; background: none; border: none; font-size: 1.5em; cursor: pointer; color: #555;" onclick="document.getElementById('preference-center-overlay').style.display='none';">&times;</button>
                </div>
        <h2>${currentLanguageContent.title}</h2>
        <p>${currentLanguageContent.general_purpose_description}</p>
        <p>${currentLanguageContent.important_note}</p>
        <div style="margin-top: 20px;">
    `;


    currentLanguageContent.data_processing_purposes.forEach(purpose => {
        const isMandatory = purpose.is_mandatory_for_service;
        const toggleId = `toggle-${purpose.id}`;
        const dataCategoriesNames = purpose.data_categories_involved
            .map(catId => {
                const cat = currentLanguageContent.data_categories_details.find(d => d.id === catId);
                return cat ? cat.name : catId; // Fallback to ID if not found
            })
            .join(', ');
        const thirdPartiesNames = purpose.recipients_or_third_parties && purpose.recipients_or_third_parties.length > 0
            ? purpose.recipients_or_third_parties.join(', ')
            : currentLanguageContent.not_applicable || 'N/A';

        categoriesHtml += `
            <div class="category" data-category="${purpose.id}">
                <h3>${purpose.name}
                    ${isMandatory ? `<span style="color: #28a745; font-size: 0.8em; margin-left: 10px;">(${currentLanguageContent.mandatory_label || 'Mandatory for Service'})</span>` : `
                    <label class="toggle-switch">
                        <input type="checkbox" id="${toggleId}">
                        <span class="slider"></span>
                    </label>
                    `}
                </h3>
                <p>${purpose.description}</p>
                <div class="details">
                    <strong>${currentLanguageContent.legal_basis_label || 'Legal Basis:'}</strong> ${purpose.legal_basis}<br>
                    <strong>${currentLanguageContent.data_categories_label || 'Data Categories:'}</strong> ${dataCategoriesNames}<br>
                    <strong>${currentLanguageContent.third_parties_label || 'Third Parties:'}</strong> ${thirdPartiesNames}<br>
                    <strong>${currentLanguageContent.retention_label || 'Retention:'}</strong> ${purpose.retention_period}<br>
                </div>
            </div>
        `;
    });

    categoriesHtml += `</div>`; // Close categories container
    preferenceCenterContent.innerHTML = categoriesHtml;

    // Append footer buttons (if not already there from HTML)
    let footerButtonsDiv = preferenceCenterContent.querySelector('.footer-buttons');
    if (!footerButtonsDiv) {
        footerButtonsDiv = document.createElement('div');
        footerButtonsDiv.className = 'footer-buttons';
        footerButtonsDiv.innerHTML = `<button id="save-preferences">${currentLanguageContent.buttons.save_preferences}</button>`;
        preferenceCenterContent.appendChild(footerButtonsDiv);
        document.getElementById('save-preferences').addEventListener('click', handleSavePreferences);
    }
}


/**
 * Initializes the preference center checkboxes based on current preferences.
 * @param {Object} currentPreferences - The user's current consent preferences.
 */
function initPreferenceCenter(currentPreferences) {
    currentLanguageContent.data_processing_purposes.forEach(purpose => {
        const toggle = document.getElementById(`toggle-${purpose.id}`);
        if (toggle) {
            if (purpose.is_mandatory_for_service) {
                toggle.checked = true; // Essential always checked
                toggle.disabled = true; // Cannot be unchecked
            } else {
                // Set based on saved preference, defaulting to false if not found
                toggle.checked = currentPreferences[purpose.id] !== undefined ? currentPreferences[purpose.id] : false;
                toggle.disabled = false;
            }
        }
    });
}

// --- New Function: Display Current Preferences as JSON ---
function displayCurrentPreferencesAsJson() {
    const stored = localStorage.getItem(CONSENT_LOCAL_STORAGE_KEY);
    let displayContent;

    if (stored) {
        const consentData = JSON.parse(stored);
        displayContent = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${JSON.stringify(consentData, null, 2)}</pre>`;
    } else {
        displayContent = `
            <p style="text-align: center; font-size: 1.1em; color: #666;">
                No consent preferences found. Please make your choices using the "Manage My Preferences" option.
            </p>
        `;
    }

    let displayHtml = `
        <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 1002;">
            <div style="background-color: white; padding: 20px; border-radius: 8px; max-width: 700px; width: 90%; max-height: 90vh; overflow-y: auto; font-family: monospace; font-size: 0.9em; color: #333;">
                <button style="float: right; background: none; border: none; font-size: 1.5em; cursor: pointer; color: #555;" onclick="this.parentNode.parentNode.remove();">&times;</button>
                <h2>Your Current Consent Preferences</h2>
                ${displayContent}
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', displayHtml);
}

// --- New Function: Validate Add Post Access ---
function validateAddPostAccess() {
     const principalId = localStorage.getItem('tsi_coop_principal_id');
     console.log(principalId);
    // --- New check: If no anonymous ID, display a message and stop ---
    if (principalId === null) {
        displayCustomModal(
                   "Link Principal!",
                   "Your need to login/register first before you can add a post",
                   `<div style="text-align: center; margin-top: 20px;">
                       <button onclick="document.getElementById('custom-message-modal-overlay').remove();"
                               style="background-color: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                           Close
                       </button>
                   </div>`
               );
        return; // Stop execution of the function
    }

    const currentPreferences = getConsentState();
    const engagementPurposeId = "purpose_community_engagement"; // ID from your policy JSON

    // Safely check if the preference exists and is true
    const isEngagedConsentGranted = currentPreferences && currentPreferences[engagementPurposeId] === true;

    let messageTitle;
    let messageBody;
    let actionButtonHtml = '';

    if (isEngagedConsentGranted) {
        messageTitle = "Access Granted!";
        messageBody = "You are eligible to add a post as your 'Community Engagement' preference is enabled.";
        actionButtonHtml = `
            <div style="text-align: center; margin-top: 20px;">
                <button onclick="alert('Proceeding to Add Post functionality!'); document.getElementById('custom-message-modal-overlay').remove();"
                        style="background-color: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                    Proceed to Add Post
                </button>
            </div>
        `;
    } else {
        messageTitle = "Access Denied";
        messageBody = "You are not eligible to add a post. To enable this feature, please update your consent preferences for 'Community Engagement'.";
        actionButtonHtml = `
            <div style="text-align: center; margin-top: 20px;">
                <button onclick="document.getElementById('preference-center-overlay').style.display='flex'; document.getElementById('custom-message-modal-overlay').remove();"
                        style="background-color: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                    Manage Preferences
                </button>
            </div>
        `;
    }

    let displayHtml = `
        <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 1003;" id="custom-message-modal-overlay">
            <div style="background-color: white; padding: 20px; border-radius: 8px; max-width: 500px; width: 90%; max-height: 90vh; overflow-y: auto; font-family: Arial, sans-serif; color: #333;">
                <button style="float: right; background: none; border: none; font-size: 1.5em; cursor: pointer; color: #555;" onclick="document.getElementById('custom-message-modal-overlay').remove();">&times;</button>
                <h2>${messageTitle}</h2>
                <p style="font-size: 1em; text-align: center; margin-top: 15px;">${messageBody}</p>
                ${actionButtonHtml}
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', displayHtml);
}

// --- New Function: Validate ProviderZone Access ---
function validateProviderZoneAccess() {
         const principalId = localStorage.getItem('tsi_coop_principal_id');
         console.log(principalId);
        // --- New check: If no anonymous ID, display a message and stop ---
        if (principalId === null) {
            displayCustomModal(
                       "Link Principal!",
                       "Your need to login/register first before accessing Provider Zone",
                       `<div style="text-align: center; margin-top: 20px;">
                           <button onclick="document.getElementById('custom-message-modal-overlay').remove();"
                                   style="background-color: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                               Close
                           </button>
                       </div>`
                   );
            return; // Stop execution of the function
        }

    const currentPreferences = getConsentState();
    const showcasePurposeId = "purpose_solution_service_training_showcase"; // ID from your policy JSON

    // Safely check if the preference exists and is true
    const isShowcaseConsentGranted = currentPreferences && currentPreferences[showcasePurposeId] === true;

    let messageTitle;
    let messageBody;
    let actionButtonHtml = '';

    if (isShowcaseConsentGranted) {
        messageTitle = "Access Granted!";
        messageBody = "You are eligible to access the Provider Zone as your 'Solutions & Services Showcase' preference is enabled.";
        actionButtonHtml = `
            <div style="text-align: center; margin-top: 20px;">
                <button onclick="alert('Proceeding to Provider Zone!'); document.getElementById('custom-message-modal-overlay').remove();"
                        style="background-color: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                    Proceed to Provider Zone
                </button>
            </div>
        `;
    } else {
        messageTitle = "Access Denied";
        messageBody = "You are not eligible to access the Provider Zone. To enable this feature, please update your consent preferences for 'Solutions & Services Showcase'.";
        actionButtonHtml = `
            <div style="text-align: center; margin-top: 20px;">
                <button onclick="document.getElementById('preference-center-overlay').style.display='flex'; document.getElementById('custom-message-modal-overlay').remove();"
                        style="background-color: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                    Manage Preferences
                </button>
            </div>
        `;
    }

    let displayHtml = `
        <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 1003;" id="custom-message-modal-overlay">
            <div style="background-color: white; padding: 20px; border-radius: 8px; max-width: 500px; width: 90%; max-height: 90vh; overflow-y: auto; font-family: Arial, sans-serif; color: #333;">
                <button style="float: right; background: none; border: none; font-size: 1.5em; cursor: pointer; color: #555;" onclick="document.getElementById('custom-message-modal-overlay').remove();">&times;</button>
                <h2>${messageTitle}</h2>
                <p style="font-size: 1em; text-align: center; margin-top: 15px;">${messageBody}</p>
                ${actionButtonHtml}
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', displayHtml);
}

// --- Link Principal Function ---
async function initiateLinkPrincipalFlow() {
     const principalId = localStorage.getItem('tsi_coop_principal_id');
     console.log(principalId);
    // --- New check: If no anonymous ID, display a message and stop ---
    if (!principalId === false) {
        displayCustomModal(
                   "Account Already Linked!",
                   "Your browser's privacy choices are currently associated with a Data Principal ID",
                   `<div style="text-align: center; margin-top: 20px;">
                       <button onclick="document.getElementById('custom-message-modal-overlay').remove();"
                               style="background-color: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                           Close
                       </button>
                   </div>`
               );
        return; // Stop execution of the function
    }
    // --- End new check ---

    const anonymousUserId = localStorage.getItem('tsi_coop_user_id');
    //console.log(anonymousUserId);
    // --- New check: If no anonymous ID, display a message and stop ---
    if (!anonymousUserId || anonymousUserId.startsWith('anon_') === false) { // Assuming anon IDs start with 'anon_'
        displayCustomModal(
            "No Anonymous ID to Link",
            "There is no anonymous user ID found in your browser's local storage to link. This feature is for users who interacted with the site before logging in.",
            `<div style="text-align: center; margin-top: 20px;">
                <button onclick="document.getElementById('custom-message-modal-overlay').remove();"
                        style="background-color: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                    Close
                </button>
            </div>`
        );
        return; // Stop execution of the function
    }
    // --- End new check ---

    let modalTitle = "Link Your Account";
    let modalBodyHtml = `
        <p>To link your anonymous activity with your user account, please provide your name and email. This helps us consolidate your privacy choices.</p>
        <div style="text-align: left; margin-top: 20px;">
            <label for="link-name" style="display: block; margin-bottom: 5px; font-weight: bold;">Name:</label>
            <input type="text" id="link-name" placeholder="Your Name" style="width: 100%; padding: 8px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px;">
            <label for="link-email" style="display: block; margin-bottom: 5px; font-weight: bold;">Email:</label>
            <input type="email" id="link-email" placeholder="your.email@example.com" style="width: 100%; padding: 8px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px;">
            <p style="font-size: 0.8em; color: #888;">Your current anonymous ID: <strong>${anonymousUserId || 'Not set'}</strong></p>
        </div>
        <div style="text-align: center; margin-top: 20px;">
            <button id="submit-link-principal" style="background-color: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                Submit & Link Account
            </button>
        </div>
    `;

    displayCustomModal(modalTitle, modalBodyHtml);

    const submitButton = document.getElementById('submit-link-principal');
    if (submitButton) {
        submitButton.onclick = async () => {
            const name = document.getElementById('link-name').value;
            const email = document.getElementById('link-email').value;

            if (!name || !email) {
                alert('Please enter both name and email.');
                return;
            }

            // Display loading state
            submitButton.disabled = true;
            submitButton.textContent = 'Linking...';

            try {
                // --- Mock API Call ---
                const mockPrincipalId = await mockLinkPrincipalApiCall(anonymousUserId, name, email);
                // --- End Mock API Call ---

                // Store the principal-id in local storage
                localStorage.setItem('tsi_coop_principal_id', mockPrincipalId);
                console.log(`Principal ID stored: ${mockPrincipalId}`);

                // Update the modal to display the entire localStorage content
                const currentLocalStorageContent = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    currentLocalStorageContent[key] = localStorage.getItem(key);
                }

                const displayHtml = `
                    <h2 style="color: #28a745;">Account Linked Successfully!</h2>
                    <p style="font-size: 1em; text-align: center;">Your anonymous ID has been linked to your Data Principal ID: <strong>${mockPrincipalId}</strong></p>
                    <p style="font-size: 0.9em; text-align: center; margin-top: 20px;">Current Local Storage Content:</p>
                    <pre style="white-space: pre-wrap; word-wrap: break-word; text-align: left; background-color: #f0f0f0; padding: 10px; border-radius: 4px;">${JSON.stringify(currentLocalStorageContent, null, 2)}</pre>
                    <div style="text-align: center; margin-top: 20px;">
                        <button onclick="document.getElementById('custom-message-modal-overlay').remove();"
                                style="background-color: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                            Close
                        </button>
                    </div>
                `;
                // Replace content of the active modal
                document.querySelector('#custom-message-modal-overlay div').innerHTML = displayHtml;

                // In a real scenario, you'd also call your backend API to link the IDs
                // on the server-side as per Functional Design: Link Principal.
                // await fetch(`${API_BASE_URL}/consent/link-user`, {
                //     method: 'POST',
                //     headers: { 'Content-Type': 'application/json' },
                //     body: JSON.stringify({ anonymous_user_id: anonymousUserId, authenticated_user_id: mockPrincipalId, name, email })
                // });

            } catch (error) {
                console.error("Error during linking process:", error);
                alert("Failed to link account. Please try again.");
                submitButton.disabled = false;
                submitButton.textContent = 'Submit & Link Account';
            }
        };
    }
}

// --- Mock API Call for Linking ---
async function mockLinkPrincipalApiCall(anonymousId, name, email) {
    console.log(`MOCK API Call: Linking anonymous ID "${anonymousId}" with Name: "${name}", Email: "${email}"`);
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 500));
    // Simulate server-generated principal ID
    const newPrincipalId = `auth_user_${email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '')}_${Math.random().toString(36).substring(2, 6)}`;
    return newPrincipalId;
}




// --- Event Handlers ---

const handleAcceptAll = () => {
    const preferences = {};
    currentLanguageContent.data_processing_purposes.forEach(purpose => {
        preferences[purpose.id] = true; // Grant consent for all
    });
    saveConsentState(preferences, 'accept_all_banner');
};

const handleRejectAll = () => {
    const preferences = {};
    currentLanguageContent.data_processing_purposes.forEach(purpose => {
        preferences[purpose.id] = purpose.is_mandatory_for_service; // Grant only mandatory
    });
    saveConsentState(preferences, 'reject_all_banner');
};

const viewPreferences = () => {
    const currentPreferences = getConsentState() || {};
    // Ensure all purposes have a default if not found in stored consent
    currentLanguageContent.data_processing_purposes.forEach(purpose => {
        if (currentPreferences[purpose.id] === undefined) {
             currentPreferences[purpose.id] = purpose.is_mandatory_for_service; // Default to mandatory if not present
        }
    });
    viewPreferencesOverlay.style.display = 'flex';
    preferenceCenterOverlay.style.display = 'none'; // Show preference center
    cookieBanner.style.display = 'none'; // Hide banner
};




const handleManagePreferences = () => {
    const currentPreferences = getConsentState() || {};
    // Ensure all purposes have a default if not found in stored consent
    currentLanguageContent.data_processing_purposes.forEach(purpose => {
        if (currentPreferences[purpose.id] === undefined) {
             currentPreferences[purpose.id] = purpose.is_mandatory_for_service; // Default to mandatory if not present
        }
    });
    initPreferenceCenter(currentPreferences);
    preferenceCenterOverlay.style.display = 'flex'; // Show preference center
    cookieBanner.style.display = 'none'; // Hide banner
};

const handleSavePreferences = () => {
    const preferences = {};
    currentLanguageContent.data_processing_purposes.forEach(purpose => {
        const toggle = document.getElementById(`toggle-${purpose.id}`);
        if (toggle) {
            preferences[purpose.id] = toggle.checked;
        } else {
            // For mandatory purposes that might not have a toggle (if applicable)
            preferences[purpose.id] = purpose.is_mandatory_for_service;
        }
    });
    saveConsentState(preferences, 'save_preferences_center');
    preferenceCenterOverlay.style.display = 'none'; // Hide preference center
};

openCookieSettingsLink.addEventListener('click', (e) => {
    e.preventDefault(); // Prevent page jump
    handleManagePreferences(); // Re-use manage preferences logic
});

// New Event Listener for "View Preferences"
if (viewPreferencesLink) {
    viewPreferencesLink.addEventListener('click', (e) => {
        e.preventDefault();
        displayCurrentPreferencesAsJson();
    });
}

// Add event listener for "Add Post" link
if (addPostLink) {
    addPostLink.addEventListener('click', (e) => {
        e.preventDefault(); // Prevent default link behavior
        validateAddPostAccess(); // Call our new validation function
    });
}

// Add event listener for "Provider Zone" link
if (providerZoneLink) {
    providerZoneLink.addEventListener('click', (e) => {
        e.preventDefault(); // Prevent default link behavior
        validateProviderZoneAccess(); // Call our new validation function
    });
}

// Add event listener for "Link Principal" link
if (linkPrincipalLink) {
    linkPrincipalLink.addEventListener('click', (e) => {
        e.preventDefault();
        initiateLinkPrincipalFlow();
    });
}

// --- Initialization ---
async function initConsentManager() {
    currentPolicy = await fetchConsentPolicy();
    if (!currentPolicy) {
        console.error("Consent Manager cannot initialize: Policy not loaded.");
        return; // Cannot proceed without policy
    }

    const langCode = getPreferredLanguage();
    currentLanguageContent = currentPolicy.policy_content[langCode];
    if (!currentLanguageContent) {
        console.error(`No content for language ${langCode}. Defaulting to first available.`);
        currentLanguageContent = currentPolicy.policy_content[Object.keys(currentPolicy.policy_content)[0]]; // Fallback
    }
    document.documentElement.lang = langCode; // Set page lang for accessibility

    // Prepare a map for quick lookup of purpose configs
    currentLanguageContent.data_processing_purposes.forEach(p => {
        consentCategoriesConfig[p.id] = p;
    });

    renderCookieBanner(); // Render banner content dynamically
    renderPreferenceCenter(); // Render preference center content dynamically

    const currentConsent = getConsentState();

    if (currentConsent) {
        // Consent found and not expired/policy changed, apply directly
        applyConsent(currentConsent);
        cookieBanner.style.display = 'none'; // Hide banner
    } else {
        // No consent or expired/policy changed, show banner
        cookieBanner.style.display = 'flex';
        // For fresh visit, ensure all non-mandatory scripts are initially blocked
        const initialBlockedPreferences = {};
        currentLanguageContent.data_processing_purposes.forEach(purpose => {
            initialBlockedPreferences[purpose.id] = purpose.is_mandatory_for_service;
        });
        applyConsent(initialBlockedPreferences);
    }
}

document.addEventListener('DOMContentLoaded', initConsentManager);