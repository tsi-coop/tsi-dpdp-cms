# TSI DPDP Consent Management System API Reference

This document provides a comprehensive reference for the RESTful APIs of the TSI DPDP Consent Management System. It details the request and response structures for various operations, designed to facilitate seamless integration for Data Fiduciaries, Data Processors, and internal CMS users, ensuring compliance with the Digital Personal Data Protection Act (DPDP Act), 2023.

---

## 1. API Endpoints and Base URL

All API requests should be made using the `POST` HTTP method to the respective service path. The specific operation is determined by the `_func` attribute in the JSON request body.

**Base URL:** `https://api.tsicoop.com/dpdp/api/v1` (Production)
**Staging URL:** `https://staging.tsicoop.com/dpdp/api/v1`

**Service Paths:**
* `/user` (for User Service)
* `/policy` (for Policy Service)
* `/consent` (for Consent Record Service)
* `/fiduciary` (for Fiduciary Service)
* `/processor` (for Processor Service)
* `/grievance` (for Grievance Service)
* `/notification` (for Notification Service)
* `/audit` (for Audit Log Service)
* `/retention` (for Data Retention Service)
* `/regulatory` (for Regulatory Service)
* `/app/register` (for Account Management Dedup - Public Endpoint)

---

## 2. Authentication and Authorization

* **API Keys (`X-API-KEY` header):** Used for server-to-server or trusted client-side applications (e.g., Fiduciary's website frontend submitting consent). These keys are generated and managed via the CMS's API Keys Management module and are associated with specific permissions.
* **OAuth 2.0 / JWTs (`Authorization: Bearer <token>` header):** Used for administrative dashboards (DPO, Admin, Auditor) and authenticated Data Principal dashboards. JWTs are obtained after user login and carry user roles and permissions.
* **Mutual TLS (Two-Way SSL):** Required for highly sensitive communication, such as integration with the Data Protection Board (DPB). Both client and server verify X.509 certificates.
* **Role-Based Access Control (RBAC):** All API operations are protected by granular permissions checked at the backend.

---

## 3. Common Error Response Structure

All API errors will return a standard JSON structure:

```json
{
  "error": {
    "code": "STRING_ERROR_CODE",
    "message": "Human-readable error message explaining the issue.",
    "details": [
      "Optional: More specific details, e.g., validation errors for a field."
    ]
  }
}
```
Common HTTP Status Codes:

**400 Bad Request**: Invalid input, missing required fields.

**401 Unauthorized**: Authentication failed (invalid/missing credentials).

**403 Forbidden**: Authenticated but not authorized to perform the action.

**404 Not Found**: Resource not found.

**409 Conflict**: Resource already exists, or deletion conflict (e.g., role assigned to users).

**500 Internal Server Error**: Unexpected server-side error.

**503 Service Unavailable**: Temporary server issue.

---

## 4. API Reference by Service

### 4.1. User Service (/user)
Manages CMS backend users (Admin, DPO, Auditor, Operator) and their roles.

#### a) list_users

Description: Retrieves a list of CMS users with optional filtering and pagination.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "list_users",
  "status": "ACTIVE",  // Optional: "ACTIVE", "INACTIVE", "PENDING_MFA_SETUP"
  "search": "john.doe", // Optional: Search username or email
  "page": 1,           // Optional: Default 1
  "limit": 10          // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "user_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "username": "john.doe",
    "email": "john.doe@example.com",
    "status": "ACTIVE",
    "role": "Administrator",
    "last_login_at": "2025-05-29T10:00:00Z",
    "created_at": "2025-01-01T00:00:00Z",
    "last_updated_at": "2025-05-29T10:00:00Z"
  }
]
b) get_user

Description: Retrieves details for a single CMS user by ID.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "get_user",
  "user_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "user_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "username": "john.doe",
    "email": "john.doe@example.com",
    "status": "ACTIVE",
    "role_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef",
    "role_name": "Administrator",
    "last_login_at": "2025-05-29T10:00:00Z",
    "created_at": "2025-01-01T00:00:00Z",
    "last_updated_at": "2025-05-29T10:00:00Z"
  }
}
c) create_user

Description: Creates a new CMS user account.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "create_user",
  "username": "newadminuser",       // Required
  "email": "new.admin@example.com", // Required
  "password": "StrongPassword!1",   // Required (must meet complexity requirements)
  "role_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef" // Required (UUID of an existing role, e.g., Admin)
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "user_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "username": "newadminuser",
    "email": "new.admin@example.com",
    "status": "ACTIVE",
    "role_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef",
    "message": "User created successfully."
  }
}
d) update_user

Description: Updates an existing CMS user's details.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "update_user",
  "user_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "username": "updatedadmin",       // Optional: New username
  "email": "updated.email@example.com", // Optional: New email
  "password": "NewStrongPassword!2",   // Optional: New password (hashed by service, must meet complexity)
  "role_id": "c1d2e3f4-a5b6-7890-1234-567890abcdef", // Optional: New role ID
  "status": "INACTIVE"              // Optional: "ACTIVE", "INACTIVE", "PENDING_MFA_SETUP"
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "User updated successfully."
}
e) delete_user

Description: Deletes a CMS user. (Note: This is typically a soft delete in production systems).

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "delete_user",
  "user_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef" // Required
}
Response (204 No Content): (Empty response body)

f) list_roles

Description: Retrieves a list of defined CMS roles.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "list_roles",
  "search": "admin", // Optional: Search role name or description
  "page": 1,         // Optional: Default 1
  "limit": 10        // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "role_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef",
    "name": "Administrator",
    "description": "Full system administration access.",
    "is_system_role": true,
    "created_at": "2025-01-01T00:00:00Z",
    "last_updated_at": "2025-01-01T00:00:00Z"
  },
  {
    "role_id": "c1d2e3f4-a5b6-7890-1234-567890abcdef",
    "name": "DPO",
    "description": "Data Protection Officer role with compliance oversight.",
    "is_system_role": false,
    "created_at": "2025-02-15T00:00:00Z",
    "last_updated_at": "2025-02-15T00:00:00Z"
  }
]
g) get_role

Description: Retrieves details for a single CMS role by ID, including its permissions.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "get_role",
  "role_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "role_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef",
    "name": "Administrator",
    "description": "Full system administration access.",
    "is_system_role": true,
    "created_at": "2025-01-01T00:00:00Z",
    "last_updated_at": "2025-01-01T00:00:00Z",
    "permissions": [
      {"resource": "cms:user", "action": "manage"},
      {"resource": "policy", "action": "read"}
    ]
  }
}
h) create_role

Description: Creates a new CMS role with specified permissions.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "create_role",
  "name": "Custom Editor",           // Required
  "description": "Can edit content and view reports.", // Optional
  "permissions": [                  // Required: Array of permission objects
    {"resource": "cms:content", "action": "edit"},
    {"resource": "report:audit", "action": "read"}
  ]
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "role_id": "d1e2f3a4-b5b6-7890-1234-567890abcdef",
    "name": "Custom Editor",
    "description": "Can edit content and view reports.",
    "is_system_role": false,
    "message": "Role created successfully."
  }
}
i) update_role

Description: Updates an existing CMS role's details or permissions.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "update_role",
  "role_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef", // Required
  "name": "Updated Editor Role",     // Optional: New name
  "description": "Updated description for editor role.", // Optional: New description
  "permissions": [                  // Optional: New array of permissions (replaces existing)
    {"resource": "cms:content", "action": "edit"},
    {"resource": "report:audit", "action": "read"},
    {"resource": "cms:user", "action": "read"}
  ]
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Role updated successfully."
}
j) delete_role

Description: Deletes a CMS role. Fails if role is assigned to users or is a system role.

Authentication: OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "delete_role",
  "role_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef" // Required
}
Response (204 No Content): (Empty response body)

4.2. Policy Service (/policy)
Manages consent policies.

a) list_policies

Description: Retrieves a list of consent policies with optional filtering and pagination.

Authentication: OAuth2 (e.g., policy:read scope)

Request:

JSON

{
  "_func": "list_policies",
  "status": "ACTIVE", // Optional: "DRAFT", "ACTIVE", "ARCHIVED", "EXPIRED"
  "search": "privacy", // Optional: Search within policy content
  "fiduciary_id_filter": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Optional: Filter by specific Fiduciary
  "page": 1,           // Optional: Default 1
  "limit": 10          // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "id": "tsi_coop_web_data_policy",
    "version": "1.0",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "effective_date": "2025-06-03T00:00:00Z",
    "status": "ACTIVE",
    "jurisdiction": "IN",
    "created_at": "2025-06-01T00:00:00Z",
    "last_updated_at": "2025-06-03T07:30:00Z"
  }
]
b) get_policy

Description: Retrieves full details of a specific consent policy version.

Authentication: OAuth2 (e.g., policy:read scope)

Request:

JSON

{
  "_func": "get_policy",
  "policy_id": "tsi_coop_web_data_policy", // Required
  "version": "1.0"                      // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "policy_id": "tsi_coop_web_data_policy",
    "version": "1.0",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "effective_date": "2025-06-03T00:00:00Z",
    "status": "ACTIVE",
    "jurisdiction": "IN",
    "policy_content": {
      "en": {
        "title": "TSI Coop Website Data & Privacy Policy",
        "introduction": "At TSI Coop, we are committed to transparently collecting...",
        "data_processing_purposes": [
          {"id": "purpose_account_management", "name": "Account Registration & Management", "is_mandatory_for_service": true}
        ]
      }
      // ... other languages and full content
    },
    "created_at": "2025-06-01T00:00:00Z",
    "created_by_user_id": "user-uuid-1",
    "last_updated_at": "2025-06-03T07:30:00Z",
    "last_updated_by_user_id": "user-uuid-2"
  }
}
c) get_active_policy

Description: Retrieves the currently active consent policy for a specified Data Fiduciary and jurisdiction. This is the primary endpoint for client applications.

Authentication: API Key (for Fiduciary App) or OAuth2 (e.g., policy:read scope)

Request:

JSON

{
  "_func": "get_active_policy",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "jurisdiction": "IN"                     // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "policy_id": "tsi_coop_web_data_policy",
    "version": "1.0",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "effective_date": "2025-06-03T00:00:00Z",
    "status": "ACTIVE",
    "jurisdiction": "IN",
    "policy_content": {
      "en": {
        "title": "TSI Coop Website Data & Privacy Policy",
        "introduction": "At TSI Coop, we are committed to transparently collecting...",
        "general_purpose_description": "We collect data for account management...",
        "data_processing_purposes": [
          {"id": "purpose_account_management", "name": "Account Registration & Management", "legal_basis": "Contractual Necessity (DPDP Act, Section 7(b))", "is_mandatory_for_service": true, "is_sensitive": false}
        ],
        "data_categories_details": [
          {"id": "email_address", "name": "Email Address", "description": "Your professional email address...", "is_sensitive": false}
        ],
        "data_principal_rights_summary": "As per the Digital Personal Data Protection Act, 2023, you have rights...",
        "grievance_redressal_info": "For any data protection concerns...",
        "buttons": {"accept_all": "Accept All & Continue"},
        "links": {"full_privacy_policy_text": "Full Privacy Policy", "full_privacy_policy_url": "[https://www.tsicoop.com/privacy-policy-en](https://www.tsicoop.com/privacy-policy-en)"},
        "important_note": "Your email address and basic account details are essential..."
      }
    },
    "created_at": "2025-06-01T00:00:00Z",
    "created_by_user_id": "user-uuid-1",
    "last_updated_at": "2025-06-03T07:30:00Z",
    "last_updated_by_user_id": "user-uuid-2"
  }
}
d) create_policy

Description: Creates a new consent policy version (initially in DRAFT status).

Authentication: OAuth2 (e.g., policy:manage scope)

Request:

JSON

{
  "_func": "create_policy",
  "policy_id": "new_app_privacy_policy",    // Required
  "version": "1.0",                         // Required
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "effective_date": "2025-06-01T00:00:00Z", // Required (ISO 8601 format)
  "jurisdiction": "IN",                     // Required
  "policy_content": {                       // Required: Full multilingual policy JSON
    "en": {
      "title": "New App Privacy Policy",
      "data_processing_purposes": [
        {"id": "purpose_app_analytics", "name": "App Analytics", "description": "...", "legal_basis": "Consent", "is_mandatory_for_service": false}
      ]
    }
    // ... other languages
  }
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "policy_id": "new_app_privacy_policy",
    "version": "1.0",
    "message": "Policy created successfully."
  }
}
e) update_policy

Description: Updates an existing draft policy version. Active policies cannot be updated directly.

Authentication: OAuth2 (e.g., policy:manage scope)

Request:

JSON

{
  "_func": "update_policy",
  "policy_id": "new_app_privacy_policy",    // Required
  "version": "1.0",                         // Required (must be a DRAFT policy)
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Optional: Can update if policy is DRAFT
  "effective_date": "2025-06-05T00:00:00Z", // Optional: Can update if policy is DRAFT
  "jurisdiction": "IN",                     // Optional: Can update if policy is DRAFT
  "policy_content": {                       // Optional: Full updated multilingual policy JSON
    "en": {
      "title": "Updated Active Policy Title",
      "data_processing_purposes": [
        {"id": "purpose_app_analytics", "name": "App Analytics", "description": "Updated description...", "legal_basis": "Consent", "is_mandatory_for_service": false}
      ]
    }
  }
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Policy updated successfully."
}
f) publish_policy

Description: Publishes a policy version, setting its status to ACTIVE. Automatically archives any previously active policy for that Fiduciary and jurisdiction.

Authentication: OAuth2 (e.g., policy:publish scope)

Request:

JSON

{
  "_func": "publish_policy",
  "policy_id": "new_app_privacy_policy", // Required
  "version": "1.0"                    // Required (must be a DRAFT policy)
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Policy published successfully."
}
g) delete_policy (Soft delete)

Description: Soft deletes a policy version. Only non-active policies can be deleted.

Authentication: OAuth2 (e.g., policy:manage scope)

Request:

JSON

{
  "_func": "delete_policy",
  "policy_id": "old_unused_policy", // Required
  "version": "0.5"                 // Required (must NOT be an ACTIVE policy)
}
Response (204 No Content): (Empty response body)

4.3. Consent Record Service (/consent)
Manages Data Principal consent records.

a) record_consent

Description: Records a new consent decision or updates an existing one by creating a new active record and deactivating the old. This ensures consent provenance.

Authentication: API Key (for Fiduciary App)

Request:

JSON

{
  "_func": "record_consent",
  "user_id": "data_principal_xyz789",       // Required: Data Principal's ID from Fiduciary's system
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "policy_id": "tsi_coop_web_data_policy",  // Required: ID of policy consented to
  "policy_version": "1.0",                  // Required: Version of policy consented to
  "timestamp": "2025-05-30T10:00:00Z",      // Required: When consent was given (ISO 8601)
  "jurisdiction": "IN",                     // Required
  "language_selected": "en",                // Required
  "consent_status_general": "custom",       // Required: "granted_all", "denied_non_essential", "custom", "withdrawn"
  "consent_mechanism": "preference_center_save_click", // Required: e.g., "accept_all_banner_click", "digilocker_verified_parent_consent"
  "ip_address": "192.168.1.10",             // Required: IP address of user (captured by API Gateway/Servlet)
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36", // Required
  "data_point_consents": {                  // Required: Granular consent for each purpose
    "purpose_account_management": true,
    "purpose_website_analytics": true,
    "purpose_engagement_tracking": false,
    "purpose_product_service_showcase": true,
    "purpose_maturity_assessment": false,
    "purpose_education_network": true
  }
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "consent_record_id": "c1o2n3s4-e5n6t7-8901-2345-67890abcdef",
    "user_id": "data_principal_xyz789",
    "message": "Consent recorded successfully."
  }
}
b) get_active_consent

Description: Retrieves the currently active consent record for a given user and fiduciary.

Authentication: API Key (for Fiduciary App) or OAuth2 (e.g., consent:read scope)

Request:

JSON

{
  "_func": "get_active_consent",
  "user_id": "data_principal_xyz789",       // Required
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "id": "c1o2n3s4-e5n6t7-8901-2345-67890abcdef",
    "user_id": "data_principal_xyz789",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "policy_id": "tsi_coop_web_data_policy",
    "policy_version": "1.0",
    "timestamp": "2025-05-30T10:00:00Z",
    "jurisdiction": "IN",
    "language_selected": "en",
    "consent_status_general": "custom",
    "consent_mechanism": "preference_center_save_click",
    "ip_address": "192.168.1.10",
    "user_agent": "Mozilla/5.0...",
    "data_point_consents": {
      "purpose_account_management": true,
      "purpose_website_analytics": true,
      "purpose_engagement_tracking": false
    },
    "is_active_consent": true
  }
}
c) list_consent_history

Description: Retrieves a paginated list of all consent records for a given user and fiduciary, ordered by timestamp.

Authentication: OAuth2 (e.g., consent:read scope)

Request:

JSON

{
  "_func": "list_consent_history",
  "user_id": "data_principal_xyz789",       // Required
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "page": 1,                                // Optional: Default 1
  "limit": 10                               // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "id": "c1o2n3s4-e5n6t7-8901-2345-67890abcdef",
    "user_id": "data_principal_xyz789",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "policy_id": "tsi_coop_web_data_policy",
    "policy_version": "1.0",
    "timestamp": "2025-05-30T10:00:00Z",
    "consent_status_general": "custom",
    "is_active_consent": true
    // ... other fields
  },
  {
    "id": "c1o2n3s4-e5n6t7-8901-2345-67890abcde0",
    "user_id": "data_principal_xyz789",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "policy_id": "tsi_coop_web_data_policy",
    "policy_version": "1.0",
    "timestamp": "2025-05-29T09:00:00Z",
    "consent_status_general": "granted_all",
    "is_active_consent": false
    // ... other fields
  }
]
d) link_user

Description: Links anonymous user consent records to an authenticated Data Principal ID.

Authentication: API Key (for Fiduciary App) or OAuth2 (e.g., account:manage scope)

Request:

JSON

{
  "_func": "link_user",
  "anonymous_user_id": "anon_1678901234_abc", // Required: The temporary client-side ID
  "authenticated_user_id": "data_principal_xyz789" // Required: The definitive server-side ID
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "User consent records linked successfully."
}
4.4. Fiduciary Service (/fiduciary)
Manages Data Fiduciary profiles.

a) list_fiduciaries

Description: Retrieves a list of Data Fiduciary profiles with optional filtering and pagination.

Authentication: OAuth2 (e.g., fiduciary:manage scope)

Request:

JSON

{
  "_func": "list_fiduciaries",
  "status": "ACTIVE", // Optional: "PENDING", "VALIDATED", "FAILED", "ACTIVE", "INACTIVE", "REVOKED"
  "search": "TSI Coop", // Optional: Search by name, domain, or email
  "page": 1,          // Optional: Default 1
  "limit": 10         // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "name": "TSI Coop",
    "email": "privacy@tsicoop.com",
    "primary_domain": "tsicoop.com",
    "cms_cname": "consent.tsicoop.com",
    "status": "ACTIVE",
    "domain_validation_status": "VALIDATED",
    "is_significant_data_fiduciary": false,
    "created_at": "2025-01-01T00:00:00Z",
    "last_updated_at": "2025-05-30T00:00:00Z"
  }
]
b) get_fiduciary

Description: Retrieves full details of a specific Data Fiduciary profile.

Authentication: OAuth2 (e.g., fiduciary:manage scope)

Request:

JSON

{
  "_func": "get_fiduciary",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "name": "TSI Coop",
    "contact_person": "Jane Doe",
    "email": "privacy@tsicoop.com",
    "phone": "+919000011223",
    "address": "123 Tech Plaza, Coimbatore, India",
    "primary_domain": "tsicoop.com",
    "cms_cname": "consent.tsicoop.com",
    "dns_txt_record_token": "dpdp-verify-xyz123abc",
    "domain_validation_status": "VALIDATED",
    "is_significant_data_fiduciary": false,
    "dpo_user_id": "d1e2f3a4-b5c6-7890-1234-567890abcdef",
    "dpb_registration_id": "DPB-REG-XYZ789",
    "status": "ACTIVE",
    "created_at": "2025-01-01T00:00:00Z",
    "created_by_user_id": "user-uuid-1",
    "last_updated_at": "2025-05-30T00:00:00Z",
    "last_updated_by_user_id": "user-uuid-2"
  }
}
c) create_fiduciary

Description: Creates a new Data Fiduciary profile. Generates a DNS TXT record token for domain validation.

Authentication: OAuth2 (e.g., fiduciary:manage scope)

Request:

JSON

{
  "_func": "create_fiduciary",
  "name": "New Business Solutions Ltd.",      // Required
  "contact_person": "Alice Manager",          // Optional
  "email": "privacy@newbusiness.com",         // Required
  "phone": "+919876512345",                    // Optional
  "address": "101 Business Park, Chennai, India", // Optional
  "primary_domain": "newbusiness.com",        // Required
  "cms_cname": "consent.newbusiness.com",     // Required
  "is_significant_data_fiduciary": false,   // Optional: Default false
  "dpo_user_id": null,                      // Optional: UUID of CMS user if DPO already exists
  "dpb_registration_id": null               // Optional: If already registered directly with DPB
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "name": "New Business Solutions Ltd.",
    "primary_domain": "newbusiness.com",
    "cms_cname": "consent.newbusiness.com",
    "dns_txt_record_token": "dpdp-verify-xyz123abc",
    "domain_validation_status": "PENDING",
    "message": "Fiduciary created successfully. Please add the DNS TXT record for validation."
  }
}
d) update_fiduciary

Description: Updates an existing Data Fiduciary profile.

Authentication: OAuth2 (e.g., fiduciary:manage scope)

Request:

JSON

{
  "_func": "update_fiduciary",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "name": "New Business Solutions Pvt. Ltd.", // Optional
  "email": "compliance@newbusiness.com",      // Optional
  "status": "INACTIVE",                       // Optional: "ACTIVE", "INACTIVE", "REVOKED"
  "dpo_user_id": "d1e2f3a4-b5c6-7890-1234-567890abcdef" // Optional: Assign DPO
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Fiduciary updated successfully."
}
e) delete_fiduciary (Soft delete)

Description: Soft deletes a Data Fiduciary profile.

Authentication: OAuth2 (e.g., fiduciary:manage scope)

Request:

JSON

{
  "_func": "delete_fiduciary",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef" // Required
}
Response (204 No Content): (Empty response body)

f) validate_domain

Description: Initiates the DNS TXT record validation process for a Fiduciary's domain.

Authentication: OAuth2 (e.g., fiduciary:manage scope)

Request:

JSON

{
  "_func": "validate_fiduciary_domain",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef" // Required
}
Response (200 OK):

JSON

{
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "domain_validation_status": "VALIDATED",
  "message": "Domain validation successful."
}
4.5. Processor Service (/processor)
Manages Data Processor profiles.

a) list_processors

Description: Retrieves a list of Data Processor profiles for a specific Fiduciary.

Authentication: OAuth2 (e.g., processor:manage scope)

Request:

JSON

{
  "_func": "list_processors",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "status": "ACTIVE", // Optional: "ACTIVE", "INACTIVE", "REVOKED"
  "search": "analytics", // Optional: Search by name, email, DPA reference
  "page": 1,           // Optional: Default 1
  "limit": 10          // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "processor_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "name": "AnalyticsPro Inc.",
    "contact_person": "John Smith",
    "email": "info@analyticspro.com",
    "status": "ACTIVE",
    "dpa_reference": "DPA-FID1-ANALYTICS-2025",
    "processing_purposes": ["purpose_website_analytics"],
    "data_categories_processed": ["website_usage_data"]
    // ... other fields
  }
]
b) get_processor

Description: Retrieves full details of a specific Data Processor profile.

Authentication: OAuth2 (e.g., processor:manage scope)

Request:

JSON

{
  "_func": "get_processor",
  "processor_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef", // Required
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef"  // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "processor_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "name": "AnalyticsPro Inc.",
    "contact_person": "John Smith",
    "email": "info@analyticspro.com",
    "phone": "+919876543210",
    "address": "123 Analytics St, Bangalore, India",
    "jurisdiction": "IN",
    "dpa_reference": "DPA-FID1-ANALYTICS-2025",
    "dpa_effective_date": "2025-05-01",
    "dpa_expiry_date": null,
    "processing_purposes": ["purpose_website_analytics", "purpose_engagement_tracking"],
    "data_categories_processed": ["website_usage_data", "device_info"],
    "security_measures_description": "ISO 27001 certified, AES-256 encryption at rest.",
    "status": "ACTIVE",
    "created_at": "2025-05-01T00:00:00Z",
    "created_by_user_id": "user-uuid-1",
    "last_updated_at": "2025-05-01T00:00:00Z",
    "last_updated_by_user_id": "user-uuid-1"
  }
}
c) create_processor

Description: Creates a new Data Processor profile for a specific Fiduciary.

Authentication: OAuth2 (e.g., processor:manage scope)

Request:

JSON

{
  "_func": "create_processor",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "name": "Cloud Storage Solutions",    // Required
  "contact_person": "Bob Integrator",   // Optional
  "email": "contact@cloudstorage.com",  // Optional
  "phone": "+919123456789",             // Optional
  "address": "Cloud Park, Mumbai, India", // Optional
  "jurisdiction": "IN",                 // Optional
  "dpa_reference": "DPA-TSI-Fid-Cloud-2025", // Optional: Reference to DPA document
  "dpa_effective_date": "2025-05-01T00:00:00Z", // Optional (ISO 8601)
  "dpa_expiry_date": null,              // Optional (ISO 8601)
  "processing_purposes": [              // Required: Array of purpose IDs
    "purpose_website_analytics",
    "purpose_engagement_tracking"
  ],
  "data_categories_processed": [        // Required: Array of data category IDs
    "website_usage_data",
    "device_info",
    "engagement_interactions"
  ],
  "security_measures_description": "ISO 27001 certified, AES-256 encryption at rest.", // Optional
  "status": "ACTIVE"                    // Optional: Default ACTIVE
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "processor_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef",
    "name": "Cloud Storage Solutions",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "message": "Processor created successfully."
  }
}
d) update_processor

Description: Updates an existing Data Processor profile.

Authentication: OAuth2 (e.g., processor:manage scope)

Request:

JSON

{
  "_func": "update_processor",
  "processor_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef", // Required
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "name": "Cloud Storage Solutions (Updated)", // Optional
  "email": "support@cloudstorage.com",        // Optional
  "status": "INACTIVE"                        // Optional
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Processor updated successfully."
}
e) delete_processor (Soft delete)

Description: Soft deletes a Data Processor profile.

Authentication: OAuth2 (e.g., processor:manage scope)

Request:

JSON

{
  "_func": "delete_processor",
  "processor_id": "b1c2d3e4-f5a6-7890-1234-567890abcdef", // Required
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef"  // Required
}
Response (204 No Content): (Empty response body)

4.6. Grievance Service (/grievance)
Manages Data Principal grievances and requests.

a) submit_grievance

Description: Allows Data Principals to submit a new grievance or privacy request.

Authentication: OAuth2 (e.g., grievance:submit scope)

Request:

JSON

{
  "_func": "submit_grievance",
  "user_id": "data_principal_xyz789",       // Required: Data Principal's ID
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "type": "ERASURE_REQUEST",                // Required: "DATA_ACCESS_REQUEST", "CORRECTION_REQUEST", "ERASURE_REQUEST", "GENERAL_COMPLAINT"
  "subject": "Request to delete my account data", // Required
  "description": "I would like all my personal data associated with my account to be permanently deleted from your systems as per my right to erasure.", // Required
  "attachments": [],                        // Optional: Array of file references/URLs
  "language": "en"                          // Optional: Language of submission
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "grievance_id": "g1h2i3j4-k5l6-7890-1234-567890abcdef",
    "user_id": "data_principal_xyz789",
    "message": "Grievance submitted successfully."
  }
}
b) get_grievance

Description: Retrieves full details of a specific grievance.

Authentication: OAuth2 (e.g., grievance:submit scope for self, grievance:manage for DPO/Admin)

Request:

JSON

{
  "_func": "get_grievance",
  "grievance_id": "g1h2i3j4-k5l6-7890-1234-567890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "grievance_id": "g1h2i3j4-k5l6-7890-1234-567890abcdef",
    "user_id": "data_principal_xyz789",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "type": "GENERAL_COMPLAINT",
    "subject": "Issue with service access",
    "description": "I am unable to access the provider zone after updating my consent preferences.",
    "submission_timestamp": "2025-05-30T10:00:00Z",
    "status": "NEW",
    "assigned_dpo_user_id": null,
    "resolution_details": null,
    "resolution_timestamp": null,
    "communication_log": [
      {
        "timestamp": "2025-05-30T10:00:00Z",
        "sender": "Data Principal",
        "message": "Grievance submitted: Issue with service access",
        "channel": "PORTAL"
      }
    ],
    "attachments": [],
    "due_date": "2025-06-29T10:00:00Z",
    "last_updated_at": "2025-05-30T10:00:00Z",
    "last_updated_by_user_id": null
  }
}
c) list_grievances

Description: Retrieves a paginated list of grievances, with filtering options.

Authentication: OAuth2 (e.g., grievance:manage scope)

Request:

JSON

{
  "_func": "list_grievances",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "status": "NEW", // Optional: "NEW", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "CLOSED", "ESCALATED"
  "type": "ERASURE_REQUEST", // Optional: Filter by type
  "assigned_dpo_user_id": "d1e2f3a4-b5c6-7890-1234-567890abcdef", // Optional: Filter by assigned DPO
  "search": "account deletion", // Optional: Search subject or description
  "page": 1,                     // Optional: Default 1
  "limit": 10                    // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "grievance_id": "g1h2i3j4-k5l6-7890-1234-567890abcdef",
    "user_id": "data_principal_xyz789",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "type": "GENERAL_COMPLAINT",
    "subject": "Issue with service access",
    "submission_timestamp": "2025-05-30T10:00:00Z",
    "status": "NEW",
    "assigned_dpo_user_id": null,
    "due_date": "2025-06-29T10:00:00Z"
  }
]
d) update_grievance_status

Description: Updates the status and resolution details of a grievance.

Authentication: OAuth2 (e.g., grievance:manage scope)

Request:

JSON

{
  "_func": "update_grievance_status",
  "grievance_id": "g1h2i3j4-k5l6-7890-1234-567890abcdef", // Required
  "status": "IN_PROGRESS",                               // Required: New status
  "resolution_details": "Data deletion confirmed and verified.", // Optional: Details of resolution
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Grievance status updated successfully."
}
e) add_grievance_communication

Description: Adds a communication entry to a grievance's communication log.

Authentication: OAuth2 (e.g., grievance:manage scope)

Request:

JSON

{
  "_func": "add_grievance_communication",
  "grievance_id": "g1h2i3j4-k5l6-7890-1234-567890abcdef", // Required
  "message": "Acknowledged request and started investigation.", // Required
  "sender": "DPO",                                         // Required: "DP", "DPO", "SYSTEM"
  "channel": "PORTAL"                                      // Required: "PORTAL", "EMAIL", "SMS"
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Communication added successfully."
}
4.7. Notification Service (/notification)
This service manages notification templates and dispatches notifications.

a) create_template

Description: Creates a new notification template.

Authentication: OAuth2 (e.g., notification:manage scope)

Request:

JSON

{
  "_func": "create_template",
  "name": "Policy Update Notification",         // Required
  "category": "Compliance",                     // Required: "Compliance", "Security", "Grievance", "Operational"
  "severity": "INFO",                           // Required: "CRITICAL", "HIGH", "MEDIUM", "INFO"
  "channels_enabled": ["EMAIL", "IN_APP"],      // Required: Array of "EMAIL", "SMS", "IN_APP"
  "content_template": {                         // Required: Multilingual content template
    "en": {
      "subject": "Important: Privacy Policy Update",
      "body": "Dear {user_name},\n\nOur Privacy Policy has been updated to version {policy_version}, effective {effective_date}. Please review the changes. {action_link}",
      "action_text": "Review Policy"
    },
    "ta": {
      "subject": "முக்கியமானது: தனியுரிமைக் கொள்கை புதுப்பிப்பு",
      "body": "அன்புள்ள {user_name},\n\nஎங்கள் தனியுரிமைக் கொள்கை பதிப்பு {policy_version} புதுப்பிக்கப்பட்டுள்ளது, இது {effective_date} முதல் நடைமுறைக்கு வருகிறது. மாற்றங்களை மதிப்பாய்வு செய்யவும். {action_link}",
      "action_text": "கொள்கையை மதிப்பாய்வு செய்யவும்"
    }
  },
  "action_link_template": "[https://www.tsicoop.com/privacy-policy-v](https://www.tsicoop.com/privacy-policy-v){policy_version}" // Optional: URL template
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "template_id": "t1e2m3p4-l5a6-7890-1234-567890abcdef",
    "name": "Policy Update Notification",
    "message": "Notification template created successfully."
  }
}
b) update_template

Description: Updates an existing notification template.

Authentication: OAuth2 (e.g., notification:manage scope)

Request:

JSON

{
  "_func": "update_template",
  "template_id": "t1e2m3p4-l5a6-7890-1234-567890abcdef", // Required
  "name": "Policy Update Notification (Revised)", // Optional
  "severity": "HIGH",                           // Optional
  "channels_enabled": ["EMAIL", "SMS", "IN_APP"], // Optional
  "content_template": {                         // Optional: Updated multilingual content
    "en": {
      "subject": "URGENT: Privacy Policy Update",
      "body": "Dear {user_name},\n\nOur Privacy Policy has been updated to version {policy_version}, effective {effective_date}. Please review the changes immediately. {action_link}"
    }
  }
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Notification template updated successfully."
}
c) get_template

Description: Retrieves details of a specific notification template.

Authentication: OAuth2 (e.g., notification:manage scope)

Request:

JSON

{
  "_func": "get_template",
  "template_id": "t1e2m3p4-l5a6-7890-1234-567890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "template_id": "t1e2m3p4-l5a6-7890-1234-567890abcdef",
    "name": "Policy Update Notification",
    "category": "Compliance",
    "severity": "INFO",
    "channels_enabled": ["EMAIL", "IN_APP"],
    "content_template": {
      "en": {
        "subject": "Important: Privacy Policy Update",
        "body": "Dear {user_name},\n\nOur Privacy Policy has been updated to version {policy_version}...",
        "action_text": "Review Policy"
      }
    },
    "action_link_template": "[https://www.tsicoop.com/privacy-policy-v](https://www.tsicoop.com/privacy-policy-v){policy_version}",
    "created_at": "2025-05-01T00:00:00Z",
    "created_by_user_id": "user-uuid-1",
    "last_updated_at": "2025-05-01T00:00:00Z",
    "last_updated_by_user_id": "user-uuid-1"
  }
}
d) list_templates

Description: Retrieves a paginated list of notification templates.

Authentication: OAuth2 (e.g., notification:manage scope)

Request:

JSON

{
  "_func": "list_templates",
  "category": "Compliance", // Optional: "Compliance", "Security", "Grievance", "Operational"
  "severity": "HIGH",       // Optional: "CRITICAL", "HIGH", "MEDIUM", "INFO"
  "search": "policy",       // Optional: Search template name or content
  "page": 1,                // Optional: Default 1
  "limit": 10               // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "template_id": "t1e2m3p4-l5a6-7890-1234-567890abcdef",
    "name": "Policy Update Notification",
    "category": "Compliance",
    "severity": "INFO",
    "channels_enabled": ["EMAIL", "IN_APP"],
    "created_at": "2025-05-01T00:00:00Z",
    "last_updated_at": "2025-05-01T00:00:00Z"
  }
]
e) dispatch_notification

Description: Dispatches a notification based on a template and payload. This is typically called internally by other microservices.

Authentication: OAuth2 (e.g., notification:dispatch scope)

Request:

JSON

{
  "_func": "dispatch_notification",
  "template_id": "t1e2m3p4-l5a6-7890-1234-567890abcdef", // Required: ID of the template to use
  "recipient_type": "DATA_PRINCIPAL",                   // Required: "DATA_PRINCIPAL", "DPO_ADMIN", "DATA_PROCESSOR"
  "recipient_id": "data_principal_xyz789",              // Required: ID of the specific recipient (user_id, fiduciary_id, processor_id)
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required: Contextual Fiduciary ID
  "payload_data": {                                     // Required: Data to populate template placeholders
    "user_name": "John Doe",
    "policy_version": "1.1",
    "effective_date": "2025-06-01"
  }
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Notification dispatch initiated."
}
f) list_notification_instances

Description: Retrieves a paginated list of sent notification instances.

Authentication: OAuth2 (e.g., notification:manage scope)

Request:

JSON

{
  "_func": "list_notification_instances",
  "recipient_type": "DATA_PRINCIPAL",                   // Optional: "DATA_PRINCIPAL", "DPO_ADMIN", "DATA_PROCESSOR"
  "recipient_id": "data_principal_xyz789",              // Optional: Filter by specific recipient ID
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Optional: Filter by Fiduciary
  "status": "SENT",                                     // Optional: "SENT", "FAILED", "DELIVERED", "READ"
  "page": 1,                                            // Optional: Default 1
  "limit": 10                                           // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "instance_id": "i1n2s3t4-a5n6c7e-8901-2345-67890abcdef",
    "template_id": "t1e2m3p4-l5a6-7890-1234-567890abcdef",
    "recipient_type": "DATA_PRINCIPAL",
    "recipient_id": "data_principal_xyz789",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "status": "SENT",
    "channel_used": "EMAIL",
    "sent_at": "2025-05-30T10:05:00Z",
    "payload_data": {
      "user_name": "John Doe",
      "policy_version": "1.1"
    },
    "error_details": null,
    "read_at": null
  }
]
g) mark_notification_read

Description: Marks a specific notification instance as read.

Authentication: OAuth2 (e.g., notification:manage scope)

Request:

JSON

{
  "_func": "mark_notification_read",
  "instance_id": "i1n2s3t4-a5n6c7e-8901-2345-67890abcdef" // Required: ID of the notification instance
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Notification marked as read."
}
8. Audit Log Service (/audit)
This service manages immutable audit logs.

a) log_event

Description: Logs an event to the audit_logs table. This is typically called internally by other services.

Authentication: OAuth2 (e.g., audit:write scope) or internal service token.

Request:

JSON

{
  "_func": "log_event",
  "actor_user_id": "u1s2e3r4-a5d6-7890-1234-567890abcdef", // Optional: UUID of CMS user who performed action
  "actor_system_id": "ConsentRecordService",              // Optional: ID of the system process/service
  "action_type": "CONSENT_RECORDED",                      // Required: e.g., "POLICY_PUBLISHED", "USER_LINKED", "GRIEVANCE_SUBMITTED"
  "entity_type": "ConsentRecord",                         // Required: e.g., "ConsentPolicy", "User", "Grievance"
  "entity_id": "c1o2n3s4-e5n6t7-8901-2345-67890abcdef",   // Required: ID of the affected entity
  "context_details": {                                    // Optional: JSON payload of relevant data/changes
    "preferences_changed": {"purpose_analytics": true},
    "previous_status": "PENDING"
  },
  "ip_address": "192.168.1.100",                          // Optional: IP address from where action originated
  "status": "SUCCESS",                                    // Required: "SUCCESS", "FAILURE"
  "source_module": "ConsentRecordService"                 // Required: The module that generated the log
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "audit_log_id": "a1u2d3i4t-l5o6g7-8901-2345-67890abcdef",
    "message": "Audit log entry created successfully."
  }
}
b) list_audit_logs

Description: Retrieves a paginated list of audit logs with extensive filtering capabilities.

Authentication: OAuth2 (e.g., audit:read scope)

Request:

JSON

{
  "_func": "list_audit_logs",
  "search": "user_linked",          // Optional: Free text search
  "action_type_filter": "USER_LINKED", // Optional: Filter by specific action type
  "entity_type_filter": "User",     // Optional: Filter by entity type
  "entity_id_filter": "data_principal_xyz789", // Optional: Filter by specific entity ID
  "status_filter": "SUCCESS",       // Optional: "SUCCESS", "FAILURE"
  "start_date": "2025-05-01T00:00:00Z", // Optional: ISO 8601
  "end_date": "2025-05-30T23:59:59Z",   // Optional: ISO 8601
  "page": 1,                        // Optional: Default 1
  "limit": 10                       // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "id": "a1u2d3i4t-l5o6g7-8901-2345-67890abcdef",
    "timestamp": "2025-05-30T10:00:00Z",
    "actor_user_id": "u1s2e3r4-a5d6-7890-1234-567890abcdef",
    "actor_system_id": "ConsentRecordService",
    "action_type": "CONSENT_RECORDED",
    "entity_type": "ConsentRecord",
    "entity_id": "c1o2n3s4-e5n6t7-8901-2345-67890abcdef",
    "context_details": {
      "preferences_changed": {
        "purpose_analytics": true
      },
      "previous_status": "PENDING"
    },
    "ip_address": "192.168.1.100",
    "status": "SUCCESS",
    "source_module": "ConsentRecordService"
  }
]
c) get_audit_log_entry

Description: Retrieves full details of a specific audit log entry.

Authentication: OAuth2 (e.g., audit:read scope)

Request:

JSON

{
  "_func": "get_audit_log_entry",
  "audit_log_id": "a1u2d3i4t-l5o6g7-8901-2345-67890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "id": "a1u2d3i4t-l5o6g7-8901-2345-67890abcdef",
    "timestamp": "2025-05-30T10:00:00Z",
    "actor_user_id": "u1s2e3r4-a5d6-7890-1234-567890abcdef",
    "actor_system_id": "ConsentRecordService",
    "action_type": "CONSENT_RECORDED",
    "entity_type": "ConsentRecord",
    "entity_id": "c1o2n3s4-e5n6t7-8901-2345-67890abcdef",
    "context_details": {
      "preferences_changed": {
        "purpose_analytics": true
      },
      "previous_status": "PENDING"
    },
    "ip_address": "192.168.1.100",
    "status": "SUCCESS",
    "source_module": "ConsentRecordService"
  }
}
9. Data Retention Service (/retention)
This service manages data retention policies and purge operations.

a) create_retention_policy

Description: Creates a new data retention policy.

Authentication: OAuth2 (e.g., retention:manage scope)

Request:

JSON

{
  "_func": "create_retention_policy",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "name": "Marketing Data 2 Year Retention", // Required
  "description": "Policy for marketing consent data retention.", // Optional
  "applicable_purposes": ["purpose_marketing_communication"], // Optional: Array of purpose IDs
  "applicable_data_categories": ["email_address", "product_interest_summary"], // Optional: Array of data category IDs
  "retention_duration_value": 2,          // Required
  "retention_duration_unit": "YEARS",     // Required: "DAYS", "MONTHS", "YEARS"
  "retention_start_event": "CONSENT_WITHDRAWN", // Required: "CONSENT_GIVEN", "SERVICE_TERMINATED", "LAST_ACTIVITY_DATE", "TRANSACTION_COMPLETED", "CONSENT_WITHDRAWN"
  "action_at_expiry": "DELETE",           // Required: "DELETE", "ANONYMIZE", "ARCHIVE"
  "legal_reference": "DPDP Act, Section X", // Optional
  "status": "ACTIVE"                      // Optional: Default ACTIVE
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "policy_id": "r1e2t3e4n-t5i6o7n-8901-2345-67890abcdef",
    "name": "Marketing Data 2 Year Retention",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "message": "Retention policy created successfully."
  }
}
b) update_retention_policy

Description: Updates an existing data retention policy.

Authentication: OAuth2 (e.g., retention:manage scope)

Request:

JSON

{
  "_func": "update_retention_policy",
  "policy_id": "r1e2t3e4n-t5i6o7n-8901-2345-67890abcdef", // Required
  "name": "Marketing Data 2 Year Retention (Revised)", // Optional
  "retention_duration_value": 3,          // Optional
  "retention_duration_unit": "YEARS",     // Optional
  "status": "INACTIVE"                    // Optional
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Retention policy updated successfully."
}
c) get_retention_policy

Description: Retrieves details of a specific data retention policy.

Authentication: OAuth2 (e.g., retention:manage scope)

Request:

JSON

{
  "_func": "get_retention_policy",
  "policy_id": "r1e2t3e4n-t5i6o7n-8901-2345-67890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "policy_id": "r1e2t3e4n-t5i6o7n-8901-2345-67890abcdef",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "name": "Marketing Data 2 Year Retention",
    "description": "Policy for marketing consent data retention.",
    "applicable_purposes": ["purpose_marketing_communication"],
    "applicable_data_categories": ["email_address"],
    "retention_duration_value": 2,
    "retention_duration_unit": "YEARS",
    "retention_start_event": "CONSENT_WITHDRAWN",
    "action_at_expiry": "DELETE",
    "legal_reference": "DPDP Act, Section X",
    "status": "ACTIVE",
    "created_at": "2025-05-01T00:00:00Z",
    "created_by_user_id": "user-uuid-1",
    "last_updated_at": "2025-05-01T00:00:00Z",
    "last_updated_by_user_id": "user-uuid-1"
  }
}
d) list_retention_policies

Description: Retrieves a paginated list of data retention policies.

Authentication: OAuth2 (e.g., retention:manage scope)

Request:

JSON

{
  "_func": "list_retention_policies",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "status": "ACTIVE", // Optional: "ACTIVE", "INACTIVE"
  "search": "marketing", // Optional: Search by name, description, legal reference
  "page": 1,           // Optional: Default 1
  "limit": 10          // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "policy_id": "r1e2t3e4n-t5i6o7n-8901-2345-67890abcdef",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "name": "Marketing Data 2 Year Retention",
    "description": "Policy for marketing consent data retention.",
    "retention_duration_value": 2,
    "retention_duration_unit": "YEARS",
    "retention_start_event": "CONSENT_WITHDRAWN",
    "action_at_expiry": "DELETE",
    "status": "ACTIVE",
    "created_at": "2025-05-01T00:00:00Z",
    "last_updated_at": "2025-05-01T00:00:00Z"
  }
]
e) delete_retention_policy (Soft delete)

Description: Soft deletes a data retention policy.

Authentication: OAuth2 (e.g., retention:manage scope)

Request:

JSON

{
  "_func": "delete_retention_policy",
  "policy_id": "r1e2t3e4n-t5i6o7n-8901-2345-67890abcdef" // Required
}
Response (204 No Content): (Empty response body)

f) initiate_purge_request (Called by other services like GrievanceService)

Description: Initiates a data purge request.

Authentication: OAuth2 (e.g., purge:initiate scope) or internal service token.

Request:

JSON

{
  "_func": "initiate_purge_request",
  "user_id": "data_principal_xyz789",       // Required
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "processor_id": null,                     // Optional: If purge is specific to a processor
  "trigger_event": "ERASURE_REQUEST",       // Required: "ERASURE_REQUEST", "RETENTION_POLICY_EXPIRY"
  "data_categories_to_purge": ["email_address", "website_usage_data"], // Optional: Specific categories to purge
  "processing_purposes_affected": ["purpose_marketing_communication"] // Optional: Specific purposes affected
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "purge_request_id": "p1u2r3g4e-r5e6q7-8901-2345-67890abcdef",
    "status": "PENDING",
    "message": "Purge request initiated successfully."
  }
}
g) confirm_purge_status (Called by Data Fiduciary/Processor via API)

Description: Confirms the status of a data purge operation executed by a Data Fiduciary or Data Processor.

Authentication: API Key (for DF/DP) or OAuth2 (e.g., purge:confirm scope)

Request:

JSON

{
  "_func": "confirm_purge_status",
  "purge_request_id": "p1u2r3g4e-r5e6q7-8901-2345-67890abcdef", // Required
  "status": "COMPLETED",                                        // Required: "COMPLETED", "FAILED", "IN_PROGRESS"
  "records_affected_count": 123,                                // Optional: Number of records purged
  "details": "User data deleted from CRM and Analytics DB.",     // Optional: Details of purge
  "error_message": null,                                        // Optional: If status is FAILED
  "confirmed_by_entity_id": "f1d2u3c4i-a5r6y7-8901-2345-67890abcdef" // Required: ID of the DF/DP confirming
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "Purge status confirmed."
}
h) list_purge_requests

Description: Retrieves a paginated list of data purge requests.

Authentication: OAuth2 (e.g., retention:manage scope)

Request:

JSON

{
  "_func": "list_purge_requests",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "status": "PENDING", // Optional: "PENDING", "IN_PROGRESS", "COMPLETED", "FAILED", "UNDER_LEGAL_HOLD"
  "trigger_event": "ERASURE_REQUEST", // Optional: "ERASURE_REQUEST", "RETENTION_POLICY_EXPIRY"
  "search": "user_xyz", // Optional: Search user_id or details
  "page": 1,           // Optional: Default 1
  "limit": 10          // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "purge_request_id": "p1u2r3g4e-r5e6q7-8901-2345-67890abcdef",
    "user_id": "data_principal_xyz789",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "processor_id": null,
    "trigger_event": "ERASURE_REQUEST",
    "status": "PENDING",
    "initiated_at": "2025-05-30T11:00:00Z",
    "completed_at": null,
    "records_affected_count": null,
    "details": null,
    "legal_exception_applied_id": null,
    "error_message": null
  }
]
10. Regulatory Service (/regulatory)
This service manages communication and reporting with the DPB.

a) create_dpb_registration

Description: Creates a new DPB registration record for a Data Fiduciary.

Authentication: OAuth2 (e.g., regulatory:manage scope)

Request:

JSON

{
  "_func": "create_dpb_registration",
  "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef", // Required
  "dpb_registration_id": "DPB-REG-XYZ789", // Required: ID provided by DPB
  "dpb_endpoint_url": "[https://api.dpb.gov.in/v1/fiduciary-register](https://api.dpb.gov.in/v1/fiduciary-register)", // Required
  "client_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----", // Required (PEM format)
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----", // Required (PEM format)
  "status": "PENDING" // Optional: Default PENDING
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "dpb_registration_id": "DPB-REG-XYZ789",
    "message": "DPB registration created successfully."
  }
}
b) update_dpb_registration

Description: Updates an existing DPB registration record.

Authentication: OAuth2 (e.g., regulatory:manage scope)

Request:

JSON

{
  "_func": "update_dpb_registration",
  "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef", // Required
  "dpb_endpoint_url": "[https://api.dpb.gov.in/v1/fiduciary-register-new](https://api.dpb.gov.in/v1/fiduciary-register-new)", // Optional
  "status": "REGISTERED" // Optional: "PENDING", "REGISTERED", "FAILED"
}
Response (200 OK):

JSON

{
  "success": true,
  "message": "DPB registration updated successfully."
}
c) get_dpb_registration

Description: Retrieves details of a specific DPB registration.

Authentication: OAuth2 (e.g., regulatory:manage scope)

Request:

JSON

{
  "_func": "get_dpb_registration",
  "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef" // Required
}
Response (200 OK):

JSON

{
  "success": true,
  "data": {
    "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "dpb_registration_id": "DPB-REG-XYZ789",
    "dpb_endpoint_url": "[https://api.dpb.gov.in/v1/fiduciary-register](https://api.dpb.gov.in/v1/fiduciary-register)",
    "client_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "status": "PENDING",
    "last_successful_communication_at": null,
    "created_at": "2025-05-30T00:00:00Z",
    "created_by_user_id": "user-uuid-1",
    "last_updated_at": "2025-05-30T00:00:00Z",
    "last_updated_by_user_id": "user-uuid-1"
  }
}
d) list_dpb_registrations

Description: Retrieves a paginated list of DPB registrations.

Authentication: OAuth2 (e.g., regulatory:manage scope)

Request:

JSON

{
  "_func": "list_dpb_registrations",
  "status": "REGISTERED", // Optional: "PENDING", "REGISTERED", "FAILED"
  "search": "TSI",       // Optional: Search by DPB ID or endpoint URL
  "page": 1,             // Optional: Default 1
  "limit": 10            // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef",
    "fiduciary_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "dpb_registration_id": "DPB-REG-XYZ789",
    "dpb_endpoint_url": "[https://api.dpb.gov.in/v1/fiduciary-register](https://api.dpb.gov.in/v1/fiduciary-register)",
    "status": "REGISTERED",
    "last_successful_communication_at": "2025-05-30T10:00:00Z",
    "created_at": "2025-05-30T00:00:00Z",
    "last_updated_at": "2025-05-30T00:00:00Z"
  }
]
e) test_dpb_connection

Description: Tests the secure connection to the DPB's endpoint for a specific registration.

Authentication: OAuth2 (e.g., regulatory:manage scope)

Request:

JSON

{
  "_func": "test_dpb_connection",
  "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef" // Required
}
Response (200 OK):

JSON

{
  "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef",
  "connection_status": "SUCCESS",
  "message": "DPB connection test successful."
}
f) submit_dpb_report

Description: Submits a specific type of report (e.g., breach notification, compliance report) to the DPB.

Authentication: OAuth2 (e.g., regulatory:manage scope) and Mutual TLS (if required by DPB).

Request:

JSON

{
  "_func": "submit_dpb_report",
  "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef", // Required
  "report_type": "BREACH_NOTIFICATION",                       // Required: "BREACH_NOTIFICATION", "COMPLIANCE_REPORT", etc.
  "report_data": {                                            // Required: The actual report payload (JSON structure depends on report type)
    "breach_id": "BREACH-2025-001",
    "incident_timestamp": "2025-05-28T10:00:00Z",
    "affected_data_principals_count": 1500,
    "data_categories_affected": ["email_address", "phone_number"],
    "details": "Unauthorized access to marketing database."
  }
}
Response (201 Created):

JSON

{
  "success": true,
  "data": {
    "submission_id": "s1u2b3m4i5s6s7i8o9n-1234-5678-90ab-cdef12345678",
    "message": "DPB report submission record saved successfully."
  }
}
g) list_dpb_submissions

Description: Retrieves a paginated list of DPB report submissions.

Authentication: OAuth2 (e.g., regulatory:manage scope)

Request:

JSON

{
  "_func": "list_dpb_submissions",
  "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef", // Required
  "report_type_filter": "BREACH_NOTIFICATION",                 // Optional
  "status_filter": "SUBMITTED",                                // Optional: "SUBMITTED", "FAILED"
  "page": 1,                                                   // Optional: Default 1
  "limit": 10                                                  // Optional: Default 10
}
Response (200 OK):

JSON

[
  {
    "submission_id": "s1u2b3m4i5s6s7i8o9n-1234-5678-90ab-cdef12345678",
    "registration_id": "r1e2g3i4s-t5r6a7t-8901-2345-67890abcdef",
    "report_type": "BREACH_NOTIFICATION",
    "submission_timestamp": "2025-05-30T10:00:00Z",
    "status": "SUBMITTED",
    "confirmation_receipt": "DPB_CONF_XYZ789",
    "error_details": null,
    "submitted_by_user_id": "user-uuid-1"
  }
]

1. Operation: Generate New API Key (generate_api_key)
   Used by CMS Administrators to create a new, cryptographically secure access key for a Data Fiduciary or Data Processor.


Sample Request (Generate Key for Fiduciary Frontend)
JSON

{
"_func": "generate_api_key",
"fiduciary_id": "a1b2c3d4-e5f6-4000-8000-000000000001",
"owner_type": "FIDUCIARY_APP",
"description": "Website Frontend Consent Submission Key",
"permissions": ["consent:write", "policy:read"]
}
Sample Success Response (HTTP 201 Created)
Note: The raw_api_key is returned only once upon generation and must be stored securely by the consumer.

JSON

{
"success": true,
"data": {
"key_id": "9b1a2b3c-4d5e-5f60-7a8b-1234567890ab",
"raw_api_key": "7b5c3e1a-2d4f-5g6h-7i8j-k1l2m3n4o5p67890abcdef",
"permissions": ["consent:write", "policy:read"],
"fiduciary_id": "a1b2c3d4-e5f6-4000-8000-000000000001"
},
"message": "API Key created successfully. STORE THIS KEY SAFELY, IT WILL NOT BE SHOWN AGAIN."
}
2. Operation: Revoke API Key (revoke_api_key)
   Used by CMS Administrators to permanently invalidate an API key.

Sample Request (Revoke Key)
JSON

{
"_func": "revoke_api_key",
"key_id": "9b1a2b3c-4d5e-5f60-7a8b-1234567890ab"
}
Sample Success Response (HTTP 200 OK)
JSON

{
"success": true,
"message": "API Key revoked successfully."
}
3. Operation: List API Keys (list_api_keys)
   Used by CMS Administrators to retrieve all keys associated with a Data Fiduciary, with filtering options.

Sample Request (List Active Keys for Fiduciary)
JSON

{
"_func": "list_api_keys",
"fiduciary_id": "a1b2c3d4-e5f6-4000-8000-000000000001",
"status": "ACTIVE"
}
Sample Success Response (HTTP 200 OK)
JSON

{
"success": true,
"data": [
{
"key_id": "9b1a2b3c-4d5e-5f60-7a8b-1234567890ab",
"fiduciary_id": "a1b2c3d4-e5f6-4000-8000-000000000001",
"owner_type": "FIDUCIARY_APP",
"description": "Website Frontend Consent Submission Key",
"status": "ACTIVE",
"permissions": ["consent:write", "policy:read"],
"created_at": "2025-05-30T09:30:00Z",
"last_used_at": "2025-05-30T10:30:00Z",
"expires_at": null
},
{
"key_id": "c1d2e3f4-g5h6-7i8j-9k0l-1m2n3o4p5q6r",
"fiduciary_id": "a1b2c3d4-e5f6-4000-8000-000000000001",
"owner_type": "PROCESSOR_INTEGRATION",
"description": "Analytics Purge Confirmation Key",
"status": "REVOKED",
"permissions": ["purge:confirm"],
"created_at": "2024-01-15T12:00:00Z",
"expires_at": null
}
]
}
