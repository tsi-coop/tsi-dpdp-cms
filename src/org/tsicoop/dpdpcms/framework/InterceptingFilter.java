package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject; // For parsing input in validateRequestFunc
import org.tsicoop.dpdpcms.service.v1.Job;
import org.tsicoop.dpdpcms.service.v1.Wallet;

import java.io.IOException;
import java.util.*;


public class InterceptingFilter implements Filter {

    private static final String URL_DELIMITER = "/";
    private static final String ADMIN_URI_PATH = "admin";
    private static final String CLIENT_URI_PATH = "client";

    private static final String BOOTSTRAP_URI_PATH = "bootstrap";
    private static final String API_PREFIX = "/api/v1/"; // Assuming API paths are /api/v1/user, /api/v1/policy etc.

    // Whitelist of _func values allowed for client API calls
    private static final Set<String> CLIENT_ALLOWED_FUNCS = new HashSet<>(Arrays.asList(
            "record_consent",
            "get_active_consent", // Renamed from getPrincipal to match ConsentRecordService
            "get_policy", // For specific policy version retrieval
            "get_active_policy", // For active policy retrieval
            "link_user",
            "submit_grievance", // Allowing grievance submission from client
            "get_grievance",
            "validate_consent",
            "list_consent_history",
            "list_user_grievances",
            "get_consent_record_details",
            "withdraw_consent",
            "erasure_request",
            "list_purge_requests",
            "update_purge_status",
            "list_notifications",
            "mark_notification_read",
            "record_parent_consent"
            // Add other client-facing functions as needed
    ));

    private static final Set<String> ADMIN_NOAUTH_FUNCS = new HashSet<>(Arrays.asList(
            "reset_password",
            "login",
            "verify_recovery_key",
            "reset_password_via_recovery"
    ));

    // Permission Scopes
    private static final String SCOPE_READ = "READ";
    private static final String SCOPE_WRITE = "WRITE";
    private static final String SCOPE_PURGE = "PURGE";

    // Mapping of functions to Permission Scopes as per rbac_mapping.md
    private static final Map<String, String> CLIENT_FUNC_SCOPES = new HashMap<>();

    static {
        // --- WRITE SCOPE ---
        CLIENT_FUNC_SCOPES.put("record_consent", SCOPE_WRITE);
        CLIENT_FUNC_SCOPES.put("record_parent_consent", SCOPE_WRITE);
        CLIENT_FUNC_SCOPES.put("link_user", SCOPE_WRITE);
        CLIENT_FUNC_SCOPES.put("withdraw_consent", SCOPE_WRITE);
        CLIENT_FUNC_SCOPES.put("submit_grievance", SCOPE_WRITE);
        CLIENT_FUNC_SCOPES.put("mark_notification_read", SCOPE_WRITE);
        CLIENT_FUNC_SCOPES.put("erasure_request", SCOPE_WRITE);

        // --- READ SCOPE ---
        CLIENT_FUNC_SCOPES.put("get_active_consent", SCOPE_READ);
        CLIENT_FUNC_SCOPES.put("list_consent_history", SCOPE_READ);
        CLIENT_FUNC_SCOPES.put("get_consent_record_details", SCOPE_READ);
        CLIENT_FUNC_SCOPES.put("validate_consent", SCOPE_READ);
        CLIENT_FUNC_SCOPES.put("get_grievance", SCOPE_READ);
        CLIENT_FUNC_SCOPES.put("list_user_grievances", SCOPE_READ);
        CLIENT_FUNC_SCOPES.put("get_policy", SCOPE_READ);
        CLIENT_FUNC_SCOPES.put("get_active_policy", SCOPE_READ);
        CLIENT_FUNC_SCOPES.put("list_notifications", SCOPE_READ);

        // --- PURGE SCOPE ---
        CLIENT_FUNC_SCOPES.put("list_purge_requests", SCOPE_PURGE);
        CLIENT_FUNC_SCOPES.put("update_purge_status", SCOPE_PURGE);
    }
    
    @Override
    public void destroy() {
        // Any cleanup of resources
    }

    static {
        // Static initialization if needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String method = req.getMethod();
        String uri = req.getRequestURI();
        String servletPath = req.getServletPath(); // e.g., /api/v1/user, /api/v1/policy

        // Set common response headers (CORS, Content-Type, Encoding)
        // CORS headers are crucial for frontend access from different origins
        res.setHeader("Access-Control-Allow-Origin", "*"); // For development, allow all. Restrict in production.
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-API-KEY");
        res.setHeader("Access-Control-Max-Age", "3600");
        res.setCharacterEncoding("UTF-8");
        res.setContentType("application/json");

        // Security Context Routing
        // The Wallet Sync endpoint uses scoped tokens instead of master API keys.
        // We bypass the standard key validation for this specific path.
        // To do: Dont directly reference Wallet class here
        if (uri.contains("/client/wallet/sync")) {
            // Forward to Wallet Service logic
            // The Wallet service handles its own 'validateSyncToken' logic internally
            InputProcessor.processInput(req, res);
            new Wallet().post(req, res);
            return;
        }

        if ("GET".equalsIgnoreCase(method) && uri.contains("/admin/job")) {
            // Forward to Job service
            // The Wallet service handles its own 'validateSyncToken' logic internally
            InputProcessor.processInput(req, res);
            new Job().post(req, res);
            return;
        }

        // Handle OPTIONS preflight requests for CORS
        if ("OPTIONS".equalsIgnoreCase(method)) {
            res.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        Properties apiRegistry = SystemConfig.getProcessorConfig(); // Assuming this loads servlet mappings
        // Properties config = SystemConfig.getAppConfig(); // Unused in original, keeping for template consistency

        // Check if the request URI starts with our API prefix
        if (!uri.startsWith(API_PREFIX)) {
            chain.doFilter(request, response); // Not an API call we manage, pass through
            return;
        }

        // Determine if it's an Admin or Client API call based on path
        String pathAfterApiPrefix = uri.substring(API_PREFIX.length()); // e.g., "user", "policy", "admin/user", "client/consent"
        String[] pathSegments = pathAfterApiPrefix.split(URL_DELIMITER);

        String apiCategory = null; // "admin" or "client"
        String serviceName = null; // "user", "policy", "consent" etc.

        if (pathSegments.length >= 1) {
            if (CLIENT_URI_PATH.equalsIgnoreCase(pathSegments[0])) {
                apiCategory = CLIENT_URI_PATH;
                if (pathSegments.length >= 2) {
                    serviceName = pathSegments[1]; // e.g., /api/v1/client/consent -> serviceName "consent"
                }
            } else if (ADMIN_URI_PATH.equalsIgnoreCase(pathSegments[0])){
                // If it's directly /api/v1/user or /api/v1/policy, assume it's an admin endpoint by default
                // Or, you could make it explicitly invalid if not prefixed with /admin or /client
                apiCategory = ADMIN_URI_PATH; // Default to admin if no explicit category
                if (pathSegments.length >= 2) {
                    serviceName = pathSegments[1]; // e.g., /api/v1/admin/policy -> serviceName "policy"
                }
            } else if (BOOTSTRAP_URI_PATH.equalsIgnoreCase(pathSegments[0])){
                // If it's directly /api/v1/user or /api/v1/policy, assume it's an admin endpoint by default
                // Or, you could make it explicitly invalid if not prefixed with /admin or /client
                apiCategory = BOOTSTRAP_URI_PATH; // Default to admin if no explicit category
                if (pathSegments.length >= 2) {
                    serviceName = pathSegments[1]; // e.g., /api/v1/admin/policy -> serviceName "policy"
                }
            }else{
                apiCategory = ADMIN_URI_PATH; // Default to admin if no explicit category
                serviceName = pathSegments[0];
            }
        }

        // Construct the full servlet path for lookup in apiRegistry
        // This assumes apiRegistry stores paths like "/api/v1/user" not "/api/v1/admin/user"
        // If your apiRegistry stores "/api/v1/admin/user", then use servletPath directly.
        String targetServletPath = API_PREFIX + (serviceName != null ? serviceName : "");
        if (!apiRegistry.containsKey(targetServletPath.trim())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "API endpoint not found: " + uri, uri);
            return;
        }

        String classname = apiRegistry.getProperty(targetServletPath.trim());
        if (classname == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Configuration Error", "Servlet class not mapped for: " + uri, uri);
            return;
        }

        boolean authenticated = false;
        String errorMessage = "Authentication failed.";

        // --- Validate _func and specific permissions for POST requests ---
        if (!"POST".equalsIgnoreCase(method)) {
            res.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed");
            return;
        }

        // --- Authentication & Authorization ---
        try {
            InputProcessor.processInput(req, res);
            JSONObject inputJson = InputProcessor.getInput(req); // InputProcessor should parse and set this
            String func = (String) inputJson.get("_func");

            // Basic TSI Framework Validations
            if (inputJson == null) { // Should not happen if InputProcessor.validate passed
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing JSON request body.", uri);
                return;
            }
            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", uri);
                return;
            }
            if (!InputProcessor.validate(req, res)) { // Validates content-type and basic body parsing
                return; // Error response already sent by InputProcessor
            }

            // Enforce _func whitelist for Client APIs
            if (CLIENT_URI_PATH.equalsIgnoreCase(apiCategory)) {
                if (!CLIENT_ALLOWED_FUNCS.contains(func.toLowerCase())) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Function '" + func + "' is not allowed for client API access.", uri);
                    return;
                }

                String requiredScope = CLIENT_FUNC_SCOPES.get(func.toLowerCase());
                // B. Authenticate Credentials (API Key/Secret)
                if (InputProcessor.processClientHeader(req, res)) {
                    // RBAC Verification
                    // InputProcessor.hasPermission checks if the API Key/Token possesses the required scope (READ/WRITE/PURGE)
                    if (InputProcessor.hasPermission(req, requiredScope)) {
                        authenticated = true;
                    }
                }
            } else if (ADMIN_URI_PATH.equalsIgnoreCase(apiCategory)) {
                if (ADMIN_NOAUTH_FUNCS.contains(func.toLowerCase())) {
                    authenticated = true;
                } else {
                    authenticated = InputProcessor.processAdminHeader(req, res);
                    //authenticated = true; // go easy for now
                }
            }else if (BOOTSTRAP_URI_PATH.equalsIgnoreCase(apiCategory)){
                authenticated = true;
            }else {
                // If no category specified, or unknown category, deny by default
                errorMessage = "API category not specified or recognized. Access denied.";
            }

            if (!authenticated) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", errorMessage, uri);
                return;
            }

            // --- Instantiate and execute Servlet ---
            Action action = ((Action) Class.forName(classname).getConstructor().newInstance());

            // The service's own validate method (e.g., checking method, specific input fields)
            boolean validRequest = action.validate(method, req, res);
            if (validRequest) {
                action.post(req, res);
            }
        } catch (Exception e) { // Catch any other unexpected exceptions
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), uri);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        SystemConfig.loadProcessorConfig(filterConfig.getServletContext()); // Assuming this method name
        System.out.println("Loaded TSI Processor Config");
        SystemConfig.loadAppConfig(filterConfig.getServletContext());
        System.out.println("Loaded TSI App Config");
        JSONSchemaValidator.createInstance(filterConfig.getServletContext());
        System.out.println("Loaded TSI Schema Validator");
        System.out.println("TSI DPDP CMS Service started in " + System.getenv("TSI_DPDP_CMS_ENV") + " environment");
    }
}