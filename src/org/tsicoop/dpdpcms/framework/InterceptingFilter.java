package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject; // For parsing input in validateRequestFunc
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.UUID; // For UUID parsing


public class InterceptingFilter implements Filter {

    private static final String URL_DELIMITER = "/";
    private static final String ADMIN_URI_PATH = "admin";
    private static final String CLIENT_URI_PATH = "client";
    private static final String API_PREFIX = "/api/v1/"; // Assuming API paths are /api/v1/user, /api/v1/policy etc.

    // Whitelist of _func values allowed for client API calls
    private static final Set<String> CLIENT_ALLOWED_FUNCS = new HashSet<>(Arrays.asList(
            "record_consent",
            "get_active_consent", // Renamed from getPrincipal to match ConsentRecordService
            "get_policy", // For specific policy version retrieval
            "get_active_policy", // For active policy retrieval
            "link_user",
            "submit_grievance" // Allowing grievance submission from client
            // Add other client-facing functions as needed
    ));

    private static final Set<String> ADMIN_NOAUTH_FUNCS = new HashSet<>(Arrays.asList(
            "reset_password",
            "login"
    ));

    private static final HashMap<String, String> filterConfig = new HashMap<>(); // Unused in original, keeping for template consistency

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
            if (ADMIN_URI_PATH.equalsIgnoreCase(pathSegments[0])) {
                apiCategory = ADMIN_URI_PATH;
                if (pathSegments.length >= 2) {
                    serviceName = pathSegments[1]; // e.g., /api/v1/admin/user -> serviceName "user"
                }
            } else if (CLIENT_URI_PATH.equalsIgnoreCase(pathSegments[0])) {
                apiCategory = CLIENT_URI_PATH;
                if (pathSegments.length >= 2) {
                    serviceName = pathSegments[1]; // e.g., /api/v1/client/consent -> serviceName "consent"
                }
            } else {
                // If it's directly /api/v1/user or /api/v1/policy, assume it's an admin endpoint by default
                // Or, you could make it explicitly invalid if not prefixed with /admin or /client
                apiCategory = ADMIN_URI_PATH; // Default to admin if no explicit category
                serviceName = pathSegments[0];
            }
        }

        // Construct the full servlet path for lookup in apiRegistry
        // This assumes apiRegistry stores paths like "/api/v1/user" not "/api/v1/admin/user"
        // If your apiRegistry stores "/api/v1/admin/user", then use servletPath directly.
        String targetServletPath = API_PREFIX + (serviceName != null ? serviceName : "");
        //System.out.println("Target Servlet Path:"+targetServletPath);

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

        // --- Authentication & Authorization ---
        try {
            InputProcessor.processInput(req, res);
            JSONObject inputJson = InputProcessor.getInput(req); // InputProcessor should parse and set this
            String func = (String) inputJson.get("_func");

            // --- Validate _func and specific permissions for POST requests ---
            if ("POST".equalsIgnoreCase(method)) {
                if (!InputProcessor.validate(req, res)) { // Validates content-type and basic body parsing
                    return; // Error response already sent by InputProcessor
                }
                if (inputJson == null) { // Should not happen if InputProcessor.validate passed
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing JSON request body.", uri);
                    return;
                }

                if (func == null || func.trim().isEmpty()) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", uri);
                    return;
                }

                // Enforce _func whitelist for Client APIs
                if (CLIENT_URI_PATH.equalsIgnoreCase(apiCategory)) {
                    if (!CLIENT_ALLOWED_FUNCS.contains(func.toLowerCase())) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Function '" + func + "' is not allowed for client API access.", uri);
                        return;
                    }
                    // For client APIs, ensure the API key is associated with a Fiduciary
                    /*if (authContext.getFiduciaryId() == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "API Key not associated with a Data Fiduciary.", uri);
                        return;
                    }*/
                }

                // Generic permission check based on authContext.getPermissions()
                // This would be more complex in a real system, matching resource:action
                // For example: authContext.hasPermission(serviceName + ":" + func.toLowerCase())
                // For now, relies on the service's internal validation for granular checks.
            }

            if (ADMIN_URI_PATH.equalsIgnoreCase(apiCategory)) {
                if (ADMIN_NOAUTH_FUNCS.contains(func.toLowerCase())) {
                    authenticated = true;
                }else{
                    authenticated = InputProcessor.processAdminHeader(req, res);
                }
            } else if (CLIENT_URI_PATH.equalsIgnoreCase(apiCategory)) {
                authenticated = InputProcessor.processClientHeader(req, res);
            } else {
                // If no category specified, or unknown category, deny by default
                errorMessage = "API category not specified or recognized. Access denied.";
            }

            if (!authenticated) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", errorMessage, uri);
                return;
            }


            // --- Instantiate and execute Servlet ---
            REST action = ((REST) Class.forName(classname).getConstructor().newInstance());

            // The service's own validate method (e.g., checking method, specific input fields)
            boolean validRequest = action.validate(method, req, res);
            if (validRequest) {
                // Call the appropriate method on the REST service
                if (method.equalsIgnoreCase("POST")) { // All our services use POST
                    action.post(req, res);
                } else {
                    // This should ideally not be reached if validate method correctly handles non-POST
                    res.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed");
                }
            }

        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | java.lang.reflect.InvocationTargetException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server Error", "Failed to instantiate API handler: " + e.getMessage(), uri);
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

        // Initialize JWT and API Key validators here if they need global setup
        // JwtValidator.init(SystemConfig.getAppConfig().getProperty("jwt.secret"));
        // ApiKeyValidator.init(SystemConfig.getPoolDB()); // Or pass connection pool
    }
}