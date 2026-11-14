package org.tsicoop.dpdpcms.framework;

import com.networknt.schema.ValidationMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.framework.PasswordHasher;
import org.tsicoop.dpdpcms.service.v1.Audit;
import org.tsicoop.dpdpcms.util.Constants;

import java.io.BufferedReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class InputProcessor {
    public final static String REQUEST_DATA = "input_json";
    public final static String AUTH_TOKEN = "auth_token";

    // Cookie lifetime follows the operator token lifetime (TOKEN_TTL_MINUTES, default 8 hours)
    private static final long CONSOLE_SESSION_MAX_AGE_SECONDS = JWTUtil.operatorTtlSeconds();

    /**
     * Sets the HttpOnly session cookie that ConsoleAuthFilter checks before serving
     * /console/admin/* and /console/dpo/* pages. Built as a raw header rather than via
     * jakarta.servlet.http.Cookie because Servlet 5.0's Cookie API has no SameSite support.
     * Secure is omitted only in the "local" env so http-only local dev keeps working.
     */
    public static void setConsoleSessionCookie(HttpServletResponse res, String token) {
        boolean secure = !"local".equals(System.getenv("TSI_DPDP_CMS_ENV"));
        StringBuilder cookie = new StringBuilder();
        cookie.append(Constants.CONSOLE_SESSION_COOKIE).append('=').append(token)
                .append("; Path=/console; Max-Age=").append(CONSOLE_SESSION_MAX_AGE_SECONDS)
                .append("; HttpOnly; SameSite=Strict");
        if (secure) cookie.append("; Secure");
        res.addHeader("Set-Cookie", cookie.toString());
    }

    /** Expires the console session cookie set at login. Used on logout. */
    public static void clearConsoleSessionCookie(HttpServletResponse res) {
        boolean secure = !"local".equals(System.getenv("TSI_DPDP_CMS_ENV"));
        StringBuilder cookie = new StringBuilder();
        cookie.append(Constants.CONSOLE_SESSION_COOKIE).append("=; Path=/console; Max-Age=0; HttpOnly; SameSite=Strict");
        if (secure) cookie.append("; Secure");
        res.addHeader("Set-Cookie", cookie.toString());
    }

    private static final String CLIENT_PERMISSIONS = "CLIENT_PERMISSIONS";

    private static Map<String,Set<String>> permissionsMap = new ConcurrentHashMap<String, Set<String>>();

    private static final long API_CACHE_TTL_MS = 60_000L;

    private static class CachedEntry {
        final boolean valid;
        final long expiresAt;
        CachedEntry(boolean valid) {
            this.valid = valid;
            this.expiresAt = System.currentTimeMillis() + API_CACHE_TTL_MS;
        }
        boolean isExpired() { return System.currentTimeMillis() > expiresAt; }
    }

    private static final Map<String, CachedEntry> apiClientCache = new ConcurrentHashMap<>();


    /**
     * Verifies if the authenticated client or user possesses the required permission scope.
     * This method is called by InterceptingFilter after processClientHeader has loaded the scopes.
     */
    public static boolean hasPermission(HttpServletRequest req, String requiredScope) {
        Object permsObj = retrievePerms(req);
        if (permsObj instanceof Set) {
            Set<String> permissions = (Set<String>) permsObj;
            String permstr = permissions.toString();
            return permstr.contains(requiredScope.toUpperCase());
        }
        return false;
    }

    /**
     * Retrieves app permissions.
     * Loads authorized scopes (READ, WRITE, PURGE) from the registry into the request context.
     */
    public static Set<String> retrievePerms(HttpServletRequest req) {
        String key = req.getHeader("X-API-Key");
        String secret = req.getHeader("X-API-Secret");
        Set<String> scopeSet = null;
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        if(permissionsMap.get(key)!=null){
            scopeSet = (Set<String>) permissionsMap.get(key);
        }
        else {
            UUID keyUuid;
            try {
                keyUuid = UUID.fromString(key);
            } catch (Exception e) {
                // Malformed (non-UUID) key -- treat as "no permissions", not a crash.
                return null;
            }
            try {
                pool = new PoolDB();
                conn = pool.getConnection();
                String sql = "SELECT fiduciary_id, permissions, key_value FROM api_keys WHERE id = ? AND status = 'ACTIVE'";
                pstmt = conn.prepareStatement(sql);
                pstmt.setObject(1, keyUuid);
                rs = pstmt.executeQuery();

                if (rs.next() && new PasswordHasher().checkPassword(secret, rs.getString("key_value"))) {
                    req.setAttribute("fiduciary_id", rs.getObject("fiduciary_id"));

                    String rawPerms = rs.getString("permissions");
                    scopeSet = new HashSet<>();
                    if (rawPerms != null) {
                        for (String p : rawPerms.split(",")) {
                            scopeSet.add(p.trim().toUpperCase());
                        }
                    }
                    permissionsMap.put(key, scopeSet);
                }
            } catch (Exception e) {
                System.err.println("Client Auth Failure: " + e.getMessage());
            } finally {
                pool.cleanup(rs, pstmt, conn);
            }
        }
        return scopeSet;
    }

    public static void processInput(HttpServletRequest request, HttpServletResponse response) {
        StringBuilder buffer = new StringBuilder();
        try {
            // 1. Attempt to read from the input stream (POST body)
            BufferedReader reader = request.getReader();
            String line = null;
            while ((line = reader.readLine()) != null) {
                buffer.append(line);
                buffer.append(System.lineSeparator());
            }

            String data = buffer.toString().trim();

            // 2. Fallback: If data is empty, extract parameters and wrap in JSON
            if (data.isEmpty()) {
                JSONObject jsonParams = new JSONObject();
                Enumeration<String> paramNames = request.getParameterNames();

                while (paramNames.hasMoreElements()) {
                    String name = paramNames.nextElement();
                    String[] values = request.getParameterValues(name);

                    if (values != null && values.length > 0) {
                        // Handle single vs multiple values for the same parameter key
                        if (values.length == 1) {
                            jsonParams.put(name, values[0]);
                        } else {
                            JSONArray valArray = new JSONArray();
                            for (String v : values) {
                                valArray.add(v);
                            }
                            jsonParams.put(name, valArray);
                        }
                    }
                }
                data = jsonParams.toJSONString();
            }

            // 3. Persist the normalized JSON data as a request attribute
            request.setAttribute(REQUEST_DATA, data);

        } catch (Exception e) {
            System.err.println("InputProcessor critical failure: " + e.getMessage());
            request.setAttribute(REQUEST_DATA, "{}");
        }
    }

    public static boolean processAdminHeader(HttpServletRequest request, HttpServletResponse response) {
        boolean validheader = false;
        JSONObject authToken = null;
        try {
            authToken = getAdminAuthToken(request, response);
            if(authToken != null) {
                request.setAttribute(AUTH_TOKEN, authToken);
                validheader = true;
            }
        }catch (Exception e){}
        return validheader;
    }

    public static boolean processClientHeader(HttpServletRequest req, HttpServletResponse res) {
        boolean validheader = false;
        String apiKey = req.getHeader("X-API-Key");
        String apiSecret = req.getHeader("X-API-Secret");

        if (apiKey == null || apiSecret == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing API Key or Secret.", req.getRequestURI());
            return false;
        }

        // Validate API Key and Secret against the api_user table
        try {
            if (!isValidApiClient(apiKey, apiSecret)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or inactive API Key/Secret.", req.getRequestURI());
                return false;
            }
            else{
                validheader = true;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "Authentication failed due to database error.", req.getRequestURI());
            return false;
        }
        return validheader;
    }

    private static boolean isValidApiClient(String apiKey, String apiSecret) throws SQLException {
        String cacheKey = apiKey + ":" + apiSecret;
        CachedEntry cached = apiClientCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.valid;
        }
        apiClientCache.remove(cacheKey);

        UUID keyUuid;
        try {
            keyUuid = UUID.fromString(apiKey);
        } catch (Exception e) {
            // Malformed (non-UUID) key -- not a valid client, not a server error.
            return false;
        }

        boolean valid = false;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT status, key_value FROM api_keys WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, keyUuid);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String status = rs.getString("status");
                String storedHash = rs.getString("key_value");
                if (status.equalsIgnoreCase("ACTIVE") && new PasswordHasher().checkPassword(apiSecret, storedHash)) {
                    valid = true;
                    apiClientCache.put(cacheKey, new CachedEntry(true));
                }
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return valid;
    }

    public static String getEmail(HttpServletRequest req){
        JSONObject authToken = null;
        String email = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            email = (String) authToken.get("email");
        }catch(Exception e){
            e.printStackTrace();
        }
        return email;
    }

    public static UUID getAuthenticatedUserId(HttpServletRequest req){
        JSONObject authToken = null;
        UUID loginUserId = null;
        String email = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        String sql = "SELECT id FROM operators WHERE email_hmac = " + DbEncryption.HMAC;

        authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
        if(authToken == null) return null;
        email = (String) authToken.get("email");

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            DbEncryption.bindHmac(pstmt, 1, email);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                loginUserId = UUID.fromString(rs.getString("id"));
            }
        }catch(Exception e){
            e.printStackTrace();
        }finally{
            pool.cleanup(rs,pstmt,conn);
        }
        return loginUserId;
    }

    /** True if the caller's session passed a TOTP check. */
    public static boolean hasMfa(HttpServletRequest req) {
        JSONObject authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
        return authToken != null && Boolean.TRUE.equals(authToken.get("mfa"));
    }

    public static String getName(HttpServletRequest req){
        JSONObject authToken = null;
        String name = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            name = (String) authToken.get("name");
        }catch(Exception e){
            e.printStackTrace();
        }
        return name;
    }

    public static String getRole(HttpServletRequest req){
        JSONObject authToken = null;
        String role = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            role = (String) authToken.get("role");
        }catch(Exception e){
            e.printStackTrace();
        }
        return role;
    }

    /** Immediately evicts a revoked/deactivated API key from both in-process caches. */
    public static void evictApiKeyCache(String apiKeyId) {
        permissionsMap.remove(apiKeyId);
        apiClientCache.entrySet().removeIf(e -> e.getKey().startsWith(apiKeyId + ":"));
    }

    private static final String VERIFIED_OPERATOR = "verified_operator";

    /** Role and fiduciary of the authenticated operator as stored in the database (not the JWT claims). */
    private static final class VerifiedOperator {
        final String role; final UUID fiduciaryId;
        VerifiedOperator(String role, UUID fiduciaryId) { this.role = role; this.fiduciaryId = fiduciaryId; }
    }

    /** One query per request: the result is kept on the request, so repeated calls cost nothing. */
    private static VerifiedOperator verifiedOperator(HttpServletRequest req) {
        Object cached = req.getAttribute(VERIFIED_OPERATOR);
        if (cached instanceof VerifiedOperator) return (VerifiedOperator) cached;
        JSONObject authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
        if (authToken == null) return null;
        String email = (String) authToken.get("email");
        if (email == null) return null;

        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT role, fiduciary_id FROM operators WHERE email_hmac = " + DbEncryption.HMAC + " AND status = 'ACTIVE'");
            DbEncryption.bindHmac(pstmt, 1, email);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                VerifiedOperator v = new VerifiedOperator(rs.getString("role"), (UUID) rs.getObject("fiduciary_id"));
                req.setAttribute(VERIFIED_OPERATOR, v);
                return v;
            }
        } catch (Exception e) {
            System.err.println("[ERROR] InputProcessor.verifiedOperator: " + e);
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }

    /** Returns the role from the database for the authenticated user, not from the JWT claim. */
    public static String getVerifiedRole(HttpServletRequest req) {
        VerifiedOperator v = verifiedOperator(req);
        return v == null ? null : v.role;
    }

    // ---------------------------------------------------------------------------------------
    // Record ownership: "is this caller allowed to touch a record of fiduciary X?"
    // The caller's fiduciary comes from their credential, never from the request body:
    //   operator       -> operators.fiduciary_id
    //   principal JWT  -> the token's fid claim (stamped on the request by the filter)
    //   API key        -> api_keys.fiduciary_id (only after the key and secret validated)
    // ---------------------------------------------------------------------------------------
    private static final long KEY_FID_CACHE_MS = 60_000L;
    private static final Map<String, Object[]> apiKeyFiduciaryCache = new ConcurrentHashMap<>(); // keyId -> {UUID, fetchedAt}

    public static boolean isAdminCaller(HttpServletRequest req) {
        return "ADMIN".equalsIgnoreCase(getVerifiedRole(req));
    }

    /** The fiduciary the caller is bound to, or null if they have none / it cannot be established. */
    public static UUID getCallerFiduciaryId(HttpServletRequest req) {
        try {
            if (req.getAttribute(AUTH_TOKEN) != null) {
                return getVerifiedFiduciaryId(req); // operator
            }
            if (Boolean.TRUE.equals(req.getAttribute("auth_via_principal_jwt"))) {
                Object fid = req.getAttribute("fiduciary_id");
                return fid == null ? null : UUID.fromString(fid.toString());
            }
            String key = req.getHeader("X-API-Key");
            String secret = req.getHeader("X-API-Secret");
            if (key != null && secret != null && isValidApiClient(key, secret)) {
                return apiKeyFiduciary(UUID.fromString(key));
            }
        } catch (Exception e) {
            System.err.println("[ERROR] InputProcessor.getCallerFiduciaryId: " + e);
        }
        return null;
    }

    private static UUID apiKeyFiduciary(UUID keyId) throws SQLException {
        Object[] hit = apiKeyFiduciaryCache.get(keyId.toString());
        long now = System.currentTimeMillis();
        if (hit != null && now - (Long) hit[1] < KEY_FID_CACHE_MS) return (UUID) hit[0];
        PoolDB pool = null; Connection conn = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT fiduciary_id FROM api_keys WHERE id = ?");
            ps.setObject(1, keyId);
            rs = ps.executeQuery();
            UUID fid = rs.next() ? (UUID) rs.getObject(1) : null;
            apiKeyFiduciaryCache.put(keyId.toString(), new Object[]{fid, now});
            return fid;
        } finally {
            if (pool != null) pool.cleanup(rs, ps, conn);
        }
    }

    /** True if {@code operatorId} is an ACTIVE operator account of {@code fiduciaryId} (used to validate assignees). */
    public static boolean isActiveOperatorOf(UUID operatorId, UUID fiduciaryId) {
        if (operatorId == null || fiduciaryId == null) return false;
        PoolDB pool = null; Connection conn = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT 1 FROM operators WHERE id = ? AND fiduciary_id = ? AND status = 'ACTIVE'");
            ps.setObject(1, operatorId);
            ps.setObject(2, fiduciaryId);
            rs = ps.executeQuery();
            return rs.next();
        } catch (Exception e) {
            System.err.println("[ERROR] InputProcessor.isActiveOperatorOf: " + e);
            return false;
        } finally {
            if (pool != null) pool.cleanup(rs, ps, conn);
        }
    }

    /** Subject (data principal id) of a principal-JWT caller, else null. */
    public static String getPrincipalSubject(HttpServletRequest req) {
        if (!Boolean.TRUE.equals(req.getAttribute("auth_via_principal_jwt"))) return null;
        Object s = req.getAttribute("principal_user_id");
        return s == null ? null : s.toString();
    }

    /** May the caller touch a record of {@code recordFiduciaryId}? See {@link org.tsicoop.dpdpcms.util.RecordOwnership}. */
    public static boolean callerOwns(HttpServletRequest req, UUID recordFiduciaryId) {
        if (isAdminCaller(req)) return true;
        return org.tsicoop.dpdpcms.util.RecordOwnership.allowed(false, getCallerFiduciaryId(req), recordFiduciaryId);
    }

    /** Fiduciary the authenticated operator is bound to (null for platform ADMIN accounts). */
    public static UUID getVerifiedFiduciaryId(HttpServletRequest req) {
        VerifiedOperator v = verifiedOperator(req);
        return v == null ? null : v.fiduciaryId;
    }

    /**
     * Rejects the request with 403 if the authenticated caller's verified role is OPERATOR.
     * Used to keep governance actions (policy authoring, settings, breach reporting, etc.)
     * restricted to DPO/ADMIN while still allowing delegated closure work elsewhere.
     * @return true if the request was rejected (caller must stop processing), false otherwise.
     */
    public static boolean rejectIfOperator(HttpServletRequest req, HttpServletResponse res) {
        if ("OPERATOR".equalsIgnoreCase(getVerifiedRole(req))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                    "Operators are not permitted to perform this action.", req.getRequestURI());
            return true;
        }
        return false;
    }

    public static JSONObject getAdminAuthToken(HttpServletRequest req, HttpServletResponse res) throws Exception{
        JSONObject tokenDetails = null;
        String authorization = null;
        StringTokenizer strTok = null;
        String token = null;

        try {
            // Header only. Tokens in the URL (?auth=) leak through logs, history and Referer headers.
            authorization = req.getHeader("Authorization");
            if (authorization != null) {
                strTok = new StringTokenizer(authorization, " ");
                strTok.nextToken();
                token = strTok.nextToken();
            }
            if (token != null && JWTUtil.isTokenValid(token)) {
                tokenDetails = new JSONObject();
                tokenDetails.put("email",JWTUtil.getEmailFromToken(token));
                tokenDetails.put("name",JWTUtil.getNameFromToken(token));
                tokenDetails.put("role",JWTUtil.getRoleFromToken(token));
                tokenDetails.put("mfa",JWTUtil.hasMfa(token));
            } else if (token != null) {
                String tokenPrefix = token.length() > 12 ? token.substring(0, 12) : token;
                String sourceIp = req.getRemoteAddr();
                new Audit().logEventAsync(
                        tokenPrefix, UUID.fromString("00000000-0000-0000-0000-000000000000"),
                        Constants.SERVICE_TYPE_SYSTEM, null,
                        "JWT_VALIDATION_FAILED", "ip=" + sourceIp);
            }
        } catch (Exception e) {
            System.err.println("[ERROR] InputProcessor.getAdminAuthToken: " + e);
        }
        //System.out.println("tokenDetails:"+tokenDetails);
        return tokenDetails;
    }

    public static JSONObject getInput(HttpServletRequest req) throws Exception {
        JSONObject input = null;
        try {
            String inputs = (String) req.getAttribute(InputProcessor.REQUEST_DATA);
            if (inputs != null) inputs = inputs.trim();
            input = JacksonUtil.parse(inputs);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return input;
    }

    public static boolean validate(HttpServletRequest req, HttpServletResponse res) {

        JSONObject input = null;
        Set<ValidationMessage> errors = null;
        boolean valid = true;
        String func = null;

        try {
            input = InputProcessor.getInput(req);
            func = (String) input.get("_func");

            if(func == null){
                OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST,"_func missing");
                valid = false;
            }else{
                errors = JSONSchemaValidator.getHandle().validateSchema(func, input);
            }

            if(errors != null && errors.size()>0) {
                OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST, errors.toString());
                valid = false;
            }

        }catch(Exception e){
            e.printStackTrace();
            OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST,"Unknown input validation error");
            valid = false;
        }
        return valid;
    }

    public static String applyRules(String value) {
        if (value != null && value.trim().length() > 0) {
            try {
                value = URLDecoder.decode(value, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                //log.error(e.getMessage());
            }
            //value = StringEscapeUtils.unescapeHtml(value);
        } else {
            value = "";
        }
        return value;
    }
}
