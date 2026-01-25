package org.tsicoop.dpdpcms.framework;

import com.networknt.schema.ValidationMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.BufferedReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.UUID;

public class InputProcessor {
    public final static String REQUEST_DATA = "input_json";
    public final static String AUTH_TOKEN = "auth_token";

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
        boolean valid = false;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT status FROM api_keys WHERE id = ? AND key_value = ?";
        //System.out.println("API Key:"+apiKey);
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(apiKey));
            pstmt.setString(2, "HASHED_"+apiSecret);
            rs = pstmt.executeQuery();
            if(rs.next()){
                String status = rs.getString("status");
                if(status.equalsIgnoreCase("ACTIVE")){
                    valid = true;
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
        String sql = "SELECT id FROM operators WHERE email=?";

        authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
        if(authToken == null) return null;
        email = (String) authToken.get("email");

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, email);
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

    public static JSONObject getAdminAuthToken(HttpServletRequest req, HttpServletResponse res) throws Exception{
        JSONObject tokenDetails = null;
        String authorization = null;
        StringTokenizer strTok = null;
        String token = null;

        try {
            authorization = req.getHeader("Authorization");
            if(authorization == null){
                token = req.getParameter("auth");
            }else {
                strTok = new StringTokenizer(authorization, " ");
                strTok.nextToken();
                token = strTok.nextToken();
            }
            if (JWTUtil.isTokenValid(token)) {
                tokenDetails = new JSONObject();
                tokenDetails.put("email",JWTUtil.getEmailFromToken(token));
                tokenDetails.put("name",JWTUtil.getNameFromToken(token));
                tokenDetails.put("role",JWTUtil.getRoleFromToken(token));
                //System.out.println("name:"+JWTUtil.getUsernameFromToken(token)+" role:"+JWTUtil.getRoleFromToken(token));
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        //System.out.println("tokenDetails:"+tokenDetails);
        return tokenDetails;
    }

    public static JSONObject getInput(HttpServletRequest req) throws Exception{
        JSONObject input = null;
        String inputs = null;
        try {
            inputs = (String) req.getAttribute(InputProcessor.REQUEST_DATA);
            if(inputs!=null) inputs = inputs.trim();
            //System.out.println("inputs:"+inputs);
            //inputs = applyRules(inputs);
            input = (JSONObject) new JSONParser().parse(inputs);
        }catch(Exception e){
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
