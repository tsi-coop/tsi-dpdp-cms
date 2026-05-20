package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;

public class OutputProcessor {

    /**
     * Sends a successful or data-bearing JSON response serialized by Jackson.
     * Accepts JSONObject, JSONArray, or any Jackson-serializable type.
     */
    public static void send(HttpServletResponse res, int status, Object data) {
        res.setStatus(status);
        res.setCharacterEncoding("UTF-8");
        res.setContentType("application/json; charset=UTF-8");

        try {
            PrintWriter out = res.getWriter();
            if (data == null) {
                out.print("{}");
            } else {
                out.print(JacksonUtil.toJson(data));
            }
            out.flush();
        } catch (IOException e) {
            System.err.println("Failed to write response: " + e.getMessage());
        }
    }

    public static void errorResponse(HttpServletResponse res, int code, String error, String message, String path) {
        res.setStatus(code);
        res.setCharacterEncoding("UTF-8");
        res.setContentType("application/json; charset=UTF-8");

        JSONObject errorJson = new JSONObject();
        errorJson.put("timestamp", Instant.now().toString());
        errorJson.put("status", code);
        errorJson.put("error", error);
        errorJson.put("message", message);
        errorJson.put("path", path);

        try {
            PrintWriter out = res.getWriter();
            out.print(JacksonUtil.toJson(errorJson));
            out.flush();
        } catch (IOException e) {
            System.err.println("Critical error sending error response: " + e.getMessage());
        }
    }

    public static void sendError(HttpServletResponse res, int code, String error) {
        res.setStatus(code);
        res.setCharacterEncoding("UTF-8");
        res.setContentType("application/json; charset=UTF-8");

        JSONObject errorJson = new JSONObject();
        errorJson.put("timestamp", Instant.now().toString());
        errorJson.put("status", code);
        errorJson.put("error", error);

        try {
            PrintWriter out = res.getWriter();
            out.print(JacksonUtil.toJson(errorJson));
            out.flush();
        } catch (IOException e) {
            System.err.println("Critical error sending error response: " + e.getMessage());
        }
    }
}
