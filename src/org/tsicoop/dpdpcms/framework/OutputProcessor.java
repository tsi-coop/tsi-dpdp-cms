package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONAware;
import org.json.simple.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class OutputProcessor {

    /**
     * Sends a successful or data-bearing JSON response.
     */
    public static void send(HttpServletResponse res, int status, Object data) {
        // Set headers BEFORE getting the writer to lock in UTF-8
        res.setStatus(status);
        res.setCharacterEncoding("UTF-8");
        res.setContentType("application/json; charset=UTF-8");

        try {
            PrintWriter out = res.getWriter();
            if (data == null) {
                out.print("{}");
            } else if (data instanceof JSONAware) {
                out.print(((JSONAware) data).toJSONString());
            } else {
                // Defensive: ensure we don't print internal objects like HttpOutput
                out.print(JSONObject.escape(data.toString()));
            }
            out.flush();
        } catch (IOException e) {
            System.err.println("Failed to write response: " + e.getMessage());
        }
    }

    /**
     * Standardized error response to ensure the frontend always receives
     * valid JSON, even when things go wrong on the backend.
     */
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
            out.print(errorJson.toJSONString());
            out.flush();
        } catch (IOException e) {
            System.err.println("Critical error sending error response: " + e.getMessage());
        }
    }

    /**
     * Standardized error response to ensure the frontend always receives
     * valid JSON, even when things go wrong on the backend.
     */
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
            out.print(errorJson.toJSONString());
            out.flush();
        } catch (IOException e) {
            System.err.println("Critical error sending error response: " + e.getMessage());
        }
    }
}
