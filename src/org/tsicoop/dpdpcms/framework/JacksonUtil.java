package org.tsicoop.dpdpcms.framework;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.List;
import java.util.Map;

/**
 * Central Jackson-based JSON utility.
 * The ObjectMapper is the security-critical replacement for json-simple's JSONParser,
 * which is unmaintained and should not be used to parse untrusted or external input.
 *
 * parse() / toJson() are the two primary entry points. Service code that already
 * holds JSONObject/JSONArray containers does not need to change.
 */
public class JacksonUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.USE_LONG_FOR_INTS, true); // match json-simple's Long for integers

    private JacksonUtil() {}

    public static ObjectMapper mapper() { return MAPPER; }

    /**
     * Parses a JSON string using Jackson's secure parser and converts the result
     * into a json-simple-compatible JSONObject tree (so service code requires no changes).
     */
    @SuppressWarnings("unchecked")
    public static JSONObject parse(String json) throws Exception {
        if (json == null || json.trim().isEmpty()) return new JSONObject();
        Object parsed = MAPPER.readValue(json, Object.class);
        return toJsonObject(parsed);
    }

    /** Converts a Jackson-deserialized Map into a JSONObject, recursively. */
    @SuppressWarnings("unchecked")
    public static JSONObject toJsonObject(Object obj) {
        JSONObject result = new JSONObject();
        if (obj instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) obj).entrySet()) {
                result.put(e.getKey().toString(), toValue(e.getValue()));
            }
        }
        return result;
    }

    /** Recursively converts a Jackson value to the appropriate json-simple type. */
    static Object toValue(Object value) {
        if (value instanceof Map) return toJsonObject(value);
        if (value instanceof List) {
            JSONArray arr = new JSONArray();
            for (Object item : (List<?>) value) arr.add(toValue(item));
            return arr;
        }
        return value; // String, Long, Double, Boolean, null — all native types
    }

    /** Serializes any object to a JSON string using Jackson. Falls back to "{}" on error. */
    public static String toJson(Object obj) {
        try {
            return MAPPER.writeValueAsString(obj);
        } catch (Exception e) {
            System.err.println("[ERROR] JacksonUtil.toJson: " + e.getMessage());
            return "{}";
        }
    }
}
