package org.tsicoop.dpdpcms.framework;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.*;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;

public class CESUtil {

    public static JSONArray appendConsentExpiry(JSONObject policy, JSONArray consents, String action) {
        // Retrieve the processing purposes array from the English ('en') policy section
        JSONObject langJSON = (JSONObject) policy.get("en");
        JSONArray policyPurposes = (JSONArray) langJSON.get("data_processing_purposes");
        JSONArray result = new JSONArray();

        ZonedDateTime now = ZonedDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ISO_INSTANT;

        Iterator<JSONObject> consentIt = consents.iterator();
        JSONObject consent = null;
        while (consentIt.hasNext()) {
            consent = (JSONObject) consentIt.next();
            String dataPointId = (String) consent.get("data_point_id");
            boolean granted = (Boolean) consent.get("consent_granted");

            // Find corresponding purpose in policy
            JSONObject matchedPurpose = null;
            for (int j = 0; j < policyPurposes.size(); j++) {
                JSONObject p = (JSONObject) policyPurposes.get(j);
                if (((String)p.get("id")).equals(dataPointId)) {
                    matchedPurpose = p;
                    break;
                }
            }

            if (matchedPurpose != null) {
                String startEvent = (String) matchedPurpose.get("retention_start_event");
                int durationValue = (int)(long)matchedPurpose.get("retention_duration_value");
                String durationUnit = (String) matchedPurpose.get("retention_duration_unit");
                ZonedDateTime expiryDate;

                if ("CONSENT_GIVEN".equals(action)) {
                    if ("CONSENT_GIVEN".equals(startEvent)) {
                        expiryDate = calculateExpiry(now, durationValue, durationUnit);
                    } else {
                        // If given but policy event is different, leave null or default
                        expiryDate = null;
                    }
                } else if ("CONSENT_WITHDRAWN".equals(action)) {
                    consent.put("consent_granted",false);
                    if ("CONSENT_WITHDRAWN".equals(startEvent)) {
                        expiryDate = calculateExpiry(now, durationValue, durationUnit);
                    } else if ("CONSENT_GIVEN".equals(startEvent)) {
                        // Per requirement: set to current time if start event was CONSENT_GIVEN
                        expiryDate = now;
                    } else {
                        expiryDate = null;
                    }
                } else {
                    expiryDate = null;
                }
                if (expiryDate != null) {
                    consent.put("consent_expiry", formatter.format(expiryDate));
                }
            }
            result.add(consent);
        }
        return result;
    }

    private static ZonedDateTime calculateExpiry(ZonedDateTime base, int value, String unit) {
        switch (unit.toUpperCase()) {
            case "YEARS": return base.plusYears(value);
            case "MONTHS": return base.plusMonths(value);
            case "DAYS": return base.plusDays(value);
            default: return base;
        }
    }

    public static JSONObject readJSON(String filePath) {
        JSONParser parser = new JSONParser();
        JSONObject jsonObject = new JSONObject();
        StringBuffer buff = new StringBuffer();
        try {
            InputStream inputStream = new FileInputStream(filePath);
            if (inputStream != null) {
                try (InputStreamReader isReader = new InputStreamReader(inputStream);
                     BufferedReader reader = new BufferedReader(isReader)) { // BufferedReader for efficient line reading
                    String line;
                    while ((line = reader.readLine()) != null) {
                        buff.append(line);
                    }
                } catch (Exception e) {
                    System.err.println("Error reading stream: " + e.getMessage());
                }
            }
            jsonObject = (JSONObject) parser.parse(buff.toString());
        } catch (Exception e) {
            System.err.println("Error reading JSON file from path " + filePath + ": " + e.getMessage());
        }
        return jsonObject;
    }

    public static JSONArray readJSONArray(String filePath) {
        JSONParser parser = new JSONParser();
        JSONArray jsonArr = new JSONArray();
        StringBuffer buff = new StringBuffer();
        try {
            InputStream inputStream = new FileInputStream(filePath);
            if (inputStream != null) {
                try (InputStreamReader isReader = new InputStreamReader(inputStream);
                     BufferedReader reader = new BufferedReader(isReader)) { // BufferedReader for efficient line reading
                    String line;
                    while ((line = reader.readLine()) != null) {
                        buff.append(line);
                    }
                } catch (Exception e) {
                    System.err.println("Error reading stream: " + e.getMessage());
                }
            }
            jsonArr = (JSONArray) parser.parse(buff.toString());
        } catch (Exception e) {
            System.err.println("Error reading JSON file from path " + filePath + ": " + e.getMessage());
        }
        return jsonArr;
    }

    public static void main(String[] args){
        JSONObject policy = CESUtil.readJSON("C:\\work\\tsi-dpdp-cms\\tests\\curl\\admin\\sample_policy_en.json");
        JSONArray consentsIn = CESUtil.readJSONArray("C:\\work\\tsi-dpdp-cms\\tests\\curl\\admin\\sample_consents.json");
        JSONArray consentsOut = CESUtil.appendConsentExpiry(policy, consentsIn, "CONSENT_WITHDRAWN");
        System.out.println(consentsOut);
    }
}
