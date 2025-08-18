package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;

public interface Action {

    String NONE = "none";
    String CSV_OUTPUT = "csv";
    String JSON_OUTPUT = "json";
    String XML_OUTPUT = "xml";
    String DELIMITER = ".";
    JSONObject validator = null;

    void post(HttpServletRequest req, HttpServletResponse res);

    boolean validate(String method, HttpServletRequest req, HttpServletResponse res);
}
