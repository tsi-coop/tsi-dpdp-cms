package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;

public interface REST {

    String NONE = "none";
    String CSV_OUTPUT = "csv";
    String JSON_OUTPUT = "json";
    String XML_OUTPUT = "xml";
    String DELIMITER = ".";
    JSONObject validator = null;

    void get(HttpServletRequest req, HttpServletResponse res);

    void post(HttpServletRequest req, HttpServletResponse res);

    void delete(HttpServletRequest req, HttpServletResponse res);

    void put(HttpServletRequest req, HttpServletResponse res);

    boolean validate(String method, HttpServletRequest req, HttpServletResponse res);
}
