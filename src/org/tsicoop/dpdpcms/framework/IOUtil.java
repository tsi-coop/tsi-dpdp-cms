package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.http.HttpServletRequest;
import org.json.simple.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IOUtil {

    public static String getDataFormat(HttpServletRequest req) {
        String dataformat = "json";
        if (req.getServletPath().contains(".xml")) {
            dataformat = "xml";
        }
        return dataformat;
    }

    public static String getRequestAsString(HttpServletRequest req) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = req.getReader();
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } finally {
            reader.close();
        }
        return sb.toString();
    }

    public static HashMap<String, HashMap<String, String>> readCSV(HttpServletRequest req, String keycolumn) throws IOException {
        HashMap<String, HashMap<String, String>> hm = new HashMap<String, HashMap<String, String>>();
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = req.getReader();
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } finally {
            reader.close();
        }
        return hm;
    }


    public static boolean checkForSymbols(String str) {
        Pattern pattern = Pattern.compile("[^a-z0-9 ]", Pattern.CASE_INSENSITIVE);
        Matcher m = pattern.matcher(str);
        return m.find();
    }

    public static boolean specialCharacterCheck(ArrayList<String> list) {
        Iterator<String> itr = list.iterator();
        while (itr.hasNext()) {
            if (IOUtil.checkForSymbols(itr.next()))
                return true;
        }
        return false;
    }

    public static String csvString(JSONObject json, String key) {
        String retval = "";
        if (json == null || key == null || json.get(key) == null) return retval;
        retval = String.valueOf(json.get(key));
        if (retval.contains(",")) {
            retval = "\"" + retval + "\"";
        }
        return retval;
    }

    public static String convertBackSlashes(String path) {
        String pathString = path.replace('\\', '/');
        return pathString;
    }

    public static boolean containsWhitespace(String str) {
        int strLen = str.length();
        for (int i = 0; i < strLen; i++) {
            if (Character.isWhitespace(str.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    public static boolean checkUpperCase(String construct_name) {
        String check = construct_name.toLowerCase();
        return check.equals(construct_name);
    }
}
