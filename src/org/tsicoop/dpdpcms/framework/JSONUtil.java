package org.tsicoop.dpdpcms.framework;

import org.json.simple.JSONArray;

import java.util.ArrayList;
import java.util.List;

public class JSONUtil {

    public static String[] toStringArray(JSONArray array) {
        List<String> list = new ArrayList<String>();
        if(array!=null) {
            for (int i = 0; i < array.size(); i++) {
                list.add((String) array.get(i));
            }
        }
        String[] stringArray = list.toArray(new String[list.size()]);
        return stringArray;
    }

    public static JSONArray toJSONArray(String[] array) {
        JSONArray jarray = new JSONArray();
        for (int i=0; i<array.length; i++) {
            jarray.add(array[i]);
        }
        return jarray;
    }

}
