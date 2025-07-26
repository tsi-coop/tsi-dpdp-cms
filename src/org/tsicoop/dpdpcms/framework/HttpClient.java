package org.tsicoop.dpdpcms.framework;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class HttpClient {

    private final java.net.http.HttpClient httpClient = java.net.http.HttpClient.newBuilder()
            .version(java.net.http.HttpClient.Version.HTTP_2)
            .build();

    public static void main(String[] args) throws Exception {
        HttpClient obj = new HttpClient();
        String authorization = "Zoho-enczapikey wSsVR61/+xT0WK11zjb/ce0wmwlcBFnxR0l+3wSh4nWvHPnB9MdtkUzOBgeuGqVNGW9oEDpErLkrkB4AhDNYh4glzlBSCiiF9mqRe1U4J3x17qnvhDzDXGhVlxqLK4INww5om2lnG8gl+g== ";
        JSONObject test = new JSONObject();
        JSONObject fromOb = new JSONObject();
        fromOb.put("address","noreply@tsicoop.org");
        fromOb.put("name","TSI Coop Notification");
        test.put("from",fromOb);
        JSONObject address = new JSONObject();
        address.put("address","satish@tsiconsulting.in");
        address.put("name","Satish");
        JSONObject toAddress = new JSONObject();
        toAddress.put("email_address",address);
        JSONArray toArray = new JSONArray();
        toArray.add(toAddress);
        test.put("to",toArray);
        test.put("subject","Your Login Password");
        test.put("htmlbody","<div><b> Test email sent successfully. </b></div>");
        //System.out.println(test);
        JSONObject output = obj.sendPost("https://api.zeptomail.com/v1.1/email", authorization,test);
        System.out.println(output);
    }


    public void sendGet(String url) throws Exception {

        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(url))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // print status code
        System.out.println(response.statusCode());

        // print response body
        System.out.println(response.body());

    }

    public JSONObject sendGet(String url,String authorization) throws Exception {
        JSONObject res = null;
        String resstring = null;
        JSONParser parser = new JSONParser();
        //HttpRequest request = null;
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(url))
                .setHeader("ent_authorization", authorization)
                .setHeader("Content-Type", "application/json")
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // print status code
        System.out.println(response.statusCode());

        // print response body
        System.out.println(response.body());
        resstring = response.body();
        res = (JSONObject) parser.parse(resstring);
        return res;
    }

    public JSONObject sendPost(String url, String authorization, JSONObject data) throws Exception {
        JSONObject res = null;
        String resstring = null;
        JSONParser parser = new JSONParser();
        HttpRequest request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
                .uri(URI.create(url))
                .setHeader("authorization", authorization)
                .setHeader("Content-Type", "application/json")
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        resstring = response.body();
        res = (JSONObject) parser.parse(resstring);
        return res;
    }

    public JSONObject sendPost(String url, JSONObject data,String authheader, String authheadervalue) throws Exception {
        JSONObject res = null;
        String resstring = null;
        JSONParser parser = new JSONParser();
        HttpRequest request = null;
        System.out.println(url);
        //System.out.println(authorization);
        System.out.println(data);
        request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
                .uri(URI.create(url))
                .setHeader(authheader, authheadervalue)
                .setHeader("Content-Type", "application/json")
                .build();
        System.out.println("Request "+request);
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        resstring = response.body();
        res = (JSONObject) parser.parse(resstring);
        return res;
    }
}
