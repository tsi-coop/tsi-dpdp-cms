package org.tsicoop.dpdpcms.framework;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtil {

    public static String arrayToString(String[] arr) {
        if (arr == null || arr.length == 0) {
            return "";
        }
        return Arrays.stream(arr).reduce((a, b) -> a + " " + b).orElse("");
    }

    public static String formatSearchQuery(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        String withoutAmpersands = input.replace("&", ""); // Remove all ampersands
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < withoutAmpersands.length(); i++) {
            char currentChar = withoutAmpersands.charAt(i);
            if (currentChar == ' ') {
                result.append('&');
            } else {
                result.append(currentChar);
            }
        }
        return result.toString();
    }

    public static String linkifyUrls(String text) {
        // Updated regex to find URLs:
        // 1. (https?://\\S+)         -> Matches http:// or https:// followed by non-whitespace characters (greedy)
        // OR
        // 2. (www\\.\\S+)            -> Matches www. followed by non-whitespace characters (greedy)
        // OR
        // 3. (\\b[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*(?:\\.(com|org|eu|in|co|io|net|gov|edu|biz|info|us|ca|uk|fr|de|jp|au|pk))\\b(?:/\\S*)?)
        //    Let's break down the 3rd part for clarity:
        //    \\b                                    - Word boundary
        //    [a-zA-Z0-9-]+                          - Matches the main domain name part (e.g., "abc" in "abc.com")
        //    (\\.[a-zA-Z0-9-]+)* - Matches optional subdomains (e.g., ".sub" in "sub.abc.com")
        //    (?:\\.(com|org|eu|in|co|io|net|gov|edu|biz|info|us|ca|uk|fr|de|jp|au|pk)) - Non-capturing group for the last dot and explicitly listed TLDs
        //    \\b                                    - Word boundary after the TLD
        //    (?:/\\S*)?                             - Optional: Non-capturing group to include a path starting with / and any non-whitespace characters
        String urlRegex = "(https?://\\S+)|(www\\.\\S+)|(\\b[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*(?:\\.(com|org|eu|in|co|io|net|gov|edu|biz|info|us|ca|uk|fr|de|jp|au|pk))\\b(?:/\\S*)?)";
        Pattern pattern = Pattern.compile(urlRegex);
        Matcher matcher = pattern.matcher(text);

        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String url = matcher.group(); // Get the entire matched string
            //System.out.println(url);

            // Prepend "http://" if the URL doesn't already have a protocol
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "http://" + url; // Default to http://
            }

            // Replace the found match with an <a> tag including target="_blank"
            matcher.appendReplacement(result, "<a href=\"" + url + "\" target=\"_blank\">" + matcher.group() + "</a>");
        }
        matcher.appendTail(result); // Append the rest of the string

        return result.toString();
    }

    public static void main(String[] args){
        System.out.println(StringUtil.linkifyUrls("sandbox.tsicoop.com"));
    }
}
