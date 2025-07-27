package org.tsicoop.dpdpcms.framework;

import org.xbill.DNS.*; // Import all classes from dnsjava
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for performing DNS lookups, specifically for TXT records.
 * Uses the dnsjava library.
 */
public class DnsVerifier {

    /**
     * Verifies if a specific TXT record value exists for a given domain.
     * This method is case-sensitive for the TXT record value by default.
     *
     * @param domain The domain name to query (e.g., "example.com" or "_dpdp.example.com").
     * @param expectedTxtValue The exact TXT record value to look for.
     * @return true if the TXT record with the expected value is found, false otherwise.
     */
    public static boolean verifyDnsTxtRecord(String domain, String expectedTxtValue) {
        if (domain == null || domain.trim().isEmpty()) {
            System.err.println("DnsVerifier: Domain cannot be null or empty.");
            return false;
        }
        if (expectedTxtValue == null || expectedTxtValue.trim().isEmpty()) {
            System.err.println("DnsVerifier: Expected TXT value cannot be null or empty.");
            return false;
        }

        try {
            // Create a lookup object for TXT records
            Lookup lookup = new Lookup(domain, Type.TXT);
            // Optional: Set a specific DNS server if needed, otherwise it uses system configured ones
            // SimpleResolver resolver = new SimpleResolver("8.8.8.8"); // Example Google DNS
            // lookup.setResolver(resolver);

            lookup.run(); // Perform the DNS query

            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                org.xbill.DNS.Record[] records = lookup.getAnswers();
                if (records != null) {
                    for (org.xbill.DNS.Record record : records) {
                        if (record instanceof TXTRecord) { // Ensure it's a TXT record
                            TXTRecord txtRecord = (TXTRecord) record;
                            // TXTRecord can contain multiple strings, iterate through them
                            List<String> strings = txtRecord.getStrings();
                            for (String s : strings) {
                                if (s.trim().equals(expectedTxtValue.trim())) {
                                    System.out.println(String.format("DnsVerifier: Found matching TXT record for domain '%s': '%s'", domain, s));
                                    return true;
                                }
                            }
                        }
                    }
                }
                System.out.println(String.format("DnsVerifier: No matching TXT record found for domain '%s' with value '%s'.", domain, expectedTxtValue));
            } else if (lookup.getResult() == Lookup.HOST_NOT_FOUND) {
                System.out.println(String.format("DnsVerifier: Domain '%s' not found or no TXT records exist.", domain));
            } else {
                System.err.println(String.format("DnsVerifier: DNS query failed for domain '%s': %s (Error Code: %d)", domain, lookup.getErrorString(), lookup.getResult()));
            }

        } catch (TextParseException e) {
            System.err.println("DnsVerifier: Invalid domain name format: " + domain + " - " + e.getMessage());
        } catch (Exception e) { // Catch broader exceptions for network issues etc.
            System.err.println("DnsVerifier: An unexpected error occurred during DNS query for domain '" + domain + "': " + e.getMessage());
            e.printStackTrace(); // Print stack trace for unexpected errors
        }
        return false;
    }

    /**
     * Retrieves all TXT records for a given domain.
     *
     * @param domain The domain name to query.
     * @return A list of all TXT record values found, or an empty list if none/error.
     */
    public static List<String> getAllTxtRecords(String domain) {
        List<String> txtValues = new ArrayList<>();
        if (domain == null || domain.trim().isEmpty()) {
            System.err.println("DnsVerifier: Domain cannot be null or empty when getting all TXT records.");
            return txtValues;
        }

        try {
            Lookup lookup = new Lookup(domain, Type.TXT);
            lookup.run();

            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                org.xbill.DNS.Record[] records = lookup.getAnswers();
                if (records != null) {
                    for (org.xbill.DNS.Record record : records) {
                        if (record instanceof TXTRecord) {
                            TXTRecord txtRecord = (TXTRecord) record;
                            txtValues.addAll(txtRecord.getStrings());
                        }
                    }
                }
            } else if (lookup.getResult() == Lookup.HOST_NOT_FOUND) {
                System.out.println(String.format("DnsVerifier: No TXT records found for domain '%s'.", domain));
            } else {
                System.err.println(String.format("DnsVerifier: DNS query failed for domain '%s': %s (Error Code: %d)", domain, lookup.getErrorString(), lookup.getResult()));
            }
        } catch (TextParseException e) {
            System.err.println("DnsVerifier: Invalid domain name format: " + domain + " - " + e.getMessage());
        } catch (Exception e) {
            System.err.println("DnsVerifier: An unexpected error occurred during DNS query: " + e.getMessage());
            e.printStackTrace();
        }
        return txtValues;
    }

    // Main method for quick testing
    public static void main(String[] args) {
        // Example usage:
        String testDomain = "google.com"; // A well-known domain with TXT records
        String testCname = "_acme-challenge.example.com"; // A hypothetical CNAME for verification
        String testToken = "some-random-verification-token";

        System.out.println("--- Testing verifyDnsTxtRecord ---");
        boolean verified = DnsVerifier.verifyDnsTxtRecord(testDomain, "v=spf1 include:_spf.google.com ~all");
        System.out.println("Google SPF record verification: " + verified);

        System.out.println("\n--- Testing verifyDnsTxtRecord with a hypothetical CNAME ---");
        boolean cnameVerified = DnsVerifier.verifyDnsTxtRecord(testCname, "dpdp-verify=" + testToken);
        System.out.println("Hypothetical CNAME verification: " + cnameVerified);

        System.out.println("\n--- Testing getAllTxtRecords ---");
        List<String> txtRecords = DnsVerifier.getAllTxtRecords(testDomain);
        System.out.println("All TXT records for " + testDomain + ": " + txtRecords);

        List<String> nonExistentTxt = DnsVerifier.getAllTxtRecords("nonexistent-domain-12345.com");
        System.out.println("All TXT records for nonexistent-domain-12345.com: " + nonExistentTxt);
    }
}