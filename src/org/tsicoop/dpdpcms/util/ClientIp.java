package org.tsicoop.dpdpcms.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Works out the client's address behind reverse proxies. {@code X-Forwarded-For} is only believed when the
 * TCP peer is one of the configured trusted proxies, and then it is read from the RIGHT: each trusted proxy
 * appends the address it received from, so the first address that is not a trusted proxy is the client.
 * (Reading from the left would let a client choose its own recorded address by sending the header itself.)
 */
public final class ClientIp {
    private ClientIp() {}

    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]+$");

    public static List<String> parseTrusted(String csv) {
        List<String> out = new ArrayList<>();
        if (csv == null) return out;
        for (String s : csv.split(",")) { String t = s.trim(); if (!t.isEmpty()) out.add(t); }
        return out;
    }

    public static String resolve(String remoteAddr, String forwardedFor, List<String> trustedProxies) {
        if (remoteAddr == null || trustedProxies == null || !trustedProxies.contains(remoteAddr)) return remoteAddr;
        if (forwardedFor == null || forwardedFor.isBlank()) return remoteAddr;
        String[] parts = forwardedFor.split(",");
        String leftmostTrusted = null;
        for (int i = parts.length - 1; i >= 0; i--) {
            String entry = parts[i].trim();
            if (!isIpLiteral(entry)) continue;
            if (trustedProxies.contains(entry)) { leftmostTrusted = entry; continue; }
            return entry;
        }
        return leftmostTrusted != null ? leftmostTrusted : remoteAddr;
    }

    static boolean isIpLiteral(String s) {
        if (s == null || s.isEmpty()) return false;
        java.util.regex.Matcher m = IPV4.matcher(s);
        if (m.matches()) {
            for (int g = 1; g <= 4; g++) if (Integer.parseInt(m.group(g)) > 255) return false;
            return true;
        }
        return s.indexOf(':') >= 0 && IPV6.matcher(s).matches();
    }
}
