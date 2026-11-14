package org.tsicoop.dpdpcms.util;

import java.util.Collection;
import java.util.Map;

/**
 * Permission strings are "resource:level" with level read < write < manage.
 * A held "x:write" satisfies a requirement of "x:read" or "x:write". "*" holds everything and
 * "*:read" holds read on every resource.
 */
public final class Permissions {
    private Permissions() {}

    private static final Map<String, Integer> LEVEL = Map.of("read", 1, "write", 2, "manage", 3);

    public static boolean isWellFormed(String p) {
        if (p == null) return false;
        if (p.equals("*")) return true;
        int i = p.indexOf(':');
        return i > 0 && i == p.lastIndexOf(':') && i < p.length() - 1 && LEVEL.containsKey(p.substring(i + 1));
    }

    /** True if any held permission covers {@code required} (which must be "resource:level"). */
    public static boolean satisfies(Collection<String> held, String required) {
        if (held == null || required == null || !isWellFormed(required) || required.equals("*")) return false;
        int i = required.indexOf(':');
        String res = required.substring(0, i);
        int need = LEVEL.get(required.substring(i + 1));
        for (String h : held) {
            if (!isWellFormed(h)) continue;
            if (h.equals("*")) return true;
            int j = h.indexOf(':');
            String hres = h.substring(0, j);
            if ((hres.equals("*") || hres.equals(res)) && LEVEL.get(h.substring(j + 1)) >= need) return true;
        }
        return false;
    }
}
