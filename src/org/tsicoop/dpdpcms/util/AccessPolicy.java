package org.tsicoop.dpdpcms.util;

import java.util.Collection;
import java.util.Locale;

/** The access decision for one (role, service, function). Pure; the filter applies it. */
public final class AccessPolicy {
    private AccessPolicy() {}

    public enum Decision {
        ALLOW, DENY_NO_PERMISSION, DENY_UNMAPPED, DENY_UNKNOWN_ROLE, DENY_NOT_OPERATOR_API;
        public boolean allowed() { return this == ALLOW; }
    }

    public static Decision decide(String role, Collection<String> permissions, String service, String func) {
        String req = AccessMap.required(service, func);
        if (req == null) return Decision.DENY_UNMAPPED;
        if (req.equals("NOAUTH")) return Decision.ALLOW;
        if (req.equals("NONE")) return Decision.DENY_NOT_OPERATOR_API;
        if (!RolePermissions.isKnownRole(role)) return Decision.DENY_UNKNOWN_ROLE;
        if (req.equals("AUTH")) return Decision.ALLOW;
        return Permissions.satisfies(permissions, req) ? Decision.ALLOW : Decision.DENY_NO_PERMISSION;
    }

    /** ACCESS_CONTROL_MODE: only the exact value "enforce" enforces; anything else (or unset) is shadow mode. */
    public static boolean isEnforce(String mode) {
        return mode != null && mode.trim().toLowerCase(Locale.ROOT).equals("enforce");
    }

    public static boolean isRecognisedMode(String mode) {
        if (mode == null || mode.isBlank()) return true;
        String m = mode.trim().toLowerCase(Locale.ROOT);
        return m.equals("enforce") || m.equals("shadow");
    }
}
