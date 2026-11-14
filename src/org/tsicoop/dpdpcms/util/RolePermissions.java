package org.tsicoop.dpdpcms.util;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Built-in roles. These mirror what the services enforced before the central permission map existed
 * (ADMIN everything; DPO their own fiduciary; OPERATOR delegated closure work) plus the new read-only
 * AUDITOR. The same values are seeded into the roles table (db/20_roles.sql), which an administrator
 * can later adjust; these defaults are the fallback if that table cannot be read.
 */
public final class RolePermissions {
    private RolePermissions() {}

    private static final Map<String, List<String>> DEFAULTS = Map.of(
            "ADMIN", List.of("*"),
            "DPO", List.of("users:manage", "fiduciaries:read", "apps:read", "policies:write", "ropa:write",
                    "consents:write", "purges:manage", "grievances:manage", "breaches:write", "settings:write",
                    "webhooks:manage", "audit:read", "certificates:write", "dashboard:read", "jobs:write", "rights:manage", "purposes:manage"),
            "OPERATOR", List.of("users:read", "fiduciaries:read", "apps:read", "policies:read", "ropa:read",
                    "breaches:read", "purges:write", "grievances:write", "jobs:write", "settings:read",
                    "certificates:read", "audit:read", "dashboard:read", "rights:write", "purposes:read"),
            "AUDITOR", List.of("*:read"));

    public static boolean isKnownRole(String role) {
        return role != null && DEFAULTS.containsKey(role.trim().toUpperCase(Locale.ROOT));
    }

    /** Default permissions for the role; empty for an unknown role. */
    public static List<String> defaults(String role) {
        if (role == null) return List.of();
        return DEFAULTS.getOrDefault(role.trim().toUpperCase(Locale.ROOT), List.of());
    }
}
