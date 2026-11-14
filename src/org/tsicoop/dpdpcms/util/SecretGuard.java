package org.tsicoop.dpdpcms.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Refuses missing, placeholder or published development secrets outside local development.
 * Length: JWT_SECRET must be at least 32 characters (it can be changed at any time). DB_ENCRYPTION_KEY and
 * TSI_LOOKUP_SALT cannot be changed without re-encrypting stored data, so an existing short one only produces a
 * warning: refusing to start would leave the operator with no safe way to fix it.
 */
public final class SecretGuard {
    private SecretGuard() {}

    static final int MIN_LENGTH = 32;
    static final List<String> SECRETS = List.of("JWT_SECRET", "DB_ENCRYPTION_KEY", "TSI_LOOKUP_SALT");
    private static final Set<String> LENGTH_IS_FATAL = Set.of("JWT_SECRET");
    /** Values published in docker-compose.yml / docs. */
    private static final Set<String> PUBLISHED = Set.of(
            "tsi-dpdp-cms-local-dev-secret-do-not-use-in-production",
            "local-dev-enc-key-do-not-use-in-production",
            "local-dev-lookup-salt-do-not-use-in-production");

    private static boolean looksLikeAPlaceholder(String v) {
        String l = v.toLowerCase();
        return l.contains("do-not-use") || l.contains("<<") || l.contains(">>") || l.contains("generate-with")
                || l.contains("change-me") || l.contains("changeme") || l.contains("replace_with") || l.contains("replace-with");
    }

    /** Reasons the application must not start (never the secret itself). */
    public static List<String> problems(Map<String, String> env) {
        List<String> out = new ArrayList<>();
        for (String name : SECRETS) {
            String v = env.get(name);
            if (v == null || v.isBlank()) out.add(name + " is not set");
            else if (PUBLISHED.contains(v) || looksLikeAPlaceholder(v)) out.add(name + " is a published default or an unedited placeholder");
            else if (v.length() < MIN_LENGTH && LENGTH_IS_FATAL.contains(name)) out.add(name + " is shorter than " + MIN_LENGTH + " characters");
        }
        return out;
    }

    /** Things worth fixing that must not stop an existing deployment from starting. */
    public static List<String> warnings(Map<String, String> env) {
        List<String> out = new ArrayList<>();
        for (String name : SECRETS) {
            String v = env.get(name);
            if (v != null && !v.isBlank() && v.length() < MIN_LENGTH && !LENGTH_IS_FATAL.contains(name)) {
                out.add(name + " is shorter than " + MIN_LENGTH + " characters. It cannot be changed without re-encrypting stored data, so use a longer value for new installations.");
            }
        }
        return out;
    }

    /** Throws (so the application does not start) unless running as TSI_DPDP_CMS_ENV=local. */
    public static void enforce() {
        String env = Env.raw() == null ? "" : Env.raw().trim();
        if (env.equalsIgnoreCase("local")) return;
        for (String w : warnings(System.getenv())) System.err.println("[WARNING] " + w);
        List<String> problems = problems(System.getenv());
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Refusing to start outside TSI_DPDP_CMS_ENV=local with unsafe secrets: "
                    + String.join("; ", problems) + ". Generate each with: openssl rand -hex 32");
        }
    }
}
