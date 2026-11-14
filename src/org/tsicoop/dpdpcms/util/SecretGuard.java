package org.tsicoop.dpdpcms.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Refuses weak or published development secrets outside local development. */
public final class SecretGuard {
    private SecretGuard() {}

    static final int MIN_LENGTH = 32;
    static final List<String> SECRETS = List.of("JWT_SECRET", "DB_ENCRYPTION_KEY", "TSI_LOOKUP_SALT");
    /** Values published in docker-compose.yml / docs. Anything containing "do-not-use" is also refused. */
    private static final Set<String> PUBLISHED = Set.of(
            "tsi-dpdp-cms-local-dev-secret-do-not-use-in-production",
            "local-dev-enc-key-do-not-use-in-production",
            "local-dev-lookup-salt-do-not-use-in-production");

    /** Returns one message per bad secret (never the secret itself). */
    public static List<String> problems(Map<String, String> env) {
        List<String> out = new ArrayList<>();
        for (String name : SECRETS) {
            String v = env.get(name);
            if (v == null || v.isBlank()) out.add(name + " is not set");
            else if (v.length() < MIN_LENGTH) out.add(name + " is shorter than " + MIN_LENGTH + " characters");
            else if (PUBLISHED.contains(v) || v.toLowerCase().contains("do-not-use")) out.add(name + " is a published development default");
        }
        return out;
    }

    /** Throws (so the application does not start) unless running as TSI_DPDP_CMS_ENV=local. */
    public static void enforce() {
        String env = Env.raw() == null ? "" : Env.raw().trim();
        if (env.equalsIgnoreCase("local")) return;
        List<String> problems = problems(System.getenv());
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Refusing to start outside TSI_DPDP_CMS_ENV=local with weak secrets: "
                    + String.join("; ", problems) + ". Generate each with: openssl rand -hex 32");
        }
    }
}
