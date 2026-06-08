package org.tsicoop.dpdpcms.framework;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Central access point for the partner/reseller brand name (BRAND_NAME env var).
 *
 * The default brand "TSI DPDP CMS" is exactly 12 characters. The 12-character cap
 * on BRAND_NAME is a deliberate drop-in-replacement constraint: it guarantees a
 * partner's brand fits every layout (sidebar widths, title bars, report footers)
 * that was designed around the default string, with zero redesign risk. A brand
 * that exceeds the limit fails the application at startup, mirroring how
 * JWT_SECRET / DB_ENCRYPTION_KEY are validated (see JWTUtil, DbEncryption).
 */
public class BrandConfig {

    public static final String ENV_VAR = "BRAND_NAME";
    public static final String DEFAULT_BRAND = "TSI DPDP CMS";
    public static final int MAX_LENGTH = DEFAULT_BRAND.length();

    /**
     * Brand-token variants found across web/, ordered longest-match-first so that
     * "TSI DPDP CMS" is substituted before its prefix "TSI DPDP" — otherwise the
     * shorter match would fire first and leave a mangled "{brand} CMS" behind.
     */
    private static final List<String> BRAND_TOKENS = Collections.unmodifiableList(Arrays.asList(
            "TSI DPDP CMS",
            "TSI Coop",
            "TSI DPDP",
            "TSI CMS"
    ));

    private static final String brand;

    static {
        String configured = System.getenv(ENV_VAR);
        if (configured == null || configured.trim().isEmpty()) {
            brand = DEFAULT_BRAND;
        } else {
            String trimmed = configured.trim();
            if (trimmed.length() > MAX_LENGTH) {
                throw new IllegalStateException(
                        ENV_VAR + " must be at most " + MAX_LENGTH + " characters " +
                        "(got " + trimmed.length() + ": '" + trimmed + "'). " +
                        "The limit matches the length of the default brand '" + DEFAULT_BRAND +
                        "' so that partner brands are guaranteed to fit existing layouts.");
            }
            brand = trimmed;
        }
    }

    private BrandConfig() {}

    /** The active brand name: the configured partner brand, or the default. */
    public static String name() {
        return brand;
    }

    /** True only when a non-default brand is active — lets callers skip rewriting work in the common case. */
    public static boolean isCustomized() {
        return !DEFAULT_BRAND.equals(brand);
    }

    /** Brand-token variants to replace, longest match first. Each maps to {@link #name()}. */
    public static List<String> tokens() {
        return BRAND_TOKENS;
    }
}
