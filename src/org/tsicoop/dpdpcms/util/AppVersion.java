package org.tsicoop.dpdpcms.util;

import org.tsicoop.dpdpcms.framework.BrandConfig;

import java.io.InputStream;
import java.util.Properties;

/**
 * The running application's version. The only place the version is written is pom.xml;
 * Maven filters it into version.properties at build time and this class reads it back, so
 * the certificate, reports, exports and logs can never drift from the build.
 */
public final class AppVersion {

    private static final String VERSION = load();

    private AppVersion() {}

    /** Version number as built, e.g. "0.5.4" ("unknown" if the build did not package it). */
    public static String get() {
        return VERSION;
    }

    /**
     * The product name as this deployment presents it: the partner brand when BRAND_NAME is set
     * (white-labelling), otherwise "TSI DPDP CMS". Artifacts use this, not a hardcoded name, so a
     * partner-branded deployment never shows the upstream product name in its reports.
     */
    public static String product() {
        return BrandConfig.name();
    }

    /** Product name and version for stamping onto artifacts, e.g. "TSI DPDP CMS v0.5.4". */
    public static String display() {
        return product() + " v" + VERSION;
    }

    private static String load() {
        try (InputStream in = AppVersion.class.getResourceAsStream("/version.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                String v = p.getProperty("version");
                // An unfiltered file (read straight from source) still holds the placeholder
                if (v != null && !v.isBlank() && !v.contains("${")) return v.trim();
            }
        } catch (Exception ignored) {
            // fall through
        }
        return "unknown";
    }
}
