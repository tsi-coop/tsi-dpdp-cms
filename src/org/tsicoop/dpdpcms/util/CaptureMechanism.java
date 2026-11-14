package org.tsicoop.dpdpcms.util;

/** How consent reached the CMS, derived from the authenticated path, never from the request body. */
public final class CaptureMechanism {
    private CaptureMechanism() {}
    public static final String PRINCIPAL_PORTAL = "PRINCIPAL_PORTAL";
    public static final String API_INTEGRATION = "API_INTEGRATION";
    public static final String WALLET = "WALLET";

    public static String of(boolean viaPrincipalJwt, boolean viaApiKey) {
        return viaPrincipalJwt ? PRINCIPAL_PORTAL : API_INTEGRATION;
    }
}
