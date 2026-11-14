package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

import static org.junit.jupiter.api.Assertions.*;

class AccessControlTest {

    // ---------- permission matching ----------
    @Test
    void levelsImplyLowerLevels() {
        assertTrue(Permissions.satisfies(List.of("policies:manage"), "policies:read"));
        assertTrue(Permissions.satisfies(List.of("policies:write"), "policies:read"));
        assertTrue(Permissions.satisfies(List.of("policies:write"), "policies:write"));
        assertFalse(Permissions.satisfies(List.of("policies:read"), "policies:write"));
        assertFalse(Permissions.satisfies(List.of("policies:write"), "policies:manage"));
    }

    @Test
    void wildcardsAndOtherResources() {
        assertTrue(Permissions.satisfies(List.of("*"), "anything:manage"));
        assertTrue(Permissions.satisfies(List.of("*:read"), "audit:read"));
        assertFalse(Permissions.satisfies(List.of("*:read"), "audit:write"));
        assertFalse(Permissions.satisfies(List.of("ropa:manage"), "policies:read"));
        assertFalse(Permissions.satisfies(List.of(), "policies:read"));
        assertFalse(Permissions.satisfies(null, "policies:read"));
    }

    @Test
    void malformedRequirementIsNeverSatisfied() {
        assertFalse(Permissions.satisfies(List.of("*"), "noresource"));
        assertFalse(Permissions.satisfies(List.of("*"), "x:bogus"));
        assertFalse(Permissions.satisfies(List.of("*"), null));
    }

    // ---------- the map must cover every function ----------
    private static Map<String, Set<String>> casesInServices() throws IOException {
        Map<String, String> reg = new HashMap<>();
        for (String l : Files.readAllLines(Paths.get("web/WEB-INF/_processor.tsi"))) {
            l = l.trim();
            if (l.isEmpty() || l.startsWith("#") || !l.contains("=")) continue;
            String[] kv = l.split("=");
            String cls = kv[1].substring(kv[1].lastIndexOf('.') + 1);
            reg.put(cls, kv[0].substring(kv[0].lastIndexOf('/') + 1));
        }
        Map<String, Set<String>> out = new TreeMap<>();
        try (Stream<Path> files = Files.list(Paths.get("src/org/tsicoop/dpdpcms/service/v1"))) {
            for (Path f : files.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList())) {
                String cls = f.getFileName().toString().replace(".java", "");
                if (!reg.containsKey(cls)) continue;
                Matcher m = Pattern.compile("case\\s+\"([a-z_0-9]+)\"").matcher(Files.readString(f));
                Set<String> s = new TreeSet<>();
                while (m.find()) s.add(m.group(1));
                out.put(reg.get(cls), s);
            }
        }
        return out;
    }

    @Test
    void everyServiceFunctionIsClassified() throws IOException {
        List<String> missing = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : casesInServices().entrySet())
            for (String func : e.getValue())
                if (AccessMap.required(e.getKey(), func) == null) missing.add(e.getKey() + "." + func);
        assertTrue(missing.isEmpty(), "functions missing from AccessMap (add them, or they are denied under enforcement): " + missing);
    }

    @Test
    void mapHasNoStaleEntries() throws IOException {
        Map<String, Set<String>> cases = casesInServices();
        List<String> stale = new ArrayList<>();
        for (String key : AccessMap.keys()) {
            String[] sf = key.split("\\.", 2);
            if (!cases.getOrDefault(sf[0], Set.of()).contains(sf[1])) stale.add(key);
        }
        assertTrue(stale.isEmpty(), "AccessMap entries with no matching function: " + stale);
    }

    @Test
    void everyRequirementIsWellFormed() {
        for (String key : AccessMap.keys()) {
            String req = AccessMap.required(key.split("\\.", 2)[0], key.split("\\.", 2)[1]);
            assertTrue(req.equals("AUTH") || req.equals("NOAUTH") || req.equals("NONE") || Permissions.isWellFormed(req), key + " -> " + req);
        }
    }

    // ---------- the matrix: roles x functions ----------
    private static boolean allowed(String role, String service, String func) {
        return AccessPolicy.decide(role, RolePermissions.defaults(role), service, func).allowed();
    }

    @Test
    void adminMayDoEverythingThatIsReachableByOperators() throws IOException {
        for (Map.Entry<String, Set<String>> e : casesInServices().entrySet())
            for (String func : e.getValue()) {
                String req = AccessMap.required(e.getKey(), func);
                if ("NONE".equals(req)) continue; // public-API functions are not operator functions at all
                assertTrue(allowed("ADMIN", e.getKey(), func), "ADMIN denied " + e.getKey() + "." + func);
            }
    }

    @Test
    void auditorCanNeverWriteOrManageAnything() throws IOException {
        List<String> bad = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : casesInServices().entrySet())
            for (String func : e.getValue()) {
                String req = AccessMap.required(e.getKey(), func);
                boolean mutating = req != null && (req.endsWith(":write") || req.endsWith(":manage"));
                if (mutating && allowed("AUDITOR", e.getKey(), func)) bad.add(e.getKey() + "." + func);
            }
        assertTrue(bad.isEmpty(), "AUDITOR allowed to change data: " + bad);
    }

    @Test
    void auditorCanReadButNotApiKeysOrAdminMetrics() {
        assertTrue(allowed("AUDITOR", "audit", "list_audit_logs"));
        assertTrue(allowed("AUDITOR", "audit", "verify_audit_chain"));
        assertTrue(allowed("AUDITOR", "policy", "list_policies"));
        assertFalse(allowed("AUDITOR", "audit", "log_event"));
        assertFalse(allowed("AUDITOR", "apikey", "list_api_keys"));
        assertFalse(allowed("AUDITOR", "admindash", "get_admin_metrics"));
        assertFalse(allowed("AUDITOR", "policy", "publish_policy"));
        assertFalse(allowed("AUDITOR", "consent", "withdraw_consent"));
    }

    @Test
    void dpoManagesTheirFiduciaryButNotThePlatform() {
        assertTrue(allowed("DPO", "policy", "publish_policy"));
        assertTrue(allowed("DPO", "ropa", "publish_entry"));
        assertTrue(allowed("DPO", "breach", "report_breach"));
        assertTrue(allowed("DPO", "operator", "create_user"));
        assertTrue(allowed("DPO", "fiduciary", "get_fiduciary"));
        assertFalse(allowed("DPO", "fiduciary", "create_fiduciary"));
        assertFalse(allowed("DPO", "fiduciary", "delete_fiduciary"));
        assertFalse(allowed("DPO", "app", "create_app"));
        assertFalse(allowed("DPO", "apikey", "generate_api_key"));
        assertFalse(allowed("DPO", "audit", "log_event"));
        assertFalse(allowed("DPO", "admindash", "get_admin_metrics"));
    }

    @Test
    void operatorDoesDelegatedWorkOnly() {
        assertTrue(allowed("OPERATOR", "grievance", "update_grievance_status"));
        assertTrue(allowed("OPERATOR", "compliance", "update_purge_status"));
        assertTrue(allowed("OPERATOR", "policy", "list_policies"));
        assertTrue(allowed("OPERATOR", "operator", "list_users"));
        assertFalse(allowed("OPERATOR", "policy", "publish_policy"));
        assertFalse(allowed("OPERATOR", "ropa", "publish_entry"));
        assertFalse(allowed("OPERATOR", "breach", "report_breach"));
        assertFalse(allowed("OPERATOR", "compliance", "assign_purge_request"));
        assertFalse(allowed("OPERATOR", "consent", "erasure_request"));
        assertFalse(allowed("OPERATOR", "notification", "set_webhook_config"));
        assertFalse(allowed("OPERATOR", "operator", "create_user"));
    }

    @Test
    void anyAuthenticatedFunctionsAreOpenToEveryKnownRoleButNotUnknownOnes() {
        for (String role : List.of("ADMIN", "DPO", "OPERATOR", "AUDITOR"))
            assertTrue(allowed(role, "operator", "logout"), role);
        assertFalse(allowed("HACKER", "operator", "logout"));
        assertFalse(allowed(null, "operator", "logout"));
    }

    @Test
    void unmappedFunctionAndUnknownRoleAreDenied() {
        assertEquals(AccessPolicy.Decision.DENY_UNMAPPED, AccessPolicy.decide("ADMIN", List.of("*"), "policy", "brand_new_func"));
        assertFalse(allowed("HACKER", "policy", "list_policies"));
        assertFalse(allowed(null, "policy", "list_policies"));
    }

    @Test
    void publicApiFunctionsAreNotOperatorFunctions() {
        assertEquals(AccessPolicy.Decision.DENY_NOT_OPERATOR_API, AccessPolicy.decide("ADMIN", List.of("*"), "principal", "principal_login"));
    }

    @Test
    void auditorRoleIsKnown() {
        assertTrue(RolePermissions.isKnownRole("AUDITOR"));
        assertTrue(RolePermissions.isKnownRole("dpo"));
        assertFalse(RolePermissions.isKnownRole("ROOT"));
        assertFalse(RolePermissions.isKnownRole(null));
    }

    @Test
    void sqlSeedMatchesCompiledInRoleDefaults() throws IOException {
        String sql = Files.readString(Paths.get("db/20_roles.sql"));
        Matcher m = Pattern.compile("\\(\\s*'(ADMIN|DPO|OPERATOR|AUDITOR)',\\s*'[^']*',\\s*ARRAY\\[(.*?)\\]", Pattern.DOTALL).matcher(sql);
        Set<String> seen = new HashSet<>();
        while (m.find()) {
            Set<String> seeded = Arrays.stream(m.group(2).split(",")).map(x -> x.trim().replace("'", "")).filter(x -> !x.isEmpty()).collect(Collectors.toCollection(TreeSet::new));
            assertEquals(new TreeSet<>(RolePermissions.defaults(m.group(1))), seeded, "db/20_roles.sql and RolePermissions disagree for " + m.group(1));
            seen.add(m.group(1));
        }
        assertEquals(Set.of("ADMIN", "DPO", "OPERATOR", "AUDITOR"), seen);
    }

    // ---------- tenant binding ----------
    private static final UUID FID_A = UUID.fromString("aaaaaaaa-0000-0000-0000-00000000000a");
    private static final UUID FID_B = UUID.fromString("bbbbbbbb-0000-0000-0000-00000000000b");
    private static final UUID NIL = UUID.fromString("00000000-0000-0000-0000-000000000000");

    @Test
    void adminIsNeverTenantBound() {
        assertEquals(TenantRule.Outcome.NOT_APPLICABLE, TenantRule.evaluate("ADMIN", null, FID_B).outcome);
        assertEquals(TenantRule.Outcome.NOT_APPLICABLE, TenantRule.evaluate("ADMIN", FID_A, null).outcome);
    }

    @Test
    void fiduciaryScopedOperatorWithNoBodyValueIsFilled() {
        TenantRule.Result r = TenantRule.evaluate("DPO", FID_A, null);
        assertEquals(TenantRule.Outcome.FILL, r.outcome);
        assertEquals(FID_A, r.fiduciaryId);
    }

    @Test
    void matchingBodyValueIsLeftAlone() {
        assertEquals(TenantRule.Outcome.OK, TenantRule.evaluate("OPERATOR", FID_A, FID_A).outcome);
    }

    @Test
    void foreignBodyValueIsOverwrittenWithTheTokenOwners() {
        TenantRule.Result r = TenantRule.evaluate("AUDITOR", FID_A, FID_B);
        assertEquals(TenantRule.Outcome.OVERWRITE, r.outcome);
        assertEquals(FID_A, r.fiduciaryId);
    }

    @Test
    void nonAdminWithoutAFiduciaryIsUnbound() {
        assertEquals(TenantRule.Outcome.UNBOUND, TenantRule.evaluate("DPO", null, FID_A).outcome);
        assertEquals(TenantRule.Outcome.UNBOUND, TenantRule.evaluate("OPERATOR", NIL, FID_A).outcome);
    }

    // ---------- mode ----------
    @Test
    void modeDefaultsToShadowAndOnlyExactEnforceEnforces() {
        assertFalse(AccessPolicy.isEnforce(null));
        assertFalse(AccessPolicy.isEnforce(""));
        assertFalse(AccessPolicy.isEnforce("shadow"));
        assertFalse(AccessPolicy.isEnforce("enfore")); // a typo stays in shadow mode (and is warned about at startup)
        assertTrue(AccessPolicy.isEnforce("enforce"));
        assertTrue(AccessPolicy.isEnforce(" ENFORCE "));
    }
}
