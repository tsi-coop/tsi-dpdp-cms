package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Fails when a migration adds a column that holds a principal's identity without it being listed in ErasureTargets, so a new
 * table can never silently escape an erasure (or the principal-ID encryption that follows).
 */
class ErasureTargetsTest {
    /** Column names that hold a principal's identity. recipient_id counts only on notifications (it also holds DPO and app ids elsewhere). */
    private static final Set<String> PRINCIPAL_COLUMNS = Set.of("user_id", "guardian_id", "guardian_principal_id", "child_principal_id", "subject_principal_id");
    private static final Pattern CREATE = Pattern.compile("CREATE TABLE(?: IF NOT EXISTS)?\\s+(\\w+)\\s*\\((.*?)\\n\\);", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern ADD_COLUMN = Pattern.compile("ALTER TABLE\\s+(\\w+)\\s+ADD COLUMN(?: IF NOT EXISTS)?\\s+(\\w+)", Pattern.CASE_INSENSITIVE);

    private static Set<String> principalColumnsInSchema() throws IOException {
        Set<String> found = new TreeSet<>();
        List<Path> files;
        try (Stream<Path> s = Files.list(Paths.get("db"))) { files = s.filter(p -> p.toString().endsWith(".sql")).sorted().collect(Collectors.toList()); }
        for (Path f : files) {
            String sql = Files.readString(f);
            Matcher m = CREATE.matcher(sql);
            while (m.find()) {
                String table = m.group(1);
                for (String line : m.group(2).split("\n")) {
                    String col = line.trim().split("\\s+")[0].replace(",", "");
                    if (PRINCIPAL_COLUMNS.contains(col) || (table.equals("notifications") && col.equals("recipient_id"))) found.add(table + "." + col);
                }
            }
            Matcher a = ADD_COLUMN.matcher(sql);
            while (a.find()) if (PRINCIPAL_COLUMNS.contains(a.group(2))) found.add(a.group(1) + "." + a.group(2));
        }
        return found;
    }

    @Test
    void everyPrincipalColumnInTheSchemaIsListed() throws IOException {
        List<String> missing = new ArrayList<>();
        for (String c : principalColumnsInSchema()) {
            String[] tc = c.split("\\.");
            if (!ErasureTargets.isRegistered(tc[0], tc[1])) missing.add(c);
        }
        assertTrue(missing.isEmpty(), "principal columns not in ErasureTargets (decide what happens to them on erasure): " + missing);
    }

    @Test
    void theListHasNoStaleEntries() throws IOException {
        Set<String> schema = principalColumnsInSchema();
        List<String> stale = new ArrayList<>();
        for (ErasureTargets.Target t : ErasureTargets.ALL) if (!schema.contains(t.key())) stale.add(t.key());
        assertTrue(stale.isEmpty(), "ErasureTargets entries with no such column: " + stale);
    }

    @Test
    void noEntryIsListedTwiceAndEveryEntryExplainsItself() {
        Set<String> seen = new HashSet<>();
        for (ErasureTargets.Target t : ErasureTargets.ALL) {
            assertTrue(seen.add(t.key()), "duplicate " + t.key());
            assertNotNull(t.disposition);
            assertFalse(t.note == null || t.note.isBlank(), t.key());
        }
    }

    @Test
    void theAppendOnlyLedgerIsNeverPlannedForEditing() {
        for (ErasureTargets.Target t : ErasureTargets.ALL)
            if (t.table.equals("audit_logs")) assertEquals(ErasureTargets.Disposition.IMMUTABLE_PSEUDONYM_AT_WRITE, t.disposition);
    }
}
