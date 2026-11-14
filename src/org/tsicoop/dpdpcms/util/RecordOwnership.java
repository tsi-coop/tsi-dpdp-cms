package org.tsicoop.dpdpcms.util;

import java.util.UUID;

/**
 * May this caller touch a record that belongs to {@code recordFiduciary}?
 * ADMIN: yes. Everyone else (operator, API key, principal token): only if the fiduciary they are bound to
 * is the record's. An unresolved caller, an unbound account (nil UUID) or a record with no fiduciary is
 * refused, so a lookup that fails closes the door rather than opening it.
 */
public final class RecordOwnership {
    private RecordOwnership() {}
    private static final UUID NIL = new UUID(0L, 0L);

    public static boolean allowed(boolean admin, UUID callerFiduciary, UUID recordFiduciary) {
        if (admin) return true;
        if (callerFiduciary == null || recordFiduciary == null) return false;
        if (NIL.equals(callerFiduciary)) return false;
        return callerFiduciary.equals(recordFiduciary);
    }
}
