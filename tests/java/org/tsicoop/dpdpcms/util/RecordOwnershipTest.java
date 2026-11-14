package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class RecordOwnershipTest {
    private static final UUID A = UUID.fromString("aaaaaaaa-0000-0000-0000-00000000000a");
    private static final UUID B = UUID.fromString("bbbbbbbb-0000-0000-0000-00000000000b");

    @Test void adminMayAccessAnyRecord() { assertTrue(RecordOwnership.allowed(true, null, B)); assertTrue(RecordOwnership.allowed(true, A, B)); }
    @Test void callerMayAccessOwnFiduciaryRecords() { assertTrue(RecordOwnership.allowed(false, A, A)); }
    @Test void callerMayNotAccessAnotherFiduciarysRecords() { assertFalse(RecordOwnership.allowed(false, A, B)); }
    @Test void unresolvedCallerIsDenied() { assertFalse(RecordOwnership.allowed(false, null, A)); }
    @Test void recordWithNoFiduciaryIsPlatformOnly() { assertFalse(RecordOwnership.allowed(false, A, null)); assertTrue(RecordOwnership.allowed(true, A, null)); }
    @Test void unboundAccountIsDenied() { assertFalse(RecordOwnership.allowed(false, new UUID(0, 0), A)); assertFalse(RecordOwnership.allowed(false, new UUID(0, 0), new UUID(0, 0))); }
}
