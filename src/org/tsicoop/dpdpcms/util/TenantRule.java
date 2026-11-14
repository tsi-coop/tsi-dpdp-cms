package org.tsicoop.dpdpcms.util;

import java.util.UUID;

/**
 * Tenant binding: a fiduciary-scoped operator (DPO, OPERATOR, AUDITOR) acts only on their own
 * fiduciary, whatever the request body says. ADMIN is platform-wide and never bound.
 */
public final class TenantRule {
    private TenantRule() {}
    private static final UUID NIL = new UUID(0L, 0L);

    public enum Outcome {
        NOT_APPLICABLE,  // ADMIN
        UNBOUND,         // non-ADMIN account with no fiduciary: refused
        OK,              // body already names the operator's fiduciary
        FILL,            // body has none: set it to the operator's fiduciary
        OVERWRITE        // body names another fiduciary: replace with the operator's
    }

    public static final class Result {
        public final Outcome outcome;
        public final UUID fiduciaryId;
        Result(Outcome o, UUID f) { outcome = o; fiduciaryId = f; }
    }

    public static Result evaluate(String role, UUID operatorFiduciary, UUID bodyFiduciary) {
        if ("ADMIN".equalsIgnoreCase(role)) return new Result(Outcome.NOT_APPLICABLE, null);
        if (operatorFiduciary == null || NIL.equals(operatorFiduciary)) return new Result(Outcome.UNBOUND, null);
        if (bodyFiduciary == null) return new Result(Outcome.FILL, operatorFiduciary);
        if (bodyFiduciary.equals(operatorFiduciary)) return new Result(Outcome.OK, operatorFiduciary);
        return new Result(Outcome.OVERWRITE, operatorFiduciary);
    }
}
