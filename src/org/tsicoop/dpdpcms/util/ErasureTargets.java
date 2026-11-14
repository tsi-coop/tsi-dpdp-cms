package org.tsicoop.dpdpcms.util;

import java.util.List;

/**
 * The one list of every table column that holds a data principal's identity, and what is intended to happen to it when the
 * principal's data is erased. It is not an erasure routine: it is the inventory an erasure routine (and the planned principal-ID
 * encryption) must cover, and ErasureTargetsTest fails if a table gains a principal column that is not listed here.
 *
 * Dispositions describe the INTENDED handling. Whether the CMS erases or pseudonymises its own copy at all is a decision for the
 * fiduciary's counsel (evidence of consent and of the erasure itself against the right to erasure); nothing here executes it.
 */
public final class ErasureTargets {
    private ErasureTargets() {}

    public enum Disposition {
        /** Delete the row. */
        DELETE,
        /** Keep the row as evidence but replace the principal's identity with a one-way token. */
        PSEUDONYMISE,
        /** Keep (evidence of the erasure itself); identity is already a pseudonym or must stay linkable for the Board. */
        RETAIN_EVIDENCE,
        /** Append-only ledger: cannot be changed, so the identity must be stored pseudonymised from the start. */
        IMMUTABLE_PSEUDONYM_AT_WRITE
    }

    public static final class Target {
        public final String table, column;
        public final Disposition disposition;
        public final String note;
        Target(String table, String column, Disposition d, String note) { this.table = table; this.column = column; this.disposition = d; this.note = note; }
        public String key() { return table + "." + column; }
    }

    private static Target t(String table, String column, Disposition d, String note) { return new Target(table, column, d, note); }

    public static final List<Target> ALL = List.of(
        t("consent_records", "user_id", Disposition.PSEUDONYMISE, "consent evidence; keep the record, drop the identity"),
        t("data_principal", "user_id", Disposition.DELETE, "the CES work list entry"),
        t("data_principal", "guardian_id", Disposition.DELETE, "the guardian's identity"),
        t("consent_validations", "user_id", Disposition.DELETE, "which app checked consent for whom"),
        t("purge_requests", "user_id", Disposition.RETAIN_EVIDENCE, "evidence that the erasure was carried out; pseudonymise after the retention period"),
        t("notifications", "recipient_id", Disposition.DELETE, "in-app notices addressed to the principal (recipient_type PRINCIPAL)"),
        t("grievances", "user_id", Disposition.PSEUDONYMISE, "the complaint record; its attachments are deleted with the principal"),
        t("rights_requests", "user_id", Disposition.PSEUDONYMISE, "access and correction requests"),
        t("nominations", "user_id", Disposition.DELETE, "the principal's nominee (the nominee's own details are deleted with it)"),
        t("legal_holds", "user_id", Disposition.RETAIN_EVIDENCE, "a hold exists because the data must be kept: ends first, then erasure proceeds"),
        t("parental_verification_logs", "child_principal_id", Disposition.PSEUDONYMISE, "guardian verification evidence"),
        t("parental_verification_logs", "guardian_principal_id", Disposition.PSEUDONYMISE, "guardian verification evidence"),
        t("breach_affected_principals", "user_id", Disposition.PSEUDONYMISE, "who a breach affected; the Board record keeps the count"),
        t("evidence_certificates", "subject_principal_id", Disposition.RETAIN_EVIDENCE, "signed evidence issued to a court or the Board"),
        t("audit_logs", "user_id", Disposition.IMMUTABLE_PSEUDONYM_AT_WRITE, "append-only and hash-chained: cannot be edited afterwards")
    );

    public static boolean isRegistered(String table, String column) {
        for (Target x : ALL) if (x.table.equals(table) && x.column.equals(column)) return true;
        return false;
    }
}
