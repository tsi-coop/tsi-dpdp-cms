# Log and record retention

What the CMS keeps, for how long, and what removes it. Periods that the code does not enforce are marked
**to be confirmed by the DPO**; this document does not state legal retention periods.

| Record | Kept | Removed by | Notes |
|---|---|---|---|
| Audit ledger (`audit_logs`) | Indefinitely | Nothing. The table is **append-only**: updates, deletes and truncation are refused by the database (`db/18_audit_ledger_integrity.sql`) | Hash-chained; `verify_audit_chain` checks it. **Minimum 7 years** (the audit-retention floor). Archiving to a verifiable archive after that is not built yet; until it is, nothing leaves the table |
| Audit chain verification results | Indefinitely | Nothing (immutable) | |
| Consent records and history | Indefinitely | Nothing in the application | Evidence of what the principal agreed to. Retention and erasure at the CMS are a legal decision, left unchanged |
| Purge requests, legal holds, breach incidents, rights requests, grievances | Indefinitely | Nothing in the application | Retention period **to be confirmed by the DPO** |
| Webhook delivery log (`webhook_deliveries`) | 365 days for delivered and for failed rows | A scheduled cleanup (`WebhookDispatcher`, `KEEP_DELIVERED_DAYS` and `KEEP_FAILED_DAYS`) | Holds the payloads sent, which can contain principal IDs |
| Notifications | The database refuses to delete a notification younger than 365 days (`db/18`) | Nothing in the application | |
| Revoked login tokens | Until the token's own expiry | Automatic cleanup in `OperatorSessions` | |
| Generated report exports | Until deleted from the export folder (`TSI_EXPORT_PATH`) | Manual | May contain principal IDs; apply your own retention to the folder |
| Backups | Your policy | Your backup schedule | Must be encrypted (see `KEY_MANAGEMENT.md`) |

## What the audit log holds about people

Audit rows keep whatever principal ID the integration sent when the event happened. Because the table cannot be changed, an ID that
was an email address or phone number in the past stays that way. New integrations should send opaque IDs.

## Audit retention floor and archiving

The 7-year floor means audit rows may only leave the live table after 7 years, and only into an archive that still verifies against the
chain. Today nothing leaves the table at all, which is stricter than the floor. When archiving is built it should use yearly
partitions and be done after any change to the table's layout, so the table is rewritten once.

## Review

Review this table once a year and whenever a new log or table is added. Owner: __________
