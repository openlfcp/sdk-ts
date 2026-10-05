import { LfcpError } from "@openlfcp/core";
import type Database from "better-sqlite3";

/**
 * The SQLite schema and its migrations. Version 1 is the LFCP-034 storage
 * model; version 2 adds outbound retry state and sync state (LFCP-036).
 * A database at a newer version than this code knows is refused:
 * it is never downgraded or "repaired".
 *
 * Conventions: IDs and exact object bytes are BLOBs (memcmp order is byte
 * order); uint64 values (sequences, epochs, route versions) are 20-digit
 * zero-padded decimal TEXT, so they sort numerically and never overflow
 * SQLite's signed 64-bit INTEGER.
 */

export const MIGRATIONS: readonly (readonly [version: number, sql: string])[] = [
  [
    1,
    `
CREATE TABLE control_records (
  record_id     BLOB PRIMARY KEY,
  resource_id   BLOB NOT NULL,
  control_seq   TEXT NOT NULL,
  prev_id       BLOB,
  bytes         BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX control_records_by_resource ON control_records (resource_id, control_seq, record_id);

CREATE TABLE control_heads (
  resource_id   BLOB PRIMARY KEY,
  head          BLOB NOT NULL,
  control_seq   TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE control_conflicts (
  resource_id   BLOB PRIMARY KEY,
  heads         BLOB NOT NULL
) WITHOUT ROWID;

CREATE TABLE epochs (
  resource_id     BLOB NOT NULL,
  epoch           TEXT NOT NULL,
  dek_commitment  BLOB NOT NULL,
  opened_by       BLOB NOT NULL,
  closed_by       BLOB,
  dek_ref         TEXT,
  PRIMARY KEY (resource_id, epoch)
) WITHOUT ROWID;

CREATE TABLE data_units (
  unit_id       BLOB PRIMARY KEY,
  resource_id   BLOB NOT NULL,
  data_epoch    TEXT NOT NULL,
  actor         BLOB NOT NULL,
  actor_seq     TEXT NOT NULL,
  prev_id       BLOB,
  control_head  BLOB NOT NULL,
  bytes         BLOB NOT NULL,
  status        TEXT NOT NULL,
  detail        TEXT,
  accepted      INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX data_units_by_tuple ON data_units (resource_id, actor, actor_seq, unit_id);
CREATE INDEX data_units_by_status ON data_units (resource_id, status);

CREATE TABLE key_packages (
  package_id    BLOB PRIMARY KEY,
  resource_id   BLOB NOT NULL,
  data_epoch    TEXT NOT NULL,
  recipient     BLOB NOT NULL,
  sender        BLOB NOT NULL,
  bytes         BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX key_packages_by_recipient ON key_packages (resource_id, data_epoch, recipient);

CREATE TABLE snapshots (
  snapshot_id   BLOB PRIMARY KEY,
  resource_id   BLOB NOT NULL,
  data_epoch    TEXT NOT NULL,
  publisher     BLOB NOT NULL,
  snapshot_seq  TEXT NOT NULL,
  frontier      BLOB NOT NULL,
  bytes         BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX snapshots_by_epoch ON snapshots (resource_id, data_epoch, publisher, snapshot_seq);

CREATE TABLE resources (
  resource_id     BLOB PRIMARY KEY,
  data_profile    TEXT NOT NULL,
  local_principal BLOB,
  signing_ref     TEXT,
  agreement_ref   TEXT,
  labels          TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE routes (
  resource_id     BLOB PRIMARY KEY,
  route_version   TEXT NOT NULL,
  endpoints       TEXT NOT NULL,
  coordinator_url TEXT NOT NULL,
  source          BLOB NOT NULL
) WITHOUT ROWID;

CREATE TABLE outbound (
  position      INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id       BLOB NOT NULL UNIQUE,
  resource_id   BLOB NOT NULL,
  kind          TEXT NOT NULL,
  bytes         BLOB NOT NULL,
  attempts      INTEGER NOT NULL,
  last_attempt  TEXT
);

CREATE TABLE profile_checkpoints (
  resource_id   BLOB PRIMARY KEY,
  data_profile  TEXT NOT NULL,
  state         BLOB NOT NULL,
  actor_seq     INTEGER NOT NULL,
  units         TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE actor_sequences (
  resource_id   BLOB NOT NULL,
  principal     BLOB NOT NULL,
  last          TEXT NOT NULL,
  PRIMARY KEY (resource_id, principal)
) WITHOUT ROWID;

CREATE TABLE snapshot_sequences (
  resource_id   BLOB NOT NULL,
  epoch         TEXT NOT NULL,
  publisher     BLOB NOT NULL,
  last          TEXT NOT NULL,
  PRIMARY KEY (resource_id, epoch, publisher)
) WITHOUT ROWID;
`,
  ],
  [
    // LFCP-036: retry scheduling and blocking of outbound items; per-Resource sync state.
    2,
    `
ALTER TABLE outbound ADD COLUMN next_attempt TEXT;
ALTER TABLE outbound ADD COLUMN blocked_reason TEXT;
ALTER TABLE outbound ADD COLUMN blocked_detail TEXT;

CREATE TABLE sync_state (
  resource_id       BLOB PRIMARY KEY,
  recently_acked    BLOB NOT NULL,
  acked_durability  TEXT
) WITHOUT ROWID;
`,
  ],
];

export const SCHEMA_VERSION = MIGRATIONS.at(-1)?.[0] ?? 0;

/** The schema version of an open database (0 for a fresh one). */
export function schemaVersion(db: Database.Database): number {
  db.exec("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)");
  const row = db.prepare("SELECT version FROM schema_version").get() as
    | { version: number }
    | undefined;
  return row?.version ?? 0;
}

/** Brings the database to SCHEMA_VERSION, one migration per transaction. */
export function migrate(db: Database.Database): number {
  const current = schemaVersion(db);
  if (current > SCHEMA_VERSION)
    throw new LfcpError(
      "UNSUPPORTED_VALUE",
      `the database is at schema version ${current}, newer than this code (${SCHEMA_VERSION})`,
    );
  for (const [version, sql] of MIGRATIONS) {
    if (version <= current) continue;
    db.transaction(() => {
      db.exec(sql);
      db.exec("DELETE FROM schema_version");
      db.prepare("INSERT INTO schema_version (version) VALUES (?)").run(version);
    }).immediate();
  }
  return SCHEMA_VERSION;
}
