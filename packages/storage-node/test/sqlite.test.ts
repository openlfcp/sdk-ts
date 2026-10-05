/// <reference types="node" />
import { existsSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dataEpoch, hash32, principalId, resourceId } from "@openlfcp/core";
import { dekSecretRef } from "@openlfcp/storage";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  FileSecretStore,
  MIGRATIONS,
  PACKAGE,
  SCHEMA_VERSION,
  SqliteLfcpStorage,
  schemaVersion,
} from "../src/index.js";
import { tempStore } from "./fixture.js";

const R = resourceId(new Uint8Array(32).fill(1));
const ALICE = principalId(new Uint8Array(32).fill(10));

describe(PACKAGE, () => {
  it("creates a fresh database at the current schema version with WAL and synchronous=FULL", () => {
    const t = tempStore();
    try {
      expect(t.storage.schemaVersion).toBe(SCHEMA_VERSION);
      t.storage.close();
      const db = new Database(t.dbPath);
      try {
        expect(schemaVersion(db)).toBe(SCHEMA_VERSION);
        expect(db.pragma("journal_mode", { simple: true })).toBe("wal");
      } finally {
        db.close();
      }
      const again = SqliteLfcpStorage.open(t.dbPath);
      expect(again.schemaVersion).toBe(SCHEMA_VERSION);
      again.close();
    } finally {
      t.dispose();
    }
  });

  it("migrates a version-1 database to the current schema, keeping its rows", async () => {
    const t = tempStore();
    try {
      t.storage.close();
      const v1 = join(t.dir, "v1.sqlite");
      const db = new Database(v1);
      db.exec("CREATE TABLE schema_version (version INTEGER NOT NULL)");
      db.exec(MIGRATIONS[0]?.[1] as string);
      db.prepare("INSERT INTO schema_version (version) VALUES (1)").run();
      db.prepare(
        "INSERT INTO outbound (item_id, resource_id, kind, bytes, attempts, last_attempt) VALUES (?, ?, ?, ?, ?, ?)",
      ).run(
        Buffer.alloc(32, 7),
        Buffer.from(R),
        "data-unit",
        Buffer.from([1, 2, 3]),
        2,
        "2026-10-05T12:00:00Z",
      );
      db.close();
      t.storage = SqliteLfcpStorage.open(v1);
      expect(t.storage.schemaVersion).toBe(SCHEMA_VERSION);
      expect(SCHEMA_VERSION).toBe(2);
      expect(await t.storage.outbound.list(R)).toEqual([
        {
          itemId: hash32(new Uint8Array(32).fill(7)),
          resourceId: R,
          kind: "data-unit",
          bytes: Uint8Array.of(1, 2, 3),
          attempts: 2,
          lastAttempt: "2026-10-05T12:00:00Z",
          nextAttempt: null,
          blocked: null,
        },
      ]);
      expect(await t.storage.syncState.get(R)).toBeUndefined();
    } finally {
      t.dispose();
    }
  });

  it("refuses a database from a newer schema instead of touching it", () => {
    const t = tempStore();
    try {
      t.storage.close();
      const db = new Database(t.dbPath);
      db.prepare("UPDATE schema_version SET version = ?").run(SCHEMA_VERSION + 1);
      db.close();
      expect(() => SqliteLfcpStorage.open(t.dbPath)).toThrow(/newer than this code/);
      t.storage = SqliteLfcpStorage.open(join(t.dir, "other.sqlite"));
    } finally {
      t.dispose();
    }
  });

  it("never gives two connections the same sequence", async () => {
    const t = tempStore();
    const second = SqliteLfcpStorage.open(t.dbPath);
    try {
      const got: bigint[] = [];
      for (let i = 0; i < 50; i++) {
        got.push(await t.storage.actorSequences.reserveNext(R, ALICE));
        got.push(await second.actorSequences.reserveNext(R, ALICE));
      }
      expect(new Set(got).size).toBe(100);
      expect(got.at(-1)).toBe(100n);
    } finally {
      second.close();
      t.dispose();
    }
  });

  it("keeps secrets in 0600 files inside a 0700 directory and never names them by value", async () => {
    const t = tempStore();
    try {
      const ref = dekSecretRef(R, dataEpoch(1n));
      await t.secrets.put(ref, Uint8Array.of(0xab, 0xcd));
      expect(statSync(t.secretsDir).mode & 0o777).toBe(0o700);
      const file = join(t.secretsDir, `${Buffer.from(ref).toString("hex")}.secret`);
      expect(statSync(file).mode & 0o777).toBe(0o600);
      expect(String(t.secrets)).toBe("[FileSecretStore]");
      expect(JSON.stringify({ s: t.secrets })).toBe('{"s":"[FileSecretStore]"}');
      // A crash between temp file and rename leaves the old value readable.
      writeFileSync(join(t.secretsDir, ".tmp-1-1-x.secret"), "partial");
      expect(await t.secrets.get(ref)).toEqual(Uint8Array.of(0xab, 0xcd));
      expect(new FileSecretStore(t.secretsDir)).toBeDefined();
    } finally {
      t.dispose();
    }
  });

  it("cleans its fixture up deterministically", () => {
    const t = tempStore();
    expect(existsSync(t.dbPath)).toBe(true);
    t.dispose();
    expect(existsSync(t.dir)).toBe(false);
  });
});
