// LFCP-02-098, end to end with the real cipher: profile checkpoints written
// through the storage adapters, sealed by @openlfcp/crypto's
// localStateCipher, never reach the disk in plaintext. A unique canary is
// written into checkpoint states; after the database closes, no file of it
// (SQLite with its WAL; IndexedDB's stored records) holds the canary, while
// the same run without sealing does (so the search works). A database from
// before the scheme loses its plaintext once migrated.
//
// Cross-package (crypto + storage adapters), so it lives under conformance/:
// the storage packages may not depend on @openlfcp/crypto (LFCP-014).

/// <reference lib="dom" />
import "fake-indexeddb/auto";
import { type DataUnitId, resourceId } from "@openlfcp/core";
import { localStateCipher } from "@openlfcp/crypto";
import {
  InMemorySecretStore,
  type LocalStateCipher,
  type ProfileCheckpoint,
} from "@openlfcp/storage";
import { IdbLfcpStorage } from "@openlfcp/storage-idb";
import { FileSecretStore, SqliteLfcpStorage } from "@openlfcp/storage-node";
import { describe, expect, it } from "vitest";
import { filesContaining } from "./file-scan.mjs";
import { inDir, makeTempDir, removeTempDir } from "./temp-dir.mjs";

// The crypto package's cipher is the storage packages' interface.
const cipher: LocalStateCipher = localStateCipher;

const utf8 = (s: string) => new TextEncoder().encode(s);
const CANARY = utf8("CANARY-7f3e9a1c-a private Task title");
const R = (n: number) => resourceId(new Uint8Array(32).fill(n));
const checkpoint = (n: number): ProfileCheckpoint => ({
  resourceId: R(n),
  dataProfile: "org.openlfcp.shared-objects.v1",
  state: Uint8Array.from([...utf8(`state ${n}: `), ...CANARY]),
  actorSeq: 1,
  units: [{ unitId: new Uint8Array(32).fill(n) as unknown as DataUnitId, ref: "r" }],
});
const writes = (count: number) =>
  Array.from({ length: count }, (_, i) => ({
    op: "put-profile-checkpoint" as const,
    checkpoint: checkpoint(i + 1),
  }));

describe("local state sealed at rest, end to end (LFCP-02-098)", () => {
  it("SQLite: no file of the database holds the canary", async () => {
    const dir = makeTempDir("lfcp-local-state-");
    try {
      const db = inDir(dir, "lfcp.sqlite");
      const secrets = new FileSecretStore(inDir(dir, "secrets"));
      const storage = await SqliteLfcpStorage.openSealed(db, { secrets, cipher });
      await storage.commit(writes(40));
      for (let i = 0; i < 3; i++) await storage.commit(writes(40)); // rewrites
      const back = await storage.profileState.checkpoint(R(7));
      expect(back?.state).toEqual(checkpoint(7).state);
      storage.close();
      expect(filesContaining(dir, CANARY).filter((f) => !f.startsWith("secrets/"))).toEqual([]);
    } finally {
      removeTempDir(dir);
    }
  });

  it("SQLite: the search finds the canary without sealing", async () => {
    const dir = makeTempDir("lfcp-local-state-");
    try {
      const storage = SqliteLfcpStorage.open(inDir(dir, "lfcp.sqlite"));
      await storage.commit(writes(5));
      storage.close();
      expect(filesContaining(dir, CANARY).length).toBeGreaterThan(0);
    } finally {
      removeTempDir(dir);
    }
  });

  it("SQLite: a database from before the scheme keeps no plaintext once migrated", async () => {
    const dir = makeTempDir("lfcp-local-state-");
    try {
      const db = inDir(dir, "lfcp.sqlite");
      const plain = SqliteLfcpStorage.open(db);
      await plain.commit(writes(40));
      plain.close();
      expect(filesContaining(dir, CANARY).length).toBeGreaterThan(0);
      const secrets = new FileSecretStore(inDir(dir, "secrets"));
      const storage = await SqliteLfcpStorage.openSealed(db, { secrets, cipher });
      expect(storage.localStateDiagnostics()?.rows).toEqual({
        sealed: 40,
        plaintext: 0,
        unreadable: 0,
      });
      expect((await storage.profileState.checkpoint(R(40)))?.state).toEqual(checkpoint(40).state);
      storage.close();
      expect(filesContaining(dir, CANARY).filter((f) => !f.startsWith("secrets/"))).toEqual([]);
    } finally {
      removeTempDir(dir);
    }
  });

  it("IndexedDB: no stored checkpoint holds the canary", async () => {
    const name = "lfcp-local-state-canary";
    const local = { secrets: new InMemorySecretStore(), cipher };
    const storage = await IdbLfcpStorage.open(name, { localState: local });
    await storage.commit(writes(20));
    expect((await storage.profileState.checkpoint(R(3)))?.state).toEqual(checkpoint(3).state);
    storage.close();
    const open = indexedDB.open(name);
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
    try {
      const all = db.transaction(["checkpoints"], "readonly").objectStore("checkpoints").getAll();
      const rows = await new Promise<ProfileCheckpoint[]>((resolve, reject) => {
        all.onsuccess = () => resolve(all.result as ProfileCheckpoint[]);
        all.onerror = () => reject(all.error);
      });
      expect(rows).toHaveLength(20);
      const holds = (b: Uint8Array) => b.some((_, i) => CANARY.every((c, j) => b[i + j] === c));
      expect(rows.filter((r) => holds(r.state))).toEqual([]);
    } finally {
      db.close();
      indexedDB.deleteDatabase(name);
    }
  });
});
