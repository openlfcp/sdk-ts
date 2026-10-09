/// <reference types="node" />
import { type DataUnitId, resourceId } from "@openlfcp/core";
import { localStateKeyRef, type ProfileCheckpoint } from "@openlfcp/storage";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { SqliteLfcpStorage } from "../src/index.js";
import { tempStore } from "./fixture.js";
import { standInCipher } from "./stand-in-cipher.js";

const text = (s: string) => new TextEncoder().encode(s);
const read = (b: Uint8Array) => new TextDecoder().decode(b);
const R = (n: number) => resourceId(new Uint8Array(32).fill(n));
const checkpoint = (n: number, state: string): ProfileCheckpoint => ({
  resourceId: R(n),
  dataProfile: "org.openlfcp.shared-objects.v1",
  state: text(state),
  actorSeq: 3,
  units: [{ unitId: new Uint8Array(32).fill(n) as unknown as DataUnitId, ref: "ref" }],
});
const MAGIC = "6c736531"; // "lse1"

/** The raw state column of every checkpoint, read past the adapter. */
function rawStates(path: string): string[] {
  const db = new Database(path, { readonly: true });
  try {
    return (
      db.prepare("SELECT state FROM profile_checkpoints ORDER BY resource_id").all() as {
        state: Buffer;
      }[]
    ).map((r) => r.state.toString("hex"));
  } finally {
    db.close();
  }
}

describe("SqliteLfcpStorage local state (LFCP-02-098)", () => {
  it("seals checkpoints written through commit and opens them on read", async () => {
    const t = tempStore();
    try {
      t.storage.close();
      const local = { secrets: t.secrets, cipher: standInCipher };
      const storage = await SqliteLfcpStorage.openSealed(t.dbPath, local);
      await storage.commit([{ op: "put-profile-checkpoint", checkpoint: checkpoint(1, "Task A") }]);
      const got = await storage.profileState.checkpoint(R(1));
      expect(read(got?.state as Uint8Array)).toBe("Task A");
      expect(got?.actorSeq).toBe(3);
      expect(got?.units).toHaveLength(1);
      storage.close();
      expect(rawStates(t.dbPath)[0]?.startsWith(MAGIC)).toBe(true);
      // A sealed database refuses the plain open: its rows are envelopes.
      expect(() => SqliteLfcpStorage.open(t.dbPath)).toThrow(/openSealed/);
      const again = await SqliteLfcpStorage.openSealed(t.dbPath, local);
      expect(read((await again.profileState.checkpoint(R(1)))?.state as Uint8Array)).toBe("Task A");
      expect(again.localStateDiagnostics()).toMatchObject({
        scheme: "lse-v1",
        generation: 1,
        keyPresent: true,
        phase: "ready",
        rows: { sealed: 1, plaintext: 0, unreadable: 0 },
        lastEvent: { kind: "migrated" },
      });
      again.close();
    } finally {
      t.dispose();
    }
  });

  it("migrates a database from before the scheme, resuming after a crash between batches", async () => {
    const t = tempStore();
    try {
      await t.storage.commit(
        Array.from({ length: 70 }, (_, i) => ({
          op: "put-profile-checkpoint" as const,
          checkpoint: checkpoint(i + 1, `state ${i + 1}`),
        })),
      );
      t.storage.close();
      expect(rawStates(t.dbPath).every((s) => !s.startsWith(MAGIC))).toBe(true);
      const local = { secrets: t.secrets, cipher: standInCipher };
      const storage = await SqliteLfcpStorage.openSealed(t.dbPath, local);
      storage.close();
      expect(rawStates(t.dbPath).every((s) => s.startsWith(MAGIC))).toBe(true);

      // A crash mid-migration: the metadata says migrating, some rows are plain.
      const db = new Database(t.dbPath);
      const meta = JSON.parse(
        (db.prepare("SELECT meta FROM local_state").get() as { meta: string }).meta,
      );
      db.prepare("UPDATE local_state SET meta = ?").run(
        JSON.stringify({ ...meta, phase: "migrating" }),
      );
      db.prepare("UPDATE profile_checkpoints SET state = ? WHERE resource_id = ?").run(
        Buffer.from(text("state 5")),
        Buffer.from(R(5)),
      );
      db.close();
      const resumed = await SqliteLfcpStorage.openSealed(t.dbPath, local);
      expect(resumed.localStateDiagnostics()?.rows).toEqual({
        sealed: 70,
        plaintext: 0,
        unreadable: 0,
      });
      for (const n of [1, 5, 70])
        expect(read((await resumed.profileState.checkpoint(R(n)))?.state as Uint8Array)).toBe(
          `state ${n}`,
        );
      resumed.close();
    } finally {
      t.dispose();
    }
  });

  it("treats a checkpoint under a lost key as absent, and seals new ones under the next generation", async () => {
    const t = tempStore();
    try {
      t.storage.close();
      const local = { secrets: t.secrets, cipher: standInCipher };
      const storage = await SqliteLfcpStorage.openSealed(t.dbPath, local);
      await storage.commit([{ op: "put-profile-checkpoint", checkpoint: checkpoint(1, "Task A") }]);
      storage.close();
      const db = new Database(t.dbPath, { readonly: true });
      const meta = JSON.parse(
        (db.prepare("SELECT meta FROM local_state").get() as { meta: string }).meta,
      );
      db.close();
      await t.secrets.delete(localStateKeyRef(meta.installId, 1));

      const lost = await SqliteLfcpStorage.openSealed(t.dbPath, local);
      expect(await lost.profileState.checkpoint(R(1))).toBeUndefined();
      expect(lost.localStateDiagnostics()).toMatchObject({
        generation: 2,
        keyPresent: true,
        rows: { sealed: 0, plaintext: 0, unreadable: 1 },
        lastEvent: { kind: "key-lost" },
      });
      // The rebuilt checkpoint replaces the unreadable row.
      await lost.commit([{ op: "put-profile-checkpoint", checkpoint: checkpoint(1, "rebuilt") }]);
      expect(read((await lost.profileState.checkpoint(R(1)))?.state as Uint8Array)).toBe("rebuilt");
      expect(lost.localStateDiagnostics()?.rows).toEqual({
        sealed: 1,
        plaintext: 0,
        unreadable: 0,
      });
      lost.close();
    } finally {
      t.dispose();
    }
  });

  it("rotates only a database opened sealed", async () => {
    const t = tempStore();
    try {
      await expect(t.storage.rotateLocalStateKey()).rejects.toThrow(/openSealed/);
      expect(t.storage.localStateDiagnostics()).toBeNull();
    } finally {
      t.dispose();
    }
  });

  it("rotates the key on request and removes the old one", async () => {
    const t = tempStore();
    try {
      t.storage.close();
      const local = { secrets: t.secrets, cipher: standInCipher };
      const storage = await SqliteLfcpStorage.openSealed(t.dbPath, local);
      await storage.commit([
        { op: "put-profile-checkpoint", checkpoint: checkpoint(1, "Task A") },
        { op: "put-profile-checkpoint", checkpoint: checkpoint(2, "Task B") },
      ]);
      const before = rawStates(t.dbPath);
      const db = new Database(t.dbPath, { readonly: true });
      const { installId } = JSON.parse(
        (db.prepare("SELECT meta FROM local_state").get() as { meta: string }).meta,
      );
      db.close();
      await storage.rotateLocalStateKey();
      expect(storage.localStateDiagnostics()).toMatchObject({
        generation: 2,
        phase: "ready",
        rows: { sealed: 2, plaintext: 0, unreadable: 0 },
        lastEvent: { kind: "rotated" },
      });
      const after = rawStates(t.dbPath);
      expect(after).not.toEqual(before);
      expect(await t.secrets.get(localStateKeyRef(installId, 1))).toBeUndefined();
      expect(await t.secrets.get(localStateKeyRef(installId, 2))).toBeDefined();
      expect(read((await storage.profileState.checkpoint(R(2)))?.state as Uint8Array)).toBe(
        "Task B",
      );
      storage.close();
    } finally {
      t.dispose();
    }
  });
});
