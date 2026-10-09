/// <reference lib="dom" />
import "fake-indexeddb/auto";
import { type DataUnitId, resourceId, toHex } from "@openlfcp/core";
import {
  InMemorySecretStore,
  type LocalStateMeta,
  localStateKeyRef,
  type ProfileCheckpoint,
} from "@openlfcp/storage";
import { describe, expect, it } from "vitest";
import { IdbLfcpStorage } from "../src/index.js";
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
const isEnvelope = (b: Uint8Array) => toHex(b.subarray(0, 4)) === "6c736531"; // "lse1"

let n = 0;
const name = () => `local-state-${++n}`;

/** A raw IndexedDB connection, past the adapter. */
async function raw<T>(db: string, body: (d: IDBDatabase) => Promise<T>): Promise<T> {
  const open = indexedDB.open(db);
  const d = await new Promise<IDBDatabase>((resolve, reject) => {
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
  try {
    return await body(d);
  } finally {
    d.close();
  }
}
const request = <T>(r: IDBRequest<T>) =>
  new Promise<T>((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
const rawStates = (db: string) =>
  raw(db, async (d) =>
    (
      (await request(
        d.transaction(["checkpoints"], "readonly").objectStore("checkpoints").getAll(),
      )) as ProfileCheckpoint[]
    ).map((c) => c.state),
  );
const rawMeta = (db: string) =>
  raw(
    db,
    async (d) =>
      (await request(
        d.transaction(["meta"], "readonly").objectStore("meta").get("local-state"),
      )) as LocalStateMeta,
  );
const putRaw = (db: string, store: string, key: string, value: unknown) =>
  raw(db, async (d) => {
    await request(d.transaction([store], "readwrite").objectStore(store).put(value, key));
  });

describe("IdbLfcpStorage local state (LFCP-02-098)", () => {
  it("seals checkpoints written through commit and opens them on read", async () => {
    const db = name();
    const local = { secrets: new InMemorySecretStore(), cipher: standInCipher };
    const s = await IdbLfcpStorage.open(db, { localState: local });
    await s.commit([{ op: "put-profile-checkpoint", checkpoint: checkpoint(1, "Task A") }]);
    const got = await s.profileState.checkpoint(R(1));
    expect(read(got?.state as Uint8Array)).toBe("Task A");
    expect(got?.units).toHaveLength(1);
    s.close();
    expect((await rawStates(db)).every(isEnvelope)).toBe(true);
    await expect(IdbLfcpStorage.open(db)).rejects.toThrow(/localState/);
    const again = await IdbLfcpStorage.open(db, { localState: local });
    expect(await again.localStateDiagnostics()).toMatchObject({
      scheme: "lse-v1",
      generation: 1,
      keyPresent: true,
      phase: "ready",
      rows: { sealed: 1, plaintext: 0, unreadable: 0 },
      lastEvent: { kind: "migrated" },
    });
    again.close();
  });

  it("migrates a database from before the scheme, resuming after a crash between batches", async () => {
    const db = name();
    const plain = await IdbLfcpStorage.open(db);
    await plain.commit(
      Array.from({ length: 70 }, (_, i) => ({
        op: "put-profile-checkpoint" as const,
        checkpoint: checkpoint(i + 1, `state ${i + 1}`),
      })),
    );
    plain.close();
    expect((await rawStates(db)).some(isEnvelope)).toBe(false);
    const local = { secrets: new InMemorySecretStore(), cipher: standInCipher };
    (await IdbLfcpStorage.open(db, { localState: local })).close();
    expect((await rawStates(db)).every(isEnvelope)).toBe(true);
    // A crash mid-migration: the metadata says migrating, one row is plain.
    await putRaw(db, "meta", "local-state", { ...(await rawMeta(db)), phase: "migrating" });
    await putRaw(db, "checkpoints", toHex(R(5)), checkpoint(5, "state 5"));
    const resumed = await IdbLfcpStorage.open(db, { localState: local });
    expect((await resumed.localStateDiagnostics())?.rows).toEqual({
      sealed: 70,
      plaintext: 0,
      unreadable: 0,
    });
    for (const k of [1, 5, 70])
      expect(read((await resumed.profileState.checkpoint(R(k)))?.state as Uint8Array)).toBe(
        `state ${k}`,
      );
    resumed.close();
  });

  it("treats a checkpoint under a lost key as absent, and rotates on request", async () => {
    const db = name();
    const secrets = new InMemorySecretStore();
    const local = { secrets, cipher: standInCipher };
    const s = await IdbLfcpStorage.open(db, { localState: local });
    await s.commit([{ op: "put-profile-checkpoint", checkpoint: checkpoint(1, "Task A") }]);
    s.close();
    const { installId } = await rawMeta(db);
    await secrets.delete(localStateKeyRef(installId, 1));
    const lost = await IdbLfcpStorage.open(db, { localState: local });
    expect(await lost.profileState.checkpoint(R(1))).toBeUndefined();
    expect(await lost.localStateDiagnostics()).toMatchObject({
      generation: 2,
      rows: { sealed: 0, plaintext: 0, unreadable: 1 },
      lastEvent: { kind: "key-lost" },
    });
    await lost.commit([{ op: "put-profile-checkpoint", checkpoint: checkpoint(1, "rebuilt") }]);
    await lost.rotateLocalStateKey();
    expect(await lost.localStateDiagnostics()).toMatchObject({
      generation: 3,
      phase: "ready",
      rows: { sealed: 1, plaintext: 0, unreadable: 0 },
      lastEvent: { kind: "rotated" },
    });
    expect(await secrets.get(localStateKeyRef(installId, 2))).toBeUndefined();
    expect(read((await lost.profileState.checkpoint(R(1)))?.state as Uint8Array)).toBe("rebuilt");
    lost.close();
    const plain = await IdbLfcpStorage.open(name());
    await expect(plain.rotateLocalStateKey()).rejects.toThrow(/localState/);
    expect(await plain.localStateDiagnostics()).toBeNull();
    plain.close();
  });
});
