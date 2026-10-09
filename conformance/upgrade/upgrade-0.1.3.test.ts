// LFCP-02-029: local storage written by the released 0.1.3 SDK, opened by
// this one. The fixtures (make-fixture-0.1.3.mjs) hold one owner's Shared
// Objects Resource with three local edits still queued. CM01: the queue,
// identities, actor sequence, key reference and model survive the upgrade,
// sealed at rest or not, and the next edit continues the sequence. CM02: a
// section Resource is added beside it with its own profile and actor, and
// neither profile decodes the other's changes. CM10: once upgraded, a 0.1.x
// client is refused (SQLite schema version 4; IndexedDB version 2).

/// <reference lib="dom" />
import "fake-indexeddb/auto";
import {
  createQueuedDataUnit,
  dekResolver,
  loadControlChain,
  saveControlChain,
} from "@openlfcp/client";
import {
  actorSequence,
  dataEpoch,
  hash32,
  type ResourceId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  localStateCipher,
  sha256,
} from "@openlfcp/crypto";
import {
  checkChange,
  PROFILE_ID,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import {
  profileModel,
  SECTIONS_PROFILE_ID,
  SectionReplica,
  SharedSectionsDataProfile,
} from "@openlfcp/shared-objects/sections";
import {
  dekSecretRef,
  type EpochRow,
  InMemorySecretStore,
  type LfcpStorage,
  type SecretStore,
} from "@openlfcp/storage";
import { IDB_VERSION, IdbLfcpStorage } from "@openlfcp/storage-idb";
import { FileSecretStore, SCHEMA_VERSION, SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  principalDescriptorFromKeys,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { openRaw } from "../../packages/storage-idb/test/v1-schema.js";
import { makeTempDir, removeTempDir } from "../storage/temp-dir.mjs";
import { copySqliteFixture, readIdbFixture } from "./fixture.mjs";

// The fixture's identities (make-fixture-0.1.3.mjs).
const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = importSigningKey(bytes32(1));
const OWNER = {
  key,
  descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(101))),
};
const me = OWNER.descriptor.principalId;
const R = resourceId(bytes32(240));
const DEK = importResourceDEK(bytes32(150));
const TASK = "0192e4a0-0000-7000-8000-000000000010";
const URL = "ws://127.0.0.1:1/v1/ws";

/** CM01: everything the 0.1.3 client left is there, exactly, and work continues. */
async function legacyIntact(storage: LfcpStorage, secrets: SecretStore) {
  const chain = await loadControlChain(storage, R);
  if (chain?.kind !== "linear") throw new Error("no chain");
  expect(chain.state.seq).toBe(0n);
  expect(chain.state.dataProfile).toBe(PROFILE_ID);
  expect(await dekResolver(storage, secrets, R)(dataEpoch(0n))).toBeDefined();

  const queued = await storage.outbound.list(R);
  expect(queued.map((q) => q.kind)).toEqual(["data-unit", "data-unit", "data-unit"]);
  const units = await storage.dataUnits.range(R, me, actorSequence(1n), actorSequence(10n));
  expect(units.map((u) => u.actorSeq)).toEqual([1n, 2n, 3n]);
  // The queue holds the exact stored bytes, under their IDs.
  for (const [i, q] of queued.entries()) {
    expect(toHex(q.bytes)).toBe(toHex(units[i]?.bytes as Uint8Array));
    expect(toHex(q.itemId)).toBe(toHex(hash32(sha256(q.bytes))));
  }

  const checkpoint = await storage.profileState.checkpoint(R);
  if (checkpoint === undefined) throw new Error("no checkpoint");
  const profile = SharedObjectsDataProfile.restore(checkpoint as never, {
    resource: R,
    principal: me,
  });
  const task = profile.replica.task(TASK)?.task as Task;
  expect(task).toMatchObject({ title: "Legacy task", status: "in_progress" });

  // The next edit continues the sequence after the queued ones.
  const next = await createQueuedDataUnit(storage, {
    view: chain,
    controlHead: chain.state.head,
    actor: OWNER,
    dek: DEK,
    profile: profile.codecFor({ resourceId: R, actor: me }),
    value: checkChange(
      (profile.replica.apply(setTitle(task, "After the upgrade").intent) as { change: Uint8Array })
        .change,
    ),
  });
  expect((await storage.dataUnits.get(next.unitId))?.actorSeq).toBe(4n);
  expect((await storage.outbound.list(R)).slice(0, 3)).toEqual(queued);
  return queued;
}

/** CM02: a section Resource beside the legacy one, with its own profile and actor. */
async function sectionBeside(storage: LfcpStorage, secrets: SecretStore, legacy: unknown[]) {
  const S = resourceId(bytes32(250));
  const genesis = signControlRecord(
    { resourceId: S, controlSeq: 0n, prevControlId: null },
    {
      type: "GENESIS",
      dataProfile: SECTIONS_PROFILE_ID,
      owner: OWNER.descriptor,
      dekCommitment: dekCommitment(S, dataEpoch(0n), DEK),
      endpoints: [{ url: URL, priority: 0n }],
      coordinatorUrl: URL,
    },
    OWNER,
  );
  const chain = validateControlChain([genesis.bytes]);
  if (chain.kind !== "linear") throw new Error(chain.kind);
  await saveControlChain(storage, chain, null);
  const ref = dekSecretRef(S, dataEpoch(0n));
  await secrets.put(ref, exportSecretKeyBytes(DEK));
  const e0 = (await storage.control.epochs(S))[0] as EpochRow;
  await storage.commit([{ op: "put-epoch", resourceId: S, epoch: { ...e0, dekRef: ref } }]);

  const sections = new SharedSectionsDataProfile(
    SectionReplica.empty({ resource: S, principal: me }),
  );
  const created = sections.replica.commit([
    { intent: "section.create", sectionId: TASK, title: "New section", createdBy: me },
  ]);
  const change = checkChange(created?.parts[0]?.change as Uint8Array);
  const codec = sections.codecFor({ resourceId: S, actor: me });
  await createQueuedDataUnit(storage, {
    view: chain,
    controlHead: chain.state.head,
    actor: OWNER,
    dek: DEK,
    profile: codec,
    value: change,
  });
  // Dispatch by each Resource's own Genesis profile.
  const dispatch = async (resource: ResourceId) => {
    const c = await loadControlChain(storage, resource);
    return c?.kind === "linear" ? profileModel(c.state.dataProfile).kind : undefined;
  };
  expect(await dispatch(R)).toBe("shared-objects");
  expect(await dispatch(S)).toBe("shared-sections");
  // No cross-profile writes: the Shared Objects codec refuses a section change.
  const plaintext = codec.encode(change);
  const legacyCodec = new SharedObjectsDataProfile(
    SharedObjectsReplica.empty({ resource: S, principal: me }),
  ).codecFor({ resourceId: S, actor: me });
  expect(() => legacyCodec.decode(plaintext)).toThrow(
    expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "CHANGE_ACTOR_MISMATCH" }),
  );
  expect((await storage.outbound.list(S)).length).toBe(1);
  expect((await storage.outbound.list(R)).slice(0, 3)).toEqual(legacy);
  return S;
}

describe("upgrade from 0.1.3 storage (LFCP-02-029)", () => {
  it("SQLite: keeps the legacy queue and state, adds a section beside it, and refuses a 0.1.x client", async () => {
    const dir = makeTempDir("lfcp-upgrade-");
    try {
      const f = copySqliteFixture(dir);
      const secrets = new FileSecretStore(f.secrets);
      const storage = SqliteLfcpStorage.open(f.db);
      expect(storage.schemaVersion).toBe(SCHEMA_VERSION);
      const legacy = await legacyIntact(storage, secrets);
      await sectionBeside(storage, secrets, legacy);
      storage.close();
      // CM10: a 0.1.3 client refuses a database above its schema version 3.
      expect(SCHEMA_VERSION).toBeGreaterThan(3);
    } finally {
      removeTempDir(dir);
    }
  });

  it("SQLite, sealed at rest: the upgrade seals the legacy checkpoint and keeps everything", async () => {
    const dir = makeTempDir("lfcp-upgrade-sealed-");
    try {
      const f = copySqliteFixture(dir);
      const secrets = new FileSecretStore(f.secrets);
      const storage = await SqliteLfcpStorage.openSealed(f.db, {
        secrets,
        cipher: localStateCipher,
      });
      expect((await storage.localStateDiagnostics())?.rows).toEqual({
        sealed: 1,
        plaintext: 0,
        unreadable: 0,
      });
      await legacyIntact(storage, secrets);
      storage.close();
    } finally {
      removeTempDir(dir);
    }
  });

  it("IndexedDB: opens the version 1 database as it is, and a 0.1.x client refuses it after", async () => {
    const fixture = readIdbFixture();
    expect(fixture.version).toBe(1);
    const name = "lfcp-upgrade-0.1.3";
    const legacy = await openRaw(name, 1);
    for (const [store, rows] of Object.entries(fixture.stores))
      await new Promise<void>((resolve, reject) => {
        const tx = legacy.transaction(store, "readwrite");
        for (const [k, v] of rows) tx.objectStore(store).put(v, k as IDBValidKey);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    legacy.close();
    const secrets = new InMemorySecretStore();
    for (const [ref, bytes] of fixture.secrets) await secrets.put(ref as never, bytes);

    const storage = await IdbLfcpStorage.open(name, {
      localState: { secrets, cipher: localStateCipher },
    });
    const queued = await legacyIntact(storage, secrets);
    await sectionBeside(storage, secrets, queued);
    storage.close();
    const after = await openRaw(name, IDB_VERSION);
    expect(after.version).toBe(2);
    after.close();
    await expect(openRaw(name, 1)).rejects.toMatchObject({ name: "VersionError" });
  });
});
