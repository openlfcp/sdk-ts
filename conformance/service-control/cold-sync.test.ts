// A§3.5 (E-030): the receive path of a cold personal client of C, measured. year.test.ts measures
// the profile alone; here every unit of a bridge-style synthetic history is a signed, encrypted
// Data Unit, and a client with empty storage takes them as DATA_BATCH delivers them: the applier
// verifies, decrypts and stores each unit and the C profile admits it. A received Snapshot of C
// does not spare this: §2.2 admits a Snapshot only against the verified unit of every change, and
// ServiceControlReplica.fromSnapshot costs what replaying the units does (year.test.ts). The
// network and the server are not measured. Measured, not held: LFCP_SC_YEAR=14,365 runs those
// lengths in days and prints the figures; LFCP_SC_BATCH sets the units per batch (default 256);
// LFCP_SC_STORAGE the client's storage: `idb` (the plugin's, here on fake-indexeddb; default),
// `sqlite` (the bridge's) or `memory` (InMemoryLfcpStorage, for tests: it scans every unit).

import "fake-indexeddb/auto";

import { createDataUnit, type DataProfileHandler, DataUnitApplier } from "@openlfcp/client";
import {
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  type PrincipalId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { checkChange } from "@openlfcp/shared-objects/admission";
import {
  SERVICE_CONTROL_PROFILE_ID,
  ServiceControlDataProfile,
  type ServiceControlSignerClass,
  serviceControlCodecFor,
} from "@openlfcp/shared-objects/service-control";
import { InMemoryActorSequenceReservation, InMemoryLfcpStorage } from "@openlfcp/storage";
import { IdbLfcpStorage } from "@openlfcp/storage-idb";
import { SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  type ChainResult,
  type ControlBody,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { syntheticYear } from "../../packages/shared-objects/test/support/service-control-year.js";
import { inDir, makeTempDir, removeTempDir } from "../storage/temp-dir.mjs";

declare const process: {
  env: Record<string, string | undefined>;
  memoryUsage(): { rss: number; heapUsed: number };
};

const DAYS = (process.env.LFCP_SC_YEAR ?? "")
  .split(",")
  .filter((d) => d !== "")
  .map(Number);
const BATCH = Number(process.env.LFCP_SC_BATCH ?? "256");
const STORAGE = process.env.LFCP_SC_STORAGE ?? "idb";
const MIB = 2 ** 20;

/** The cold client's empty storage, and how to close it. */
async function openStorage(days: number) {
  if (STORAGE === "memory") return { storage: new InMemoryLfcpStorage(), close: () => {} };
  if (STORAGE === "idb") {
    const storage = await IdbLfcpStorage.open(`lfcp-c-cold-${days}`);
    return { storage, close: () => storage.close() };
  }
  if (STORAGE !== "sqlite") throw new Error(`LFCP_SC_STORAGE: ${STORAGE}`);
  const dir = makeTempDir("lfcp-c-cold-");
  const storage = SqliteLfcpStorage.open(inDir(dir, "lfcp.sqlite"));
  return {
    storage,
    close: () => {
      storage.close();
      removeTempDir(dir);
    },
  };
}

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const ROOT = signer(11);
const BRIDGE = signer(12);
const DEK0 = importResourceDEK(bytes32(90));

/** C's Control chain: the root's Genesis, then data/read and data/write for the bridge. */
function chainOf(resource: Uint8Array): Extract<ChainResult, { kind: "linear" }> {
  const records: Uint8Array[] = [];
  let head: ControlRecordId | null = null;
  const add = (body: ControlBody) => {
    const s = signControlRecord(
      { resourceId: resource as never, controlSeq: BigInt(records.length), prevControlId: head },
      body,
      ROOT,
    );
    records.push(s.bytes);
    head = s.recordId;
  };
  add({
    type: "GENESIS",
    dataProfile: SERVICE_CONTROL_PROFILE_ID,
    owner: ROOT.descriptor,
    dekCommitment: dekCommitment(resource as never, dataEpoch(0n), DEK0),
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  });
  add({ type: "CAPABILITY_GRANT", subject: BRIDGE.descriptor, abilities: [1n, 2n], delegable: [] });
  const chain = validateControlChain(records);
  if (chain.kind !== "linear") throw new Error(chain.kind);
  return chain;
}

const timed = async <T>(f: () => Promise<T>): Promise<[T, number]> => {
  const t = performance.now();
  const r = await f();
  return [r, Math.round(performance.now() - t)];
};

describe.skipIf(DAYS.length === 0)("A§3.5 receive path of a cold client of C", () => {
  for (const days of DAYS)
    it(`${days} days of bridge-style history`, { timeout: 3_600_000 }, async () => {
      const ids = new Map<string, { signer: Signer; cls: ServiceControlSignerClass }>([
        [toHex(ROOT.descriptor.principalId), { signer: ROOT, cls: "root" }],
        [toHex(BRIDGE.descriptor.principalId), { signer: BRIDGE, cls: "service-device" }],
      ]);
      const year = syntheticYear({
        days,
        root: ROOT.descriptor.principalId,
        bridge: BRIDGE.descriptor.principalId,
      });
      const view = chainOf(year.options.resource);
      const resourceId = year.options.resource;

      // The writers' side: one Data Unit per change, each actor's chained to its previous one.
      const sequences = new InMemoryActorSequenceReservation();
      const previous = new Map<string, DataUnitId>();
      const [sealed, sealMs] = await timed(async () => {
        const out: Uint8Array[] = [];
        for (const u of year.units) {
          const who = ids.get(toHex(u.signer));
          if (who === undefined) throw new Error("unknown signer");
          const created = await createDataUnit({
            view,
            controlHead: view.state.head,
            actor: who.signer,
            dek: DEK0,
            sequences,
            previousUnitId: previous.get(toHex(u.signer)) ?? null,
            profile: serviceControlCodecFor({ resourceId, actor: u.signer }),
            value: checkChange(u.bytes),
          });
          expect(Number(created.seq)).toBe(u.actorSeq);
          previous.set(toHex(u.signer), created.unitId);
          out.push(created.bytes);
        }
        return out;
      });

      // The cold client: empty storage, the units in DATA_BATCH-sized runs.
      const baseRss = process.memoryUsage().rss;
      let peakRss = baseRss;
      const profile = new ServiceControlDataProfile({
        ...year.options,
        signerClassOf: (unit) => ids.get(toHex(unit.actor as PrincipalId))?.cls ?? "other",
      });
      const { storage, close } = await openStorage(days);
      const applier = new DataUnitApplier({
        storage,
        dek: () => DEK0,
        handlers: [profile as unknown as DataProfileHandler<unknown>],
      });
      const perBatch: number[] = [];
      const [kinds, receiveMs] = await timed(async () => {
        const counts: Record<string, number> = {};
        for (let i = 0; i < sealed.length; i += BATCH) {
          const t = performance.now();
          for (const o of await applier.receiveBatch(view, sealed.slice(i, i + BATCH)))
            counts[o.kind] = (counts[o.kind] ?? 0) + 1;
          perBatch.push(performance.now() - t);
          peakRss = Math.max(peakRss, process.memoryUsage().rss);
        }
        return counts;
      });
      close();
      expect(kinds).toEqual({ applied: sealed.length });
      expect(Object.keys(profile.state().bindings)).toHaveLength(8);
      const ms = (xs: number[]) => Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 100);
      const tenth = Math.max(1, Math.floor(perBatch.length / 10));
      console.info(
        `E-030 C cold receive: ${JSON.stringify({
          days,
          units: sealed.length,
          batch: BATCH,
          storage: STORAGE,
          unitMiB: +(sealed.reduce((n, b) => n + b.length, 0) / MIB).toFixed(2),
          sealMs,
          receiveMs,
          msPer100UnitsFirstTenth: ms(perBatch.slice(0, tenth)) / BATCH,
          msPer100UnitsLastTenth: ms(perBatch.slice(-tenth)) / BATCH,
          baseRssMiB: Math.round(baseRss / MIB),
          peakRssMiB: Math.round(peakRss / MIB),
        })}`,
      );
    });
});
