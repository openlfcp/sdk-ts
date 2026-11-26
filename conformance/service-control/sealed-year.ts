// A bridge-style synthetic history of C (syntheticYear) sealed as real signed, encrypted Data
// Units, and the C profile a receiving client runs: shared by the receive-path tests of C.

import {
  createDataUnit,
  type DataProfileHandler,
  DataUnitApplier,
  type DataUnitApplierOptions,
} from "@openlfcp/client";
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
import { InMemoryActorSequenceReservation } from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlBody,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { syntheticYear } from "../../packages/shared-objects/test/support/service-control-year.js";

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

/** `days` of history of C, each change a Data Unit chained to its actor's previous one. */
export async function sealedYear(days: number) {
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
  const sequences = new InMemoryActorSequenceReservation();
  const previous = new Map<string, DataUnitId>();
  const sealed: Uint8Array[] = [];
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
    if (Number(created.seq) !== u.actorSeq) throw new Error("unexpected actor sequence");
    previous.set(toHex(u.signer), created.unitId);
    sealed.push(created.bytes);
  }
  /** A cold client's C profile and applier on `storage`. */
  const client = (storage: DataUnitApplierOptions["storage"]) => {
    const profile = new ServiceControlDataProfile({
      ...year.options,
      signerClassOf: (unit) => ids.get(toHex(unit.actor as PrincipalId))?.cls ?? "other",
    });
    const applier = new DataUnitApplier({
      storage,
      dek: () => DEK0,
      handlers: [profile as unknown as DataProfileHandler<unknown>],
    });
    return { profile, applier };
  };
  return { view, resourceId, sealed, client };
}
