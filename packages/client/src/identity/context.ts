import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  dataEpoch,
  fromHex,
  LfcpError,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  type AgreementKeyPair,
  dekCommitment,
  exportSecretKeyBytes,
  importResourceDEK,
  type ResourceDEK,
  sha256,
} from "@openlfcp/crypto";
import { dekSecretRef, type LfcpStorage, type SecretStore } from "@openlfcp/storage";
import {
  ABILITY,
  type DataUnitPayload,
  hasAbility,
  InMemorySeenUnits,
  type PrincipalDescriptor,
  parseDataUnit,
  parseKeyPackage,
  receiveDataUnit,
  receiveKeyPackage,
  type Signer,
  sealKeyPackage,
  validateControlChain,
  verifyKeyPackage,
} from "@openlfcp/wire";
import {
  adoptStoredDeks,
  loadControlChain,
  saveControlChain,
  saveControlConflict,
} from "../storage.js";
import {
  type IdentityAuthor,
  type IdentityDocumentPort,
  identityPlaintextCodec,
  identityWriterClass,
} from "./document.js";
import {
  type JournalPhase,
  type OperationJournal,
  type PackageLedger,
  phaseOf,
} from "./journal.js";
import type { IdentityChannel } from "./network.js";
import { IdentityUnavailable } from "./network.js";
import type { LinearChain, PhaseState } from "./phases.js";

/** The storage the identity flows use. */
export type IdentityStorage = Pick<
  LfcpStorage,
  "control" | "commit" | "localMarks" | "actorSequences"
>;

/** This installation, as the identity flows act for it. */
export interface Installation {
  /** Its Principal's signer: a device's, or the root's when it has no devices yet. */
  readonly signer: Signer;
  /** Its X25519 key, to open Key Packages. */
  readonly agreement: AgreementKeyPair;
}

/** The Resource or the Identity Resource is forked (§9.7): approval, reconciliation and rotation are suspended. */
export class IdentityConflict extends Error {
  constructor(
    readonly resource: ResourceId,
    message: string,
  ) {
    super(message);
    this.name = "IdentityConflict";
  }
}

/**
 * Synchronises the Control Chain of `resource` from the coordinator and
 * stores it: the local chain extended with the coordinator's later
 * records, or the coordinator's whole chain when the local one does not
 * extend. A fork is stored as a conflict and thrown (§9.7).
 */
export async function syncChain(
  storage: IdentityStorage,
  channel: IdentityChannel,
  resource: ResourceId,
): Promise<LinearChain> {
  // A fork this installation already knows stays blocking (§9.7): no branch is chosen.
  if ((await storage.control.conflict(resource)) !== undefined)
    throw new IdentityConflict(resource, "the Control Chain is forked (§9.7)");
  const local = await loadControlChain(storage, resource);
  const have = local?.kind === "linear" ? local.records.map((r) => r.signed.bytes) : [];
  let chain = validateControlChain([
    ...have,
    ...(await channel.control(resource, BigInt(have.length))),
  ]);
  if (chain.kind !== "linear" && have.length > 0) {
    // The coordinator's chain does not extend the stored one: validate both
    // together, so a competing record on a known prev is a conflict (§9.7),
    // never a silent switch to the coordinator's branch.
    const all = new Map<string, Uint8Array>();
    for (const r of [...have, ...(await channel.control(resource, 0n))])
      all.set(toHex(sha256(r)), r);
    chain = validateControlChain([...all.values()]);
  }
  if (chain.kind === "conflict") {
    await saveControlConflict(storage, resource, chain);
    throw new IdentityConflict(resource, "the Control Chain is forked (§9.7)");
  }
  if (chain.kind !== "linear")
    throw new LfcpError(
      "INVALID_CONTROL_CHAIN",
      "the coordinator's Control Chain does not validate",
    );
  if (!bytesEqual(chain.state.resourceId, resource))
    throw new LfcpError("INVALID_CONTROL_CHAIN", "the coordinator sent another Resource's chain");
  await storeChain(storage, chain, local?.kind === "linear" ? local : undefined);
  return chain;
}

async function storeChain(
  storage: IdentityStorage,
  chain: LinearChain,
  previous: LinearChain | undefined,
): Promise<void> {
  if (previous !== undefined && bytesEqual(previous.state.head, chain.state.head)) return;
  const prefix =
    previous !== undefined &&
    previous.records.length <= chain.records.length &&
    previous.records.every((r, i) =>
      bytesEqual(r.signed.id, chain.records[i]?.signed.id ?? new Uint8Array()),
    );
  const r = await saveControlChain(storage, chain, prefix ? previous.state.head : null);
  if (!r.ok && prefix) throw new Error(`the Control Chain was not stored: ${r.reason}`);
}

/** Validates `chain` extended with `record` (e.g. after an ACK) and stores it. */
export async function extendChain(
  storage: IdentityStorage,
  chain: LinearChain,
  record: Uint8Array,
): Promise<LinearChain> {
  const next = validateControlChain([...chain.records.map((r) => r.signed.bytes), record]);
  if (next.kind !== "linear")
    throw new LfcpError(
      "INVALID_CONTROL_CHAIN",
      "an acknowledged record does not validate locally",
    );
  await storeChain(storage, next, chain);
  return next;
}

export interface ControlPhaseSpec {
  readonly id: string;
  readonly kind: JournalPhase["kind"];
  readonly resource: ResourceId;
  readonly facts?: Readonly<Record<string, string>>;
  /** §9.2 classification on the synchronised chain; `isOwn` tells this installation's record IDs. */
  classify(chain: LinearChain, isOwn: (recordIdHex: string) => boolean): PhaseState;
  /** The signed record on the chain's head (§9.3: rebuilt on a new head, never re-sent as it was). */
  build(chain: LinearChain): Promise<Uint8Array> | Uint8Array;
}

export interface PhaseOutcome {
  readonly state: PhaseState | "refused";
  readonly chain: LinearChain;
  /** The NACK code of a refused phase. */
  readonly code?: string;
  readonly recordId?: ControlRecordId;
}

const MAX_HEAD_RETRIES = 8;

/**
 * Runs one Control Plane phase durably (§9.1–§9.3). The phase is
 * classified on the synchronised chain first; while it is `pending`, the
 * exact bytes are persisted before they are sent: the same bytes again
 * while the head is the one they were built on (a lost ACK is answered
 * with the same ACK, W §47), a record rebuilt on a new head otherwise.
 */
export async function runControlPhase(
  storage: IdentityStorage,
  channel: IdentityChannel,
  journal: OperationJournal,
  operation: string,
  spec: ControlPhaseSpec,
): Promise<PhaseOutcome> {
  const R = spec.resource;
  for (let attempt = 0; ; attempt++) {
    const chain = await syncChain(storage, channel, R);
    const before = phaseOf(await journal.load(operation), spec.id);
    const sent = new Set(before?.sent ?? []);
    const state = spec.classify(chain, (id) => sent.has(id));
    if (state !== "pending") {
      const recordId = state === "committed-own" ? ownRecordOn(chain, sent) : undefined;
      await journal.putPhase(operation, {
        ...(before ?? {}),
        id: spec.id,
        kind: spec.kind,
        resource: toHex(R),
        state,
        ...(spec.facts === undefined ? {} : { facts: spec.facts }),
        ...(recordId === undefined ? {} : { recordId }),
      });
      return Object.freeze({
        state,
        chain,
        ...(recordId === undefined ? {} : { recordId: controlRecordId(fromHex(recordId)) }),
      });
    }
    if (attempt >= MAX_HEAD_RETRIES)
      throw new IdentityUnavailable(`the head kept moving while proposing ${spec.id}`);
    const head = toHex(chain.state.head);
    let bytes: Uint8Array;
    if (before?.bytes !== undefined && before.expectedHead === head) bytes = fromHex(before.bytes);
    else {
      bytes = await spec.build(chain);
      const id = toHex(validateRecordId(bytes));
      await journal.putPhase(operation, {
        id: spec.id,
        kind: spec.kind,
        resource: toHex(R),
        state: "pending",
        bytes: toHex(bytes),
        expectedHead: head,
        sent: [...sent, id],
        ...(spec.facts === undefined ? {} : { facts: spec.facts }),
      });
    }
    const answer = await channel.putControl(R, chain.state.head, bytes);
    if (answer.kind === "ack") {
      const next = await extendChain(storage, chain, bytes);
      const recordId = toHex(next.state.head);
      const phase = phaseOf(await journal.load(operation), spec.id) as JournalPhase;
      await journal.putPhase(operation, { ...phase, state: "committed-own", recordId });
      return Object.freeze({ state: "committed-own", chain: next, recordId: next.state.head });
    }
    if (answer.code === "CONTROL_HEAD_MISMATCH") continue;
    const phase = phaseOf(await journal.load(operation), spec.id) as JournalPhase;
    await journal.putPhase(operation, { ...phase, state: "refused", code: answer.code });
    return Object.freeze({ state: "refused", chain, code: answer.code });
  }
}

/** A Control Record's ID: SHA-256 of its exact bytes (W §13). */
const validateRecordId = (bytes: Uint8Array): ControlRecordId => controlRecordId(sha256(bytes));

function ownRecordOn(chain: LinearChain, sent: ReadonlySet<string>): string | undefined {
  for (const r of chain.records) {
    const id = toHex(r.signed.id);
    if (sent.has(id)) return id;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// DEKs

/** The DEKs this client holds for `chain`'s epochs, each checked against its commitment. */
export async function heldDeks(
  secrets: SecretStore,
  chain: LinearChain,
): Promise<Map<string, ResourceDEK>> {
  const R = chain.state.resourceId;
  const out = new Map<string, ResourceDEK>();
  for (const e of chain.state.epochs.values()) {
    const bytes = await secrets.get(dekSecretRef(R, e.epoch));
    if (bytes === undefined) continue;
    try {
      const dek = importResourceDEK(bytes);
      if (bytesEqual(dekCommitment(R, e.epoch, dek), e.dekCommitment))
        out.set(String(e.epoch), dek);
    } finally {
      bytes.fill(0);
    }
  }
  return out;
}

/** Stores the DEK of `epoch` (secret first) and links the epoch rows to it (LFCP-034). */
export async function storeDek(
  storage: IdentityStorage,
  secrets: SecretStore,
  chain: LinearChain,
  epoch: DataEpoch,
  dek: ResourceDEK,
): Promise<void> {
  const e = chain.state.epochs.get(String(epoch));
  if (
    e !== undefined &&
    !bytesEqual(dekCommitment(chain.state.resourceId, epoch, dek), e.dekCommitment)
  )
    throw new LfcpError(
      "DEK_COMMITMENT_MISMATCH",
      `the DEK is not the one committed for epoch ${epoch}`,
    );
  const bytes = exportSecretKeyBytes(dek);
  try {
    await secrets.put(dekSecretRef(chain.state.resourceId, epoch), bytes);
  } finally {
    bytes.fill(0);
  }
  await adoptStoredDeks(storage, secrets, chain);
}

/**
 * KEY_PACKAGE_GET for `recipient` over every epoch of `chain` (§52: at most
 * 256 per request, the channel splits), opening and storing each DEK.
 */
export async function fetchDeks(
  storage: IdentityStorage,
  secrets: SecretStore,
  channel: IdentityChannel,
  chain: LinearChain,
  recipient: Installation,
): Promise<Map<string, ResourceDEK>> {
  const R = chain.state.resourceId;
  const out = await heldDeks(secrets, chain);
  const missing = [...chain.state.epochs.values()]
    .map((e) => e.epoch)
    .filter((e) => !out.has(String(e)));
  if (missing.length === 0) return out;
  for (const bytes of await channel.keyPackages(
    R,
    recipient.signer.descriptor.principalId,
    missing,
  )) {
    const r = await receiveKeyPackage(chain, bytes, {
      descriptor: recipient.signer.descriptor,
      agreement: recipient.agreement,
    });
    if (r.kind !== "opened" || out.has(String(r.epoch))) continue;
    await storeDek(storage, secrets, chain, r.epoch, r.dek);
    out.set(String(r.epoch), r.dek);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Readers and key delivery

/** Every Principal with `holds(P, 1)` at the head (W §19, §25.2): the reader set, by ID. */
export function readersAt(state: LinearChain["state"]): readonly PrincipalDescriptor[] {
  const all = new Map<string, PrincipalDescriptor>([
    [toHex(state.owner.principalId), state.owner],
    ...[...state.principals.entries()],
  ]);
  return Object.freeze(
    [...all.entries()]
      .filter(([, d]) => hasAbility(state, d.principalId, ABILITY.DATA_READ))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([, d]) => d),
  );
}

export interface KeyDelivery {
  /** Packages sealed and acknowledged now, as (epoch, recipient hex). */
  readonly sent: readonly { readonly epoch: DataEpoch; readonly recipient: string }[];
  /** Already in the ledger (§9.2 Package: complete). */
  readonly complete: number;
  /** Recipients that are not readers at the head, or packages the coordinator refused. */
  readonly skipped: readonly { readonly recipient: string; readonly reason: string }[];
}

/**
 * Seals every DEK of `deks` to each recipient at the chain's head and
 * records each acknowledged package (§9.5). A package the ledger records is
 * `complete` unless `resend` lists its epoch for that recipient (a
 * `missing_keys` hint, §7.1 step 3); a recipient that is no longer a
 * reader, or a package that would not be authorized, is skipped (§9.2).
 */
export async function deliverKeys(options: {
  readonly channel: IdentityChannel;
  readonly ledger: PackageLedger;
  readonly chain: LinearChain;
  readonly sender: Signer;
  readonly recipients: readonly PrincipalDescriptor[];
  readonly deks: ReadonlyMap<string, ResourceDEK>;
  readonly resend?: ReadonlyMap<string, ReadonlySet<string>>;
}): Promise<KeyDelivery> {
  const { chain, sender, ledger } = options;
  const R = chain.state.resourceId;
  const sent: { epoch: DataEpoch; recipient: string }[] = [];
  const skipped: { recipient: string; reason: string }[] = [];
  let complete = 0;
  const epochs = [...options.deks.keys()].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
  for (const recipient of options.recipients) {
    const rid = recipient.principalId;
    const hex = toHex(rid);
    if (bytesEqual(rid, sender.descriptor.principalId)) continue;
    if (!hasAbility(chain.state, rid, ABILITY.DATA_READ)) {
      skipped.push({ recipient: hex, reason: "not a reader at the head" });
      continue;
    }
    for (const e of epochs) {
      const epoch = dataEpoch(BigInt(e));
      if ((await ledger.has(R, epoch, rid)) && !(options.resend?.get(hex)?.has(e) ?? false)) {
        complete++;
        continue;
      }
      const sealed = await sealKeyPackage({
        resourceId: R,
        epoch,
        controlHead: chain.state.head,
        recipient,
        dek: options.deks.get(e) as ResourceDEK,
        signer: sender,
      });
      const check = verifyKeyPackage(chain, parseKeyPackage(sealed.bytes));
      if (check.kind !== "authorized") {
        skipped.push({ recipient: hex, reason: check.message });
        break;
      }
      const answer = await options.channel.putKeyPackage(R, sealed.bytes);
      if (answer.kind !== "ack") {
        skipped.push({ recipient: hex, reason: answer.code });
        continue;
      }
      await ledger.record({ resource: R, epoch, recipient: rid, packageId: sealed.packageId });
      sent.push({ epoch, recipient: hex });
    }
  }
  return Object.freeze({ sent: Object.freeze(sent), complete, skipped: Object.freeze(skipped) });
}

// ---------------------------------------------------------------------------
// The Identity Resource's document

/**
 * Fetches every Data Unit of the Identity Resource that the coordinator
 * advertises and applies the readable ones to `doc` in actor-sequence
 * order, each with its writer class at its control_ref (§2.3). Returns the
 * highest accepted sequence per actor (hex).
 */
export async function loadIdentityDocument(options: {
  readonly channel: IdentityChannel;
  readonly chain: LinearChain;
  readonly deks: ReadonlyMap<string, ResourceDEK>;
  readonly doc: IdentityDocumentPort;
}): Promise<Map<string, { seq: bigint; unitId: Uint8Array }>> {
  const { chain, doc } = options;
  const R = chain.state.resourceId;
  const root =
    chain.records[0]?.body.type === "GENESIS"
      ? chain.records[0].body.owner.principalId
      : chain.state.owner.principalId;
  const opened = await options.channel.open(R);
  if (opened.kind === "nack")
    throw new IdentityUnavailable(`RESOURCE_OPEN was refused: ${opened.code}`);
  const ranges = opened.haves.flatMap((h) => {
    const out = h.contiguous > 0n ? [{ actor: h.principalId, start: 1n, end: h.contiguous }] : [];
    for (const [start, end] of h.ranges ?? []) out.push({ actor: h.principalId, start, end });
    return out;
  });
  const units = withoutEquivocations(
    (await options.channel.dataUnits(R, ranges)).map((bytes) => ({
      bytes,
      parsed: parseDataUnit(bytes),
    })),
  ).sort((a, b) => {
    const x = toHex(a.parsed.payload.actor);
    const y = toHex(b.parsed.payload.actor);
    if (x !== y) return x < y ? -1 : 1;
    return a.parsed.payload.actorSeq < b.parsed.payload.actorSeq ? -1 : 1;
  });
  const seen = new InMemorySeenUnits();
  const latest = new Map<string, { seq: bigint; unitId: Uint8Array }>();
  for (const { bytes, parsed } of units) {
    const r = await receiveDataUnit(chain, bytes, {
      seen,
      dek: (epoch) => options.deks.get(String(epoch)),
      profile: identityPlaintextCodec,
    });
    if (r.kind !== "accepted") continue;
    const at = chain.stateAt(parsed.payload.controlHead) ?? chain.state;
    const author: IdentityAuthor = {
      signer: r.actor,
      actorSeq: r.seq,
      writerClass: identityWriterClass(at, root, r.actor),
    };
    doc.receive(r.value, author);
    latest.set(toHex(r.actor), { seq: r.seq, unitId: r.unitId });
  }
  return latest;
}

/**
 * W §26.2: two different units at one (actor, sequence) are equivocation,
 * and both are excluded (their dependants then wait for a dependency that
 * never comes: the actor's later units for its hash chain, other changes
 * for the document's). Deciding before anything is applied keeps the
 * result independent of the delivery order.
 */
export function withoutEquivocations<
  T extends { readonly bytes: Uint8Array; readonly parsed: { readonly payload: DataUnitPayload } },
>(units: readonly T[]): T[] {
  const key = (u: T) => `${toHex(u.parsed.payload.actor)}:${u.parsed.payload.actorSeq}`;
  const ids = new Map<string, Set<string>>();
  for (const u of units) {
    const set = ids.get(key(u)) ?? new Set<string>();
    set.add(toHex(sha256(u.bytes)));
    ids.set(key(u), set);
  }
  return units.filter((u) => (ids.get(key(u))?.size ?? 0) <= 1);
}

/**
 * Sends one Data Unit durably (§9.1): its exact bytes are persisted before
 * they are sent and re-sent as they are after a restart, so an actor
 * sequence is never used twice (W §26.2). A coordinator answers a unit it
 * already holds with the same ACK.
 */
export async function runUnitPhase(
  channel: IdentityChannel,
  journal: OperationJournal,
  operation: string,
  spec: {
    readonly id: string;
    readonly resource: ResourceId;
    readonly build: () => Promise<Uint8Array>;
  },
): Promise<{ readonly state: "committed-own" | "refused"; readonly code?: string }> {
  const before = phaseOf(await journal.load(operation), spec.id);
  if (before?.state === "committed-own") return { state: "committed-own" };
  let bytes: Uint8Array;
  if (before?.bytes !== undefined) bytes = fromHex(before.bytes);
  else {
    bytes = await spec.build();
    await journal.putPhase(operation, {
      id: spec.id,
      kind: "unit",
      resource: toHex(spec.resource),
      state: "pending",
      bytes: toHex(bytes),
    });
  }
  const answer = await channel.putDataUnit(spec.resource, bytes);
  const phase = phaseOf(await journal.load(operation), spec.id) as JournalPhase;
  if (answer.kind === "ack") {
    await journal.putPhase(operation, { ...phase, state: "committed-own" });
    return { state: "committed-own" };
  }
  await journal.putPhase(operation, { ...phase, state: "refused", code: answer.code });
  return { state: "refused", code: answer.code };
}
