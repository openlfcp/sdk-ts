import {
  actorSequence,
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  type DataUnitId,
  dataEpoch,
  fromHex,
  hash32,
  LfcpError,
  type PrincipalId,
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
  decodeControlRecord,
  hasAbility,
  InMemorySeenUnits,
  type Parsed,
  type PrincipalDescriptor,
  parseDataUnit,
  parseKeyPackage,
  receiveDataUnit,
  receiveKeyPackage,
  revocationOf,
  type Signer,
  sealDataUnit,
  sealKeyPackage,
  validateControlChain,
  verifyKeyPackage,
  verifySignedObject,
} from "@openlfcp/wire";
import {
  adoptStoredDeks,
  checkWriteBarrier,
  loadControlChain,
  saveControlChain,
  saveControlConflict,
} from "../storage.js";
import {
  type IdentityAuthor,
  type IdentityDocumentPort,
  type IdentityIntent,
  identityPlaintextCodec,
  identityWriterClass,
} from "./document.js";
import {
  type JournalPhase,
  type OperationJournal,
  type PackageLedger,
  phaseOf,
} from "./journal.js";
import { IDENTITY_EXTENSION, type IdentityChannel, IdentityUnavailable } from "./network.js";
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

/** `a`'s records are the first records of `b` (`b` equals or extends `a`). */
const isPrefixOf = (a: LinearChain, b: LinearChain): boolean =>
  a.records.length <= b.records.length &&
  a.records.every((r, i) => bytesEqual(r.signed.id, b.records[i]?.signed.id ?? new Uint8Array()));

/** How often storeChain re-reads a head another session moved before it gives up. */
const STORE_RETRIES = 4;

/**
 * The stored Control Chain of a Resource diverges from the one this flow
 * validated (another session stored a competing branch): local storage holds
 * a fork (§9.7). An IdentityConflict, so every flow treats it as one; `code`
 * is stable.
 */
export class ControlChainDiverged extends IdentityConflict {
  readonly code = "CONTROL_CHAIN_DIVERGED";
  constructor(resource: ResourceId) {
    super(resource, "the stored Control Chain diverges from the validated one (§9.7)");
    this.name = "ControlChainDiverged";
  }
}

/**
 * Other sessions kept moving the stored head of a Resource while this flow
 * stored its chain: try again later. An IdentityUnavailable (the operation is
 * journaled and resumes); `code` is stable.
 */
export class ControlChainBusy extends IdentityUnavailable {
  readonly code = "CONTROL_HEAD_MISMATCH";
  readonly resource: ResourceId;
  constructor(resource: ResourceId) {
    super("the stored Control Head kept moving while the chain was stored");
    this.name = "ControlChainBusy";
    this.resource = resource;
  }
}

/**
 * Stores `chain` over `previous` with the storage's compare-and-set. Another
 * session of the same Resource (an open sync session, another flow) may have
 * stored first, e.g. the very record this flow just had ACKed (W §47: the
 * coordinator pushes it to every session). On that local refusal the stored
 * chain is read again: one that already contains `chain` is accepted, one
 * that `chain` extends is replaced (compare-and-set on its head, a bounded
 * number of times: ControlChainBusy), and one that diverges is a fork: it is
 * recorded (the conflict marker, as syncChain records one) before
 * ControlChainDiverged is thrown. A chain that does not extend `previous`
 * is stored only where nothing newer is (as before 0.5.2: a refusal leaves
 * it).
 *
 * A fork already recorded for the Resource (§9.7) suspends the flow: the
 * commits here never clear the conflict marker (even one another writer
 * records meanwhile), and a marker found after a commit, or before a
 * stored chain is accepted or replaced, is an IdentityConflict.
 */
async function storeChain(
  storage: IdentityStorage,
  chain: LinearChain,
  previous: LinearChain | undefined,
): Promise<void> {
  const R = chain.state.resourceId;
  // Every return of this function, success or nothing to store, is preceded by this read,
  // after the last awaited read of the chain: a fork recorded until then suspends the flow.
  // The storage ports read head, records and conflict separately (no combined snapshot).
  const forked = async () => {
    if ((await storage.control.conflict(R)) !== undefined)
      throw new IdentityConflict(R, "the Control Chain is forked (§9.7)");
  };
  if (previous !== undefined && bytesEqual(previous.state.head, chain.state.head)) {
    await forked();
    return;
  }
  const prefix = previous !== undefined && isPrefixOf(previous, chain);
  let expected = prefix ? previous.state.head : null;
  for (let attempt = 0; ; attempt++) {
    const r = await saveControlChain(storage, chain, expected, { clearConflict: false });
    if (r.ok) {
      await forked();
      return;
    }
    await forked();
    const stored = await loadControlChain(storage, R);
    // Another session stored this chain, or a later one: nothing to store, unless a fork was
    // recorded while the stored chain was read.
    if (stored?.kind === "linear" && isPrefixOf(chain, stored)) {
      await forked();
      return;
    }
    if (!prefix) {
      await forked();
      return;
    }
    if (stored !== undefined && (stored.kind !== "linear" || !isPrefixOf(stored, chain))) {
      await recordDivergence(storage, R, chain, stored);
      throw new ControlChainDiverged(R);
    }
    if (attempt >= STORE_RETRIES) throw new ControlChainBusy(R);
    // An older state of the same chain: store over it.
    expected = stored === undefined ? null : stored.state.head;
  }
}

/**
 * Records the fork between `chain` and the stored chain as the Resource's
 * conflict marker (§9.7), as syncChain does, so that later calls are
 * suspended too, not only this one.
 */
async function recordDivergence(
  storage: IdentityStorage,
  R: ResourceId,
  chain: LinearChain,
  stored: Exclude<Awaited<ReturnType<typeof loadControlChain>>, undefined>,
): Promise<void> {
  const all = new Map<string, Uint8Array>();
  const storedRecords =
    stored.kind === "linear"
      ? stored.records.map((r) => r.signed.bytes)
      : (await storage.control.records(R)).map((r) => r.bytes);
  for (const b of [...storedRecords, ...chain.records.map((r) => r.signed.bytes)])
    all.set(toHex(sha256(b)), b);
  const both = validateControlChain([...all.values()]);
  if (both.kind === "conflict") await saveControlConflict(storage, R, both);
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
  /**
   * False for a phase whose record depends on more than the head, such as a
   * KEY_EPOCH and its frontier (§9.3): a pending record is rebuilt on every
   * attempt, even on the head it was built on. An accepted one is still
   * recognised by its journaled record ID.
   */
  readonly resend?: boolean;
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
    const journaled =
      spec.resend !== false && before?.bytes !== undefined && before.expectedHead === head;
    const bytes = journaled ? fromHex(before.bytes as string) : await spec.build(chain);
    if (!channel.extensions.includes(IDENTITY_EXTENSION) && isDeviceRecord(bytes)) {
      // W §37: no record of type 9 or 10 to a server whose READY lacks identity-01,
      // journaled bytes included (a resumed operation checks the current READY).
      await journal.putPhase(operation, {
        ...(before ?? {}),
        id: spec.id,
        kind: spec.kind,
        resource: toHex(R),
        state: "refused",
        code: IDENTITY_UNSUPPORTED,
      });
      return Object.freeze({ state: "refused", chain, code: IDENTITY_UNSUPPORTED });
    }
    if (!journaled) {
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

/**
 * The client-local refusal code of a device record or same-root Key Package
 * this client does not send to a server whose READY lacks `identity-01`
 * (LFCP-WIRE-01 §37): the Resource is hosted on a server without identity
 * support (IDENTITY-PROFILE-01 §6). No wire code.
 */
export const IDENTITY_UNSUPPORTED = "IDENTITY_UNSUPPORTED";

/** A DEVICE_GRANT (type 9) or DEVICE_REVOKE (type 10). */
function isDeviceRecord(bytes: Uint8Array): boolean {
  const type = decodeControlRecord(bytes).body.type;
  return type === "DEVICE_GRANT" || type === "DEVICE_REVOKE";
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

/**
 * IDENTITY-PROFILE-01 §7.1 step 1: whether `principal`, a reader of the
 * target state, is a device that the Identity Resource `identity` has
 * revoked, or whose current chain in the target passes through such a
 * device. Until the pair is propagated the target still counts the device
 * as active (an unpropagated pair), but the installations of `identity`'s
 * root treat it as revoked there and seal nothing to it, in a rotation as
 * in step 3.
 */
export function revokedByIdentity(
  identity: LinearChain,
  target: LinearChain["state"],
  principal: PrincipalId,
): boolean {
  const R = genesisOwner(identity);
  const revoked = (d: PrincipalId) => revocationOf(identity.state, R, d) !== undefined;
  if (revoked(principal)) return true;
  const binding = target.devices.get(toHex(principal));
  return binding !== undefined && bytesEqual(binding.root, R) && binding.issuers.some(revoked);
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
  // W §37: without identity-01 the server applies no same-root rule (W §25.2); a sender
  // without key/distribute is authorized only by it, and sends nothing there.
  const identity = options.channel.extensions.includes(IDENTITY_EXTENSION);
  const sameRootOnly =
    !identity && !hasAbility(chain.state, sender.descriptor.principalId, ABILITY.KEY_DISTRIBUTE);
  // The same for a pending package, at its own referenced head: a later key/distribute does
  // not authorize it there (W §25.2), so it is re-sealed at the current head instead.
  const resendable = (bytes: Uint8Array): boolean => {
    const parsed = parseKeyPackage(bytes);
    if (verifyKeyPackage(chain, parsed).kind !== "authorized") return false;
    if (identity) return true;
    const atHead = chain.stateAt(parsed.payload.controlHead);
    return (
      atHead !== undefined && hasAbility(atHead, parsed.payload.sender, ABILITY.KEY_DISTRIBUTE)
    );
  };
  for (const recipient of options.recipients) {
    const rid = recipient.principalId;
    const hex = toHex(rid);
    if (bytesEqual(rid, sender.descriptor.principalId)) continue;
    if (!hasAbility(chain.state, rid, ABILITY.DATA_READ)) {
      skipped.push({ recipient: hex, reason: "not a reader at the head" });
      continue;
    }
    if (sameRootOnly) {
      skipped.push({ recipient: hex, reason: IDENTITY_UNSUPPORTED });
      continue;
    }
    for (const e of epochs) {
      const epoch = dataEpoch(BigInt(e));
      if ((await ledger.has(R, epoch, rid)) && !(options.resend?.get(hex)?.has(e) ?? false)) {
        complete++;
        continue;
      }
      // §9.1: a package sent before is sent again as the same bytes, while it is still authorized.
      let bytes = await ledger.pending(R, epoch, rid);
      if (bytes !== undefined && !resendable(bytes)) bytes = undefined;
      if (bytes === undefined) {
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
        bytes = sealed.bytes;
        await ledger.putPending(R, epoch, rid, bytes);
      }
      const answer = await options.channel.putKeyPackage(R, bytes);
      if (answer.kind !== "ack") {
        skipped.push({ recipient: hex, reason: answer.code });
        continue;
      }
      await ledger.record({
        resource: R,
        epoch,
        recipient: rid,
        packageId: hash32(parseKeyPackage(bytes).signed.id),
      });
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
}): Promise<IdentityDocumentLoad> {
  const { chain, doc } = options;
  const R = chain.state.resourceId;
  const root = genesisOwner(chain);
  const opened = await options.channel.open(R);
  if (opened.kind === "nack")
    throw new IdentityUnavailable(`RESOURCE_OPEN was refused: ${opened.code}`);
  const ranges = opened.haves.flatMap((h) => {
    const out = h.contiguous > 0n ? [{ actor: h.principalId, start: 1n, end: h.contiguous }] : [];
    for (const [start, end] of h.ranges ?? []) out.push({ actor: h.principalId, start, end });
    return out;
  });
  // Units in the order of their Control Heads, then by actor and sequence: a writer
  // synchronises before writing, so a change rarely references a head older than
  // the changes it saw, and changes reach the document after their dependencies
  // (a held change is still admitted later; provenance comes from the port).
  // Both units of an equivocation are excluded first (W §26.2).
  const headSeq = (head: Uint8Array) => chain.stateAt(head)?.seq ?? chain.state.seq + 1n;
  const units = withoutEquivocations(
    chain,
    (await options.channel.dataUnits(R, ranges)).map((bytes) => {
      const parsed = parseDataUnit(bytes);
      return { bytes, parsed, at: headSeq(parsed.payload.controlHead) };
    }),
  ).sort((a, b) => {
    if (a.at !== b.at) return a.at < b.at ? -1 : 1;
    const x = toHex(a.parsed.payload.actor);
    const y = toHex(b.parsed.payload.actor);
    if (x !== y) return x < y ? -1 : 1;
    return a.parsed.payload.actorSeq < b.parsed.payload.actorSeq ? -1 : 1;
  });
  const seen = new InMemorySeenUnits();
  const latest = new Map<string, { seq: bigint; unitId: DataUnitId }>();
  const pending: { plaintext: Uint8Array; author: IdentityAuthor; unitId: DataUnitId }[] = [];
  const apply = (plaintext: Uint8Array, author: IdentityAuthor): boolean =>
    doc.receive(plaintext, author);
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
    if (!apply(r.value, author)) pending.push({ plaintext: r.value, author, unitId: r.unitId });
    latest.set(toHex(r.actor), { seq: r.seq, unitId: r.unitId });
  }
  // Changes of other actors that depend on a change applied later (SOP §14.1).
  for (let progress = true; progress && pending.length > 0; ) {
    progress = false;
    for (let i = 0; i < pending.length; ) {
      const p = pending[i] as (typeof pending)[number];
      if (apply(p.plaintext, p.author)) {
        pending.splice(i, 1);
        progress = true;
      } else i++;
    }
  }
  const unapplied = pending.map((p) =>
    Object.freeze({ actor: p.author.signer, seq: p.author.actorSeq, unitId: p.unitId }),
  );
  return { latest, unapplied: Object.freeze(unapplied) };
}

/** What loadIdentityDocument learned besides the document. */
export interface IdentityDocumentLoad {
  /** Each actor's latest accepted unit (by Principal hex): the next unit's previous (W §26.2). */
  readonly latest: ReadonlyMap<string, { readonly seq: bigint; readonly unitId: DataUnitId }>;
  /**
   * The units the wire accepted whose change the document did not take,
   * after every change it could: refused by its admission (IDENTITY-PROFILE-01
   * §3), or held for a change it never got (SOP §14.1). The port does not
   * tell the two apart. In delivery order; empty when the document holds
   * every unit.
   */
  readonly unapplied: readonly {
    readonly actor: PrincipalId;
    readonly seq: bigint;
    readonly unitId: DataUnitId;
  }[];
}

/** The Genesis owner of a chain: the root of an Identity Resource (§2.3). */
export function genesisOwner(chain: LinearChain): PrincipalId {
  const g = chain.records[0];
  return g?.body.type === "GENESIS" ? g.body.owner.principalId : chain.state.owner.principalId;
}

/** 0.4's flag write on a port without `retirement`: the entry's display fields and the flag. */
function retiredPut(doc: IdentityDocumentPort, key: string): IdentityIntent[] {
  const entry = doc.devices().get(key);
  if (entry === undefined) return [];
  const { missing_keys: _hint, ...display } = entry;
  return [{ intent: "device.put", key, entry: { ...display, revoked: true } }];
}

/**
 * Whether the retired entry `devices[key]` needs its flag (§7.1 step 4):
 * some value of its `revoked` is not `true`, or the field is absent. A port
 * without `retirement` shows one value. False when there is no valid entry.
 */
export function retiredFlagMissing(
  entries: ReadonlyMap<string, { readonly revoked?: boolean }>,
  key: string,
  revokedValues?: (key: string) => readonly unknown[],
): boolean {
  const entry = entries.get(key);
  if (entry === undefined) return false;
  if (revokedValues === undefined) return entry.revoked !== true;
  const values = revokedValues(key);
  return values.length === 0 || values.some((v) => v !== true);
}

/**
 * A new unit of `signer` in the Identity Resource carrying `intents` as
 * one change: the next actor sequence from the storage's reservation
 * (durable, never reused), the current epoch's DEK, the signer's latest
 * accepted unit as previous. The change is applied to `doc`.
 */
export async function sealIdentityUnit(options: {
  readonly storage: IdentityStorage;
  readonly chain: LinearChain;
  readonly deks: ReadonlyMap<string, ResourceDEK>;
  readonly signer: Signer;
  readonly doc: IdentityDocumentPort;
  readonly latest: IdentityDocumentLoad["latest"];
  readonly intents: readonly IdentityIntent[];
  /**
   * Retired entries whose `revoked` flag the change sets (§7.1 step 4,
   * §8.2): field by field when the port has `retirement`, else with
   * `device.put` of the entry's display fields (its `missing_keys` hint is
   * the device's own, §3 AI5).
   */
  readonly retire?: readonly string[];
  /** The sequence to use instead of a reservation (a pairing device shared by installations, §5.3). */
  readonly seq?: bigint;
  /**
   * The signer's own `missing_keys` hint, by ResourceRef (null: remove that
   * Resource), written field by field through the port's `keyHints`
   * capability, alone (no intents, no retirement) (0.5.2, §7.1 step 3, AI5).
   */
  readonly hints?: ReadonlyMap<string, readonly bigint[] | null>;
}): Promise<Uint8Array> {
  const { chain, signer } = options;
  const R = chain.state.resourceId;
  await checkWriteBarrier(options.storage, R);
  const epoch = chain.state.epoch.epoch;
  const dek = options.deks.get(String(epoch));
  if (dek === undefined)
    throw new LfcpError("KEY_PACKAGE_OPEN_FAILED", `the DEK of epoch ${epoch} is not held`);
  const me = signer.descriptor.principalId;
  const previous = options.latest.get(toHex(me));
  let seq = options.seq;
  if (seq === undefined) {
    seq = await options.storage.actorSequences.reserveNext(R, me);
    while (previous !== undefined && seq <= previous.seq)
      seq = await options.storage.actorSequences.reserveNext(R, me);
  }
  const author = {
    signer: me,
    actorSeq: seq,
    writerClass: identityWriterClass(chain.state, genesisOwner(chain), me),
  };
  const retire = options.retire ?? [];
  const { doc } = options;
  const hints = options.hints;
  if (hints !== undefined && doc.keyHints === undefined)
    throw new LfcpError("PROFILE_UNSUPPORTED", "the document port cannot write key hints");
  const plaintext =
    hints !== undefined && doc.keyHints !== undefined
      ? doc.keyHints.write(author, hints)
      : retire.length === 0
        ? doc.write(author, options.intents)
        : doc.retirement !== undefined
          ? doc.retirement.write(author, options.intents, retire)
          : doc.write(author, [
              ...options.intents,
              ...retire.flatMap((key) => retiredPut(doc, key)),
            ]);
  return sealDataUnit(
    {
      resourceId: R,
      dataEpoch: epoch,
      actorSeq: actorSequence(seq),
      prevDataUnitId: previous?.unitId ?? null,
      controlHead: chain.state.head,
    },
    plaintext,
    dek,
    signer,
  ).bytes;
}

/**
 * W §26.2: two different units at one (resource, actor, sequence), each
 * with a valid signature by its actor, are equivocation, and both are
 * excluded (their dependants then wait for a dependency that never comes:
 * the actor's later units for its hash chain, other changes for the
 * document's). Only units of `chain`'s Resource whose signature verifies
 * take part: an unsigned or forged copy proves nothing and is dropped
 * without excluding the signed unit. Authorization and decryption are not
 * conditions here. Deciding before anything is applied keeps the result
 * independent of the delivery order.
 */
export function withoutEquivocations<
  T extends {
    readonly bytes: Uint8Array;
    readonly parsed: Parsed<DataUnitPayload>;
  },
>(chain: LinearChain, units: readonly T[]): T[] {
  const signed = units.filter((u) => {
    const p = u.parsed.payload;
    if (!bytesEqual(p.resourceId, chain.state.resourceId)) return false;
    const actor = chain.state.principals.get(toHex(p.actor));
    return actor !== undefined && verifySignedObject(u.parsed.signed, actor).valid;
  });
  const key = (u: T) => `${toHex(u.parsed.payload.actor)}:${u.parsed.payload.actorSeq}`;
  const ids = new Map<string, Set<string>>();
  for (const u of signed) {
    const set = ids.get(key(u)) ?? new Set<string>();
    set.add(toHex(sha256(u.bytes)));
    ids.set(key(u), set);
  }
  return signed.filter((u) => (ids.get(key(u))?.size ?? 0) <= 1);
}

/**
 * What became of a flow's unit of display data in the Identity Resource:
 * none needed, written (`committed-own`), found already written by another
 * writer when the unit was built (`complete`, nothing sent), refused by the
 * coordinator with `code`, or not sent because the coordinator was
 * unreachable. `refused` and `unreachable` leave the flow's operation open.
 */
export interface DocumentWrite {
  readonly state: "none" | "committed-own" | "complete" | "refused" | "unreachable";
  readonly code?: string;
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
    /**
     * The unit to send, built on the current state; null when that state
     * already holds the phase's effect, written by another hand: the phase is
     * then `complete` and nothing is sent.
     */
    readonly build: () => Promise<Uint8Array | null>;
    /**
     * Refusals after which the phase's intent is written again as a new unit
     * on the current state, e.g. STALE_DATA_EPOCH after a rotation (W §19.1);
     * the refused bytes are kept in the phase as stale, never sent again.
     */
    readonly rebuildOn?: readonly string[];
    /**
     * A phase an earlier run left refused, whatever the code, is written
     * again once as a new unit on the current state: how a flow that
     * reported the refusal resumes the write (the refused bytes are kept as
     * stale, never sent again).
     */
    readonly rebuildRefused?: boolean;
  },
): Promise<{ readonly state: "committed-own" | "complete" | "refused"; readonly code?: string }> {
  for (let attempt = 0; ; attempt++) {
    const before = phaseOf(await journal.load(operation), spec.id);
    if (before?.state === "committed-own") return { state: "committed-own" };
    if (before?.state === "complete") return { state: "complete" };
    const retry =
      before?.state === "refused" &&
      before.code !== undefined &&
      ((spec.rebuildOn ?? []).includes(before.code) ||
        (attempt === 0 && spec.rebuildRefused === true));
    if (retry && attempt > 3) return { state: "refused", code: before?.code ?? "refused" };
    let bytes: Uint8Array;
    if (before?.bytes !== undefined && !retry) bytes = fromHex(before.bytes);
    else {
      const built = await spec.build();
      const facts =
        before?.bytes !== undefined && retry
          ? { facts: { ...before.facts, [`stale${attempt}`]: before.bytes } }
          : before?.facts === undefined
            ? {}
            : { facts: before.facts };
      if (built === null) {
        // Another hand wrote the effect on the state the unit would build on (§9.2).
        await journal.putPhase(operation, {
          id: spec.id,
          kind: "unit",
          resource: toHex(spec.resource),
          state: "complete",
          ...facts,
        });
        return { state: "complete" };
      }
      bytes = built;
      await journal.putPhase(operation, {
        id: spec.id,
        kind: "unit",
        resource: toHex(spec.resource),
        state: "pending",
        bytes: toHex(bytes),
        ...facts,
      });
    }
    const answer = await channel.putDataUnit(spec.resource, bytes);
    const phase = phaseOf(await journal.load(operation), spec.id) as JournalPhase;
    if (answer.kind === "ack") {
      await journal.putPhase(operation, { ...phase, state: "committed-own" });
      return { state: "committed-own" };
    }
    await journal.putPhase(operation, { ...phase, state: "refused", code: answer.code });
    if (!(spec.rebuildOn ?? []).includes(answer.code))
      return { state: "refused", code: answer.code };
  }
}
