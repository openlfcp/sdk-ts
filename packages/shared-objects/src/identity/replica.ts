import * as A from "@automerge/automerge";
import {
  bytesEqual,
  dataEpoch,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { checkChangeActor } from "../admission/actor.js";
import {
  type CheckedChange,
  checkChange,
  checkSaveHeader,
  frameChange,
  frameSnapshot,
  parsedOf,
  refusedChangeHash,
  unframeChange,
  unframeSnapshot,
} from "../admission/framing.js";
import {
  checkSnapshotExpansion,
  SNAPSHOT_LIMITS_FLOOR,
  type SnapshotLimits,
} from "../admission/limits.js";
import { ReferenceHistory } from "../admission/references.js";
import { admitBatch, admitChange, type DocumentSequences } from "../admission/sequence.js";
import { isWasmTrap } from "../replica.js";
import { principalRef } from "../values.js";
import { checkIdentityUnit, IdentityAdmission, refuseIdentity } from "./admission.js";
import { type IdentityValidation, validateIdentity } from "./schema.js";
import {
  type DeviceEntry,
  deriveIdentityActorId,
  IDENTITY_PROFILE_ID,
  type IdentityWriter,
  type PairingRequest,
  type RosterEntry,
} from "./values.js";

export interface IdentityOptions {
  readonly resource: ResourceId;
  /** Genesis owner; not the current owner of a transferred resource. */
  readonly root: PrincipalId;
}

/** Wire authorization/decryption and class derivation at control_ref happen before this boundary. */
export interface IdentityUnit extends IdentityWriter {
  readonly bytes: Uint8Array;
}

interface CheckedUnit {
  readonly unit: IdentityUnit;
  readonly change: CheckedChange;
}

export interface IdentityRefusal {
  readonly hash: string | undefined;
  readonly diagnostic: string;
  readonly code: string;
  readonly held: boolean;
  readonly message: string;
}

export interface IdentityReceiveResult {
  readonly admitted: readonly string[];
  readonly duplicates: readonly string[];
  readonly waiting: readonly string[];
  readonly refused: readonly IdentityRefusal[];
}

export type IdentityIntent =
  | { readonly intent: "identity.initialize" }
  | { readonly intent: "roster.put"; readonly key: string; readonly entry: RosterEntry }
  | { readonly intent: "device.put"; readonly key: string; readonly entry: DeviceEntry }
  | { readonly intent: "request.put"; readonly key: string; readonly entry: PairingRequest }
  | { readonly intent: "roster.delete" | "device.delete" | "request.delete"; readonly key: string };

const refusal = (hash: string | undefined, error: unknown, held = false): IdentityRefusal => ({
  hash,
  held,
  code: error instanceof LfcpError ? error.code : "PROFILE_INVALID",
  diagnostic:
    error !== null && typeof error === "object" && "diagnostic" in error
      ? String(error.diagnostic)
      : held
        ? "ACTOR_EQUIVOCATION"
        : "INVALID_AUTOMERGE_BYTES",
  message: error instanceof Error ? error.message : String(error),
});

/** Small identity documents: deterministic replay, causal admission, per-entry readers (§§2–4). */
export class IdentityReplica {
  readonly #admission: IdentityAdmission;
  readonly #options: IdentityOptions;
  readonly #accepted = new Map<string, IdentityUnit>();
  readonly #waiting = new Map<string, CheckedUnit>();
  readonly #sequences = new Map<string, number>();
  readonly #references = new ReferenceHistory();

  get #doc(): A.Doc<Record<string, unknown>> {
    return this.#admission.document as A.Doc<Record<string, unknown>>;
  }

  private constructor(options: IdentityOptions) {
    this.#options = {
      resource: options.resource.slice() as ResourceId,
      root: options.root.slice() as PrincipalId,
    };
    deriveIdentityActorId(options.resource, options.root); // Validate raw ID lengths.
    const initial = A.init();
    this.#admission = new IdentityAdmission(initial, this.#options.root);
    A.free(initial);
  }

  #history(): DocumentSequences {
    return {
      hasChange: (hash) => this.#accepted.has(hash),
      latestSeq: (actor) => this.#sequences.get(actor) ?? 0,
      references: this.#references,
    };
  }

  #record(change: CheckedChange, unit: IdentityUnit): void {
    this.#accepted.set(change.hash, unit);
    this.#sequences.set(change.actor, change.seq);
  }

  static empty(options: IdentityOptions): IdentityReplica {
    return new IdentityReplica(options);
  }

  /** Both plaintext delivery orders are accepted; missing dependencies and held units are retained. */
  static fromChanges(
    units: readonly IdentityUnit[],
    options: IdentityOptions,
  ): {
    readonly replica: IdentityReplica;
    readonly result: IdentityReceiveResult;
  } {
    const replica = IdentityReplica.empty(options);
    return { replica, result: replica.receiveChanges(units) };
  }

  /**
   * §2.2: no snapshot state is usable without the root's verified unit 1.
   * Replays the snapshot against verified carrying units for EVERY change:
   * this also checks historical writer classes and AI4 without trusting a snapshot's author.
   * Callers fetch/decrypt missing units before retrying (KEY_BLOCKED included).
   */
  static fromSave(
    save: Uint8Array,
    options: IdentityOptions,
    verifiedUnits: readonly IdentityUnit[],
    limits: SnapshotLimits = SNAPSHOT_LIMITS_FLOOR,
  ): IdentityReplica {
    checkSaveHeader(save);
    checkSnapshotExpansion(save, limits);
    let changes: Uint8Array[];
    try {
      const loaded = A.load(save);
      try {
        changes = A.getAllChanges(loaded);
      } finally {
        A.free(loaded);
      }
    } catch (e) {
      if (isWasmTrap(e)) throw e;
      refuseIdentity("INVALID_AUTOMERGE_BYTES", `invalid snapshot: ${String(e)}`);
    }
    const checked = changes.map(checkChange);
    const byHash = new Map(verifiedUnits.map((unit) => [checkChange(unit.bytes).hash, unit]));
    const initial = checked.filter((c) => c.deps.length === 0);
    if (initial.length !== 1)
      refuseIdentity("INVALID_ROOT", "snapshot must contain one initial change");
    const first = initial[0] as CheckedChange;
    const proof = byHash.get(first.hash);
    if (proof === undefined || !bytesEqual(proof.bytes, first.bytes))
      refuseIdentity(
        "INVALID_ROOT",
        "fetch and verify the root's unit 1 before using this snapshot",
      );
    checkIdentityUnit(first, proof, options.resource, options.root);
    const units = checked.map((change) => {
      const unit = byHash.get(change.hash);
      if (unit === undefined || !bytesEqual(unit.bytes, change.bytes))
        throw new LfcpError(
          "MISSING_DEPENDENCY",
          `snapshot change ${change.hash} needs its verified carrying unit`,
        );
      return unit;
    });
    const { replica, result } = IdentityReplica.fromChanges(units, options);
    if (result.refused.length > 0 || result.waiting.length > 0) {
      const error = result.refused[0];
      A.free(replica.#doc);
      throw Object.assign(
        new LfcpError("PROFILE_INVALID", error?.message ?? "snapshot has missing changes"),
        {
          diagnostic: error?.diagnostic ?? "INVALID_AUTOMERGE_BYTES",
        },
      );
    }
    return replica;
  }

  static fromSnapshot(
    plaintext: Uint8Array,
    options: IdentityOptions,
    verifiedUnits: readonly IdentityUnit[],
    limits: SnapshotLimits = SNAPSHOT_LIMITS_FLOOR,
  ): IdentityReplica {
    return IdentityReplica.fromSave(unframeSnapshot(plaintext), options, verifiedUnits, limits);
  }

  receive(plaintext: Uint8Array, writer: IdentityWriter): IdentityReceiveResult {
    return this.receiveChanges([{ ...writer, bytes: unframeChange(plaintext).bytes }]);
  }

  receiveChanges(units: readonly IdentityUnit[]): IdentityReceiveResult {
    const refused: IdentityRefusal[] = [];
    const pending = new Map(this.#waiting);
    for (const unit of units) {
      let change: CheckedChange | undefined;
      try {
        change = checkChange(unit.bytes);
        checkIdentityUnit(change, unit, this.#options.resource, this.#options.root);
        if (!pending.has(change.hash))
          pending.set(change.hash, {
            change,
            unit: { ...unit, signer: unit.signer.slice() as PrincipalId, bytes: change.bytes },
          });
      } catch (e) {
        if (isWasmTrap(e)) throw e;
        refused.push(refusal(change?.hash ?? refusedChangeHash(unit.bytes), e));
      }
    }
    const result = admitBatch(
      [...pending.values()].map((p) => p.change),
      this.#history(),
      (c) => this.#admission.accept(c, (pending.get(c.hash) as CheckedUnit).unit),
    );
    for (const refused of result.refused) if (isWasmTrap(refused.error)) throw refused.error;
    this.#waiting.clear();
    for (const c of result.admitted) this.#record(c, (pending.get(c.hash) as CheckedUnit).unit);
    for (const c of result.waiting) this.#waiting.set(c.hash, pending.get(c.hash) as CheckedUnit);
    for (const r of result.refused) {
      refused.push(refusal(r.change.hash, r.error, r.held));
      if (r.held) this.#waiting.set(r.change.hash, pending.get(r.change.hash) as CheckedUnit);
    }
    const hashes = (changes: readonly CheckedChange[]) => Object.freeze(changes.map((c) => c.hash));
    return Object.freeze({
      admitted: hashes(result.admitted),
      duplicates: hashes(result.duplicates),
      waiting: hashes(result.waiting),
      refused: Object.freeze(refused),
    });
  }

  /** SOP §14: excluded units and their dependants disappear; held alternatives are retried. */
  rebuildWithout(exclude: Iterable<string>): {
    readonly replica: IdentityReplica;
    readonly result: IdentityReceiveResult;
  } {
    const removed = new Set(exclude);
    return IdentityReplica.fromChanges(
      [
        ...this.#accepted,
        ...[...this.#waiting].map(([hash, pending]) => [hash, pending.unit] as const),
      ]
        .filter(([hash]) => !removed.has(hash))
        .map(([, unit]) => unit),
      this.#options,
    );
  }

  heads(): string[] {
    return A.getHeads(this.#doc).sort();
  }
  hasChange(hash: string): boolean {
    return this.#accepted.has(hash);
  }
  changes(): Uint8Array[] {
    return A.getAllChanges(this.#doc);
  }
  save(): Uint8Array {
    return A.save(this.#doc);
  }
  snapshot(): Uint8Array {
    return frameSnapshot(this.save());
  }
  validate(): IdentityValidation {
    return validateIdentity(this.#doc, this.#options.root);
  }
  roster(): IdentityValidation["roster"] {
    return this.validate().roster;
  }
  devices(): IdentityValidation["devices"] {
    return this.validate().devices;
  }
  requests(): IdentityValidation["requests"] {
    return this.validate().requests;
  }

  /**
   * The admitted changes that created or wrote into the value `table[key]`
   * holds now (every value of a conflict, nested lists and maps included),
   * in admission (causal) order, each with the signer of the unit that
   * carried it. Changes to an earlier value since deleted or replaced are
   * not its provenance. This is the provenance a
   * managing device checks before it shows a pairing request
   * (IDENTITY-PROFILE-01 §5.3 step 4: written only by the session's
   * pairing device) and the change hashes it journals with an approval.
   */
  origins(
    table: "roster" | "devices" | "requests",
    key: string,
  ): readonly { readonly hash: string; readonly signer: PrincipalId }[] {
    // The values `table[key]` holds now: one, or several under a conflict. Each
    // is named by the op that set it (for a map, its object ID). The history of
    // earlier values deleted or overwritten since is not their provenance.
    const container = (this.#doc as Record<string, unknown>)[table];
    const current = new Set<string>();
    if (container !== null && typeof container === "object" && Object.hasOwn(container, key)) {
      const conflicts = A.getConflicts(container as A.Doc<unknown>, key);
      if (conflicts !== undefined) for (const id of Object.keys(conflicts)) current.add(id);
      else {
        const value = (container as Record<string, unknown>)[key];
        const id = value !== null && typeof value === "object" ? A.getObjectId(value) : null;
        if (id !== null && id !== undefined) current.add(id);
      }
    }
    const entry = new Set<string>(current);
    const out: { hash: string; signer: PrincipalId }[] = [];
    if (current.size === 0) return Object.freeze(out);
    for (const [hash, unit] of this.#accepted) {
      const change = A.decodeChange(unit.bytes);
      let touched = false;
      change.ops.forEach((op, i) => {
        const id = `${change.startOp + i}@${change.actor}`;
        const makes = op.action === "makeMap" || op.action === "makeList";
        if (current.has(id) || entry.has(op.obj)) {
          touched = true;
          if (makes) entry.add(id);
        }
      });
      if (touched) out.push({ hash, signer: unit.signer.slice() as PrincipalId });
    }
    return Object.freeze(out);
  }

  /**
   * One transaction (one change) for the intent, or for several intents in
   * order, e.g. the fill change of IDENTITY-PROFILE-01 §5.1 or the devices
   * entry and the request deletion of §5.3 step 6; scalar strings/uints,
   * unknown fields preserved on updates.
   */
  write(writer: IdentityWriter, intent: IdentityIntent | readonly IdentityIntent[]): CheckedChange {
    const intents: readonly IdentityIntent[] = Array.isArray(intent)
      ? intent
      : [intent as IdentityIntent];
    if (intents.length === 0) throw new LfcpError("PROFILE_INVALID", "no intent to write");
    // AI5 (§3) refuses the change anyway; say why before building it.
    for (const i of intents)
      if (
        i.intent === "device.put" &&
        i.entry.missing_keys !== undefined &&
        i.key !== principalRef(writer.signer)
      )
        refuseIdentity(
          "UNAUTHORIZED_WRITER",
          "a device writes only its own missing_keys hints (§3 AI5)",
        );
    const actor = toHex(deriveIdentityActorId(this.#options.resource, writer.signer));
    const fork = A.clone(this.#doc, { actor });
    let bytes: Uint8Array;
    try {
      const doc = A.change(fork, { time: 0 }, (d) => {
        for (const i of intents) applyIntent(d, i, this.#options.root, A.getBackend(d));
      });
      const last = A.getLastLocalChange(doc);
      if (last === null || last === undefined)
        throw new LfcpError("PROFILE_INVALID", "the intent did not create a change");
      bytes = last;
      const validation = validateIdentity(doc, this.#options.root);
      for (const i of intents) {
        const base = "key" in i ? `/${tableOf(i)}/${i.key}` : "";
        const problem = validation.problems.find(
          (p) =>
            p.diagnostic === "INVALID_ROOT" ||
            p.pointer === base ||
            p.pointer.startsWith(`${base}/`),
        );
        if (problem !== undefined)
          throw Object.assign(new LfcpError("PROFILE_INVALID", problem.message), {
            diagnostic: problem.diagnostic,
          });
      }
    } finally {
      A.free(fork);
    }
    const change = checkChange(bytes);
    // Check only this candidate against the current indexes. Failed local
    // writes never enter the waiting queue or consume an actor sequence.
    checkIdentityUnit(change, writer, this.#options.resource, this.#options.root);
    const decision = admitChange(change, this.#history());
    if (decision.kind === "invalid" || decision.kind === "held") throw decision.error;
    if (decision.kind === "missing")
      throw new LfcpError("MISSING_DEPENDENCY", "local change is not admissible");
    if (decision.kind === "next") {
      this.#admission.accept(change, writer);
      this.#references.add(change.hash, parsedOf(change));
      this.#record(change, {
        ...writer,
        signer: writer.signer.slice() as PrincipalId,
        bytes: change.bytes,
      });
      if (this.#waiting.size > 0) this.receiveChanges([]);
    }
    // Keep the byte log private even if callers mutate the returned buffer.
    return checkChange(bytes);
  }
}

const tableOf = (intent: IdentityIntent): "roster" | "devices" | "requests" =>
  intent.intent.startsWith("roster.")
    ? "roster"
    : intent.intent.startsWith("device.")
      ? "devices"
      : "requests";

function applyIntent(
  d: Record<string, unknown>,
  intent: IdentityIntent,
  root: PrincipalId,
  backend: ReturnType<typeof A.getBackend>,
): void {
  if (intent.intent === "identity.initialize") {
    if (Object.keys(d).length !== 0)
      refuseIdentity("INVALID_ROOT", "identity is already initialized");
    d.profile = new A.ImmutableString(IDENTITY_PROFILE_ID);
    d.identity = { root: new A.ImmutableString(principalRef(root)) };
    for (const key of ["roster", "devices", "requests", "extensions"]) d[key] = {};
    return;
  }
  const map = d[tableOf(intent)] as Record<string, unknown> | undefined;
  if (map === undefined) refuseIdentity("INVALID_ROOT", "initialize the identity first");
  if (!("entry" in intent)) {
    delete map[intent.key];
    return;
  }
  if (!Object.hasOwn(map, intent.key)) map[intent.key] = {};
  const entry = map[intent.key] as Record<string, unknown>;
  for (const [key, value] of Object.entries(intent.entry))
    if (value !== undefined) putValue(entry, key, value, backend);
}

function putValue(
  target: Record<string, unknown> | unknown[],
  key: string | number,
  value: unknown,
  backend: ReturnType<typeof A.getBackend>,
): void {
  const map = target as Record<string, unknown>;
  if (typeof value === "string") map[key] = new A.ImmutableString(value);
  else if (typeof value === "number") map[key] = new A.Uint(value);
  else if (typeof value === "bigint") {
    // Uint's JS wrapper is limited to safe numbers; the backend accepts the full uint64.
    const id = A.getObjectId(target) as string;
    const epoch = dataEpoch(value);
    if (Array.isArray(target) && Number(key) === backend.length(id))
      backend.insert(id, Number(key), epoch, "uint");
    else backend.put(id, key, epoch, "uint");
  } else if (Array.isArray(value)) {
    map[key] = [];
    value.forEach((v, i) => {
      putValue(map[key] as unknown[], i, v, backend);
    });
  } else if (value !== null && typeof value === "object") {
    map[key] = {};
    for (const [k, v] of Object.entries(value))
      putValue(map[key] as Record<string, unknown>, k, v, backend);
  } else map[key] = value;
}

export const identityCodec = Object.freeze({
  dataProfile: IDENTITY_PROFILE_ID,
  encode: (change: CheckedChange): Uint8Array => frameChange(change.bytes),
  decode: unframeChange,
});
/**
 * The codec of one unit of the Identity Profile, bound to its Resource and
 * signer (§3: a change in another actor's sequence is CHANGE_ACTOR_MISMATCH).
 * The writer-class rules (AI0–AI4) need the Control state at the unit's
 * control_ref and stay with the document's admission (IdentityReplica.receive).
 */
export function identityCodecFor(unit: {
  readonly resourceId: ResourceId;
  readonly actor: PrincipalId;
}) {
  const actor = toHex(deriveIdentityActorId(unit.resourceId, unit.actor));
  const bound = (change: CheckedChange): CheckedChange => checkChangeActor(change, actor);
  return Object.freeze({
    dataProfile: IDENTITY_PROFILE_ID,
    encode: (change: CheckedChange): Uint8Array => frameChange(bound(change).bytes),
    decode: (plaintext: Uint8Array): CheckedChange => bound(unframeChange(plaintext)),
  });
}

/**
 * The Identity Profile's per-unit check without a replica (structurally the
 * client's UnitProfile): for the identity flows' rotation frontier
 * (FlowOptions.profiles), so a rotation of the Identity Resource judges its
 * units as recipients do.
 */
export const identityUnitProfile = Object.freeze({
  dataProfile: IDENTITY_PROFILE_ID,
  codecFor: identityCodecFor,
});

export const identitySnapshotCodec = Object.freeze({
  dataProfile: IDENTITY_PROFILE_ID,
  encode: frameSnapshot,
  decode: unframeSnapshot,
});
