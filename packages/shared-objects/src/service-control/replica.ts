import * as A from "@automerge/automerge";
import {
  bytesEqual,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import { checkChangeActor } from "../admission/actor.js";
import {
  type CheckedChange,
  checkChange,
  checkSaveHeader,
  frameChange,
  frameSnapshot,
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
import { admitBatch, type DocumentSequences } from "../admission/sequence.js";
import { isWasmTrap } from "../replica.js";
import {
  checkServiceControlUnit,
  refuseServiceControl,
  ServiceControlAdmission,
  type ServiceControlAdmissionDiagnostic,
  ServiceControlAdmissionError,
  type ServiceControlOptions,
  type ServiceControlWriter,
  type ServiceControlWriterClass,
} from "./admission.js";
import { isObject, ScReader } from "./reader.js";
import { type ServiceControlValidation, validateServiceControl } from "./schema.js";
import {
  deriveServiceControlActorId,
  SERVICE_CONTROL_PROFILE_ID,
  type ServiceControlContainer,
} from "./values.js";
import { applyServiceControlIntent, type ServiceControlIntent } from "./write.js";

/** Wire authorization, decryption and the signer's class at control_ref happen before this boundary. */
export interface ServiceControlUnit extends ServiceControlWriter {
  readonly bytes: Uint8Array;
}

interface CheckedUnit {
  readonly unit: ServiceControlUnit;
  readonly change: CheckedChange;
}

export interface ServiceControlRefusal {
  readonly hash: string | undefined;
  readonly diagnostic: string;
  readonly code: string;
  readonly held: boolean;
  readonly message: string;
}

export interface ServiceControlReceiveResult {
  readonly admitted: readonly string[];
  readonly duplicates: readonly string[];
  readonly waiting: readonly string[];
  readonly refused: readonly ServiceControlRefusal[];
}

const refusal = (
  hash: string | undefined,
  error: unknown,
  held = false,
): ServiceControlRefusal => ({
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

const copyOptions = (o: ServiceControlOptions): ServiceControlOptions => ({
  resource: o.resource.slice() as ResourceId,
  root: o.root.slice() as PrincipalId,
  genesisSigner: o.genesisSigner.slice() as PrincipalId,
});

/**
 * The control Resource C (SERVICE-CONTROL-PROFILE-01): causal admission of
 * every change (§4) in both delivery orders, missing dependencies and held
 * units retained, and the state readers see (§5). Nothing here confers
 * authority: the classes of §2.3 only restrict who changes what.
 */
export class ServiceControlReplica {
  readonly #admission: ServiceControlAdmission;
  readonly #options: ServiceControlOptions;
  readonly #accepted = new Map<string, ServiceControlUnit>();
  readonly #classes = new Map<string, ServiceControlWriterClass>();
  readonly #waiting = new Map<string, CheckedUnit>();
  readonly #sequences = new Map<string, number>();
  readonly #references = new ReferenceHistory();

  get #doc(): A.Doc<unknown> {
    return this.#admission.document;
  }

  private constructor(options: ServiceControlOptions) {
    this.#options = copyOptions(options);
    // Validate raw ID lengths.
    deriveServiceControlActorId(options.resource, options.root);
    deriveServiceControlActorId(options.resource, options.genesisSigner);
    this.#admission = new ServiceControlAdmission(this.#options);
  }

  #history(): DocumentSequences {
    return {
      hasChange: (hash) => this.#accepted.has(hash),
      latestSeq: (actor) => this.#sequences.get(actor) ?? 0,
      references: this.#references,
    };
  }

  static empty(options: ServiceControlOptions): ServiceControlReplica {
    return new ServiceControlReplica(options);
  }

  static fromChanges(
    units: readonly ServiceControlUnit[],
    options: ServiceControlOptions,
  ): { readonly replica: ServiceControlReplica; readonly result: ServiceControlReceiveResult } {
    const replica = ServiceControlReplica.empty(options);
    return { replica, result: replica.receiveChanges(units) };
  }

  /**
   * §2.2, SOP §13: a Snapshot is replayed against the verified units that
   * carry EVERY change, so the writer classes of the history are checked
   * again without trusting the Snapshot's author. Callers fetch and decrypt
   * missing units before retrying.
   */
  static fromSave(
    save: Uint8Array,
    options: ServiceControlOptions,
    verifiedUnits: readonly ServiceControlUnit[],
    limits: SnapshotLimits = SNAPSHOT_LIMITS_FLOOR,
  ): ServiceControlReplica {
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
      refuseServiceControl("INVALID_AUTOMERGE_BYTES", `invalid snapshot: ${String(e)}`);
    }
    const byHash = new Map(verifiedUnits.map((unit) => [checkChange(unit.bytes).hash, unit]));
    const checked = changes.map(checkChange);
    if (checked.filter((c) => c.deps.length === 0).length !== 1)
      refuseServiceControl("INVALID_ROOT", "a snapshot contains one initial change");
    const units = checked.map((change) => {
      const unit = byHash.get(change.hash);
      if (unit === undefined || !bytesEqual(unit.bytes, change.bytes))
        throw new LfcpError(
          "MISSING_DEPENDENCY",
          `snapshot change ${change.hash} needs its verified carrying unit`,
        );
      return unit;
    });
    const { replica, result } = ServiceControlReplica.fromChanges(units, options);
    if (result.refused.length > 0 || result.waiting.length > 0) {
      const error = result.refused[0];
      throw Object.assign(
        new LfcpError("PROFILE_INVALID", error?.message ?? "snapshot has missing changes"),
        { diagnostic: error?.diagnostic ?? "INVALID_AUTOMERGE_BYTES" },
      );
    }
    return replica;
  }

  static fromSnapshot(
    plaintext: Uint8Array,
    options: ServiceControlOptions,
    verifiedUnits: readonly ServiceControlUnit[],
    limits: SnapshotLimits = SNAPSHOT_LIMITS_FLOOR,
  ): ServiceControlReplica {
    return ServiceControlReplica.fromSave(
      unframeSnapshot(plaintext),
      options,
      verifiedUnits,
      limits,
    );
  }

  receive(plaintext: Uint8Array, writer: ServiceControlWriter): ServiceControlReceiveResult {
    return this.receiveChanges([{ ...writer, bytes: unframeChange(plaintext).bytes }]);
  }

  receiveChanges(units: readonly ServiceControlUnit[]): ServiceControlReceiveResult {
    const refused: ServiceControlRefusal[] = [];
    const pending = new Map(this.#waiting);
    for (const unit of units) {
      let change: CheckedChange | undefined;
      try {
        change = checkChange(unit.bytes);
        checkServiceControlUnit(change, unit, this.#options);
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
    const unitOf = (c: CheckedChange) => (pending.get(c.hash) as CheckedUnit).unit;
    const result = admitBatch(
      [...pending.values()].map((p) => p.change),
      this.#history(),
      (c) => {
        this.#classes.set(c.hash, this.#admission.accept(c, unitOf(c)));
      },
    );
    for (const r of result.refused) if (isWasmTrap(r.error)) throw r.error;
    this.#waiting.clear();
    for (const c of result.admitted) {
      this.#accepted.set(c.hash, unitOf(c));
      this.#sequences.set(c.actor, c.seq);
    }
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
    readonly replica: ServiceControlReplica;
    readonly result: ServiceControlReceiveResult;
  } {
    const removed = new Set(exclude);
    return ServiceControlReplica.fromChanges(
      [...this.#accepted, ...[...this.#waiting].map(([hash, p]) => [hash, p.unit] as const)]
        .filter(([hash]) => !removed.has(hash))
        .map(([, unit]) => unit),
      this.#options,
    );
  }

  /**
   * The writer's own change (§3): `intents` in one change on the local
   * heads, admitted here exactly as a received change is (§4, with the
   * class `writer` has at the control_ref of the unit that will carry it).
   * A change admission refuses throws ServiceControlAdmissionError with its
   * diagnostic, LIMIT_EXCEEDED for an entry over its size, and leaves the
   * replica as it was: the client does not send it ("Couldn't send", §4,
   * §11). Null when the intents change nothing (every value written is
   * the current one). The LFCP actor sequence of `writer` matters only to
   * the initial change (SC0: unit 1).
   */
  write(
    writer: ServiceControlWriter,
    intents: readonly ServiceControlIntent[],
  ): CheckedChange | null {
    if (intents.length === 0) throw new LfcpError("PROFILE_INVALID", "no intent to write");
    const actor = toHex(deriveServiceControlActorId(this.#options.resource, writer.signer));
    const fork = A.clone(this.#doc, { actor });
    const before = A.getHeads(fork).sort().join();
    let bytes: Uint8Array | undefined;
    try {
      const doc = A.change(fork, { time: 0 }, (d) => {
        for (const i of intents) applyServiceControlIntent(d as Record<string, unknown>, i);
      });
      // Values equal to the current ones make no change (getLastLocalChange would
      // then return this actor's previous change).
      if (A.getHeads(doc).sort().join() !== before) bytes = A.getLastLocalChange(doc) ?? undefined;
    } finally {
      A.free(fork);
    }
    if (bytes === undefined) return null;
    const change = checkChange(bytes);
    const r = this.receiveChanges([{ ...writer, bytes }]);
    if (r.admitted.includes(change.hash)) return checkChange(bytes);
    const refused = r.refused.find((x) => x.hash === change.hash);
    if (refused !== undefined && !refused.held)
      throw new ServiceControlAdmissionError(
        refused.diagnostic as ServiceControlAdmissionDiagnostic,
        refused.message,
      );
    this.#waiting.delete(change.hash);
    throw new LfcpError(
      "PROFILE_INVALID",
      refused?.message ?? "the change was not admitted on the local heads",
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

  /** §5: the state readers see (now, or at `heads`); invalid entries are left out. */
  validate(heads?: readonly string[]): ServiceControlValidation {
    return validateServiceControl(this.#doc, toBase64url(this.#options.resource), heads);
  }

  /**
   * §2.4: the author of an admitted change is its unit's signer, with the
   * class admission judged it by; never a field of the document. The
   * service checks this before it executes a request (§10).
   */
  authorOf(
    hash: string,
  ): { readonly signer: PrincipalId; readonly writerClass: ServiceControlWriterClass } | undefined {
    const unit = this.#accepted.get(hash);
    const writerClass = this.#classes.get(hash);
    if (unit === undefined || writerClass === undefined) return undefined;
    return Object.freeze({ signer: unit.signer.slice() as PrincipalId, writerClass });
  }

  /**
   * §2.4 for an entry: the admitted changes that created the value
   * `container[key]` holds now (each value of a conflict), with the signer
   * of the unit that carried each and the class admission judged it by. An
   * earlier value since deleted is not its provenance. This is what a client
   * checks before it trusts an entry: `pairing[rid]` admitted from `service`
   * (IDENTITY-PROFILE-01 §5.3 step 4), `requests[rid]` written by itself, an
   * approval created by `root` or `personal` (§7.2).
   */
  creatorsOf(
    container: ServiceControlContainer,
    key: string,
  ): readonly {
    readonly hash: string;
    readonly signer: PrincipalId;
    readonly writerClass: ServiceControlWriterClass;
  }[] {
    const reader = new ScReader(A.getBackend(this.#doc));
    const map = reader.map("_root", container);
    if (map === undefined) return Object.freeze([]);
    // Each value is named by the op that made it, `<counter>@<actor>`.
    const made = reader
      .all(map, key)
      .filter(isObject)
      .map((v) => {
        const [counter, actor] = String(v[1]).split("@");
        return { counter: Number(counter), actor };
      });
    const out: { hash: string; signer: PrincipalId; writerClass: ServiceControlWriterClass }[] = [];
    if (made.length === 0) return Object.freeze(out);
    for (const [hash, unit] of this.#accepted) {
      const change = A.decodeChange(unit.bytes);
      const end = change.startOp + change.ops.length;
      const writerClass = this.#classes.get(hash);
      if (writerClass === undefined) continue;
      if (
        made.some((m) => m.actor === change.actor && m.counter >= change.startOp && m.counter < end)
      )
        out.push({ hash, signer: unit.signer.slice() as PrincipalId, writerClass });
    }
    return Object.freeze(out.map((o) => Object.freeze(o)));
  }

  /**
   * Every value held at `path` (container, key, field…), concurrent values
   * included (SOP §45), as plain JavaScript: what §5 rule 3 reads before it
   * picks one, e.g. two equal maps of one approval or both question markers.
   * Each step but the last follows the engine's projection.
   */
  valuesAt(path: readonly string[]): readonly unknown[] {
    const reader = new ScReader(A.getBackend(this.#doc));
    let obj = "_root";
    for (const key of path.slice(0, -1)) {
      const next = reader.map(obj, key);
      if (next === undefined) return Object.freeze([]);
      obj = next;
    }
    const last = path[path.length - 1];
    if (last === undefined) return Object.freeze([]);
    return Object.freeze(reader.all(obj, last).map((v) => reader.plain(v)));
  }

  /** §2.3: the class a writer would have for a change made on `heads` (the local heads by default). */
  writerClassAt(
    writer: ServiceControlWriter,
    heads: readonly string[] = this.heads(),
  ): ServiceControlWriterClass {
    return this.#admission.writerClassAt(heads, writer);
  }
}

export const serviceControlCodec = Object.freeze({
  dataProfile: SERVICE_CONTROL_PROFILE_ID,
  encode: (change: CheckedChange): Uint8Array => frameChange(change.bytes),
  decode: unframeChange,
});

/**
 * The codec of one unit of C, bound to its Resource and signer (§2: a
 * change in another actor's sequence is CHANGE_ACTOR_MISMATCH). The class
 * rules need C's Control state at control_ref and the document, and stay
 * with ServiceControlReplica.receive.
 */
export function serviceControlCodecFor(unit: {
  readonly resourceId: ResourceId;
  readonly actor: PrincipalId;
}) {
  const actor = toHex(deriveServiceControlActorId(unit.resourceId, unit.actor));
  const bound = (change: CheckedChange): CheckedChange => checkChangeActor(change, actor);
  return Object.freeze({
    dataProfile: SERVICE_CONTROL_PROFILE_ID,
    encode: (change: CheckedChange): Uint8Array => frameChange(bound(change).bytes),
    decode: (plaintext: Uint8Array): CheckedChange => bound(unframeChange(plaintext)),
  });
}

/** The per-unit check of C without a replica (structurally the client's UnitProfile). */
export const serviceControlUnitProfile = Object.freeze({
  dataProfile: SERVICE_CONTROL_PROFILE_ID,
  codecFor: serviceControlCodecFor,
});

export const serviceControlSnapshotCodec = Object.freeze({
  dataProfile: SERVICE_CONTROL_PROFILE_ID,
  encode: frameSnapshot,
  decode: unframeSnapshot,
});
