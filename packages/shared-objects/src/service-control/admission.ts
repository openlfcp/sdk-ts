import * as A from "@automerge/automerge";
import {
  actorSequence,
  bytesEqual,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import { checkChangeActor } from "../admission/actor.js";
import { type CheckedChange, decodedOf, parsedOf } from "../admission/framing.js";
import { MAX_DOCUMENT_DEPTH } from "../admission/limits.js";
import { ReferenceHistory } from "../admission/references.js";
import { isWasmTrap } from "../replica.js";
import { principalRef } from "../values.js";
import { isMapValue, isStr, ScReader, type ScValue } from "./reader.js";
import {
  entryDiagnostics,
  eventIsFinal,
  eventStateOf,
  limitOf,
  readApproval,
  SERVICE_CONTROL_DIAGNOSTIC_ORDER,
} from "./schema.js";
import {
  deriveServiceControlActorId,
  EVENT_STATES,
  type EventState,
  SERVICE_CONTROL_PROFILE_ID,
  SERVICE_CONTROL_ROOT_KEYS,
  WHOLE_CONTAINERS,
} from "./values.js";

/** §4: when several rules apply, the first in this order is reported. */
export const SERVICE_CONTROL_ADMISSION_ORDER = Object.freeze([
  "INVALID_AUTOMERGE_BYTES",
  "CHANGE_ACTOR_MISMATCH",
  "INVALID_ROOT",
  "CONTAINER_REPLACED",
  "IMMUTABLE_FIELD_MUTATED",
  "UNKNOWN_ROOT_KEY",
  "UNAUTHORIZED_WRITER",
  "FORBIDDEN_MUTATION",
  ...SERVICE_CONTROL_DIAGNOSTIC_ORDER.slice(1),
] as const);
export type ServiceControlAdmissionDiagnostic = (typeof SERVICE_CONTROL_ADMISSION_ORDER)[number];

export class ServiceControlAdmissionError extends LfcpError {
  constructor(
    readonly diagnostic: ServiceControlAdmissionDiagnostic,
    message: string,
  ) {
    super("PROFILE_INVALID", message);
    this.name = "ServiceControlAdmissionError";
  }
}

export function refuseServiceControl(
  diagnostic: ServiceControlAdmissionDiagnostic,
  message: string,
): never {
  throw new ServiceControlAdmissionError(diagnostic, message);
}

/**
 * The signer's class from C's Control state at the unit's control_ref
 * alone (§2.3): `service-device` is a kind-1 device of R bound and active
 * in C, which is of class `service` only with its base approval in the
 * change's pre-state (serviceControlWriterClass).
 */
export type ServiceControlSignerClass = "root" | "personal" | "service-device" | "other";

/** §2.3: the class admission judges a change by. */
export type ServiceControlWriterClass = "root" | "personal" | "service" | "other";

/** What the verified Control Chain of C says of a signer at a unit's control_ref (W §80.1). */
export interface ServiceControlSignerFacts {
  /** C's Genesis owner R. */
  readonly owner: PrincipalId;
  readonly signer: PrincipalId;
  /** The signer as a device bound in C, if it is one. */
  readonly device?: {
    readonly kind: number;
    /** The root of the device's chain. */
    readonly root: PrincipalId;
    /** Bound in C's Control Chain (a member through its device certificate). */
    readonly boundInC: boolean;
    /** Not revoked and not suspended at control_ref. */
    readonly active: boolean;
  };
}

/** §2.3 at control_ref: root, personal (kind 0 of R), a candidate service device (kind 1 of R), or other. */
export function serviceControlSignerClass(
  facts: ServiceControlSignerFacts,
): ServiceControlSignerClass {
  if (bytesEqual(facts.signer, facts.owner)) return "root";
  const d = facts.device;
  if (d === undefined || !d.boundInC || !d.active || !bytesEqual(d.root, facts.owner))
    return "other";
  if (d.kind === 0) return "personal";
  return d.kind === 1 ? "service-device" : "other";
}

/**
 * §2.3: the class of a writer whose signer class at control_ref is
 * `signerClass`, given the keys of the valid base approvals without
 * `revoked` in the change's pre-state. `service` is exactly the Principal of
 * the only one; two of them give the class to nobody (§7.3).
 */
export function serviceControlWriterClass(
  signerClass: ServiceControlSignerClass,
  signer: PrincipalId,
  baseApprovals: readonly string[],
): ServiceControlWriterClass {
  if (signerClass !== "service-device") return signerClass;
  return baseApprovals.length === 1 && baseApprovals[0] === principalRef(signer)
    ? "service"
    : "other";
}

/** A Data Unit's writer, as the verified unit gives it. */
export interface ServiceControlWriter {
  readonly signer: PrincipalId;
  /** The LFCP Data Unit actor sequence, not the Automerge sequence. */
  readonly actorSeq: bigint | number;
  /** §2.3 at the unit's control_ref; the pre-state decides `service`. */
  readonly signerClass: ServiceControlSignerClass;
}

export interface ServiceControlOptions {
  readonly resource: ResourceId;
  /** C's Genesis owner R. */
  readonly root: PrincipalId;
  /** The Principal that signed C's Genesis: R, or the device of Genesis field 5 (W §15, §2.2). */
  readonly genesisSigner: PrincipalId;
}

/**
 * The checks of a unit that need no document, on every unit, duplicates
 * included, before SOP §14.1 sequence holding: the actor (§2), and SC0 for a
 * change without dependencies (§2.2: the Genesis signer's sequence 1).
 */
export function checkServiceControlUnit(
  change: CheckedChange,
  writer: ServiceControlWriter,
  options: ServiceControlOptions,
): void {
  if (change.deps.length === 0 && new ReferenceHistory().check(parsedOf(change)) !== null)
    refuseServiceControl("INVALID_AUTOMERGE_BYTES", "the initial change fails SOP §11.4");
  checkChangeActor(change, toHex(deriveServiceControlActorId(options.resource, writer.signer)));
  if (
    change.deps.length === 0 &&
    (change.seq !== 1 ||
      !bytesEqual(writer.signer, options.genesisSigner) ||
      (writer.actorSeq !== 1 && writer.actorSeq !== 1n))
  )
    refuseServiceControl(
      "INVALID_ROOT",
      "SC0: a change without dependencies is the Genesis signer's initial change, in its unit 1",
    );
  actorSequence(writer.actorSeq);
  if (
    (writer.signerClass === "root") !== bytesEqual(writer.signer, options.root) ||
    !["root", "personal", "service-device", "other"].includes(writer.signerClass)
  )
    refuseServiceControl("UNAUTHORIZED_WRITER", "signer class disagrees with C's Genesis owner");
}

interface Op {
  readonly action: string;
  readonly obj: string;
  readonly key?: string;
  readonly value?: unknown;
  readonly pred?: readonly string[];
}

/** §3: the classes each position's row names. */
const ROW: Readonly<Record<string, readonly ServiceControlWriterClass[]>> = {
  approvals: ["root", "personal"],
  service: ["service"],
  status: ["service"],
  lifecycle: ["service"],
  bindings: ["service"],
  pairing: ["service"],
  questions: ["service"],
  requests: ["root", "personal", "service"],
  answers: ["root", "personal", "service"],
  cancels: ["root", "personal", "service"],
  events: ["service"],
};
const ROOT_KEYS: ReadonlySet<string> = new Set(SERVICE_CONTROL_ROOT_KEYS);
const MAX_OPEN_REQUESTS = 32;
const MAX_OPEN_PAIR_SECTION = 1;

type Clock = ReadonlyMap<string, number>;

/**
 * SERVICE-CONTROL-PROFILE-01 §4 over one working document. Every condition
 * of §3 is judged on the change's pre-state (its causal history) and SC4/SC7
 * on its post-state, read at those heads; positions are located by the
 * operations that created the objects on the path, never by the engine's
 * projection. The class is decided at control_ref and on the causal
 * history, never at the merged state (§2.3).
 */
export class ServiceControlAdmission {
  #doc: A.Doc<unknown>;
  readonly #changes: Uint8Array[] = [];
  readonly #resource: string;
  /** The path of every object of the admitted history. */
  readonly #objects = new Map<string, readonly string[]>([["_root", []]]);
  /** Root keys of §2.1 by name, as the initial change made them. */
  readonly #containers = new Map<string, string>();
  /** "container/key" → the (actor, seq) of every change with an operation on that key. */
  readonly #held = new Map<string, { actor: string; seq: number }[]>();
  /** The vector clock of every admitted change. */
  readonly #clocks = new Map<string, Clock>();

  constructor(readonly options: ServiceControlOptions) {
    this.#resource = toBase64url(options.resource);
    this.#doc = A.init();
  }

  get document(): A.Doc<unknown> {
    return this.#doc;
  }

  #clockOf(deps: readonly string[]): Map<string, number> {
    const clock = new Map<string, number>();
    for (const dep of deps)
      for (const [actor, seq] of this.#clocks.get(dep) ?? [])
        if ((clock.get(actor) ?? 0) < seq) clock.set(actor, seq);
    return clock;
  }

  /** §3 "never held a value": no operation of the causal history at `clock` was on that key. */
  #everHeld(container: string, key: string, clock: Clock): boolean {
    return (this.#held.get(`${container}/${key}`) ?? []).some(
      (h) => (clock.get(h.actor) ?? 0) >= h.seq,
    );
  }

  /** The keys of the valid base approvals without `revoked` at `heads` (§2.3, §5 rule 3). */
  unrevokedBases(heads: readonly string[]): string[] {
    const approvals = this.#containers.get("approvals");
    if (approvals === undefined || heads.length === 0) return [];
    const reader = new ScReader(A.getBackend(this.#doc), heads);
    return reader.keys(approvals).filter((key) => {
      const a = readApproval(reader, approvals, key, this.#resource);
      return a !== undefined && a.role === "base" && !a.revoked;
    });
  }

  /** §2.3: the class of `writer` for a change with these dependencies (all admitted). */
  writerClassAt(deps: readonly string[], writer: ServiceControlWriter): ServiceControlWriterClass {
    return serviceControlWriterClass(
      writer.signerClass,
      writer.signer,
      writer.signerClass === "service-device" ? this.unrevokedBases(deps) : [],
    );
  }

  /**
   * Admits `change` (its dependencies already admitted) or throws
   * ServiceControlAdmissionError; returns the writer's class (§2.3).
   */
  accept(change: CheckedChange, writer: ServiceControlWriter): ServiceControlWriterClass {
    const decoded = decodedOf(change);
    const ops = decoded.ops as Op[];
    if (change.deps.length === 0) {
      this.#acceptInitial(change);
      this.#commit(change, decoded);
      return this.writerClassAt([], writer);
    }
    const found = new Set<ServiceControlAdmissionDiagnostic>();
    const pre = new ScReader(A.getBackend(this.#doc), change.deps);
    const clock = this.#clockOf(change.deps);
    const cls = this.writerClassAt(change.deps, writer);
    const container = (name: string) => this.#containers.get(name) as string;
    const preEntry = (top: string, key: string): ScValue | undefined =>
      pre.get(container(top), key);
    const preMap = (top: string, key: string) => {
      const v = preEntry(top, key);
      return isMapValue(v) ? v[1] : undefined;
    };
    const isFinal = (key: string) => {
      const e = preMap("events", key);
      return e !== undefined && eventIsFinal(pre, e);
    };
    const local = new Map<string, readonly string[]>();
    const path = (obj: string) => local.get(obj) ?? this.#objects.get(obj);
    const created = new Set<string>();
    const deleted = new Set<string>();
    const touched = new Set<string>();
    const absentAfter: [container: string, key: string][] = [];
    const forbid = () => found.add("FORBIDDEN_MUTATION");
    if (cls === "other") found.add("UNAUTHORIZED_WRITER");

    for (const [i, op] of ops.entries()) {
      const id = `${decoded.startOp + i}@${change.actor}`;
      const parent = path(op.obj);
      if (parent === undefined)
        refuseServiceControl("INVALID_AUTOMERGE_BYTES", "unknown operation object");
      const at = [...parent, op.key ?? "#"];
      if (op.action.startsWith("make")) {
        if (at.length > MAX_DOCUMENT_DEPTH)
          refuseServiceControl("INVALID_AUTOMERGE_BYTES", "the change exceeds SOP §11.2 depth");
        local.set(id, at);
      }
      if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
      if (op.obj === "_root") {
        if (op.key === "profile" || op.key === "meta") found.add("IMMUTABLE_FIELD_MUTATED");
        else found.add(ROOT_KEYS.has(String(op.key)) ? "CONTAINER_REPLACED" : "UNKNOWN_ROOT_KEY");
        continue;
      }
      const [top = "", key = "", field] = at;
      if (top === "meta") {
        found.add("IMMUTABLE_FIELD_MUTATED");
        continue;
      }
      const row = ROW[top];
      if (row === undefined) continue; // below an unknown root key: UNKNOWN_ROOT_KEY already
      if (!row.includes(cls)) {
        found.add("UNAUTHORIZED_WRITER");
        continue;
      }
      if (WHOLE_CONTAINERS.has(top)) {
        touched.add(top);
        continue;
      }
      const entry = `${top}/${key}`;
      if (at.length === 2) {
        const before = preEntry(top, key);
        // SC2: a scalar in place of an entry map.
        if (op.action === "set" && (op.pred ?? []).length > 0 && isMapValue(before)) {
          found.add("CONTAINER_REPLACED");
          continue;
        }
        touched.add(entry);
        if (op.action === "del") {
          deleted.add(entry);
          if (!this.#deletable(top, key, cls, pre, before, isFinal, absentAfter)) forbid();
          continue;
        }
        if (created.has(entry)) {
          forbid();
          continue;
        }
        created.add(entry);
        const fresh = !this.#everHeld(top, key, clock);
        const request = () => preMap("requests", key);
        const ok =
          top === "bindings" ||
          (fresh &&
            (top === "approvals" ||
              top === "questions" ||
              ((top === "requests" || top === "answers") && cls !== "service") ||
              (top === "pairing" && stringField(pre, request(), "op") === "pair-section") ||
              (top === "cancels" && cls !== "service" && request() !== undefined) ||
              (top === "events" &&
                (request() !== undefined || preMap("answers", key) !== undefined))));
        if (!ok) forbid();
        continue;
      }
      // A write below an entry: part of its creation, or a mutation its row admits.
      touched.add(entry);
      if (local.has(op.obj) || created.has(entry)) continue;
      const map = preMap(top, key);
      let ok = top === "bindings";
      if (map !== undefined && at.length === 3) {
        if (top === "approvals")
          ok =
            field === "revoked" && op.action === "makeMap" && pre.all(map, "revoked").length === 0;
        else if (top === "questions")
          ok =
            (field === "resolved" || field === "superseded") &&
            op.action === "makeMap" &&
            pre.get(map, "resolved") === undefined &&
            pre.get(map, "superseded") === undefined;
        else if (top === "events" && !isFinal(key)) {
          if (op.action === "del") ok = field === "code" || field === "detail";
          else if (op.action === "set" && field === "state")
            ok =
              typeof op.value === "string" &&
              EVENT_STATES.indexOf(op.value as EventState) >=
                EVENT_STATES.indexOf(eventStateOf(pre, map) as EventState);
          else
            ok = op.action === "set" && (field === "code" || field === "detail" || field === "at");
        }
      }
      if (!ok) forbid();
    }
    for (const k of created) if (deleted.has(k)) forbid();
    if (found.size > 0) this.#refuse(found);

    // SC4 and SC7 on the post-state of what the change creates or writes.
    this.#apply(change);
    const post = new ScReader(A.getBackend(this.#doc), [change.hash]);
    const postMap = (top: string, key: string) => post.map(container(top), key);
    for (const [top, key] of absentAfter) if (postMap(top, key) !== undefined) forbid();
    for (const t of touched) {
      const [top = "", key] = t.split("/");
      const v = key === undefined ? post.get("_root", top) : post.get(container(top), key);
      if (v === undefined) continue;
      for (const d of entryDiagnostics(post, top, key, v, this.#resource)) found.add(d);
      if (post.size(v) > limitOf(top)) found.add("LIMIT_EXCEEDED");
    }
    if ([...created].some((k) => k.startsWith("requests/"))) {
      const requests = container("requests");
      const events = container("events");
      let open = 0;
      let pairSections = 0;
      for (const rid of post.keys(requests)) {
        const event = post.map(events, rid);
        if (event !== undefined && eventIsFinal(post, event)) continue;
        open++;
        if (stringField(post, post.map(requests, rid), "op") === "pair-section") pairSections++;
      }
      if (open > MAX_OPEN_REQUESTS || pairSections > MAX_OPEN_PAIR_SECTION)
        found.add("LIMIT_EXCEEDED");
    }
    if (found.size > 0) {
      this.#rebuild();
      this.#refuse(found);
    }
    this.#commit(change, decoded, clock);
    return cls;
  }

  /** §3: a deletion of `container[key]` by `cls` whose condition holds. */
  #deletable(
    top: string,
    key: string,
    cls: ServiceControlWriterClass,
    pre: ScReader,
    before: ScValue | undefined,
    isFinal: (key: string) => boolean,
    absentAfter: [string, string][],
  ): boolean {
    if (cls !== "service") return false;
    const entry = isMapValue(before) ? before[1] : undefined;
    const container = (name: string) => this.#containers.get(name) as string;
    const settled = (q: string | undefined) =>
      q === undefined ||
      pre.get(q, "resolved") !== undefined ||
      pre.get(q, "superseded") !== undefined;
    switch (top) {
      case "bindings":
        return true;
      case "pairing": {
        if (entry === undefined) return false;
        absentAfter.push(["requests", key]);
        const principal = stringField(pre, entry, "principal");
        const state = isFinal(key)
          ? eventStateOf(pre, pre.map(container("events"), key) as string)
          : undefined;
        return (
          (principal !== undefined && pre.get(container("approvals"), principal) !== undefined) ||
          state === "cancelled" ||
          state === "rejected"
        );
      }
      case "questions":
        return entry !== undefined && settled(entry);
      case "requests":
        return isFinal(key);
      case "answers": {
        if (entry === undefined) return false;
        const qid = stringField(pre, entry, "qid");
        return settled(qid === undefined ? undefined : pre.map(container("questions"), qid));
      }
      case "cancels":
        absentAfter.push(["requests", key]);
        return true;
      case "events":
        absentAfter.push(["requests", key], ["answers", key]);
        return isFinal(key);
      default:
        return false;
    }
  }

  #acceptInitial(change: CheckedChange): void {
    if (this.#changes.length > 0)
      refuseServiceControl("INVALID_ROOT", "SC0: C already has its initial change");
    this.#apply(change);
    const r = new ScReader(A.getBackend(this.#doc));
    const keys = r.keys("_root");
    const profile = r.get("_root", "profile");
    const meta = r.map("_root", "meta");
    const ok =
      keys.length === SERVICE_CONTROL_ROOT_KEYS.length &&
      SERVICE_CONTROL_ROOT_KEYS.every((k) => keys.includes(k)) &&
      isStr(profile) &&
      profile[1] === SERVICE_CONTROL_PROFILE_ID &&
      meta !== undefined &&
      r.keys(meta).sort().join() === "attemptId,createdAt" &&
      SERVICE_CONTROL_ROOT_KEYS.slice(2).every((k) => {
        const m = r.map("_root", k);
        return m !== undefined && r.keys(m).length === 0;
      });
    if (!ok) {
      this.#rebuild();
      refuseServiceControl(
        "INVALID_ROOT",
        "SC0: the initial change creates exactly profile, meta and eleven empty maps",
      );
    }
  }

  #refuse(found: ReadonlySet<ServiceControlAdmissionDiagnostic>): never {
    const diagnostic = SERVICE_CONTROL_ADMISSION_ORDER.find((d) =>
      found.has(d),
    ) as ServiceControlAdmissionDiagnostic;
    refuseServiceControl(diagnostic, `SERVICE-CONTROL-PROFILE-01 §4: ${diagnostic}`);
  }

  #apply(change: CheckedChange): void {
    try {
      [this.#doc] = A.applyChanges(this.#doc, [change.bytes]);
    } catch (e) {
      if (isWasmTrap(e)) throw e;
      this.#rebuild();
      refuseServiceControl(
        "INVALID_AUTOMERGE_BYTES",
        `the engine refused the change: ${String(e)}`,
      );
    }
  }

  /** Back to the admitted history: the working document had a refused change applied. */
  #rebuild(): void {
    A.free(this.#doc);
    [this.#doc] = A.applyChanges(A.init(), this.#changes);
  }

  #commit(
    change: CheckedChange,
    decoded: A.DecodedChange,
    clock = new Map<string, number>(),
  ): void {
    this.#changes.push(change.bytes);
    clock.set(change.actor, Math.max(clock.get(change.actor) ?? 0, change.seq));
    this.#clocks.set(change.hash, clock);
    for (const [i, op] of (decoded.ops as Op[]).entries()) {
      const parent = this.#objects.get(op.obj);
      if (parent === undefined) continue;
      if (op.action.startsWith("make")) {
        const id = `${decoded.startOp + i}@${change.actor}`;
        this.#objects.set(id, [...parent, op.key ?? "#"]);
        if (parent.length === 0 && op.key !== undefined && !this.#containers.has(op.key))
          this.#containers.set(op.key, id);
      }
      if (parent.length === 1 && op.key !== undefined) {
        const k = `${parent[0]}/${op.key}`;
        const held = this.#held.get(k) ?? [];
        held.push({ actor: change.actor, seq: change.seq });
        this.#held.set(k, held);
      }
    }
  }
}

/** A string field of a map read through `reader`, or undefined. */
function stringField(reader: ScReader, map: string | undefined, field: string): string | undefined {
  if (map === undefined) return undefined;
  const v = reader.get(map, field);
  return isStr(v) ? v[1] : undefined;
}
