import * as A from "@automerge/automerge";
import {
  actorSequence,
  bytesEqual,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
  UINT64_MAX,
} from "@openlfcp/core";
import { checkChangeActor } from "../admission/actor.js";
import { type CheckedChange, checkChange, decodedOf, parsedOf } from "../admission/framing.js";
import { MAX_DOCUMENT_DEPTH } from "../admission/limits.js";
import { ReferenceHistory } from "../admission/references.js";
import { isWasmTrap } from "../replica.js";
import { principalRef } from "../values.js";
import { distinct, type Value } from "./reader.js";
import { deriveIdentityActorId, IDENTITY_PROFILE_ID, type IdentityWriter } from "./values.js";

export const IDENTITY_ADMISSION_ORDER = Object.freeze([
  "INVALID_AUTOMERGE_BYTES",
  "CHANGE_ACTOR_MISMATCH",
  "INVALID_ROOT",
  "CONTAINER_REPLACED",
  "IMMUTABLE_FIELD_MUTATED",
  "UNAUTHORIZED_WRITER",
  "INVALID_FIELD_TYPE",
] as const);
export type IdentityAdmissionDiagnostic = (typeof IDENTITY_ADMISSION_ORDER)[number];

export class IdentityAdmissionError extends LfcpError {
  constructor(
    readonly diagnostic: IdentityAdmissionDiagnostic,
    message: string,
  ) {
    super("PROFILE_INVALID", message);
    this.name = "IdentityAdmissionError";
  }
}

export function refuseIdentity(diagnostic: IdentityAdmissionDiagnostic, message: string): never {
  throw new IdentityAdmissionError(diagnostic, message);
}

/** Must run on every unit, even a duplicate change, BEFORE SOP §14.1 sequence holding. */
export function checkIdentityUnit(
  change: CheckedChange,
  writer: IdentityWriter,
  resource: ResourceId,
  root: PrincipalId,
): void {
  // A dependency-free seq 2 is R1, even if the root/sequence eligibility also fails.
  if (change.deps.length === 0 && new ReferenceHistory().check(parsedOf(change)) !== null)
    refuseIdentity("INVALID_AUTOMERGE_BYTES", "the initial change fails SOP §11.4");
  checkChangeActor(change, toHex(deriveIdentityActorId(resource, writer.signer)));
  if (
    change.deps.length === 0 &&
    (change.actor !== toHex(deriveIdentityActorId(resource, root)) ||
      change.seq !== 1 ||
      !bytesEqual(writer.signer, root) ||
      (writer.actorSeq !== 1 && writer.actorSeq !== 1n))
  )
    refuseIdentity(
      "INVALID_ROOT",
      "AI0: the initial change must be in the root's actor sequence 1 unit",
    );
  actorSequence(writer.actorSeq);
  if (
    (writer.writerClass === "root") !== bytesEqual(writer.signer, root) ||
    !["root", "personal", "pairing", "other"].includes(writer.writerClass)
  )
    refuseIdentity("UNAUTHORIZED_WRITER", "writer class disagrees with the verified Genesis owner");
}

interface Op {
  readonly action: string;
  readonly obj: string;
  readonly key?: string;
  readonly elemId?: string;
  readonly insert?: boolean;
  readonly value?: unknown;
  readonly datatype?: string;
  readonly pred: readonly string[];
}
interface ObjectInfo {
  readonly path: readonly (string | number)[];
  readonly type: string;
  readonly requestMap?: string;
}
const MAKE = new Map([
  ["makeMap", "map"],
  ["makeList", "list"],
  ["makeText", "text"],
  ["makeTable", "table"],
]);
const CONTAINERS = new Set(["roster", "devices", "requests", "extensions"]);
const TABLES = new Set(["roster", "devices", "requests"]);
const FIELDS: Record<string, ReadonlySet<string>> = {
  roster: new Set(["profile", "endpoints", "coordinator", "name", "archived"]),
  devices: new Set(["label", "kind", "platform", "added_at", "revoked", "missing_keys"]),
  requests: new Set([
    "descriptor",
    "pairing",
    "label",
    "kind",
    "scope",
    "platform",
    "requested_at",
  ]),
};

/** Operations are inspected before applying them. Object provenance includes overwritten maps. */
export class IdentityAdmission {
  #doc: A.Doc<unknown>;
  readonly #changes: Uint8Array[];
  #requests: string | undefined;
  readonly #objects = new Map<string, ObjectInfo>([["_root", { path: [], type: "map" }]]);
  constructor(
    doc: A.Doc<unknown>,
    readonly root: PrincipalId,
  ) {
    // One independent working document, reused for every accepted change.
    this.#doc = A.clone(doc);
    this.#changes = A.getAllChanges(doc);
    for (const bytes of this.#changes) this.#index(decodedOf(checkChange(bytes)));
  }

  get document(): A.Doc<unknown> {
    return this.#doc;
  }

  #index(change: A.DecodedChange): void {
    for (const [i, op] of (change.ops as Op[]).entries()) {
      const type = MAKE.get(op.action);
      const parent = this.#objects.get(op.obj);
      if (type === undefined || parent === undefined) continue;
      const id = `${change.startOp + i}@${change.actor}`;
      const path = [...parent.path, op.key ?? -1];
      if (path.length === 1 && path[0] === "requests") this.#requests = id;
      const requestMap = path[0] === "requests" && path.length === 2 ? id : parent.requestMap;
      this.#objects.set(id, { path, type, ...(requestMap === undefined ? {} : { requestMap }) });
    }
  }

  accept(change: CheckedChange, writer: IdentityWriter): void {
    const decoded = decodedOf(change);
    const ops = decoded.ops as Op[];
    const initial = change.deps.length === 0;
    const found = new Set<IdentityAdmissionDiagnostic>();
    const local = new Map<string, ObjectInfo>();
    const info = (id: string) => local.get(id) ?? this.#objects.get(id);
    const backend = A.getBackend(this.#doc);
    const all = (obj: string, key: string): Value[] =>
      local.has(obj) ? [] : (backend.getAll(obj, key, [...change.deps]) as Value[]);
    const restricted = writer.writerClass === "pairing" || writer.writerClass === "other";
    const own = principalRef(writer.signer);
    const touched = new Set<string>();
    const createdRequests = new Set<string>();
    const writtenTypes = new Map<string, string[]>();
    const pairings = new Map<string, Map<string, Value>>();

    if (initial) {
      const roots = ops.filter((op) => op.obj === "_root");
      const identity = roots.find((op) => op.key === "identity" && op.action === "makeMap");
      const identityIndex = identity === undefined ? -1 : ops.indexOf(identity);
      const rootValue = ops.find(
        (op) => op.obj === `${decoded.startOp + identityIndex}@${change.actor}`,
      );
      if (
        ops.length !== 7 ||
        roots.length !== 6 ||
        new Set(roots.map((op) => op.key)).size !== 6 ||
        !roots.every((op) =>
          op.key === "profile"
            ? op.action === "set" && op.value === IDENTITY_PROFILE_ID && op.datatype === undefined
            : op.key !== undefined &&
              ["identity", ...CONTAINERS].includes(op.key) &&
              op.action === "makeMap",
        ) ||
        rootValue?.key !== "root" ||
        rootValue.action !== "set" ||
        rootValue.datatype !== undefined ||
        rootValue.value !== principalRef(this.root)
      )
        found.add("INVALID_ROOT");
    }

    for (const [i, op] of ops.entries()) {
      const id = `${decoded.startOp + i}@${change.actor}`;
      const parent = info(op.obj);
      if (parent === undefined)
        refuseIdentity("INVALID_AUTOMERGE_BYTES", "unknown operation object");
      const path = parent.path;
      const top = String(path[0]);
      const key = op.key;
      const made = MAKE.get(op.action);
      if (made !== undefined) {
        if (path.length + 1 > MAX_DOCUMENT_DEPTH)
          refuseIdentity("INVALID_AUTOMERGE_BYTES", "the change exceeds SOP §11.2 depth");
        const child = [...path, key ?? -1];
        const requestMap = child[0] === "requests" && child.length === 2 ? id : parent.requestMap;
        local.set(id, {
          path: child,
          type: made,
          ...(requestMap === undefined ? {} : { requestMap }),
        });
      }
      if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
      if (!initial && op.obj === "_root") {
        if (key !== undefined && CONTAINERS.has(key)) found.add("CONTAINER_REPLACED");
        if (key === "profile" || key === "identity") found.add("IMMUTABLE_FIELD_MUTATED");
      }
      if (!initial && top === "identity") found.add("IMMUTABLE_FIELD_MUTATED");

      if (TABLES.has(top) && key !== undefined && op.action === "set") {
        const old = writtenTypes.get(`${op.obj}/${key}`) ?? all(op.obj, key).map(([type]) => type);
        if (old.some((type) => type === "list" || (path.length === 1 && type === "map")))
          found.add("CONTAINER_REPLACED");
      }
      if (key !== undefined && (made !== undefined || op.action === "set" || op.action === "del"))
        writtenTypes.set(`${op.obj}/${key}`, op.action === "del" ? [] : [made ?? "scalar"]);
      // AI3 checks structural value kinds, leaving scalar field semantics to §4.
      const defined =
        (path.length === 1 && TABLES.has(top)) ||
        (path.length === 2 && key !== undefined && FIELDS[top]?.has(key)) ||
        (path.length >= 3 && ["endpoints", "scope", "missing_keys"].includes(String(path[2])));
      if (defined && op.action !== "del") {
        const scalar =
          op.action === "set" &&
          ((typeof op.value === "string" && op.datatype === undefined) ||
            typeof op.value === "boolean" ||
            (op.datatype === "uint" &&
              ((typeof op.value === "number" && Number.isSafeInteger(op.value) && op.value >= 0) ||
                (typeof op.value === "bigint" && op.value >= 0n && op.value <= UINT64_MAX))));
        if (!scalar && made !== "map" && made !== "list") found.add("INVALID_FIELD_TYPE");
        if (parent.type === "list" && !scalar) found.add("INVALID_FIELD_TYPE");
      }
      if (!restricted) continue;
      if (op.action === "del") found.add("UNAUTHORIZED_WRITER");
      if (top !== "requests" || path.length < 1) {
        found.add("UNAUTHORIZED_WRITER");
        continue;
      }
      const entryKey = path.length === 1 ? key : String(path[1]);
      if (entryKey === undefined) {
        found.add("UNAUTHORIZED_WRITER");
        continue;
      }
      touched.add(entryKey);
      const requestMap =
        path.length === 1 ? (op.action === "makeMap" ? id : undefined) : parent.requestMap;
      const requests = path.length === 1 ? op.obj : this.#requests;
      const history = requests === undefined ? [] : all(requests, entryKey);
      if (path.length === 1) {
        if (op.action !== "makeMap" || history.length !== 0 || createdRequests.has(entryKey))
          found.add("UNAUTHORIZED_WRITER");
        createdRequests.add(entryKey);
      } else if (requestMap === undefined) found.add("UNAUTHORIZED_WRITER");
      else if (!local.has(requestMap)) {
        const pairing = distinct(all(requestMap, "pairing"));
        if (
          history.length !== 1 ||
          history[0]?.[0] !== "map" ||
          history[0][1] !== requestMap ||
          !requestMap.endsWith(`@${change.actor}`) ||
          pairing.length !== 1 ||
          pairing[0]?.[0] !== "str" ||
          pairing[0][1] !== own
        )
          found.add("UNAUTHORIZED_WRITER");
      }
      if (requestMap !== undefined && !pairings.has(requestMap))
        pairings.set(requestMap, new Map(all(requestMap, "pairing").map((v) => [String(v[2]), v])));
      if (path.length === 2 && key === "pairing" && requestMap !== undefined) {
        const values = pairings.get(requestMap) as Map<string, Value>;
        for (const pred of op.pred) values.delete(pred);
        if (op.action !== "del")
          values.set(id, [
            made ?? op.datatype ?? (typeof op.value === "string" ? "str" : typeof op.value),
            op.value,
            id,
          ]);
      }
    }
    if (restricted) {
      if (touched.size !== 1) found.add("UNAUTHORIZED_WRITER");
      for (const values of pairings.values()) {
        const final = distinct([...values.values()]);
        if (final.length !== 1 || final[0]?.[0] !== "str" || final[0][1] !== own)
          found.add("UNAUTHORIZED_WRITER");
      }
    }
    const diagnostic = IDENTITY_ADMISSION_ORDER.find((d) => found.has(d));
    if (diagnostic !== undefined)
      refuseIdentity(diagnostic, `IDENTITY-PROFILE-01 §3: ${diagnostic}`);
    // Do not copy the accumulated history on every accepted change. The byte
    // log and object index are committed only after apply succeeds; if the
    // engine aborts, replay that trusted log into a fresh working document.
    const actor = A.getActorId(this.#doc);
    try {
      [this.#doc] = A.applyChanges(this.#doc, [change.bytes]);
    } catch (e) {
      if (isWasmTrap(e)) throw e;
      A.free(this.#doc);
      [this.#doc] = A.applyChanges(A.init({ actor }), this.#changes);
      refuseIdentity("INVALID_AUTOMERGE_BYTES", `the engine refused the change: ${String(e)}`);
    }
    this.#changes.push(change.bytes);
    this.#index(decoded);
  }
}
