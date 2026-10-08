import * as A from "@automerge/automerge";
import { LfcpError, type ResourceId, toHex } from "@openlfcp/core";
import { type CheckedChange, decodedOf } from "../admission/framing.js";
import { MAX_DOCUMENT_DEPTH } from "../admission/limits.js";
import { parsePrincipalRef } from "../values.js";
import { deriveSectionActorId } from "./values.js";

/**
 * The structural admission of SHARED-SECTIONS-PROFILE-01 §14.1 (LFCP-02-017):
 * rules A1–A5 and the readiness rule of §12.1, decided from the change's own
 * operations and the objects they write into, in time linear in the change.
 * It runs after the inherited SOP checks (framing, limits, actor, sequence)
 * and before the engine applies anything; a refused change is never merged.
 *
 * Objects of the document are identified by their path from the root
 * (Automerge objInfo); objects created by changes admitted earlier in the
 * same batch, or earlier in the change, by the operation that creates them.
 */

/** §14.1: the admission diagnostics, in their order of precedence. */
export const ADMISSION_ORDER = Object.freeze([
  "INVALID_AUTOMERGE_BYTES",
  "CHANGE_ACTOR_MISMATCH",
  "CONTAINER_REPLACED",
  "CHILDREN_LIST_MUTATED",
  "PLACEMENT_NOT_ATOMIC",
  "IMMUTABLE_FIELD_MUTATED",
  "INVALID_FIELD_TYPE",
] as const);
export type AdmissionDiagnostic = (typeof ADMISSION_ORDER)[number];

/** A change refused at admission: PROFILE_INVALID with its §14.1 diagnostic. */
export class SectionAdmissionError extends LfcpError {
  readonly diagnostic: AdmissionDiagnostic;

  constructor(diagnostic: AdmissionDiagnostic, message: string) {
    super("PROFILE_INVALID", message);
    this.name = "SectionAdmissionError";
    this.diagnostic = diagnostic;
  }
}

const ROOT_CONTAINERS = new Set([
  "profile",
  "section",
  "objects",
  "nodes",
  "placements",
  "extensions",
]);
const NODE_IMMUTABLE = new Set(["id", "kind", "created_by", "task_id"]);
const TASK_IMMUTABLE = new Set(["id", "type", "created_by"]);
const NODE_CONTAINERS = new Set(["children", "text", "extensions"]);
const MAKE = new Set(["makeMap", "makeList", "makeText", "makeTable"]);

type Path = readonly (string | number)[];
interface Op {
  readonly action: string;
  readonly obj: string;
  readonly key?: string;
  readonly elemId?: string;
  readonly insert?: boolean;
  readonly value?: unknown;
}

/** What admission knows of one object: its path, and whether it existed before the change. */
interface Known {
  readonly path: Path | undefined;
  readonly depth: number;
}

export class SectionAdmission {
  /** The document with every change admitted so far: each change is read at its own deps. */
  #work: A.Doc<unknown>;
  #backend: ReturnType<typeof A.getBackend>;
  readonly #resource: ResourceId;

  constructor(doc: A.Doc<unknown>, resource: ResourceId) {
    this.#work = doc;
    this.#backend = A.getBackend(doc);
    this.#resource = resource;
  }

  /** Admitted changes not yet applied to the working document. */
  #pending: Uint8Array[] = [];

  /**
   * Applies the admitted changes still pending, in one engine call. Done
   * only when a check reads the state they may change, so a long linear run
   * of Text edits is applied once, not change by change.
   */
  #flush(): void {
    if (this.#pending.length === 0) return;
    const batch = this.#pending;
    this.#pending = [];
    [this.#work] = A.applyChanges(this.#work, batch);
    this.#backend = A.getBackend(this.#work);
    for (const [obj, k] of this.#paths) if (k === undefined) this.#paths.delete(obj);
  }

  /** The document with the admitted changes applied. */
  get document(): A.Doc<unknown> {
    this.#flush();
    return this.#work;
  }

  /** Paths of the document's objects, read once each: objects never move. */
  readonly #paths = new Map<string, Known | undefined>();

  /** Path and depth of an object of the document; undefined when it is unknown. */
  #known(obj: string): Known | undefined {
    if (obj === "_root") return { path: [], depth: 0 };
    if (this.#paths.get(obj) !== undefined) return this.#paths.get(obj);
    this.#flush();
    let known: Known | undefined;
    try {
      const path = this.#backend.objInfo(obj as never).path as Path | undefined;
      known = { path, depth: path === undefined ? Number.NaN : path.length };
    } catch {
      known = undefined;
    }
    this.#paths.set(obj, known);
    return known;
  }

  /** Whether `key` of `obj` has a value in the change's causal history (`heads`). */
  #has(obj: string, key: string, heads: A.Heads): boolean {
    this.#flush();
    try {
      return this.#backend.getAll(obj, key, heads).length > 0;
    } catch {
      return false;
    }
  }

  /** The section's scalar `key` in the document (its ID and creator never change). */
  /** Section fields already read: they never change once written. */
  readonly #sectionFields = new Map<string, string>();

  #section(key: string): string | undefined {
    const cached = this.#sectionFields.get(key);
    if (cached !== undefined) return cached;
    this.#flush();
    const section = (this.#work as Record<string, unknown>).section as
      | Record<string, unknown>
      | undefined;
    const v = section?.[key];
    if (v === undefined) return undefined;
    this.#sectionFields.set(key, String(v));
    return String(v);
  }

  /**
   * Admits `change` against its causal history, or throws
   * SectionAdmissionError. An admitted change is applied to the working
   * document at once, so the changes after it in the batch see it.
   */
  accept(change: CheckedChange): void {
    const decoded = decodedOf(change);
    const ops = decoded.ops as readonly Op[];
    const found = new Set<AdmissionDiagnostic>();
    const local = new Map<string, Known>();
    const knownOf = (obj: string) => local.get(obj) ?? this.#known(obj);
    // Objects this change did not create existed in its causal history.
    const existed = (obj: string) => !local.has(obj) && obj !== "_root";
    const heads = decoded.deps;
    const has = (obj: string, key: string) => this.#has(obj, key, heads);

    // Created placements of this change: their fields, list entries and register writes.
    const placements = new Map<string, { node?: string; parent?: string; inserted: string[] }>();
    const registers = new Map<string, Set<string>>(); // node → PlacementIds written to its register
    const insertedInto: { owner: string; value: string }[] = [];
    let readyWrite: { value: unknown; del: boolean; again: boolean } | undefined;
    let creatorInChange: string | undefined;

    ops.forEach((op, i) => {
      const parent = knownOf(op.obj);
      const path = parent?.path;
      const key = op.key;
      const own = (p: Path | undefined, k: number) =>
        p !== undefined && p.length === k ? p : undefined;

      if (MAKE.has(op.action)) {
        const id = `${decoded.startOp + i}@${decoded.actor}`;
        if (parent === undefined)
          throw new SectionAdmissionError(
            "INVALID_AUTOMERGE_BYTES",
            `the change writes into object ${op.obj}, which the document does not have (SOP §11.2)`,
          );
        const depth = parent.depth + 1;
        if (depth > MAX_DOCUMENT_DEPTH)
          throw new SectionAdmissionError(
            "INVALID_AUTOMERGE_BYTES",
            `the change creates an object deeper than ${MAX_DOCUMENT_DEPTH} levels (SOP §11.2)`,
          );
        const childPath =
          path === undefined ? undefined : key !== undefined ? [...path, key] : [...path, -1];
        local.set(id, { path: childPath, depth });
      }

      // The root: its containers are created once (A4).
      if (op.obj === "_root") {
        if (key !== undefined && ROOT_CONTAINERS.has(key) && has("_root", key))
          found.add("CONTAINER_REPLACED");
        return;
      }
      if (path === undefined) return; // an object without a known place: nothing structural
      const [top, second] = path;

      if (top === "section" && path.length === 1) {
        if (!existed(op.obj)) {
          if (key === "created_by" && typeof op.value === "string") creatorInChange = op.value;
        } else if (key === "id" || key === "created_by") found.add("IMMUTABLE_FIELD_MUTATED");
        if ((key === "children" || key === "extensions") && existed(op.obj) && has(op.obj, key))
          found.add("CONTAINER_REPLACED");
        if (key === "ready")
          readyWrite = {
            value: op.value,
            del: op.action === "del",
            again: (readyWrite?.again ?? false) || (existed(op.obj) && has(op.obj, "ready")),
          };
        else if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
        return;
      }

      // Children lists: insert-only, entries are scalar PlacementIds (A1, A2, A5).
      const owner =
        own(path, 2)?.[0] === "section" && path[1] === "children"
          ? "section"
          : own(path, 3)?.[0] === "nodes" && path[2] === "children"
            ? String(second)
            : undefined;
      if (owner !== undefined) {
        const isNew = !existed(op.obj);
        if (op.insert) {
          if (op.action !== "set" || typeof op.value !== "string") found.add("INVALID_FIELD_TYPE");
          else insertedInto.push({ owner, value: op.value });
        } else if (!isNew || op.action === "del" || op.action === "set") {
          found.add("CHILDREN_LIST_MUTATED");
        }
        return;
      }

      if (top === "nodes" && path.length === 1) {
        // A node map is created once; replacing or deleting it is A4.
        if (key !== undefined && has(op.obj, key) && existed(op.obj))
          found.add("CONTAINER_REPLACED");
        return;
      }

      if (top === "nodes" && path.length === 2) {
        const node = String(second);
        const isNew = !existed(op.obj);
        if (key === undefined) return;
        if (!isNew) {
          if (NODE_CONTAINERS.has(key) && has(op.obj, key)) found.add("CONTAINER_REPLACED");
          if (NODE_IMMUTABLE.has(key)) found.add("IMMUTABLE_FIELD_MUTATED");
        }
        if (key === "text") {
          if (op.action !== "makeText" && op.action !== "del") found.add("INVALID_FIELD_TYPE");
        } else if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
        if (key === "placement" && op.action === "set" && typeof op.value === "string") {
          const set = registers.get(node) ?? new Set<string>();
          set.add(op.value);
          registers.set(node, set);
        }
        return;
      }

      if (top === "placements" && path.length === 1) {
        if (key !== undefined && op.action === "makeMap" && !has(op.obj, key))
          placements.set(key, { inserted: [] });
        else if (key !== undefined) found.add("IMMUTABLE_FIELD_MUTATED");
        return;
      }
      if (top === "placements" && path.length === 2) {
        if (existed(op.obj)) {
          found.add("IMMUTABLE_FIELD_MUTATED");
          return;
        }
        const p = placements.get(String(second));
        if (p !== undefined && op.action === "set" && typeof op.value === "string") {
          if (key === "node_id") p.node = op.value;
          if (key === "parent_id") p.parent = op.value;
        }
        if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
        return;
      }

      if (top === "objects" && path.length >= 2) {
        // SOP §30: every string of a Task is a scalar; §75: its identity is immutable.
        if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
        if (path.length === 2 && existed(op.obj) && key !== undefined && TASK_IMMUTABLE.has(key))
          found.add("IMMUTABLE_FIELD_MUTATED");
        return;
      }
    });

    // §12.1: ready is the scalar true, written once, by the creator's actor.
    if (readyWrite !== undefined) {
      const creator = creatorInChange ?? this.#section("created_by");
      let creatorActor: string | undefined;
      try {
        creatorActor =
          creator === undefined
            ? undefined
            : toHex(deriveSectionActorId(this.#resource, parsePrincipalRef(creator)));
      } catch {
        creatorActor = undefined;
      }
      if (
        readyWrite.del ||
        readyWrite.again ||
        readyWrite.value !== true ||
        creatorActor !== decoded.actor
      )
        found.add("IMMUTABLE_FIELD_MUTATED");
    }

    // A2: every inserted entry is a placement this change creates under that list's
    // owner; every created placement is inserted exactly once and assigned to its node.
    const sectionId =
      insertedInto.length > 0 ? this.#sectionId(ops, decoded.startOp, decoded.actor) : undefined;
    for (const { owner, value } of insertedInto) {
      const p = placements.get(value);
      if (p === undefined) found.add("PLACEMENT_NOT_ATOMIC");
      else p.inserted.push(owner === "section" ? (sectionId ?? "section") : owner);
    }
    for (const [pid, p] of placements) {
      if (p.inserted.length !== 1 || p.inserted[0] !== p.parent) found.add("PLACEMENT_NOT_ATOMIC");
      if (p.node === undefined || !(registers.get(p.node)?.has(pid) ?? false))
        found.add("PLACEMENT_NOT_ATOMIC");
    }

    const first = ADMISSION_ORDER.find((d) => found.has(d));
    if (first !== undefined)
      throw new SectionAdmissionError(
        first,
        `the change breaks SHARED-SECTIONS-PROFILE-01 §14.1: ${first}`,
      );

    // Admitted: the changes after it in the batch see it.
    // Admitted: applied before the next check that reads the document.
    this.#pending.push(change.bytes);
  }

  /** The SectionId: from the document, or from the change that creates the section. */
  #sectionId(ops: readonly Op[], startOp: number, actor: string): string | undefined {
    const known = this.#section("id");
    if (known !== undefined) return known;
    let sectionObj: string | undefined;
    ops.forEach((op, i) => {
      if (op.obj === "_root" && op.key === "section" && op.action === "makeMap")
        sectionObj = `${startOp + i}@${actor}`;
    });
    const set = ops.find((op) => op.obj === sectionObj && op.key === "id" && op.action === "set");
    return typeof set?.value === "string" ? set.value : undefined;
  }
}
