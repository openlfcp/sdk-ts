import * as A from "@automerge/automerge";
import {
  generateObjectId,
  isObjectId,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { type CheckedChange, checkChange, checkSaveHeader } from "../admission/framing.js";
import {
  checkChangeExpansion,
  checkSnapshotExpansion,
  SNAPSHOT_LIMITS_FLOOR,
  type SnapshotLimits,
} from "../admission/limits.js";
import { ProfileInvalidError } from "../profile-invalid.js";
import { prepareTaskIntent, type ReplicaIntent } from "../replica.js";
import type { Task } from "../task.js";
import type { Json } from "../validate.js";
import { frameProfilePayload, isUtcTimestamp, principalRef } from "../values.js";
import { type SectionValidation, validateSection } from "./schema.js";
import { deriveTree, type SectionTree } from "./tree.js";
import {
  deriveSectionActorId,
  LIST_STYLES,
  type ListStyle,
  PARENT_KINDS,
  SECTIONS_PROFILE_ID,
} from "./values.js";

/**
 * The writer of a SHARED-SECTIONS-PROFILE-01 document (LFCP-02-012): the
 * section and creation intents of §11, and the SOP Task intents on the
 * section's Tasks (§2), committed as batches.
 *
 * - One batch is one Automerge change (§12), with time 0 and the actor of
 *   §2 for (Resource, Principal); the batch is validated as a whole, and
 *   one refused intent refuses it with nothing written
 *   (SDK-SECTIONS-INTEGRATION-01 §3.1).
 * - The caller allocates every node and Task ID and the SDK uses them;
 *   PlacementIds are the SDK's unless the intent names one.
 * - A node, its placement, the placement's entry in the parent's children
 *   list and the node's `placement` register are written in one change
 *   (§4.3); a Task node and its Task are created together (§4.2).
 * - Writes touch single properties; unknown fields and extensions survive.
 *
 * Moves, lifecycle, Text edits and the effective tree come with LFCP-02-013
 * to 016; batches over the §16.2 budgets are refused until 016 splits them.
 */

/** Why a batch was refused before anything was written (SDK-SECTIONS-INTEGRATION-01 §3.6). */
export type SectionIntentCode =
  /** The document is not a valid section (§14.2 section-level problems). */
  | "SECTION_INVALID"
  /** section.create on a document that already has a root, or another intent before one. */
  | "SECTION_EXISTS"
  /** The section has no `ready` and this writer is not its creator (§12.1). */
  | "SECTION_IMPORTING"
  /** A new ID is not a canonical UUIDv7 or is already used in the Resource (§3). */
  | "ID_IN_USE"
  /** The parent is missing, invalid, deleted, in conflict or cannot hold content (§4.2, §6). */
  | "INVALID_PARENT"
  /** `after` is not a visible child of the parent, or is the moved node (§6). */
  | "INVALID_PREDECESSOR"
  /** The node is invalid, collides, or has concurrent placements: resolve it first (§7, §8). */
  | "NODE_IN_CONFLICT"
  /** The intent names a node the section does not have. */
  | "UNKNOWN_NODE"
  /** A value outside its domain: an ID, a list style, a timestamp, a string (§3, §4). */
  | "INVALID_INTENT"
  /** The batch is over an authoring budget of §16.2. */
  | "OVER_BUDGET";

/** A batch refused before commit, with the intent it concerns (SDK-SECTIONS-INTEGRATION-01 §3.6). */
export class SectionIntentError extends Error {
  readonly code: SectionIntentCode;
  /** The index of the refused intent in its batch. */
  readonly intentIndex: number | undefined;
  /** The node the refusal concerns, when there is one. */
  readonly nodeId: string | undefined;

  constructor(code: SectionIntentCode, message: string, intentIndex?: number, nodeId?: string) {
    super(message);
    this.name = "SectionIntentError";
    this.code = code;
    this.intentIndex = intentIndex;
    this.nodeId = nodeId;
  }
}

/** Where a new node goes: under `parent`, right after the visible sibling `after` (null: first). */
interface Position {
  /** The section ID, or a task or item node. */
  readonly parent: string;
  /** The preceding visible sibling, a node ID; null puts the node first (§6). */
  readonly after: string | null;
  /** The new PlacementId; generated when absent. */
  readonly placementId?: string;
}

export type SectionIntent =
  | {
      readonly intent: "section.create";
      readonly sectionId: string;
      readonly title: string;
      readonly createdBy: PrincipalId;
      readonly createdAt?: string;
      /** §12.1: false while an import continues in later changes; the default writes `ready`. */
      readonly ready?: boolean;
    }
  | { readonly intent: "section.set_title"; readonly title: string }
  /** §12.1: the last change of an import writes `ready`; the creator only, once. */
  | { readonly intent: "section.mark_ready" }
  | ({
      readonly intent: "task.create_in_section";
      /** The Task, from createTask (§53); its ID is the node's ID. */
      readonly task: Task;
      readonly listStyle?: ListStyle;
    } & Position)
  | ({
      readonly intent: "paragraph.create" | "item.create" | "raw.create";
      readonly id: string;
      readonly createdBy: PrincipalId;
      readonly createdAt?: string;
      /** Markdown inline source (§4.2); collaborative Text. */
      readonly text: string;
      /** item.create only. */
      readonly listStyle?: ListStyle;
    } & Position)
  /** §5, §6: a fresh placement under `parent`; the node keeps its identity and subtree. */
  | ({ readonly intent: "node.move"; readonly id: string } & Position)
  /**
   * §8: a fresh placement written to a node's register, superseding every
   * placement observed at this causal point, conflicted or not.
   */
  | ({ readonly intent: "node.resolve_placement"; readonly id: string } & Position)
  /**
   * §8: relocates several nodes atomically, as for a parent cycle; each
   * move is checked against the moves before it, so the result is acyclic.
   */
  | {
      readonly intent: "structure.resolve";
      readonly moves: readonly ({ readonly id: string } & Position)[];
    }
  /**
   * §9: the lifecycle of a node: a Task node's Task, any other node itself.
   * Always a fresh causal write, also when the value is already visible;
   * descendants are not rewritten.
   */
  | { readonly intent: "node.delete" | "node.restore"; readonly id: string }
  /** §4.2: ordered or bullet list membership, on task and item nodes. */
  | { readonly intent: "node.set_list_style"; readonly id: string; readonly listStyle: ListStyle }
  /** A SHARED-OBJECTS-PROFILE-01 Task intent on a Task of this section (§2). */
  | Exclude<ReplicaIntent, { intent: "task.create" }>;

/** What a batch knows while it is checked, intent by intent. */
interface BatchState {
  /** The validation of the document before the batch (or since section.create, mark_ready). */
  v?: SectionValidation | undefined;
  /** Nodes whose ancestor chain to the section is verified eligible in this batch. */
  readonly chainOk: Set<string>;
}

/** Intents after which every verified ancestor chain still holds. */
const KEEPS_CHAINS: ReadonlySet<string> = new Set([
  "section.create",
  "section.set_title",
  "section.mark_ready",
  "task.create_in_section",
  "paragraph.create",
  "item.create",
  "raw.create",
  "node.set_list_style",
]);

/** §16.2: what one change may carry. */
export const AUTHORING_BUDGET = Object.freeze({ textOperations: 8192, createdNodes: 256 });

export interface SectionLocalChange {
  /** The intents of the batch, by name. */
  readonly intents: readonly string[];
  readonly change: Uint8Array;
  /** The §11 Data Unit plaintext [1, change]. */
  readonly plaintext: Uint8Array;
  readonly hash: string;
  readonly seq: number;
  /** Nodes the batch creates or writes; the section ID when it writes the section. */
  readonly affectedNodeIds: readonly string[];
  /** The document heads after the change, sorted, as one string (SDK-SECTIONS-INTEGRATION-01 §3.2). */
  readonly modelRevision: string;
}

export interface SectionReplicaOptions {
  readonly resource: ResourceId;
  readonly principal: PrincipalId;
}

type Doc = A.Doc<Record<string, unknown>>;
type AMap = Record<string, unknown>;
type Write = (d: AMap) => void;

const S = (s: string) => new A.ImmutableString(s);
const str = (v: unknown): string | undefined =>
  A.isImmutableString(v) ? v.toString() : typeof v === "string" ? v : undefined;
const isListStyle = (s: unknown): s is ListStyle =>
  typeof s === "string" && (LIST_STYLES as readonly string[]).includes(s);
const revisionOf = (doc: Doc) => [...A.getHeads(doc)].sort().join(",");

/** Every concurrent value of `map[key]`. */
function values(map: AMap, key: string): unknown[] {
  if (!(key in map)) return [];
  const c = A.getConflicts(map, key);
  return c === undefined ? [map[key]] : Object.values(c);
}

export class SectionReplica {
  readonly resource: ResourceId;
  /** The §2 Automerge actor ID. */
  readonly actorId: Uint8Array;
  readonly #principal: PrincipalId;
  readonly #actor: string;
  #doc: Doc;

  private constructor(doc: Doc, opts: SectionReplicaOptions) {
    this.resource = opts.resource;
    this.#principal = opts.principal;
    this.actorId = deriveSectionActorId(opts.resource, opts.principal);
    this.#actor = toHex(this.actorId);
    this.#doc = A.getActorId(doc) === this.#actor ? doc : A.clone(doc, { actor: this.#actor });
  }

  /** An empty document, for section.create or for receiving. */
  static empty(opts: SectionReplicaOptions): SectionReplica {
    const actor = toHex(deriveSectionActorId(opts.resource, opts.principal));
    return new SectionReplica(A.init({ actor }), opts);
  }

  /** Loads a full save; SOP §13.1 limits unless it is this device's own state. */
  static fromSave(
    save: Uint8Array,
    opts: SectionReplicaOptions,
    limits: SnapshotLimits | "local-state" = SNAPSHOT_LIMITS_FLOOR,
  ): SectionReplica {
    checkSaveHeader(save);
    if (limits !== "local-state") checkSnapshotExpansion(save, limits);
    try {
      return new SectionReplica(A.load(save), opts);
    } catch (e) {
      if (e instanceof LfcpError) throw e;
      throw new ProfileInvalidError(
        "INVALID_AUTOMERGE_BYTES",
        `invalid Automerge save: ${String(e)}`,
      );
    }
  }

  /** The replica of an admitted change set; changes missing a dependency are returned unapplied. */
  static fromChanges(
    changes: Iterable<Uint8Array>,
    opts: SectionReplicaOptions,
  ): { readonly replica: SectionReplica; readonly unapplied: readonly string[] } {
    const checked = [...changes].map((b) => {
      checkChangeExpansion(b);
      return checkChange(b);
    });
    const [doc] = A.applyChanges(
      A.init<Record<string, unknown>>(),
      checked.map((c) => c.bytes),
    );
    const unapplied = checked.filter((c) => !A.hasHeads(doc, [c.hash])).map((c) => c.hash);
    return { replica: new SectionReplica(doc, opts), unapplied };
  }

  /** §3, §4, §14.2. */
  validate(): SectionValidation {
    return validateSection(this.#doc);
  }

  /** §7, §9, §14.3: the effective tree, hidden nodes and structural facts. */
  tree(): SectionTree {
    return deriveTree(this.#doc);
  }

  /** The document heads, sorted, as one string. */
  revision(): string {
    return revisionOf(this.#doc);
  }

  save(): Uint8Array {
    return A.save(this.#doc);
  }

  /** Every change of the document, in causal order. */
  changes(): Uint8Array[] {
    return A.getAllChanges(this.#doc);
  }

  /** The current state as JSON: scalar strings and Text read as strings. */
  toJSON(): Json {
    return plain(this.#doc);
  }

  /**
   * Validates `intents` as one batch and commits them as one change.
   * Returns null when the batch writes nothing. Throws SectionIntentError,
   * or ProfileError / ObjectIdCollisionError for a Task the SOP refuses.
   */
  commit(intents: readonly SectionIntent[]): SectionLocalChange | null {
    if (intents.length === 0) return null;
    if (A.getActorId(this.#doc) !== this.#actor)
      throw new Error("the document actor is not the §2 actor");
    const writes: Write[] = [];
    const affected = new Set<string>();
    let scratch = A.clone(this.#doc);
    const budget = { text: 0, nodes: 0 };
    // The validation of the document before the batch: nodes the batch
    // creates are valid by construction, so it is computed again only when
    // the batch changes the section itself (create, ready).
    const state: BatchState = { chainOk: new Set() };
    // structure.resolve is its moves, each one checked after the ones before it.
    const steps = intents.flatMap((intent, i): [SectionIntent, number][] =>
      intent.intent === "structure.resolve"
        ? intent.moves.map((m) => [{ intent: "node.resolve_placement", ...m }, i])
        : [[intent, i]],
    );
    steps.forEach(([intent, i]) => {
      const write = this.#prepare(scratch, state, intent, i, affected, budget);
      if (
        budget.text > AUTHORING_BUDGET.textOperations ||
        budget.nodes > AUTHORING_BUDGET.createdNodes
      )
        throw new SectionIntentError(
          "OVER_BUDGET",
          `the batch is over the §16.2 budgets (${budget.text} Text operations, ${budget.nodes} nodes)`,
          i,
        );
      scratch = A.change(scratch, { time: 0 }, write);
      writes.push(write);
      if (intent.intent === "section.create" || intent.intent === "section.mark_ready")
        state.v = undefined;
      // Only creations keep every verified ancestor chain as it was.
      if (!KEEPS_CHAINS.has(intent.intent)) state.chainOk.clear();
    });

    const message = intents.map((x) => x.intent).join(",");
    const before = A.getHeads(this.#doc);
    const next = A.change(this.#doc, { message, time: 0 }, (d) => {
      for (const w of writes) w(d);
    });
    if (A.getHeads(next).join() === before.join()) return null;
    const bytes = A.getLastLocalChange(next) as Uint8Array;
    let checked: CheckedChange;
    try {
      checkChangeExpansion(bytes);
      checked = checkChange(bytes);
    } catch (e) {
      throw new SectionIntentError(
        "OVER_BUDGET",
        `the batch is larger than one change may be (SOP §11.1: ${(e as Error).message})`,
      );
    }
    this.#doc = next;
    return Object.freeze({
      intents: Object.freeze(intents.map((x) => x.intent)),
      change: checked.bytes,
      plaintext: frameProfilePayload(checked.bytes),
      hash: checked.hash,
      seq: checked.seq,
      affectedNodeIds: Object.freeze([...affected].sort()),
      modelRevision: revisionOf(next),
    });
  }

  /**
   * Checks one intent against `doc`, the document with the batch so far,
   * and `state.v`, its validation before the batch; returns its write.
   */
  #prepare(
    doc: Doc,
    state: BatchState,
    intent: SectionIntent,
    i: number,
    affected: Set<string>,
    budget: { text: number; nodes: number },
  ): Write {
    const refuse = (code: SectionIntentCode, message: string, node?: string): never => {
      throw new SectionIntentError(code, message, i, node);
    };

    if (intent.intent === "section.create") {
      if (Object.keys(doc).length > 0)
        refuse("SECTION_EXISTS", "the document already has a root (§4.1)");
      if (!isObjectId(intent.sectionId))
        refuse("INVALID_INTENT", "the SectionId is not a canonical UUIDv7 (§3)");
      checkString(intent.title, "the title", refuse);
      checkCreatedAt(intent.createdAt, refuse);
      affected.add(intent.sectionId);
      const createdBy = principalRef(intent.createdBy);
      return (d) => {
        d.profile = S(SECTIONS_PROFILE_ID);
        d.section = {
          id: S(intent.sectionId),
          title: S(intent.title),
          created_by: S(createdBy),
          ...(intent.createdAt === undefined ? {} : { created_at: S(intent.createdAt) }),
          children: [],
          extensions: {},
          ...(intent.ready === false ? {} : { ready: true }),
        };
        d.objects = {};
        d.nodes = {};
        d.placements = {};
        d.extensions = {};
      };
    }

    // Every other intent writes into a valid section.
    state.v ??= validateSection(doc);
    const v = state.v;
    if (v.state === "invalid" || v.sectionId === undefined)
      refuse(
        "SECTION_INVALID",
        `the document is not a valid section: ${v.problems[0]?.message ?? "no root"}`,
      );
    const section = doc.section as AMap;
    if (v.state === "importing" && str(section.created_by) !== principalRef(this.#principal))
      refuse("SECTION_IMPORTING", "the section is being imported by its creator (§12.1)");
    const sectionId = v.sectionId as string;

    if (intent.intent === "section.mark_ready") {
      if (v.state === "ready")
        refuse("SECTION_EXISTS", "the section is ready already; ready is written once (§12.1)");
      if (str(section.created_by) !== principalRef(this.#principal))
        refuse("SECTION_IMPORTING", "only the section's creator writes ready (§12.1)");
      affected.add(sectionId);
      return (d) => {
        (d.section as AMap).ready = true;
      };
    }

    if (intent.intent === "section.set_title") {
      checkString(intent.title, "the title", refuse);
      affected.add(sectionId);
      return (d) => {
        const s = d.section as AMap;
        // §58 (G-SC4): an unchanged value is deleted first so the intent writes.
        if (str(s.title) === intent.title) delete s.title;
        s.title = S(intent.title);
      };
    }

    if (
      intent.intent === "task.create_in_section" ||
      intent.intent === "paragraph.create" ||
      intent.intent === "item.create" ||
      intent.intent === "raw.create"
    ) {
      const isTask = intent.intent === "task.create_in_section";
      const id = isTask ? String(intent.task.id) : intent.id;
      const kind = isTask ? "task" : intent.intent.slice(0, intent.intent.indexOf("."));
      if (!isObjectId(id))
        refuse("INVALID_INTENT", `the node ID ${id} is not a canonical UUIDv7 (§3)`, id);
      if (idInUse(doc, sectionId, id))
        refuse("ID_IN_USE", `the ID ${id} is already used in the Resource (§3)`, id);
      const placementId = intent.placementId ?? generateObjectId();
      if (!isObjectId(placementId))
        refuse("INVALID_INTENT", "the PlacementId is not a canonical UUIDv7 (§3)", id);
      if (placementId === id || idInUse(doc, sectionId, placementId))
        refuse("ID_IN_USE", `the PlacementId ${placementId} is already used (§3)`, id);
      const listStyle = intent.listStyle;
      if (
        listStyle !== undefined &&
        (!isListStyle(listStyle) || kind === "paragraph" || kind === "raw")
      )
        refuse(
          "INVALID_INTENT",
          "list_style is bullet or ordered, on task and item nodes only (§4.2)",
          id,
        );
      const index = insertionIndex(
        doc,
        v,
        sectionId,
        intent.parent,
        intent.after,
        refuse,
        undefined,
        state.chainOk,
      );

      let createdBy: string;
      let node: AMap;
      let taskWrite: ((o: AMap) => void) | undefined;
      if (isTask) {
        const prepared = prepareTaskIntent(doc, doc.objects as AMap, {
          intent: "task.create",
          task: intent.task,
        });
        taskWrite = prepared.perform;
        createdBy = String(intent.task.created_by);
        node = {
          id: S(id),
          kind: S("task"),
          created_by: S(createdBy),
          ...(intent.task.created_at === undefined
            ? {}
            : { created_at: S(intent.task.created_at) }),
          lifecycle: S("active"),
          placement: S(placementId),
          children: [],
          extensions: {},
          task_id: S(id),
          list_style: S(listStyle ?? "bullet"),
        };
      } else {
        checkString(intent.text, "the text", refuse);
        checkCreatedAt(intent.createdAt, refuse);
        createdBy = principalRef(intent.createdBy);
        budget.text += Array.from(intent.text).length;
        node = {
          id: S(id),
          kind: S(kind),
          created_by: S(createdBy),
          ...(intent.createdAt === undefined ? {} : { created_at: S(intent.createdAt) }),
          lifecycle: S("active"),
          placement: S(placementId),
          children: [],
          extensions: {},
          text: intent.text,
          ...(kind === "item" ? { list_style: S(listStyle ?? "bullet") } : {}),
        };
      }
      budget.nodes += 1;
      affected.add(id);
      if (intent.parent === sectionId || state.chainOk.has(intent.parent)) state.chainOk.add(id);
      const parent = intent.parent;
      return (d) => {
        taskWrite?.(d.objects as AMap);
        (d.nodes as AMap)[id] = node;
        (d.placements as AMap)[placementId] = {
          id: S(placementId),
          node_id: S(id),
          parent_id: S(parent),
          created_by: S(createdBy),
        };
        const lane = (
          parent === sectionId
            ? (d.section as AMap).children
            : ((d.nodes as AMap)[parent] as AMap).children
        ) as unknown[];
        lane.splice(index, 0, S(placementId));
      };
    }

    if (intent.intent === "node.delete" || intent.intent === "node.restore") {
      const id = intent.id;
      const node = (doc.nodes as AMap)[id] as AMap | undefined;
      if (node === undefined) refuse("UNKNOWN_NODE", `${id} names no node`, id);
      if (v.nodes.has(id) || collidedSet(v).has(id))
        refuse("NODE_IN_CONFLICT", `${id} is invalid or collides (§14.2)`, id);
      const isTask = str((node as AMap).kind) === "task";
      const value = intent.intent === "node.delete" ? "deleted" : "active";
      affected.add(id);
      return (d) => {
        const owner = (isTask ? (d.objects as AMap)[id] : (d.nodes as AMap)[id]) as AMap;
        // §9: a same-value assignment would be dropped by the binding, so the
        // other valid value is written first, in the same change.
        if (str(owner.lifecycle) === value)
          owner.lifecycle = S(value === "active" ? "deleted" : "active");
        owner.lifecycle = S(value);
      };
    }

    if (
      intent.intent === "node.move" ||
      intent.intent === "node.resolve_placement" ||
      intent.intent === "node.set_list_style"
    ) {
      const id = intent.id;
      const node = (doc.nodes as AMap)[id] as AMap | undefined;
      if (node === undefined) refuse("UNKNOWN_NODE", `${id} names no node`, id);
      if (v.nodes.has(id) || collidedSet(v).has(id))
        refuse("NODE_IN_CONFLICT", `${id} is invalid or collides (§14.2)`, id);
      const kind = str((node as AMap).kind);
      affected.add(id);
      if (intent.intent === "node.set_list_style") {
        if (!isListStyle(intent.listStyle) || (kind !== "task" && kind !== "item"))
          refuse(
            "INVALID_INTENT",
            "list_style is bullet or ordered, on task and item nodes only (§4.2)",
            id,
          );
        const style = intent.listStyle;
        return (d) => {
          const n = (d.nodes as AMap)[id] as AMap;
          // §58 (G-SC4): an unchanged value is deleted first so the intent writes.
          if (str(n.list_style) === style) delete n.list_style;
          n.list_style = S(style);
        };
      }
      if (intent.intent === "node.move" && values(node as AMap, "placement").length !== 1)
        refuse(
          "NODE_IN_CONFLICT",
          `${id} has concurrent placements: use node.resolve_placement (§7, §8)`,
          id,
        );
      const placementId = intent.placementId ?? generateObjectId();
      if (!isObjectId(placementId))
        refuse("INVALID_INTENT", "the PlacementId is not a canonical UUIDv7 (§3)", id);
      if (idInUse(doc, sectionId, placementId))
        refuse("ID_IN_USE", `the PlacementId ${placementId} is already used (§3)`, id);
      const index = insertionIndex(doc, v, sectionId, intent.parent, intent.after, refuse, id);
      const createdBy = principalRef(this.#principal);
      const parent = intent.parent;
      return (d) => {
        (d.placements as AMap)[placementId] = {
          id: S(placementId),
          node_id: S(id),
          parent_id: S(parent),
          created_by: S(createdBy),
        };
        const lane = (
          parent === sectionId
            ? (d.section as AMap).children
            : ((d.nodes as AMap)[parent] as AMap).children
        ) as unknown[];
        lane.splice(index, 0, S(placementId));
        // §5: the node's register selects the new slot; the old one stays as an anchor.
        ((d.nodes as AMap)[id] as AMap).placement = S(placementId);
      };
    }

    // A SOP Task intent on a Task of this section (§2).
    const prepared = prepareTaskIntent(
      doc,
      doc.objects as AMap,
      intent as Exclude<ReplicaIntent, { intent: "task.create" }>,
    );
    affected.add(prepared.id);
    return (d) => prepared.perform(d.objects as AMap);
  }
}

/** §3: a lone surrogate code point is not valid Unicode. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function checkString(
  text: unknown,
  what: string,
  refuse: (c: SectionIntentCode, m: string) => never,
) {
  if (typeof text !== "string" || LONE_SURROGATE.test(text))
    refuse("INVALID_INTENT", `${what} must be a string of valid Unicode (§3)`);
}

function checkCreatedAt(
  at: string | undefined,
  refuse: (c: SectionIntentCode, m: string) => never,
) {
  if (at !== undefined && !isUtcTimestamp(at))
    refuse("INVALID_INTENT", "created_at is not an RFC 3339 UTC timestamp (§3)");
}

const collidedSets = new WeakMap<SectionValidation, ReadonlySet<string>>();
/** The collided nodes of a validation as a set, built once per validation. */
function collidedSet(v: SectionValidation): ReadonlySet<string> {
  let set = collidedSets.get(v);
  if (set === undefined) {
    set = new Set(v.collided);
    collidedSets.set(v, set);
  }
  return set;
}

/** §3: whether `id` already names the section, a node, a placement or an object. */
function idInUse(doc: Doc, sectionId: string, id: string): boolean {
  return (
    id === sectionId ||
    id in (doc.nodes as AMap) ||
    id in (doc.placements as AMap) ||
    id in (doc.objects as AMap)
  );
}

/**
 * §6: the physical index in the parent's children list at which a new
 * placement goes. The parent is the section, or a valid, active,
 * unconflicted task or item node whose ancestors are too; `after` is a
 * visible child of it, and the new entry goes right after its selected
 * placement, keeping every historical slot.
 */
function insertionIndex(
  doc: Doc,
  v: SectionValidation,
  sectionId: string,
  parent: string,
  after: string | null,
  refuse: (c: SectionIntentCode, m: string, node?: string) => never,
  moving?: string,
  /** Nodes whose ancestor chain this batch already verified; unused for a move. */
  chainOk?: Set<string>,
): number {
  const nodes = doc.nodes as AMap;
  const placements = doc.placements as AMap;
  const objects = doc.objects as AMap;
  /** The selected parent of an eligible node, or why it is not eligible. */
  const eligible = (id: string): { parent: string } | { why: string } => {
    const node = nodes[id] as AMap | undefined;
    if (node === undefined) return { why: "names no node" };
    if (v.nodes.has(id) || collidedSet(v).has(id)) return { why: "is invalid (§14.2)" };
    const kind = str(node.kind);
    const owner = kind === "task" ? (objects[id] as AMap) : node;
    const life = values(owner, "lifecycle").map(str);
    if (life.length !== 1) return { why: "has a lifecycle conflict (§9)" };
    if (life[0] !== "active") return { why: "is deleted (§9)" };
    const selected = values(node, "placement").map(str);
    if (selected.length !== 1) return { why: "has a placement conflict (§7)" };
    const placement = placements[selected[0] as string] as AMap | undefined;
    if (placement === undefined) return { why: "has no placement" };
    return { parent: str(placement.parent_id) as string };
  };
  if (parent !== sectionId) {
    const kind = str((nodes[parent] as AMap | undefined)?.kind);
    if (kind === undefined || !PARENT_KINDS.has(kind as never))
      refuse(
        "INVALID_PARENT",
        `the parent ${parent} is not the section, a task or an item (§4.2)`,
        parent,
      );
    // The parent and every ancestor are eligible, without a cycle (§6, §7).
    const seen = new Set<string>();
    let p = parent;
    while (p !== sectionId) {
      if (moving === undefined && chainOk?.has(p)) break;
      if (p === moving)
        refuse(
          "INVALID_PARENT",
          `${moving} cannot move under itself or its descendant (§6)`,
          moving,
        );
      if (seen.has(p)) refuse("INVALID_PARENT", `the parent ${parent} is in a cycle (§7)`, parent);
      seen.add(p);
      const e = eligible(p);
      if ("why" in e) refuse("INVALID_PARENT", `the parent's ancestor ${p} ${e.why}`, parent);
      p = (e as { parent: string }).parent;
    }
    if (moving === undefined) for (const n of seen) chainOk?.add(n);
  }
  const lane = (
    parent === sectionId ? (doc.section as AMap).children : (nodes[parent] as AMap).children
  ) as unknown[];
  if (after === null) return 0;
  if (after === moving) refuse("INVALID_PREDECESSOR", `${after} cannot follow itself (§6)`, after);
  const e = eligible(after);
  if ("why" in e || e.parent !== parent)
    refuse("INVALID_PREDECESSOR", `${after} is not a visible child of ${parent} (§6)`, after);
  const slot = str(values(nodes[after] as AMap, "placement")[0]);
  const at = lane.findIndex((x) => str(x) === slot);
  if (at < 0)
    refuse("INVALID_PREDECESSOR", `${after}'s placement is not in the parent's list (§4.3)`, after);
  return at + 1;
}

function plain(value: unknown): Json {
  if (A.isImmutableString(value)) return value.toString();
  if (Array.isArray(value)) return value.map(plain);
  if (value !== null && typeof value === "object" && !(value instanceof Uint8Array))
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]));
  return value as Json;
}
