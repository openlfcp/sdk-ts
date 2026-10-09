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
import { admitBatch } from "../admission/sequence.js";
import { ProfileInvalidError } from "../profile-invalid.js";
import { prepareTaskIntent, type ReplicaIntent, type TaskView, taskView } from "../replica.js";
import type { Task } from "../task.js";
import type { Json } from "../validate.js";
import { frameProfilePayload, isUtcTimestamp, principalRef } from "../values.js";
import { SectionAdmission } from "./admission.js";
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
  | "OVER_BUDGET"
  /** A Text position names a base revision the SDK cannot rebase onto the current Text (§10). */
  | "STALE_BASE";

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
  /**
   * §10: edits of a node's existing Text, in Unicode scalar positions of the
   * Text at `base` (a modelRevision): sorted, not overlapping, each against
   * the base text as CodeMirror changes are. They are rebased onto the
   * current Text; a deleted range that changed since `base` is STALE_BASE.
   */
  | {
      readonly intent: "text.edit";
      readonly id: string;
      readonly base: string;
      readonly edits: readonly TextEdit[];
    }
  /**
   * §10: the node keeps the prefix before `at` (a scalar position at
   * `base`); a new node of the same kind, `newId`, gets the suffix right
   * after it under the same parent. An item's children stay with it.
   */
  | ({
      readonly intent: "paragraph.split" | "item.split";
      readonly id: string;
      readonly base: string;
      readonly at: number;
      readonly newId: string;
      readonly createdBy: PrincipalId;
    } & Pick<Position, "placementId">)
  /**
   * §10: two adjacent paragraphs, or items of one list style, without
   * children: `id` gets `separator` (default LF) and `second`'s current
   * text, and `second` is deleted with its Text history kept.
   */
  | {
      readonly intent: "node.join";
      readonly id: string;
      readonly second: string;
      readonly separator?: string;
    }
  /** §4.2: ordered or bullet list membership, on task and item nodes. */
  | { readonly intent: "node.set_list_style"; readonly id: string; readonly listStyle: ListStyle }
  /** A SHARED-OBJECTS-PROFILE-01 Task intent on a Task of this section (§2). */
  | Exclude<ReplicaIntent, { intent: "task.create" }>;

/** One Text edit in Unicode scalar positions (§10). */
export interface TextEdit {
  readonly index: number;
  readonly deleteCount: number;
  readonly insert: string;
}

/** What a batch knows while it is checked, intent by intent. */
interface BatchState {
  /** The validation of the document before the batch (or since section.create, mark_ready). */
  v?: SectionValidation | undefined;
  /** Nodes whose ancestor chain to the section is verified eligible in this batch. */
  readonly chainOk: Set<string>;
  /** §12.3: where a run of a long Text edit continues, per node (a UTF-16 index). */
  readonly cursor: Map<string, number>;
}

/** §12.3: the next run of a long Text edit, at the node's cursor in this batch. Internal. */
interface TextContinue {
  readonly intent: "text.continue";
  readonly id: string;
  readonly deleteCount: number;
  readonly insert: string;
}
type Step = SectionIntent | TextContinue;

/**
 * §12, §12.3: splits what one change cannot carry. A Text edit or a new
 * node's text over the Text budget continues in runs at its cursor; a
 * batch that creates the section writes `ready` in its last change
 * (§12.1), whatever number of changes it becomes.
 */
function expand(intents: readonly SectionIntent[]): Step[] {
  const LIMIT = AUTHORING_BUDGET.textOperations;
  const runs = (id: string, deleteCount: number, insert: string[]): TextContinue[] => {
    const out: TextContinue[] = [];
    for (let left = deleteCount; left > 0; left -= LIMIT)
      out.push({ intent: "text.continue", id, deleteCount: Math.min(left, LIMIT), insert: "" });
    for (let at = 0; at < insert.length; at += LIMIT)
      out.push({
        intent: "text.continue",
        id,
        deleteCount: 0,
        insert: insert.slice(at, at + LIMIT).join(""),
      });
    return out;
  };
  const out: Step[] = [];
  let ready = false;
  for (const intent of intents) {
    if (intent.intent === "section.create" && intent.ready !== false) {
      out.push({ ...intent, ready: false });
      ready = true;
    } else if (intent.intent === "text.edit" && intent.edits.length === 1) {
      const e = intent.edits[0] as TextEdit;
      const insert = Array.from(e.insert);
      if (e.deleteCount + insert.length <= LIMIT) out.push(intent);
      else {
        const d0 = Math.min(e.deleteCount, LIMIT);
        const i0 = insert.slice(0, LIMIT - d0);
        out.push({ ...intent, edits: [{ index: e.index, deleteCount: d0, insert: i0.join("") }] });
        out.push(...runs(intent.id, e.deleteCount - d0, insert.slice(i0.length)));
      }
    } else if (
      (intent.intent === "paragraph.create" ||
        intent.intent === "item.create" ||
        intent.intent === "raw.create") &&
      typeof intent.text === "string" &&
      Array.from(intent.text).length > LIMIT
    ) {
      const text = Array.from(intent.text);
      out.push({ ...intent, text: text.slice(0, LIMIT).join("") });
      out.push(...runs(intent.id, 0, text.slice(LIMIT)));
    } else out.push(intent);
  }
  if (ready) out.push({ intent: "section.mark_ready" });
  return out;
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

/** One change of a batch, as its Data Unit carries it. */
export interface SectionChangePart {
  readonly change: Uint8Array;
  /** The §11 Data Unit plaintext [1, change]. */
  readonly plaintext: Uint8Array;
  readonly hash: string;
  readonly seq: number;
}

/**
 * A committed batch. A batch over the §16.2 budgets is several changes
 * (§12, §12.3): `parts`, in order, one Data Unit each; `change`, `hash`,
 * `seq` and `plaintext` name the last of them (the only one, usually).
 */
export interface SectionLocalChange {
  /** The intents of the batch, by name. */
  readonly intents: readonly string[];
  /** Every change of the batch, in order. */
  readonly parts: readonly SectionChangePart[];
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

/** A received change with the Principal that signed its Data Unit (§2). */
export interface SectionUnit {
  readonly bytes: Uint8Array;
  readonly signer?: PrincipalId;
}

/** A received change that was not merged. */
export interface SectionRefusal {
  /** Its position in the received list. */
  readonly index: number;
  /** Its change hash; undefined when the SOP checks refused the bytes, which are then never decoded. */
  readonly hash: string | undefined;
  /** The §14.1 diagnostic (SOP §74.1 for the inherited checks), or ACTOR_EQUIVOCATION when held. */
  readonly diagnostic: string;
  /** Held (SOP §14.1, POST-001): its actor and sequence belong to another change; retried after a rebuild. */
  readonly held: boolean;
  readonly message: string;
}

export interface SectionReceiveResult {
  /** Merged now, in causal order. */
  readonly admitted: readonly string[];
  /** Already in the document. */
  readonly duplicates: readonly string[];
  /** Missing a dependency: not received yet, or refused, or waiting itself. */
  readonly waiting: readonly string[];
  readonly refused: readonly SectionRefusal[];
}

/** One node of a snapshot (SectionReplica.snapshot). */
export interface SectionSnapshotNode {
  readonly kind: string;
  /** The section ID or the parent node of the selected placement; undefined when it has none. */
  readonly parent: string | undefined;
  /** Paragraph, item and raw nodes: the Text, with LF line breaks. */
  readonly text?: string;
  readonly listStyle?: ListStyle;
  /** Task nodes: the Task's ID (the node's own). */
  readonly taskId?: string;
  /** Deleted itself (a Task node: its Task); delete projected lines only for this. */
  readonly deleted: boolean;
  /** Deleted itself or under a deleted ancestor: not shown. */
  readonly hidden: boolean;
}

/** One synchronous read of a section on one revision (SectionReplica.snapshot). */
export interface SectionSnapshot {
  /** The document heads, sorted, as one string: a receipt's modelRevision, text.edit's base. */
  readonly revision: string;
  readonly classification: SectionTree["classification"];
  readonly title: { readonly value: string | undefined; readonly conflicts: readonly string[] };
  /** Every node but colliding ones, by ID. */
  readonly nodes: Readonly<Record<string, SectionSnapshotNode>>;
  /** The visible nodes in projection order (preorder), with parent and depth. */
  readonly order: SectionTree["tree"];
  readonly problems: {
    readonly recovery: SectionTree["recovery"];
    readonly invalid: SectionTree["invalid"];
    readonly collisions: SectionTree["collisions"];
    readonly retainedConcurrentEdits: SectionTree["retainedConcurrentEdits"];
    readonly scalarConflicts: SectionTree["scalarConflicts"];
  };
}

/** A batch validated and changed on a copy (SectionReplica.stage): applied only on request. */
export interface StagedSectionChange {
  readonly change: SectionLocalChange;
  /** Adopts the change; throws if the replica moved on since staging. Idempotent. */
  apply(): void;
  /**
   * Undoes apply() while nothing came after it: the replica holds the
   * document it had before (its storage commit failed, or the operation
   * had committed already). Idempotent.
   */
  revert(): void;
}

export interface SectionReplicaOptions {
  readonly resource: ResourceId;
  readonly principal: PrincipalId;
  /**
   * SOP §9: the actor sequence this device already used (a restored
   * checkpoint's). Below it the replica writes nothing: its next change
   * would reuse a sequence number another change of this actor has.
   */
  readonly minSeq?: number;
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

/** PROFILE_INVALID for a Snapshot, with the diagnostic of what refused it. */
function snapshotRefused(diagnostic: string, message: string): LfcpError {
  return Object.assign(new LfcpError("PROFILE_INVALID", message), { diagnostic });
}

export class SectionReplica {
  readonly resource: ResourceId;
  /** The §2 Automerge actor ID. */
  readonly actorId: Uint8Array;
  readonly #principal: PrincipalId;
  readonly #actor: string;
  readonly #minSeq: number;
  #doc: Doc;

  private constructor(doc: Doc, opts: SectionReplicaOptions) {
    this.resource = opts.resource;
    this.#minSeq = opts.minSeq ?? 0;
    this.#principal = opts.principal;
    this.actorId = deriveSectionActorId(opts.resource, opts.principal);
    this.#actor = toHex(this.actorId);
    this.#doc = A.getActorId(doc) === this.#actor ? doc : A.clone(doc, { actor: this.#actor });
  }

  /** This actor's latest change sequence in the document (0 when it has none). */
  get actorSeq(): number {
    return this.#sequences().get(this.#actor) ?? 0;
  }

  /** SOP §9: whether this replica may write (it is not behind its actor's used sequence). */
  get writable(): boolean {
    return this.actorSeq >= this.#minSeq;
  }

  /**
   * §12.1: "ready" once the section's `ready` is written, "importing"
   * before, undefined while the document has no section. Reads one
   * register; validate() tells whether the section is valid.
   */
  sectionState(): "ready" | "importing" | undefined {
    const section = (this.#doc as AMap).section;
    if (section === null || typeof section !== "object" || A.isImmutableString(section))
      return undefined;
    return (section as AMap).ready === true ? "ready" : "importing";
  }

  /** Whether the document holds the change with this hex hash. */
  hasChange(hash: string): boolean {
    return A.hasHeads(this.#doc, [hash]);
  }

  /**
   * SOP §14.1 (G-EP7): the replica rebuilt from its changes minus `exclude`
   * (change hashes); changes that depend on an excluded one are unapplied
   * too. An excluded change of this actor is not lost state (§9): the
   * rebuilt replica writes on from its own sequence.
   */
  rebuildWithout(exclude: Iterable<string>): {
    readonly replica: SectionReplica;
    readonly unapplied: readonly string[];
  } {
    const out = new Set(exclude);
    const kept = A.getAllChanges(this.#doc).filter((c) => !out.has(A.decodeChange(c).hash));
    return SectionReplica.fromChanges(kept, {
      resource: this.resource,
      principal: this.#principal,
      minSeq: this.writable ? 0 : this.#minSeq,
    });
  }

  /**
   * This replica merged with a received Snapshot's full save (SOP §13,
   * §14): every change the save holds is admitted as if received one by
   * one (the SOP checks and A1–A5, §14.1), on an empty replica of this
   * actor, so a Snapshot that holds a change admission refuses is
   * rejected; then this replica's own changes follow, so local work the
   * Snapshot lacks is kept. The §9 sequence carries over. Throws
   * PROFILE_INVALID (with the refused change's diagnostic, or
   * INVALID_AUTOMERGE_BYTES) and keeps this replica unchanged.
   */
  mergeSave(save: Uint8Array, limits: SnapshotLimits = SNAPSHOT_LIMITS_FLOOR): SectionReplica {
    const opts = {
      resource: this.resource,
      principal: this.#principal,
      minSeq: Math.max(this.#minSeq, this.actorSeq),
    };
    const image = SectionReplica.fromSave(save, opts, limits);
    const merged = SectionReplica.empty(opts);
    const r = merged.receiveChanges(image.changes());
    const refused = r.refused.find((x) => !x.held) ?? r.refused[0];
    if (refused !== undefined)
      throw snapshotRefused(
        refused.diagnostic,
        `the Snapshot holds a change admission refuses: ${refused.message}`,
      );
    if (r.waiting.length > 0)
      throw snapshotRefused(
        "INVALID_AUTOMERGE_BYTES",
        "the Snapshot holds a change whose dependency it lacks",
      );
    const own = merged.receiveChanges(this.changes());
    const lost = own.refused[0];
    if (lost !== undefined)
      throw snapshotRefused(
        lost.diagnostic,
        `local state does not merge with the Snapshot: ${lost.message}`,
      );
    return merged;
  }

  /** An empty replica of the same actor that keeps the §9 sequence (SNAP-EP reset). */
  emptied(): SectionReplica {
    return SectionReplica.empty({
      resource: this.resource,
      principal: this.#principal,
      minSeq: Math.max(this.#minSeq, this.actorSeq),
    });
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

  /**
   * Receives changes others wrote, as LFCP accepted them (§14.1): each
   * passes the inherited SOP checks (framing, §11.1 expansion, the signer's
   * actor when `signer` is given, the sequence check, holding a taken
   * actor sequence) and the section rules A1–A5 and §12.1, against its
   * causal history, before the engine applies any. A refused change is
   * never merged; the changes that depend on it wait.
   */
  receiveChanges(items: readonly (Uint8Array | SectionUnit)[]): SectionReceiveResult {
    const refused: SectionRefusal[] = [];
    const checked: CheckedChange[] = [];
    const indexOf = new Map<string, number>();
    items.forEach((item, index) => {
      const unit = item instanceof Uint8Array ? { bytes: item } : item;
      let c: CheckedChange;
      try {
        c = checkChange(unit.bytes);
      } catch (e) {
        // Never decoded again, not even for its hash: the checks refused to expand it.
        refused.push(refusal(index, undefined, e, false));
        return;
      }
      if (
        unit.signer !== undefined &&
        c.actor !== toHex(deriveSectionActorId(this.resource, unit.signer))
      ) {
        refused.push({
          index,
          hash: c.hash,
          diagnostic: "CHANGE_ACTOR_MISMATCH",
          held: false,
          message: `the change's actor ${c.actor} is not the §2 actor of the unit's signer`,
        });
        return;
      }
      if (indexOf.has(c.hash)) return;
      indexOf.set(c.hash, index);
      checked.push(c);
    });
    const seqs = this.#sequences();
    const admission = new SectionAdmission(this.#doc, this.resource);
    const decided = admitBatch(
      checked,
      {
        hasChange: (hash) => A.hasHeads(this.#doc, [hash]),
        latestSeq: (actor) => seqs.get(actor) ?? 0,
      },
      (c) => admission.accept(c),
    );
    for (const r of decided.refused)
      refused.push(refusal(indexOf.get(r.change.hash) ?? -1, r.change.hash, r.error, r.held));
    if (decided.admitted.length > 0) {
      // The admission applied each admitted change, at its turn, to its working copy.
      this.#doc = admission.document as Doc;
      for (const c of decided.admitted)
        if (c.seq > (seqs.get(c.actor) ?? 0)) seqs.set(c.actor, c.seq);
    }
    const hashes = (list: readonly CheckedChange[]) => Object.freeze(list.map((c) => c.hash));
    return Object.freeze({
      admitted: hashes(decided.admitted),
      duplicates: hashes(decided.duplicates),
      waiting: hashes(decided.waiting),
      refused: Object.freeze(refused.sort((a, b) => a.index - b.index)),
    });
  }

  /** Each actor's latest sequence number in the document, read once and kept current. */
  #seqs: Map<string, number> | undefined;
  #sequences(): Map<string, number> {
    if (this.#seqs === undefined) {
      this.#seqs = new Map();
      for (const bytes of A.getAllChanges(this.#doc)) {
        const c = A.decodeChange(bytes);
        if (c.seq > (this.#seqs.get(c.actor) ?? 0)) this.#seqs.set(c.actor, c.seq);
      }
    }
    return this.#seqs;
  }

  /**
   * Everything an editor projects, in one synchronous read of one revision:
   * the title (and its concurrent values), each node, the visible order,
   * and the problems to show. `revision` is the modelRevision of a commit
   * receipt and the `base` of text.edit.
   */
  snapshot(): SectionSnapshot {
    const tree = deriveTree(this.#doc);
    const root = this.#doc as AMap;
    const section = (root.section ?? {}) as AMap;
    const nodes = (root.nodes ?? {}) as AMap;
    const objects = (root.objects ?? {}) as AMap;
    const placements = (root.placements ?? {}) as AMap;
    const hidden = new Set(tree.hidden);
    const titles = values(section, "title").map(str);
    const out: Record<string, SectionSnapshotNode> = {};
    for (const id of Object.keys(nodes).sort()) {
      if (tree.collisions.includes(id)) continue;
      const n = nodes[id] as AMap;
      const kind = str(n.kind) ?? "";
      const owner = (kind === "task" ? objects[id] : n) as AMap | undefined;
      const placement = placements[str(n.placement) ?? ""] as AMap | undefined;
      const text = n.text;
      out[id] = Object.freeze({
        kind,
        parent: str(placement?.parent_id),
        ...(kind !== "task" && text !== undefined ? { text: String(text) } : {}),
        ...(n.list_style !== undefined ? { listStyle: str(n.list_style) as ListStyle } : {}),
        ...(kind === "task" ? { taskId: id } : {}),
        deleted: str(owner?.lifecycle) === "deleted",
        hidden: hidden.has(id),
      });
    }
    return Object.freeze({
      revision: revisionOf(this.#doc),
      classification: tree.classification,
      title: Object.freeze({
        value: str(section.title),
        conflicts: Object.freeze(titles.length > 1 ? titles.map((t) => t ?? "").sort() : []),
      }),
      nodes: Object.freeze(out),
      order: tree.tree,
      problems: Object.freeze({
        recovery: tree.recovery,
        invalid: tree.invalid,
        collisions: tree.collisions,
        retainedConcurrentEdits: tree.retainedConcurrentEdits,
        scalarConflicts: tree.scalarConflicts,
      }),
    });
  }

  /**
   * The Task of a task node (§4.2: stored under `/objects/<id>`, the node's
   * ID) with its conflict metadata, in the form SharedObjectsReplica.task
   * gives (SOP §99); undefined if there is no object or it is not a Task.
   */
  task(id: string): TaskView | undefined {
    const objects = (this.#doc as AMap).objects;
    return taskView(
      this.#doc,
      objects !== null && typeof objects === "object" && !A.isImmutableString(objects)
        ? (objects as AMap)
        : undefined,
      id,
    );
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
    const staged = this.stage(intents);
    if (staged === null) return null;
    staged.apply();
    return staged.change;
  }

  /**
   * Validates `intents` as one batch and prepares their change without
   * changing this replica: `apply()` adopts it, once the caller has stored
   * it durably (its Data Unit, outbound entry and checkpoint). A batch that
   * is never applied leaves the replica as it was. Null when the batch
   * writes nothing.
   */
  stage(intents: readonly SectionIntent[]): StagedSectionChange | null {
    if (intents.length === 0) return null;
    if (!this.writable)
      throw new LfcpError(
        "SEQUENCE_REUSE",
        `the replica is at actor sequence ${this.actorSeq}, behind ${this.#minSeq} already used (SOP §9)`,
      );
    if (A.getActorId(this.#doc) !== this.#actor)
      throw new Error("the document actor is not the §2 actor");
    const affected = new Set<string>();
    let scratch = A.clone(this.#doc);
    // The validation of the document before the batch: nodes the batch
    // creates are valid by construction, so it is computed again only when
    // the batch changes the section itself (create, ready).
    const state: BatchState = { chainOk: new Set(), cursor: new Map() };
    // structure.resolve is its moves, each one checked after the ones before it.
    const steps = expand(intents).flatMap((intent): Step[] =>
      intent.intent === "structure.resolve"
        ? intent.moves.map((m) => ({ intent: "node.resolve_placement", ...m }))
        : [intent],
    );
    // §12, §16.2: each change carries at most the budgets; a batch over them
    // is several changes, one after the other.
    const chunks: Write[][] = [[]];
    const used = { text: 0, nodes: 0 };
    let i = -1;
    for (const step of steps) {
      if (step.intent !== "text.continue") i = Math.min(i + 1, intents.length - 1);
      const cost = { text: 0, nodes: 0 };
      const write = this.#prepare(scratch, state, step, i, affected, cost);
      if (cost.text > AUTHORING_BUDGET.textOperations || cost.nodes > AUTHORING_BUDGET.createdNodes)
        throw new SectionIntentError(
          "OVER_BUDGET",
          `one intent is over the §16.2 budgets (${cost.text} Text operations, ${cost.nodes} nodes)`,
          i,
        );
      const current = chunks[chunks.length - 1] as Write[];
      if (
        current.length > 0 &&
        (used.text + cost.text > AUTHORING_BUDGET.textOperations ||
          used.nodes + cost.nodes > AUTHORING_BUDGET.createdNodes)
      ) {
        chunks.push([write]);
        used.text = cost.text;
        used.nodes = cost.nodes;
      } else {
        current.push(write);
        used.text += cost.text;
        used.nodes += cost.nodes;
      }
      scratch = A.change(scratch, { time: 0 }, write);
      if (step.intent === "section.create" || step.intent === "section.mark_ready")
        state.v = undefined;
      // Only creations keep every verified ancestor chain as it was.
      if (!KEEPS_CHAINS.has(step.intent)) state.chainOk.clear();
    }

    const message = intents.map((x) => x.intent).join(",");
    const before = A.getHeads(this.#doc);
    // On a clone: A.change outdates the handle it is given, and this
    // replica keeps its own until apply().
    let next = A.clone(this.#doc, { actor: this.#actor });
    const parts: SectionChangePart[] = [];
    for (const chunk of chunks) {
      if (chunk.length === 0) continue;
      const heads = A.getHeads(next).join();
      next = A.change(next, { message, time: 0 }, (d) => {
        for (const w of chunk) w(d);
      });
      if (A.getHeads(next).join() === heads) continue;
      const bytes = A.getLastLocalChange(next) as Uint8Array;
      let checked: CheckedChange;
      try {
        checkChangeExpansion(bytes);
        checked = checkChange(bytes);
      } catch (e) {
        throw new SectionIntentError(
          "OVER_BUDGET",
          `a change of the batch is larger than one change may be (SOP §11.1: ${(e as Error).message})`,
        );
      }
      parts.push(
        Object.freeze({
          change: checked.bytes,
          plaintext: frameProfilePayload(checked.bytes),
          hash: checked.hash,
          seq: checked.seq,
        }),
      );
    }
    if (parts.length === 0 || A.getHeads(next).join() === before.join()) return null;
    const last = parts[parts.length - 1] as SectionChangePart;
    const change: SectionLocalChange = Object.freeze({
      intents: Object.freeze(intents.map((x) => x.intent)),
      parts: Object.freeze(parts),
      ...last,
      affectedNodeIds: Object.freeze([...affected].sort()),
      modelRevision: revisionOf(next),
    });
    const base = revisionOf(this.#doc);
    const prior = this.#doc;
    const priorSeqs = this.#seqs === undefined ? undefined : new Map(this.#seqs);
    let applied = false;
    return Object.freeze({
      change,
      apply: () => {
        if (applied) return;
        if (revisionOf(this.#doc) !== base)
          throw new Error("the replica changed since the batch was staged; stage it again");
        this.#doc = next;
        if (this.#seqs !== undefined && last.seq > (this.#seqs.get(this.#actor) ?? 0))
          this.#seqs.set(this.#actor, last.seq);
        applied = true;
      },
      revert: () => {
        if (!applied) return;
        if (this.#doc !== next)
          throw new Error("the replica changed after the batch was applied; it cannot be reverted");
        this.#doc = prior;
        this.#seqs = priorSeqs === undefined ? undefined : new Map(priorSeqs);
        applied = false;
      },
    });
  }

  /**
   * Checks one intent against `doc`, the document with the batch so far,
   * and `state.v`, its validation before the batch; returns its write.
   */
  #prepare(
    doc: Doc,
    state: BatchState,
    intent: Step,
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
      // A long text continues in later runs (§12.3) from the end of this one.
      if (!isTask) state.cursor.set(id, (intent as { text: string }).text.length);
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

    if (intent.intent === "text.continue") {
      // §12.3: the next run of a long edit, where the previous one ended.
      const id = intent.id;
      const at = state.cursor.get(id);
      const text = String(((doc.nodes as AMap)[id] as AMap | undefined)?.text ?? "");
      if (at === undefined)
        refuse("INVALID_INTENT", `no Text edit of ${id} to continue (§12.3)`, id);
      const removed = Array.from(text.slice(at)).slice(0, intent.deleteCount).join("");
      budget.text += intent.deleteCount + Array.from(intent.insert).length;
      state.cursor.set(id, (at as number) + intent.insert.length);
      affected.add(id);
      const path = ["nodes", id, "text"];
      return (d) => A.splice(d as never, path, at as number, removed.length, intent.insert);
    }

    if (
      intent.intent === "text.edit" ||
      intent.intent === "paragraph.split" ||
      intent.intent === "item.split" ||
      intent.intent === "node.join"
    ) {
      const id = intent.id;
      const node = (doc.nodes as AMap)[id] as AMap | undefined;
      if (node === undefined) refuse("UNKNOWN_NODE", `${id} names no node`, id);
      if (v.nodes.has(id) || collidedSet(v).has(id))
        refuse("NODE_IN_CONFLICT", `${id} is invalid or collides (§14.2)`, id);
      const kind = str((node as AMap).kind);
      if (kind === "task") refuse("INVALID_INTENT", "a task node has no Text (§4.2)", id);
      const current = String((node as AMap).text ?? "");
      const path = ["nodes", id, "text"];

      if (intent.intent === "text.edit") {
        const ranges = rebase(doc, path, intent.base, intent.edits, refuse, id);
        const lastRange = ranges[ranges.length - 1];
        if (lastRange !== undefined) {
          // A later run of this edit (§12.3) continues after what it inserts.
          const shift = ranges
            .slice(0, -1)
            .reduce((n, r) => n + r.insert.length - (r.to - r.from), 0);
          state.cursor.set(id, lastRange.from + shift + lastRange.insert.length);
        }
        for (const e of intent.edits) {
          checkString(e.insert, "inserted text", refuse);
          budget.text += Array.from(e.insert).length + e.deleteCount;
        }
        affected.add(id);
        return (d) => {
          // From the end, so earlier positions stay valid.
          for (const r of [...ranges].reverse())
            A.splice(d as never, path, r.from, r.to - r.from, r.insert);
        };
      }

      if (intent.intent === "node.join") {
        const second = intent.second;
        const other = (doc.nodes as AMap)[second] as AMap | undefined;
        if (other === undefined) refuse("UNKNOWN_NODE", `${second} names no node`, second);
        if (v.nodes.has(second) || collidedSet(v).has(second))
          refuse("NODE_IN_CONFLICT", `${second} is invalid or collides (§14.2)`, second);
        const otherKind = str((other as AMap).kind);
        const sameStyle =
          kind === "paragraph" ||
          values(node as AMap, "list_style").join() === values(other as AMap, "list_style").join();
        if (otherKind !== kind || (kind !== "paragraph" && kind !== "item") || !sameStyle)
          refuse(
            "INVALID_INTENT",
            "only two paragraphs, or two items of one list style, join (§10)",
            id,
          );
        const kids = (n: AMap) => ((n.children as unknown[] | undefined) ?? []).length;
        if (kids(node as AMap) > 0 || kids(other as AMap) > 0)
          refuse("INVALID_INTENT", "a node with children does not join (§10)", id);
        if (!adjacent(doc, v, id, second))
          refuse(
            "INVALID_INTENT",
            `${second} is not the visible sibling right after ${id} (§10)`,
            second,
          );
        const separator = intent.separator ?? "\n";
        checkString(separator, "the separator", refuse);
        const appended = separator + String((other as AMap).text ?? "");
        const at = current.length;
        budget.text += Array.from(appended).length;
        affected.add(id);
        affected.add(second);
        return (d) => {
          A.splice(d as never, path, at, 0, appended);
          // §9, §10: the second node is deleted with a fresh write; its Text stays.
          const o = (d.nodes as AMap)[second] as AMap;
          if (str(o.lifecycle) === "deleted") o.lifecycle = S("active");
          o.lifecycle = S("deleted");
        };
      }

      // split: a deletion of the suffix and a new node after this one.
      if (intent.intent.slice(0, intent.intent.indexOf(".")) !== kind)
        refuse("INVALID_INTENT", `${intent.intent} on a ${kind} node (§10)`, id);
      if (
        values(node as AMap, "placement").length !== 1 ||
        new Set(values(node as AMap, "lifecycle")).size !== 1
      )
        refuse("NODE_IN_CONFLICT", `${id} has unresolved structure (§10)`, id);
      const cut = rebase(
        doc,
        path,
        intent.base,
        [{ index: intent.at, deleteCount: 0, insert: "" }],
        refuse,
        id,
      )[0] as { from: number };
      const suffix = current.slice(cut.from);
      const placement = (doc.placements as AMap)[str((node as AMap).placement) as string] as AMap;
      const parent = str(placement.parent_id) as string;
      const create = this.#prepare(
        doc,
        state,
        {
          intent: kind === "item" ? "item.create" : "paragraph.create",
          id: intent.newId,
          parent,
          after: id,
          text: suffix,
          createdBy: intent.createdBy,
          ...(kind === "item"
            ? { listStyle: (str((node as AMap).list_style) ?? "bullet") as ListStyle }
            : {}),
          ...(intent.placementId === undefined ? {} : { placementId: intent.placementId }),
        },
        i,
        affected,
        budget,
      );
      budget.text += Array.from(suffix).length;
      affected.add(id);
      return (d) => {
        A.splice(d as never, path, cut.from, current.length - cut.from, "");
        create(d);
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

/**
 * §10: the Text edits at `base` as UTF-16 ranges of the current Text.
 * Each position is the current place of the character it stood before at
 * `base` (an Automerge cursor taken at the base heads); a deleted range
 * must still hold exactly the text it held then.
 */
function rebase(
  doc: Doc,
  path: string[],
  base: string,
  edits: readonly TextEdit[],
  refuse: (c: SectionIntentCode, m: string, node?: string) => never,
  node: string,
): { from: number; to: number; insert: string }[] {
  const heads = base === "" ? [] : base.split(",");
  let view: Doc;
  try {
    if (!heads.every((h) => /^[0-9a-f]{64}$/.test(h)) || !A.hasHeads(doc, heads)) throw new Error();
    view = A.view(doc, heads);
  } catch {
    return refuse("STALE_BASE", `the base revision is not in this document (§10)`, node);
  }
  const before = String(
    ((view.nodes as AMap | undefined)?.[path[1] as string] as AMap | undefined)?.text ?? "",
  );
  const scalars = Array.from(before);
  const utf16 = (scalar: number) => scalars.slice(0, scalar).join("").length;
  const now = String(((doc.nodes as AMap)[path[1] as string] as AMap).text ?? "");
  let last = 0;
  return edits.map((e) => {
    if (
      !Number.isInteger(e.index) ||
      !Number.isInteger(e.deleteCount) ||
      e.index < last ||
      e.deleteCount < 0 ||
      e.index + e.deleteCount > scalars.length
    )
      refuse(
        "INVALID_INTENT",
        "Text edits are sorted, do not overlap and stay within the base Text (§10)",
        node,
      );
    last = e.index + e.deleteCount;
    const position = (scalar: number) => {
      try {
        return A.getCursorPosition(doc, path, A.getCursor(view, path, utf16(scalar)));
      } catch {
        return refuse("STALE_BASE", "a Text position cannot be rebased (§10)", node);
      }
    };
    const from = position(e.index);
    const to = e.deleteCount === 0 ? from : position(e.index + e.deleteCount);
    const removed = scalars.slice(e.index, e.index + e.deleteCount).join("");
    if (now.slice(from, to) !== removed)
      refuse("STALE_BASE", "the deleted Text changed since the base revision (§10)", node);
    return { from, to, insert: e.insert };
  });
}

/** §10: whether `second` is the visible sibling right after `first`, both unblocked. */
function adjacent(doc: Doc, v: SectionValidation, first: string, second: string): boolean {
  const entries = deriveTree(doc, v).tree;
  const i = entries.findIndex((e) => e.id === first);
  if (i < 0) return false;
  const { parent, depth } = entries[i] as { parent: string; depth: number };
  for (let k = i + 1; k < entries.length; k++) {
    const e = entries[k] as { id: string; parent: string; depth: number };
    if (e.depth < depth) return false;
    if (e.parent === parent) return e.id === second;
  }
  return false;
}

function refusal(
  index: number,
  hash: string | undefined,
  e: unknown,
  held: boolean,
): SectionRefusal {
  const diagnostic =
    (e as { diagnostic?: string }).diagnostic ??
    (held ? "ACTOR_EQUIVOCATION" : ((e as { code?: string }).code ?? "INVALID_AUTOMERGE_BYTES"));
  return { index, hash, diagnostic, held, message: e instanceof Error ? e.message : String(e) };
}

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
