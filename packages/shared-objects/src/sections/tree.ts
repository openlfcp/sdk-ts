import * as A from "@automerge/automerge";
import { type SectionValidation, validateSection } from "./schema.js";

/**
 * The effective tree of a section and its structural facts
 * (SHARED-SECTIONS-PROFILE-01 §7, §9, §14.3; LFCP-02-014), derived from the
 * fully merged state, never from arrival order:
 *
 * - a node with more than one concurrent placement is PLACEMENT_CONFLICT;
 *   its lifecycle (a Task node's: its Task's) with concurrent different
 *   values is LIFECYCLE_CONFLICT (equal values agree);
 * - every member of a cycle of the selected parent graph is PARENT_CYCLE;
 * - every node under a conflicted, cyclic, invalid or collided node is
 *   BLOCKED_PARENT, to a fixed point;
 * - a deleted node, and every node under one, is hidden;
 * - the tree scans each children list in its merged order and emits a node
 *   only when it is eligible, visible and selects exactly that entry.
 *
 * No winner is chosen and nothing is rewritten: blocked and hidden content
 * stays in the document, and recovery lists it. Traversals are iterative,
 * so deep or adversarial graphs do not depend on the call stack (§16.4).
 */

export type StructuralFact =
  | "PLACEMENT_CONFLICT"
  | "PARENT_CYCLE"
  | "BLOCKED_PARENT"
  | "LIFECYCLE_CONFLICT";

export interface TreeEntry {
  readonly id: string;
  /** The section ID or the parent node's ID. */
  readonly parent: string;
  /** 0 under the section. */
  readonly depth: number;
  readonly kind: string;
}

export interface SectionTree {
  /**
   * PROFILE_INVALID: section-level problems, nothing projected; IMPORTING:
   * no `ready` (§12.1), nothing projected; STRUCTURAL_ATTENTION: a
   * recovery fact, an invalid node or a collision; VALID otherwise.
   */
  readonly classification: "PROFILE_INVALID" | "IMPORTING" | "STRUCTURAL_ATTENTION" | "VALID";
  /** The visible nodes in projection order (preorder). */
  readonly tree: readonly TreeEntry[];
  /** Nodes hidden by their own or an ancestor's deletion, sorted. */
  readonly hidden: readonly string[];
  /** Blocked nodes with their fact, sorted by node ID for presentation only. */
  readonly recovery: readonly { readonly id: string; readonly code: StructuralFact }[];
  /** Invalid nodes with their §14.2 diagnostic, sorted. */
  readonly invalid: readonly { readonly id: string; readonly diagnostic: string }[];
  /** Colliding IDs (§14.2), sorted. */
  readonly collisions: readonly string[];
  /** Each blocked node's candidate placements and their parents (§7 recovery information). */
  readonly candidates: ReadonlyMap<
    string,
    readonly { readonly placement: string; readonly parent: string }[]
  >;
  /** The schema validation the tree was derived from. */
  readonly validation: SectionValidation;
}

type AMap = Record<string, unknown>;

const str = (v: unknown): string | undefined =>
  A.isImmutableString(v) ? v.toString() : typeof v === "string" ? v : undefined;

/** Every concurrent value of `map[key]`, as strings. */
function values(map: AMap | undefined, key: string): (string | undefined)[] {
  if (map === undefined || !(key in map)) return [];
  const c = A.getConflicts(map, key);
  return (c === undefined ? [map[key]] : Object.values(c)).map(str);
}

const byId = <T extends { readonly id: string }>(a: T, b: T) =>
  a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

/** §7: the effective tree and structural facts of `doc`. Reads only. */
export function deriveTree(
  doc: A.Doc<unknown>,
  validation: SectionValidation = validateSection(doc),
): SectionTree {
  const root = doc as AMap;
  const nodes = (root.nodes ?? {}) as AMap;
  const placements = (root.placements ?? {}) as AMap;
  const objects = (root.objects ?? {}) as AMap;
  const sectionId = validation.sectionId;
  const invalid = validation.nodes;
  const collided = new Set(validation.collided);
  const blocked = new Map<string, StructuralFact>();
  const parents = new Map<string, string>();
  const candidates = new Map<string, { placement: string; parent: string }[]>();
  const keys = Object.keys(nodes).sort();
  const node = (id: string) => nodes[id] as AMap | undefined;
  const owner = (id: string) =>
    (str(node(id)?.kind) === "task" ? objects[id] : node(id)) as AMap | undefined;

  // One pass over the nodes: selected parent, deletion, conflicts.
  const deleted = new Set<string>();
  for (const id of keys) {
    if (str(owner(id)?.lifecycle) === "deleted") deleted.add(id);
    if (collided.has(id)) continue;
    const n = node(id) as AMap;
    const selected = values(n, "placement");
    const parentOf = (p: string | undefined) =>
      p === undefined ? undefined : str((placements[p] as AMap | undefined)?.parent_id);
    // The default value selects the parent used for hiding and for the walk below.
    const parent = parentOf(str(n.placement));
    if (parent !== undefined) parents.set(id, parent);
    if (selected.length > 1) {
      blocked.set(id, "PLACEMENT_CONFLICT");
      candidates.set(
        id,
        selected.map((p) => ({ placement: p ?? "", parent: parentOf(p) ?? "" })),
      );
    }
    if (new Set(values(owner(id), "lifecycle")).size > 1) blocked.set(id, "LIFECYCLE_CONFLICT");
  }
  for (const id of invalid.keys()) blocked.delete(id);

  // Every member of a cycle of the selected parent graph (§7.4), whatever
  // the start: each node has one parent, so one coloured walk per start
  // that stops at any node already done finds them all in linear time.
  const done = new Set<string>();
  for (const start of keys) {
    const path: string[] = [];
    const onPath = new Map<string, number>();
    let n: string | undefined = start;
    while (
      n !== undefined &&
      n !== sectionId &&
      node(n) !== undefined &&
      !done.has(n) &&
      !blocked.has(n) &&
      !collided.has(n) &&
      !invalid.has(n)
    ) {
      const at = onPath.get(n);
      if (at !== undefined) {
        for (const c of path.slice(at)) blocked.set(c, "PARENT_CYCLE");
        break;
      }
      onPath.set(n, path.length);
      path.push(n);
      n = parents.get(n);
    }
    for (const c of path) done.add(c);
  }

  /**
   * Resolves `fact(id)` = own(id) || fact(parent) along the parent chain,
   * iteratively and memoized; a walk that comes back to a node of its own
   * path stops there, with what the loop holds.
   */
  const chained = (own: (id: string) => boolean): ((id: string) => boolean) => {
    const memo = new Map<string, boolean>();
    return (id) => {
      const path: string[] = [];
      const onPath = new Set<string>();
      let tail = false;
      let n: string | undefined = id;
      while (n !== undefined && n !== sectionId && node(n) !== undefined) {
        const known = memo.get(n);
        if (known !== undefined) {
          tail = known;
          break;
        }
        if (onPath.has(n)) {
          // A loop: every node of it sees all of it.
          tail = path.slice(path.indexOf(n)).some(own);
          break;
        }
        onPath.add(n);
        path.push(n);
        n = parents.get(n);
      }
      for (let k = path.length - 1; k >= 0; k--) {
        tail = tail || own(path[k] as string);
        memo.set(path[k] as string, tail);
      }
      return memo.get(id) ?? tail;
    };
  };

  // §7.5: blocked structure propagates to every descendant.
  const out = (id: string | undefined) =>
    id !== undefined && (blocked.has(id) || invalid.has(id) || collided.has(id));
  const isOut = new Set(keys.filter((id) => out(id)));
  const blockedAbove = chained((id) => isOut.has(id));
  for (const id of keys) {
    const parent = parents.get(id);
    if (!isOut.has(id) && parent !== undefined && blockedAbove(parent))
      blocked.set(id, "BLOCKED_PARENT");
  }

  // §9: a deleted node or a descendant of one is hidden, not removed.
  const isHidden = chained((id) => deleted.has(id));
  const hidden = new Set(keys.filter((id) => isHidden(id)));

  const tree: TreeEntry[] = [];
  const projectable = validation.state === "ready" && sectionId !== undefined;
  if (projectable) {
    const laneOf = (p: string) =>
      ((p === sectionId ? (root.section as AMap).children : node(p)?.children) ?? []) as unknown[];
    // An explicit stack of (parent, depth, next index) instead of recursion.
    const stack: { parent: string; depth: number; lane: unknown[]; i: number }[] = [
      { parent: sectionId, depth: 0, lane: laneOf(sectionId), i: 0 },
    ];
    const emitted = new Set<string>();
    while (stack.length > 0) {
      const top = stack[stack.length - 1] as (typeof stack)[number];
      if (top.i >= top.lane.length) {
        stack.pop();
        continue;
      }
      const slot = str(top.lane[top.i++]);
      if (slot === undefined || collided.has(slot)) continue;
      const id = str((placements[slot] as AMap | undefined)?.node_id);
      if (id === undefined || node(id) === undefined || out(id) || hidden.has(id)) continue;
      if (str(node(id)?.placement) !== slot || emitted.has(id)) continue;
      emitted.add(id);
      tree.push(
        Object.freeze({
          id,
          parent: top.parent,
          depth: top.depth,
          kind: str(node(id)?.kind) ?? "",
        }),
      );
      stack.push({ parent: id, depth: top.depth + 1, lane: laneOf(id), i: 0 });
    }
  }

  const classification =
    validation.state === "invalid"
      ? "PROFILE_INVALID"
      : validation.state === "importing"
        ? "IMPORTING"
        : blocked.size > 0 || invalid.size > 0 || validation.collisions.length > 0
          ? "STRUCTURAL_ATTENTION"
          : "VALID";
  return Object.freeze({
    classification,
    tree: Object.freeze(tree),
    hidden: Object.freeze([...hidden].sort()),
    recovery: Object.freeze([...blocked].map(([id, code]) => ({ id, code })).sort(byId)),
    invalid: Object.freeze(
      [...invalid].map(([id, p]) => ({ id, diagnostic: p.diagnostic })).sort(byId),
    ),
    collisions: validation.collisions,
    candidates,
    validation,
  });
}
