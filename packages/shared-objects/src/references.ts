// Operation references (SHARED-OBJECTS-PROFILE-01 §11.4, SPEC-PATCH-10,
// ADR 0010): a change's operations refer only to its own causal history H
// (its dependencies and all their ancestors) or to operations earlier in
// the change. An engine applies a change that refers elsewhere (a
// predecessor on another key, an element of another list, an object that is
// not one), but then cannot write it back out, and some such changes abort
// the apply itself, which in Automerge JS terminates its wasm module. The
// rules are decided against H only, never anything else the receiver holds,
// so every replica decides alike.
//
// H is held as a vector clock: an admitted change's actor chain is
// contiguous in its history (R1), so the latest sequence number of each
// actor in H says exactly which changes H holds. An operation is found by
// its actor's changes and their counter ranges.

import * as A from "@automerge/automerge";
import { checkCanonicalChange, type ParsedChange, type ParsedOp } from "./canonical.js";

/** What a reference may land on: an operation of the history, by its ID. */
interface Target {
  readonly obj: string;
  /** "p:" + a property, or "e:" + an element ID (an insertion's own ID). */
  readonly slot: string;
  readonly insert: boolean;
  readonly del: boolean;
  /** The object an operation makes (0 map, 2 list, 4 text, 6 table), else null. */
  readonly make: number | null;
}

interface Entry {
  readonly actor: string;
  readonly seq: number;
  readonly startOp: number;
  readonly ops: readonly Target[];
  /** H of the change plus the change: the latest sequence of each actor. */
  readonly clock: ReadonlyMap<string, number>;
}

/** A §11.4 rule a change breaks. */
export type ReferenceRule = "R1" | "R2" | "R3" | "R4" | "R5" | "R6" | "R7";

const MAKE = new Set([0, 2, 4, 6]);
const MAP_LIKE = new Set([0, 6]);

function slotOf(op: ParsedOp, id: string): string {
  if (op.insert) return `e:${id}`;
  if (op.key.kind === "prop") return `p:${op.key.name}`;
  if (op.key.kind === "elem") return `e:${op.key.id}`;
  return "e:_head";
}

const targetOf = (op: ParsedOp, id: string): Target => ({
  obj: op.obj,
  slot: slotOf(op, id),
  insert: op.insert,
  del: op.action === 3,
  make: MAKE.has(op.action) ? op.action : null,
});

function splitId(id: string): { ctr: number; actor: string } {
  const at = id.indexOf("@");
  return { ctr: Number(id.slice(0, at)), actor: id.slice(at + 1) };
}

/**
 * The changes of a document as §11.4 reads them. A replica keeps it current
 * as changes are admitted and committed, or builds it again from its
 * document.
 */
export class ReferenceHistory {
  readonly #byHash = new Map<string, Entry>();
  /** Each actor's changes by sequence number (index seq - 1). */
  readonly #byActor = new Map<string, Entry[]>();

  get size(): number {
    return this.#byHash.size;
  }

  has(hash: string): boolean {
    return this.#byHash.has(hash);
  }

  /** H of a change with these dependencies: the latest sequence of each actor. */
  #history(deps: readonly string[]): Map<string, number> {
    const clock = new Map<string, number>();
    for (const d of deps) {
      const e = this.#byHash.get(d);
      if (e === undefined) continue;
      for (const [a, s] of e.clock) if ((clock.get(a) ?? 0) < s) clock.set(a, s);
    }
    return clock;
  }

  /**
   * Adds a change the document now holds. Its dependencies are added
   * first; one this index does not hold adds nothing to its history.
   */
  add(hash: string, change: ParsedChange): void {
    if (this.#byHash.has(hash)) return;
    const clock = this.#history(change.deps);
    if ((clock.get(change.actor) ?? 0) < change.seq) clock.set(change.actor, change.seq);
    const entry: Entry = {
      actor: change.actor,
      seq: change.seq,
      startOp: change.startOp,
      ops: change.ops.map((op, i) => targetOf(op, `${change.startOp + i}@${change.actor}`)),
      clock,
    };
    this.#byHash.set(hash, entry);
    const list = this.#byActor.get(change.actor) ?? [];
    list[change.seq - 1] = entry;
    this.#byActor.set(change.actor, list);
  }

  /** The change of `actor` holding operation counter `ctr`, among its first `upToSeq` changes. */
  #find(actor: string, ctr: number, upToSeq: number): { entry: Entry; index: number } | null {
    const list = this.#byActor.get(actor);
    if (list === undefined) return null;
    let lo = 0;
    let hi = Math.min(upToSeq, list.length) - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const e = list[mid];
      if (e === undefined) return null;
      if (ctr < e.startOp) hi = mid - 1;
      else if (ctr >= e.startOp + e.ops.length) lo = mid + 1;
      else return { entry: e, index: ctr - e.startOp };
    }
    return null;
  }

  /** The §11.4 rule `change` breaks against its causal history, or null. */
  check(change: ParsedChange): ReferenceRule | null {
    const H = this.#history(change.deps);
    // R1: the actor's previous change is in H.
    if (change.seq > 1 && (H.get(change.actor) ?? 0) < change.seq - 1) return "R1";
    // R2: the start op follows H's largest counter (each actor's latest change in H has its largest).
    let top = 0;
    for (const [a, s] of H) {
      const e = this.#byActor.get(a)?.[s - 1];
      if (e !== undefined && e.startOp + e.ops.length - 1 > top) top = e.startOp + e.ops.length - 1;
    }
    if (change.startOp !== top + 1) return "R2";

    const own: Target[] = [];
    // An operation of H or earlier in this change; deletions are not targets.
    const target = (id: string): Target | undefined => {
      const { ctr, actor } = splitId(id);
      let t: Target | undefined;
      if (actor === change.actor && ctr >= change.startOp && ctr < change.startOp + own.length)
        t = own[ctr - change.startOp];
      else {
        const found = this.#find(actor, ctr, H.get(actor) ?? 0);
        t = found === null ? undefined : found.entry.ops[found.index];
      }
      return t === undefined || t.del ? undefined : t;
    };
    for (const [i, op] of change.ops.entries()) {
      const id = `${change.startOp + i}@${change.actor}`;
      // R3: the root, or an object an operation made; its key form.
      let sequence: boolean;
      if (op.obj === "_root") sequence = false;
      else {
        const made = target(op.obj)?.make ?? null;
        if (made === null) return "R3";
        sequence = !MAP_LIKE.has(made);
      }
      if (!sequence && (op.insert || op.key.kind !== "prop")) return op.insert ? "R4" : "R3";
      if (sequence && op.key.kind === "prop") return "R3";
      const element = (e: string): boolean => {
        const t = target(e);
        return t !== undefined && t.insert && t.obj === op.obj;
      };
      // R4: an insertion goes after the head or an element of the same object, without predecessors.
      if (op.insert && (op.pred.length > 0 || (op.key.kind === "elem" && !element(op.key.id))))
        return "R4";
      // R5: any other sequence operation names an element of the same object.
      if (sequence && !op.insert && (op.key.kind !== "elem" || !element(op.key.id))) return "R5";
      // R6: predecessors on the same object and key.
      const slot = slotOf(op, id);
      for (const p of op.pred) {
        const t = target(p);
        if (t === undefined || t.obj !== op.obj || t.slot !== slot) return "R6";
      }
      // R7: a deletion has a predecessor.
      if (op.action === 3 && op.pred.length === 0) return "R7";
      own.push(targetOf(op, id));
    }
    return null;
  }
}

/**
 * The index of every change a document holds, as the engine hands them
 * out (in its encoding, so canonical), dependencies first. A change the
 * walk cannot read is left out: references into it are then refused.
 */
export function referenceHistoryOf(doc: A.Doc<unknown>): ReferenceHistory {
  const parsed = new Map<string, ParsedChange>();
  for (const bytes of A.getAllChanges(doc)) {
    try {
      parsed.set(A.decodeChange(bytes).hash, checkCanonicalChange(bytes));
    } catch {
      // not readable: left out
    }
  }
  const refs = new ReferenceHistory();
  const placed = new Set<string>();
  for (const start of parsed.keys()) {
    // Iterative depth-first: dependencies first, without recursion.
    const stack: { hash: string; next: number }[] = [{ hash: start, next: 0 }];
    while (stack.length > 0) {
      const top = stack[stack.length - 1] as { hash: string; next: number };
      const change = parsed.get(top.hash);
      if (change === undefined || placed.has(top.hash)) {
        stack.pop();
        continue;
      }
      const dep = change.deps[top.next];
      if (dep !== undefined) {
        top.next++;
        if (!placed.has(dep) && parsed.has(dep)) stack.push({ hash: dep, next: 0 });
        continue;
      }
      placed.add(top.hash);
      refs.add(top.hash, change);
      stack.pop();
    }
  }
  return refs;
}
