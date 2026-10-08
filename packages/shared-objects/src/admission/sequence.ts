import { LfcpError } from "@openlfcp/core";
import { ProfileInvalidError } from "../profile-invalid.js";
import type { CheckedChange } from "./framing.js";

/**
 * SHARED-OBJECTS-PROFILE-01 §14.1, the sequence admission, for any profile
 * that inherits it (SHARED-SECTIONS-PROFILE-01 §2): which received changes
 * the engine may apply, in which order, and why the others wait or are
 * refused. It reads the document through `DocumentSequences` and knows no
 * profile semantics; a profile adds its own checks through `accept`.
 */

/** What admission needs to know of the document. */
export interface DocumentSequences {
  /** Whether the document holds the change with this hex hash. */
  hasChange(hash: string): boolean;
  /** The actor's latest sequence number in the document; 0 when it has none. */
  latestSeq(actor: string): number;
}

/** A change admission refused: held (§14.1, POST-001) or invalid. */
export interface RefusedChange {
  readonly change: CheckedChange;
  readonly error: LfcpError;
  /**
   * The actor and sequence number belong to a different change of the
   * document (ACTOR_EQUIVOCATION): a profile holds it and retries it after a
   * rebuild that removes changes; it is not profile-invalid.
   */
  readonly held: boolean;
}

export interface BatchAdmission {
  /** Changes to apply, in an order where each comes after its dependencies. */
  readonly admitted: readonly CheckedChange[];
  /** Changes the document holds already. */
  readonly duplicates: readonly CheckedChange[];
  /** Changes whose dependencies are neither in the document nor admitted. */
  readonly waiting: readonly CheckedChange[];
  /** Held and invalid changes, in the order they were decided. */
  readonly refused: readonly RefusedChange[];
}

const held = (c: CheckedChange): LfcpError =>
  new LfcpError(
    "ACTOR_EQUIVOCATION",
    `actor ${c.actor} sequence ${c.seq} already has a different change (§26.2)`,
  );

/**
 * Admits many changes at once: each once its dependencies inside the batch
 * are admitted (Kahn's order), against the document and the batch so far.
 * A taken sequence is held, a change naming an actor the document does not
 * know or skipping a sequence is INVALID_AUTOMERGE_BYTES (§11.1, §14.1),
 * and `accept` (the profile's own checks, e.g. §11.2 depth) may refuse by
 * throwing; a refused change does not stop the others, and the changes
 * that depend on it wait. `changes` must hold each hash once.
 */
export function admitBatch(
  changes: readonly CheckedChange[],
  doc: DocumentSequences,
  accept: (change: CheckedChange) => void = () => undefined,
): BatchAdmission {
  const all = [...changes];
  const index = new Map(all.map((c, i) => [c.hash, i]));
  const blocking = all.map(() => 0);
  const unreachable = all.map(() => false);
  const children = new Map<string, number[]>();
  all.forEach((c, i) => {
    for (const d of c.deps) {
      if (doc.hasChange(d)) continue;
      if (index.has(d)) {
        blocking[i] = (blocking[i] as number) + 1;
        children.set(d, [...(children.get(d) ?? []), i]);
      } else unreachable[i] = true;
    }
  });
  const seqs = new Map<string, number>();
  const latest = (actor: string) => seqs.get(actor) ?? doc.latestSeq(actor);
  const admitted: CheckedChange[] = [];
  const duplicates: CheckedChange[] = [];
  const refused: RefusedChange[] = [];
  const done = all.map(() => false);
  const ready = all.flatMap((_, i) => (blocking[i] === 0 && !unreachable[i] ? [i] : []));
  for (let k = 0; k < ready.length; k++) {
    const i = ready[k] as number;
    const c = all[i] as CheckedChange;
    done[i] = true;
    if (doc.hasChange(c.hash)) duplicates.push(c);
    else if (c.seq <= latest(c.actor)) {
      refused.push({ change: c, error: held(c), held: true });
      continue;
    } else if (c.otherActors.some((a) => latest(a) === 0)) {
      refused.push({
        change: c,
        error: new ProfileInvalidError(
          "INVALID_AUTOMERGE_BYTES",
          `the change names an actor unknown to this document (§11.1)`,
        ),
        held: false,
      });
      continue;
    } else if (c.seq !== latest(c.actor) + 1) {
      refused.push({
        change: c,
        error: new ProfileInvalidError(
          "INVALID_AUTOMERGE_BYTES",
          `actor ${c.actor} sequence ${c.seq} skips sequence ${latest(c.actor) + 1} (§14.1)`,
        ),
        held: false,
      });
      continue;
    } else {
      try {
        accept(c);
      } catch (e) {
        refused.push({ change: c, error: e as LfcpError, held: false });
        continue;
      }
      seqs.set(c.actor, c.seq);
      admitted.push(c);
    }
    for (const child of children.get(c.hash) ?? []) {
      blocking[child] = (blocking[child] as number) - 1;
      if (blocking[child] === 0 && !unreachable[child]) ready.push(child);
    }
  }
  return Object.freeze({
    admitted: Object.freeze(admitted),
    duplicates: Object.freeze(duplicates),
    waiting: Object.freeze(all.filter((_, i) => !done[i])),
    refused: Object.freeze(refused),
  });
}

/** One change against the document (receiveChange): what §14.1 says of it. */
export type ChangeAdmission =
  | { readonly kind: "duplicate" }
  | { readonly kind: "missing"; readonly missing: readonly string[] }
  /** Its actor and sequence belong to another change: held (§14.1, POST-001). */
  | { readonly kind: "held"; readonly error: LfcpError }
  | { readonly kind: "invalid"; readonly error: ProfileInvalidError }
  /** The actor's next change, every dependency present: the engine may apply it. */
  | { readonly kind: "next" };

/**
 * One change: a duplicate, missing dependencies, a held sequence, an actor
 * the document does not know (§11.1) or a skipped sequence (§14.1), checked
 * in that order before the engine sees it; or the actor's next change.
 */
export function admitChange(change: CheckedChange, doc: DocumentSequences): ChangeAdmission {
  if (doc.hasChange(change.hash)) return { kind: "duplicate" };
  const missing = change.deps.filter((d) => !doc.hasChange(d));
  if (missing.length > 0) return { kind: "missing", missing: Object.freeze(missing) };
  const latest = doc.latestSeq(change.actor);
  if (change.seq <= latest) return { kind: "held", error: held(change) };
  const unknown = change.otherActors.find((a) => doc.latestSeq(a) === 0);
  if (unknown !== undefined)
    return {
      kind: "invalid",
      error: new ProfileInvalidError(
        "INVALID_AUTOMERGE_BYTES",
        `the change names actor ${unknown}, unknown to this document (§11.1)`,
      ),
    };
  if (change.seq !== latest + 1)
    return {
      kind: "invalid",
      error: new ProfileInvalidError(
        "INVALID_AUTOMERGE_BYTES",
        `actor ${change.actor} sequence ${change.seq} skips sequence ${latest + 1} (§14.1)`,
      ),
    };
  return { kind: "next" };
}
