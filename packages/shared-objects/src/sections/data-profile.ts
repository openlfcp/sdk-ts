import {
  type DataUnitId,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { checkChangeActor } from "../admission/actor.js";
import { type CheckedChange, frameChange, unframeChange } from "../admission/framing.js";
import { SectionReplica, type SectionSnapshot } from "./replica.js";
import { deriveSectionActorId, SECTIONS_PROFILE_ID } from "./values.js";

/**
 * The Shared Sections Data Profile handler (LFCP-02-025): what the
 * profile-agnostic Data Unit applier of @openlfcp/client calls once LFCP
 * has accepted a unit of a org.openlfcp.shared-sections.v1 Resource. It
 * matches the client's DataProfileHandler structurally; this package
 * depends on neither client nor wire.
 *
 * - decode: the plaintext is [1, change], a change of the section actor of
 *   the unit's signer (SHARED-SECTIONS-PROFILE-01 §2), else
 *   CHANGE_ACTOR_MISMATCH: the refusal is the unit's, never the change's;
 * - apply: the change goes through the section admission (§14.1,
 *   SectionReplica.receiveChanges); it merges, waits for the changes it
 *   depends on, is held (a taken actor sequence, SOP §14.1) or is refused;
 * - exclude (G-EP7): the replica is rebuilt without given units;
 * - checkpoint/restore: the persisted state, with the units of every merged
 *   change and this actor's sequence (§9).
 */

/** An accepted unit as the applier passes it (structurally the client's ProfileUnit). */
export interface SectionsUnit {
  readonly unitId: DataUnitId;
}

/** The §11 codec of one unit (structurally the wire DataProfileCodec). */
export interface SectionsCodec {
  readonly dataProfile: string;
  encode(change: CheckedChange): Uint8Array;
  decode(plaintext: Uint8Array): CheckedChange;
}

/** The persisted state (structurally the storage ProfileCheckpoint). */
export interface SectionsCheckpoint {
  readonly resourceId: ResourceId;
  readonly dataProfile: string;
  readonly state: Uint8Array;
  readonly actorSeq: number;
  readonly units: readonly { readonly unitId: DataUnitId; readonly ref: string }[];
}

export interface SectionsApplyResult {
  readonly merged: readonly DataUnitId[];
  /** Nodes (and the section) whose projected state changed. */
  readonly objects: readonly string[];
  readonly diagnostics: readonly never[];
  readonly pending?: string;
  readonly held?: string;
}

export interface SectionsBatchResult {
  readonly merged: readonly DataUnitId[];
  readonly pending: readonly DataUnitId[];
  readonly held: readonly DataUnitId[];
  readonly rejected: readonly {
    readonly unitId: DataUnitId;
    readonly code: string;
    readonly diagnostic: string;
    readonly message: string;
  }[];
  readonly objects: readonly string[];
  readonly diagnostics: readonly never[];
}

export interface SectionsExcludeResult {
  readonly objects: readonly string[];
  readonly pending: readonly DataUnitId[];
  readonly released: readonly DataUnitId[];
}

/** SDK-SECTIONS-INTEGRATION-01 §5 nodes-changed: what changed, and why. */
export interface SectionsNodesChanged {
  readonly nodeIds: readonly string[];
  readonly origin: "local" | "remote" | "rebuild";
  readonly modelRevision: string;
}

interface Buffered {
  readonly unitId: DataUnitId;
  readonly change: CheckedChange;
}

/** Each node's (and the title's) projected state, to tell which ones a merge changed. */
function fingerprints(s: SectionSnapshot): Map<string, string> {
  const out = new Map<string, string>();
  for (const [id, n] of Object.entries(s.nodes)) out.set(id, JSON.stringify(n));
  out.set("", JSON.stringify(s.title));
  s.order.forEach((e, i) => {
    out.set(e.id, `${out.get(e.id) ?? ""}|${i}:${e.parent}:${e.depth}`);
  });
  return out;
}

function changed(before: Map<string, string>, after: Map<string, string>): string[] {
  const ids = new Set([...before.keys(), ...after.keys()]);
  return [...ids].filter((id) => id !== "" && before.get(id) !== after.get(id)).sort();
}

export class SharedSectionsDataProfile {
  readonly dataProfile = SECTIONS_PROFILE_ID;
  #replica: SectionReplica;
  /** Merged units: unit ID hex → change hash. */
  readonly #merged = new Map<string, { unitId: DataUnitId; hash: string }>();
  /** LFCP-accepted units waiting for Automerge dependencies, by unit ID hex. */
  readonly #pending = new Map<string, Buffered>();
  /** LFCP-accepted units whose actor sequence a different change has (SOP §14.1), by unit ID hex. */
  readonly #held = new Map<string, Buffered>();
  readonly #listeners = new Set<(event: SectionsNodesChanged) => void>();

  constructor(replica: SectionReplica) {
    this.#replica = replica;
  }

  /** The current replica (a rebuild replaces it). */
  get replica(): SectionReplica {
    return this.#replica;
  }

  /** §5 nodes-changed for remote merges, rebuilds and recorded local changes. */
  onNodesChanged(listener: (event: SectionsNodesChanged) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #emit(nodeIds: readonly string[], origin: SectionsNodesChanged["origin"]): void {
    if (nodeIds.length === 0) return;
    const event = Object.freeze({ nodeIds, origin, modelRevision: this.#replica.revision() });
    for (const l of this.#listeners) l(event);
  }

  /** The codec of one unit, bound to its signer's section actor (§2). */
  codecFor(unit: { readonly resourceId: ResourceId; readonly actor: PrincipalId }): SectionsCodec {
    const actor = toHex(deriveSectionActorId(unit.resourceId, unit.actor));
    const bound = (c: CheckedChange) => checkChangeActor(c, actor);
    return {
      dataProfile: SECTIONS_PROFILE_ID,
      encode: (change) => frameChange(bound(change).bytes),
      decode: (plaintext) => bound(unframeChange(plaintext)),
    };
  }

  /**
   * Records which change one of this client's own units carries: the change
   * is in the replica already (SectionReplica.stage, then apply). A later
   * exclusion of the unit rebuilds without it, and the checkpoint keeps it.
   */
  recordLocal(
    unitId: DataUnitId,
    change: { readonly hash: string; readonly affectedNodeIds?: readonly string[] },
  ): void {
    if (!this.#replica.hasChange(change.hash))
      throw new LfcpError(
        "PROFILE_INVALID",
        "the change is not in this replica; record only local changes",
      );
    this.#merged.set(toHex(unitId), { unitId, hash: change.hash });
    if (change.affectedNodeIds !== undefined) this.#emit(change.affectedNodeIds, "local");
  }

  /** Merges one accepted unit's change; throws when the section admission refuses it. */
  apply(unit: SectionsUnit, change: CheckedChange): SectionsApplyResult {
    const key = toHex(unit.unitId);
    const r = this.applyBatch([{ unit, value: change }]);
    const own = r.rejected.find((x) => toHex(x.unitId) === key);
    if (own !== undefined) {
      const e = new LfcpError("PROFILE_INVALID", own.message);
      (e as LfcpError & { diagnostic: string }).diagnostic = own.diagnostic;
      throw e;
    }
    const base = { objects: r.objects, diagnostics: r.diagnostics };
    if (this.#held.has(key))
      return Object.freeze({
        merged: r.merged,
        ...base,
        held: `held: a different change has actor ${change.actor} sequence ${change.seq} (SOP §14.1)`,
      });
    if (!r.merged.some((id) => toHex(id) === key))
      return Object.freeze({
        merged: r.merged,
        ...base,
        pending: "waiting for the changes it depends on",
      });
    return Object.freeze({
      merged: [unit.unitId, ...r.merged.filter((id) => toHex(id) !== key)],
      ...base,
    });
  }

  /**
   * Merges many accepted units at once, with every unit still waiting: one
   * admission and one engine call for a catch-up. A refused change rejects
   * only its unit; the units that depend on it wait.
   */
  applyBatch(
    units: readonly { readonly unit: SectionsUnit; readonly value: CheckedChange }[],
  ): SectionsBatchResult {
    for (const { unit, value } of units)
      this.#pending.set(toHex(unit.unitId), { unitId: unit.unitId, change: value });
    return this.#offer(false);
  }

  /** Offers every waiting (and, with `retryHeld`, held) unit to the replica. */
  #offer(retryHeld: boolean): SectionsBatchResult {
    if (retryHeld) {
      for (const [key, b] of this.#held) this.#pending.set(key, b);
      this.#held.clear();
    }
    const offered = [...this.#pending.values()];
    const unitsOf = new Map<string, Buffered[]>();
    for (const b of offered) unitsOf.set(b.change.hash, [...(unitsOf.get(b.change.hash) ?? []), b]);
    const before = fingerprints(this.#replica.snapshot());
    const out = this.#replica.receiveChanges(offered.map((b) => b.change.bytes));
    const merged: DataUnitId[] = [];
    const settle = (hash: string, to: "merged" | "held" | "pending") => {
      for (const b of unitsOf.get(hash) ?? []) {
        const key = toHex(b.unitId);
        this.#pending.delete(key);
        if (to === "merged") {
          this.#merged.set(key, { unitId: b.unitId, hash });
          merged.push(b.unitId);
        } else if (to === "held") this.#held.set(key, b);
        else this.#pending.set(key, b);
      }
    };
    for (const h of [...out.admitted, ...out.duplicates]) settle(h, "merged");
    const rejected: SectionsBatchResult["rejected"][number][] = [];
    for (const r of out.refused) {
      const hash = r.hash ?? offered[r.index]?.change.hash;
      if (hash === undefined) continue;
      if (r.held) settle(hash, "held");
      else
        for (const b of unitsOf.get(hash) ?? []) {
          this.#pending.delete(toHex(b.unitId));
          rejected.push({
            unitId: b.unitId,
            code: "PROFILE_INVALID",
            diagnostic: r.diagnostic,
            message: r.message,
          });
        }
    }
    const objects =
      merged.length > 0 ? changed(before, fingerprints(this.#replica.snapshot())) : [];
    this.#emit(objects, "remote");
    return Object.freeze({
      merged: Object.freeze(merged),
      pending: Object.freeze([...this.#pending.values()].map((b) => b.unitId)),
      held: Object.freeze([...this.#held.values()].map((b) => b.unitId)),
      rejected: Object.freeze(rejected),
      objects: Object.freeze(objects),
      diagnostics: Object.freeze([]),
    });
  }

  /**
   * G-EP7: the state without `unitIds`, rebuilt from the remaining changes.
   * Merged units whose changes build on an excluded one wait again; held
   * units are retried, since the rebuild may free their actor sequence.
   */
  exclude(unitIds: readonly DataUnitId[]): SectionsExcludeResult {
    const hashes: string[] = [];
    for (const id of unitIds) {
      const key = toHex(id);
      this.#pending.delete(key);
      this.#held.delete(key);
      const m = this.#merged.get(key);
      if (m !== undefined) {
        hashes.push(m.hash);
        this.#merged.delete(key);
      }
    }
    if (hashes.length === 0) return Object.freeze({ objects: [], pending: [], released: [] });
    const before = fingerprints(this.#replica.snapshot());
    const { replica, unapplied } = this.#replica.rebuildWithout(hashes);
    this.#replica = replica;
    const waiting = new Set(unapplied);
    const pending: DataUnitId[] = [];
    for (const [key, m] of [...this.#merged]) {
      if (!waiting.has(m.hash)) continue;
      this.#merged.delete(key);
      pending.push(m.unitId);
    }
    const objects = changed(before, fingerprints(this.#replica.snapshot()));
    this.#emit(objects, "rebuild");
    const heldBefore = new Set(this.#held.keys());
    const retried = heldBefore.size > 0 ? this.#offer(true) : undefined;
    const released = (retried?.merged ?? []).filter((id) => heldBefore.has(toHex(id)));
    return Object.freeze({
      objects: Object.freeze(objects),
      pending: Object.freeze(pending),
      released: Object.freeze(released),
    });
  }

  /** Whether this handler holds the unit's change (merged, recorded, waiting or held). */
  has(unitId: DataUnitId): boolean {
    const key = toHex(unitId);
    return this.#merged.has(key) || this.#pending.has(key) || this.#held.has(key);
  }

  heldUnits(): DataUnitId[] {
    return [...this.#held.values()].map((b) => b.unitId);
  }

  pendingUnits(): DataUnitId[] {
    return [...this.#pending.values()].map((b) => b.unitId);
  }

  /** Forgets the whole state, keeping the §9 sequence (SNAP-EP). */
  reset(): void {
    const before = fingerprints(this.#replica.snapshot());
    this.#replica = this.#replica.emptied();
    this.#merged.clear();
    this.#pending.clear();
    this.#held.clear();
    this.#emit(changed(before, fingerprints(this.#replica.snapshot())), "rebuild");
  }

  /**
   * The state to persist: the full save, this actor's sequence and each
   * merged unit's change, with `local`, this client's units committed in
   * the same transaction as the checkpoint.
   */
  checkpoint(
    local: readonly { readonly unitId: DataUnitId; readonly ref: string }[] = [],
  ): SectionsCheckpoint {
    const units = new Map(
      [...this.#merged.values()].map((m) => [toHex(m.unitId), { unitId: m.unitId, ref: m.hash }]),
    );
    // Own units being committed with this checkpoint (recordLocal once committed).
    for (const u of local) units.set(toHex(u.unitId), { unitId: u.unitId, ref: u.ref });
    return Object.freeze({
      resourceId: this.#replica.resource,
      dataProfile: SECTIONS_PROFILE_ID,
      state: this.#replica.save(),
      actorSeq: this.#replica.actorSeq,
      units: Object.freeze(
        [...units.values()]
          .map((m) => Object.freeze({ unitId: m.unitId, ref: m.ref }))
          .sort((a, b) => (toHex(a.unitId) < toHex(b.unitId) ? -1 : 1)),
      ),
    });
  }

  /** The handler of a persisted checkpoint; its replica writes nothing below the checkpoint's sequence (§9). */
  static restore(
    checkpoint: SectionsCheckpoint,
    options: { readonly resource: ResourceId; readonly principal: PrincipalId },
  ): SharedSectionsDataProfile {
    if (checkpoint.dataProfile !== SECTIONS_PROFILE_ID)
      throw new LfcpError(
        "DATA_PROFILE_MISMATCH",
        `a ${checkpoint.dataProfile} checkpoint is not ${SECTIONS_PROFILE_ID}`,
      );
    // This device's own persisted state: not held to the Snapshot limits (SOP §13.1).
    const replica = SectionReplica.fromSave(
      checkpoint.state,
      { ...options, minSeq: checkpoint.actorSeq },
      "local-state",
    );
    const profile = new SharedSectionsDataProfile(replica);
    for (const u of checkpoint.units) {
      if (!replica.hasChange(u.ref))
        throw new LfcpError(
          "PROFILE_INVALID",
          `the checkpoint names change ${u.ref}, which its state lacks`,
        );
      profile.#merged.set(toHex(u.unitId), { unitId: u.unitId, hash: u.ref });
    }
    return profile;
  }
}
