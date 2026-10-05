import {
  type DataUnitId,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  type CheckedChange,
  frameChange,
  frameSnapshot,
  unframeChange,
  unframeSnapshot,
} from "./automerge-bytes.js";
import { type ObjectChange, type ReplicaOptions, SharedObjectsReplica } from "./replica.js";
import { type Json, ProfileInvalidError } from "./validate.js";
import { deriveActorId, PROFILE_ID } from "./values.js";

/**
 * The Shared Objects Data Profile handler (LFCP-033): what a profile-
 * agnostic Data Unit applier (@openlfcp/client DataUnitApplier) calls once
 * LFCP has accepted a unit. It matches the client's DataProfileHandler
 * structurally; this package depends on neither client nor wire.
 *
 * - decode: the §11 plaintext is one checked Automerge change, written by
 *   the §8 actor of the unit's signing Principal (§8, §11, SO-SEC1);
 * - apply: the change merges into the replica, or waits in a buffer until
 *   the changes it depends on arrive in other units (profile-pending), and
 *   every buffered change it unblocks merges with it;
 * - one object becoming profile-invalid is a diagnostic, never a refusal:
 *   the other objects stay usable (§77);
 * - exclude (§14.1, G-EP7): rebuilds the replica without given units.
 */

/** An accepted unit as the applier passes it (structurally the client's ProfileUnit). */
export interface SharedObjectsUnit {
  readonly unitId: DataUnitId;
}

export interface SharedObjectsDiagnostic {
  readonly objectId?: string;
  readonly code: string;
  readonly diagnostic?: string;
  readonly pointer?: string;
  readonly message: string;
}

export interface SharedObjectsApplyResult {
  readonly merged: readonly DataUnitId[];
  readonly objects: readonly string[];
  readonly diagnostics: readonly SharedObjectsDiagnostic[];
  readonly pending?: string;
}

export interface SharedObjectsExcludeResult {
  readonly objects: readonly string[];
  readonly pending: readonly DataUnitId[];
}

/** A persisted handler state (structurally the storage ProfileCheckpoint). */
export interface SharedObjectsCheckpoint {
  readonly resourceId: ResourceId;
  readonly dataProfile: string;
  readonly state: Uint8Array;
  readonly actorSeq: number;
  readonly units: readonly { readonly unitId: DataUnitId; readonly ref: string }[];
}

/** The §13 Snapshot codec (structurally the wire DataProfileCodec): plaintext ↔ full save. */
export interface SharedObjectsSnapshotCodec {
  readonly dataProfile: string;
  encode(save: Uint8Array): Uint8Array;
  decode(plaintext: Uint8Array): Uint8Array;
}

/** The §11 codec of one unit (structurally the wire DataProfileCodec). */
export interface SharedObjectsCodec {
  readonly dataProfile: string;
  encode(change: CheckedChange): Uint8Array;
  decode(plaintext: Uint8Array): CheckedChange;
}

interface Buffered {
  readonly unitId: DataUnitId;
  readonly change: CheckedChange;
}

export class SharedObjectsDataProfile {
  readonly dataProfile = PROFILE_ID;
  #replica: SharedObjectsReplica;
  /** Merged units: unit ID hex → change hash. */
  readonly #merged = new Map<string, { unitId: DataUnitId; hash: string }>();
  /** LFCP-accepted units waiting for Automerge dependencies, by unit ID hex. */
  readonly #pending = new Map<string, Buffered>();
  readonly #listeners = new Set<(change: ObjectChange) => void>();

  constructor(replica: SharedObjectsReplica) {
    this.#replica = replica;
  }

  /**
   * The local state to persist (structurally the storage ProfileCheckpoint,
   * LFCP-034/035): the Automerge full save, this actor's sequence (the §9
   * minSeq on restore) and which unit carried which merged change (for a
   * G-EP7 rebuild). Units buffered for Automerge dependencies are not in it:
   * they stay "profile-pending" in storage and are offered again on restore.
   */
  checkpoint(): SharedObjectsCheckpoint {
    return Object.freeze({
      resourceId: this.#replica.resource,
      dataProfile: PROFILE_ID,
      state: this.#replica.save(),
      actorSeq: this.#replica.actorSeq,
      units: Object.freeze(
        [...this.#merged.values()]
          .map((m) => Object.freeze({ unitId: m.unitId, ref: m.hash }))
          .sort((a, b) => (toHex(a.unitId) < toHex(b.unitId) ? -1 : 1)),
      ),
    });
  }

  /**
   * The handler of a persisted checkpoint. The replica refuses local writes
   * if its actor is behind the checkpoint's sequence (§9).
   */
  static restore(
    checkpoint: SharedObjectsCheckpoint,
    options: Pick<ReplicaOptions, "resource" | "principal">,
  ): SharedObjectsDataProfile {
    if (checkpoint.dataProfile !== PROFILE_ID)
      throw new LfcpError(
        "DATA_PROFILE_MISMATCH",
        `a ${checkpoint.dataProfile} checkpoint is not ${PROFILE_ID}`,
      );
    const replica = SharedObjectsReplica.fromSave(checkpoint.state, {
      ...options,
      minSeq: checkpoint.actorSeq,
    });
    const profile = new SharedObjectsDataProfile(replica);
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

  /** The current replica (a G-EP7 rebuild replaces it). */
  get replica(): SharedObjectsReplica {
    return this.#replica;
  }

  /** §98, §100: object change notifications for remote merges and rebuilds. */
  onObjectChanged(listener: (change: ObjectChange) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #emit(changes: readonly ObjectChange[]): void {
    for (const c of changes) for (const l of this.#listeners) l(c);
  }

  /**
   * Records which change one of this client's OWN units carries (the unit
   * was created from a local change, so it is merged already). A later
   * G-EP7 exclusion of that unit then rebuilds the replica without it, and
   * the checkpoint keeps the reference. Use it as createQueuedDataUnit's
   * onCreated.
   */
  recordLocal(unitId: DataUnitId, change: CheckedChange): void {
    if (!this.#replica.hasChange(change.hash))
      throw new LfcpError(
        "PROFILE_INVALID",
        "the change is not in this replica; record only local changes",
      );
    this.#merged.set(toHex(unitId), { unitId, hash: change.hash });
  }

  /**
   * The §13 Snapshot codec (structurally the wire DataProfileCodec): an
   * Automerge full save framed as [1, save]; decoding requires a document
   * chunk. For receiveSnapshot and createSnapshot.
   */
  snapshotCodec(): SharedObjectsSnapshotCodec {
    return {
      dataProfile: PROFILE_ID,
      encode: (save) => frameSnapshot(save),
      decode: (plaintext) => unframeSnapshot(plaintext),
    };
  }

  /** The state to publish as a Snapshot: the replica's full save. */
  snapshotState(): Uint8Array {
    return this.#replica.save();
  }

  /**
   * Loads a received Snapshot's full save (§13, §66 step 3): the replica
   * becomes the save merged with everything it held, and buffered units
   * whose dependencies the Snapshot brings are merged. Returns the objects
   * that changed and the units merged from the buffer.
   */
  loadSnapshot(save: Uint8Array): {
    readonly objects: readonly string[];
    readonly merged: readonly DataUnitId[];
  } {
    const before = this.#replica;
    const { replica } = before.mergeSave(save);
    this.#replica = replica;
    const merged: DataUnitId[] = [];
    for (let progress = true; progress; ) {
      progress = false;
      for (const [key, b] of this.#pending) {
        const r = this.#replica.receiveChange(b.change.bytes);
        if (r.status === "missing_dependencies") continue;
        this.#pending.delete(key);
        this.#merged.set(key, { unitId: b.unitId, hash: b.change.hash });
        merged.push(b.unitId);
        progress = true;
      }
    }
    const changes = rebuildChanges(before, replica).map((c) =>
      Object.freeze({ ...c, origin: "remote" as const }),
    );
    this.#emit(changes);
    return Object.freeze({ objects: changes.map((c) => c.objectId), merged });
  }

  /**
   * Forgets the whole state (an empty replica that keeps the §9 sequence,
   * no merged or buffered units), so it can be rebuilt from accepted units
   * only (SNAP-EP: Snapshot-derived state dropped). Notifies the changes.
   */
  reset(): void {
    const before = this.#replica;
    this.#replica = before.emptied();
    this.#merged.clear();
    this.#pending.clear();
    this.#emit(rebuildChanges(before, this.#replica));
  }

  /** Whether this handler holds the unit's change (merged, recorded or buffered). */
  has(unitId: DataUnitId): boolean {
    const key = toHex(unitId);
    return this.#merged.has(key) || this.#pending.has(key);
  }

  /** The units waiting for Automerge dependencies. */
  pendingUnits(): DataUnitId[] {
    return [...this.#pending.values()].map((b) => b.unitId);
  }

  codecFor(unit: {
    readonly resourceId: ResourceId;
    readonly actor: PrincipalId;
  }): SharedObjectsCodec {
    const actor = toHex(deriveActorId(unit.resourceId, unit.actor));
    // §8, §11 (SO-SEC1): a unit carries only changes of its signer's §8
    // actor, so no Principal can write into another Principal's Automerge
    // history. Anything else is PROFILE_INVALID / CHANGE_ACTOR_MISMATCH.
    const bound = (change: CheckedChange): CheckedChange => {
      if (change.actor !== actor)
        throw new ProfileInvalidError(
          "CHANGE_ACTOR_MISMATCH",
          `the change's Automerge actor ${change.actor} is not the §8 actor ${actor} of the unit's signer (§11, SO-SEC1)`,
        );
      return change;
    };
    return {
      dataProfile: PROFILE_ID,
      encode: (change) => frameChange(bound(change).bytes),
      decode: (plaintext) => bound(unframeChange(plaintext)),
    };
  }

  apply(unit: SharedObjectsUnit, change: CheckedChange): SharedObjectsApplyResult {
    const r = this.#replica.receiveChange(change.bytes);
    if (r.status === "missing_dependencies") {
      this.#pending.set(toHex(unit.unitId), { unitId: unit.unitId, change });
      return Object.freeze({
        merged: [],
        objects: [],
        diagnostics: [],
        pending: `waiting for Automerge changes ${r.missing.join(", ")}`,
      });
    }
    // "duplicate": the replica holds the change already (e.g. this client's
    // own change coming back): merged, nothing changes.
    this.#merged.set(toHex(unit.unitId), { unitId: unit.unitId, hash: change.hash });
    const merged: DataUnitId[] = [unit.unitId];
    const changes: ObjectChange[] = r.status === "applied" ? [...r.objects] : [];
    for (let progress = true; progress; ) {
      progress = false;
      for (const [key, b] of this.#pending) {
        const again = this.#replica.receiveChange(b.change.bytes);
        if (again.status === "missing_dependencies") continue;
        this.#pending.delete(key);
        this.#merged.set(key, { unitId: b.unitId, hash: b.change.hash });
        merged.push(b.unitId);
        if (again.status === "applied") changes.push(...again.objects);
        progress = true;
      }
    }
    this.#emit(changes);
    const objects = [...new Set(changes.map((c) => c.objectId))].sort();
    return Object.freeze({ merged, objects, diagnostics: this.#diagnostics(objects) });
  }

  /** §74.1 problems and §21 collisions of the given objects (§77: the rest are unaffected). */
  #diagnostics(objects: readonly string[]): SharedObjectsDiagnostic[] {
    if (objects.length === 0) return [];
    const validation = this.#replica.validate();
    const out: SharedObjectsDiagnostic[] = [];
    for (const id of objects) {
      for (const p of validation.objects.get(id) ?? [])
        out.push({
          objectId: id,
          code: p.code,
          diagnostic: p.diagnostic,
          pointer: p.pointer,
          message: p.message,
        });
      if (validation.collisions.includes(id))
        out.push({
          objectId: id,
          code: "OBJECT_ID_COLLISION",
          message: `${id}: concurrent objects share this Object ID (§21)`,
        });
    }
    return out;
  }

  /**
   * §14.1 (G-EP7): the state without `unitIds`, rebuilt from the
   * remaining changes. Merged units whose changes build on an excluded one
   * go back to the buffer and are reported as pending.
   */
  exclude(unitIds: readonly DataUnitId[]): SharedObjectsExcludeResult {
    const hashes: string[] = [];
    for (const id of unitIds) {
      const key = toHex(id);
      this.#pending.delete(key);
      const m = this.#merged.get(key);
      if (m !== undefined) {
        hashes.push(m.hash);
        this.#merged.delete(key);
      }
    }
    if (hashes.length === 0) return Object.freeze({ objects: [], pending: [] });
    const before = this.#replica;
    const { replica, unapplied } = before.rebuildWithout(hashes);
    this.#replica = replica;
    const pending: DataUnitId[] = [];
    for (const change of unapplied) {
      const entry = [...this.#merged].find(([, m]) => m.hash === change.hash);
      if (entry === undefined) continue; // a local change: kept out with its dependency
      this.#merged.delete(entry[0]);
      this.#pending.set(entry[0], { unitId: entry[1].unitId, change });
      pending.push(entry[1].unitId);
    }
    const changes = rebuildChanges(before, replica);
    this.#emit(changes);
    return Object.freeze({ objects: changes.map((c) => c.objectId), pending });
  }
}

/** §100 notifications for every object that differs between two replicas of one Resource. */
function rebuildChanges(before: SharedObjectsReplica, after: SharedObjectsReplica): ObjectChange[] {
  const ids = [...new Set([...before.objectIds(), ...after.objectIds()])].sort();
  const beforeConflicts = before.conflicts();
  const afterConflicts = after.conflicts();
  const out: ObjectChange[] = [];
  for (const id of ids) {
    const was = (before.getObject(id) ?? {}) as Record<string, Json>;
    const now = (after.getObject(id) ?? {}) as Record<string, Json>;
    const fields = [...new Set([...Object.keys(was), ...Object.keys(now)])]
      .filter((f) => JSON.stringify(was[f]) !== JSON.stringify(now[f]))
      .sort();
    const wasC = Object.keys(beforeConflicts[id] ?? {});
    const nowC = Object.keys(afterConflicts[id] ?? {});
    if (fields.length === 0 && JSON.stringify(wasC) === JSON.stringify(nowC)) continue;
    out.push(
      Object.freeze({
        resource: after.resource,
        objectId: id,
        objectType:
          typeof now.type === "string"
            ? now.type
            : typeof was.type === "string"
              ? was.type
              : undefined,
        fields: Object.freeze(fields),
        conflictsAppeared: Object.freeze(nowC.filter((f) => !wasC.includes(f)).sort()),
        conflictsDisappeared: Object.freeze(wasC.filter((f) => !nowC.includes(f)).sort()),
        origin: "rebuild",
      }),
    );
  }
  return out;
}
