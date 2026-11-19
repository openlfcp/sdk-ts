import {
  type DataUnitId,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import type { CheckedChange } from "../admission/framing.js";
import { GuardedListeners } from "../listeners.js";
import type { ServiceControlOptions, ServiceControlSignerClass } from "./admission.js";
import {
  type ServiceControlReceiveResult,
  ServiceControlReplica,
  type ServiceControlUnit,
  serviceControlCodecFor,
  serviceControlSnapshotCodec,
} from "./replica.js";
import type { ServiceControlValidation } from "./schema.js";
import { SERVICE_CONTROL_PROFILE_ID } from "./values.js";
import type { ServiceControlIntent } from "./write.js";

/**
 * The Data Profile handler of the control Resource C
 * (SERVICE-CONTROL-PROFILE-01): what the profile-agnostic Data Unit applier
 * of @openlfcp/client calls once LFCP has accepted a unit of C, the commit
 * binding through which a client writes its records, the Snapshot it
 * publishes, and subscriptions to the state readers see (§5). It matches the
 * client's DataProfileHandler, CommitBinding and SnapshotBinding
 * structurally; this package depends on neither client nor wire.
 *
 * Admission needs the signer's class at the unit's control_ref (§2.3): the
 * applier passes C's Control state there as `unit.control`, and
 * `signerClassOf` turns it into the class (the client's
 * serviceControlSignerFacts with serviceControlSignerClass).
 *
 * A received Snapshot of C is never loaded: its changes would be admitted
 * without the units that carry them (§2.2, SOP §13), so a reader replays
 * the units. The profile publishes Snapshots (§9: by the human's clients).
 */

/** An accepted unit as the applier passes it (structurally the client's ProfileUnit). */
export interface ServiceControlProfileUnit {
  readonly unitId: DataUnitId;
  readonly actor: PrincipalId;
  readonly seq: bigint | number;
  /** C's Control state at the unit's control_ref, as the applier gives it. */
  readonly control?: unknown;
}

export interface ServiceControlDataProfileOptions extends ServiceControlOptions {
  /** §2.3 at the unit's control_ref; a unit without it is of class `other`. */
  readonly signerClassOf: (unit: ServiceControlProfileUnit) => ServiceControlSignerClass;
}

/** What a merge, a local write or a rebuild changed in the state readers see. */
export interface ServiceControlChanged {
  /**
   * The entries whose read state changed, as `service`, `status`,
   * `lifecycle` or `<container>/<key>` (e.g. `events/<rid>`), sorted.
   */
  readonly keys: readonly string[];
  readonly origin: "local" | "remote" | "rebuild";
  /** The state after the change (§5). */
  readonly state: ServiceControlValidation;
}

export interface ServiceControlListenerFailure {
  readonly error: unknown;
  readonly event: ServiceControlChanged;
}

export interface ServiceControlBatchResult {
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

/** A local write staged for commit (structurally the client's StagedOperation). */
export interface ServiceControlStagedOperation {
  readonly values: readonly CheckedChange[];
  readonly affectedNodeIds: readonly string[];
  readonly modelRevision: string;
  apply(): void;
  revert(): void;
  writes(units: readonly { readonly unitId: DataUnitId }[]): readonly never[];
  committed(unitIds: readonly DataUnitId[]): void;
}

interface Waiting {
  readonly unitId: DataUnitId;
  readonly hash: string;
}

/** Each entry's read state, to tell which ones changed. */
function fingerprints(v: ServiceControlValidation): Map<string, string> {
  const json = (x: unknown) =>
    JSON.stringify(x, (_, value) => (typeof value === "bigint" ? `${value}n` : value));
  const out = new Map<string, string>();
  for (const top of ["service", "status", "lifecycle"] as const)
    if (v[top] !== undefined) out.set(top, json(v[top]));
  for (const top of [
    "approvals",
    "bindings",
    "pairing",
    "questions",
    "requests",
    "answers",
    "cancels",
    "events",
  ] as const)
    for (const [key, entry] of Object.entries(v[top])) out.set(`${top}/${key}`, json(entry));
  return out;
}

function changedKeys(before: Map<string, string>, after: Map<string, string>): string[] {
  const keys = new Set([...before.keys(), ...after.keys()]);
  return [...keys].filter((k) => before.get(k) !== after.get(k)).sort();
}

export class ServiceControlDataProfile {
  readonly dataProfile = SERVICE_CONTROL_PROFILE_ID;
  readonly #options: ServiceControlDataProfileOptions;
  #replica: ServiceControlReplica;
  #state: ServiceControlValidation;
  #prints: Map<string, string>;
  /** Merged units: unit ID hex → change hash. */
  readonly #merged = new Map<string, Waiting>();
  /** Units waiting for their dependencies, by unit ID hex. */
  readonly #pending = new Map<string, Waiting>();
  /** Units whose actor sequence a different change has (SOP §14.1), by unit ID hex. */
  readonly #held = new Map<string, Waiting>();
  readonly #listeners = new GuardedListeners<ServiceControlChanged, ServiceControlListenerFailure>(
    (error, event) => Object.freeze({ error, event }),
  );

  constructor(options: ServiceControlDataProfileOptions) {
    this.#options = options;
    this.#replica = ServiceControlReplica.empty(options);
    this.#state = this.#replica.validate();
    this.#prints = fingerprints(this.#state);
  }

  /** The current replica (a rebuild replaces it). */
  get replica(): ServiceControlReplica {
    return this.#replica;
  }

  /** The state readers see (§5): invalid entries left out. */
  state(): ServiceControlValidation {
    return this.#state;
  }

  /**
   * Subscribes to changes of the state readers see: received units, this
   * client's committed writes, rebuilds. A listener that throws never turns
   * the merge or the write into a failure (onListenerError).
   */
  onChanged(listener: (event: ServiceControlChanged) => void): () => void {
    return this.#listeners.add(listener);
  }

  onListenerError(handler: (failure: ServiceControlListenerFailure) => void): () => void {
    return this.#listeners.onError(handler);
  }

  /** Re-reads the state; emits the entries that changed. Returns them. */
  #refresh(origin: ServiceControlChanged["origin"]): string[] {
    this.#state = this.#replica.validate();
    const prints = fingerprints(this.#state);
    const keys = changedKeys(this.#prints, prints);
    this.#prints = prints;
    if (keys.length > 0)
      this.#listeners.emit([
        Object.freeze({ keys: Object.freeze(keys), origin, state: this.#state }),
      ]);
    return keys;
  }

  /** The codec of one unit, bound to its signer's actor (§2). */
  codecFor(unit: { readonly resourceId: ResourceId; readonly actor: PrincipalId }) {
    return serviceControlCodecFor(unit);
  }

  /** Merges one accepted unit's change; throws when §4 refuses it. */
  apply(unit: ServiceControlProfileUnit, change: CheckedChange) {
    const key = toHex(unit.unitId);
    const r = this.applyBatch([{ unit, value: change }]);
    const own = r.rejected.find((x) => toHex(x.unitId) === key);
    if (own !== undefined)
      throw Object.assign(new LfcpError("PROFILE_INVALID", own.message), {
        diagnostic: own.diagnostic,
      });
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
   * Merges many accepted units at once, each with its signer's class at its
   * control_ref; units still waiting are retried. A refused change rejects
   * only its unit; the units that depend on it wait.
   */
  applyBatch(
    units: readonly { readonly unit: ServiceControlProfileUnit; readonly value: CheckedChange }[],
  ): ServiceControlBatchResult {
    const offered: ServiceControlUnit[] = [];
    for (const { unit, value } of units) {
      this.#pending.set(toHex(unit.unitId), { unitId: unit.unitId, hash: value.hash });
      offered.push({
        signer: unit.actor,
        actorSeq: unit.seq,
        signerClass: this.#options.signerClassOf(unit),
        bytes: value.bytes,
      });
    }
    return this.#settle(this.#replica.receiveChanges(offered), "remote");
  }

  #settle(
    r: ServiceControlReceiveResult,
    origin: ServiceControlChanged["origin"],
    rebuilt = false,
  ): ServiceControlBatchResult {
    const byHash = new Map<string, Waiting[]>();
    for (const w of [...this.#pending.values(), ...this.#held.values()])
      byHash.set(w.hash, [...(byHash.get(w.hash) ?? []), w]);
    const merged: DataUnitId[] = [];
    for (const hash of [...r.admitted, ...r.duplicates])
      for (const w of byHash.get(hash) ?? []) {
        const k = toHex(w.unitId);
        this.#pending.delete(k);
        this.#held.delete(k);
        this.#merged.set(k, w);
        merged.push(w.unitId);
      }
    const rejected: ServiceControlBatchResult["rejected"][number][] = [];
    for (const x of r.refused)
      for (const w of x.hash === undefined ? [] : (byHash.get(x.hash) ?? [])) {
        const k = toHex(w.unitId);
        this.#pending.delete(k);
        if (x.held) this.#held.set(k, w);
        else {
          this.#held.delete(k);
          rejected.push({
            unitId: w.unitId,
            code: x.code,
            diagnostic: x.diagnostic,
            message: x.message,
          });
        }
      }
    const objects = merged.length > 0 || rebuilt ? this.#refresh(origin) : [];
    return Object.freeze({
      merged: Object.freeze(merged),
      pending: Object.freeze([...this.#pending.values()].map((w) => w.unitId)),
      held: Object.freeze([...this.#held.values()].map((w) => w.unitId)),
      rejected: Object.freeze(rejected),
      objects: Object.freeze(objects),
      diagnostics: Object.freeze([]),
    });
  }

  /**
   * W §19.1 (G-EP7): the state without `unitIds`, rebuilt from the other
   * changes; merged units that build on an excluded one wait again, held
   * ones are retried.
   */
  exclude(unitIds: readonly DataUnitId[]) {
    const hashes: string[] = [];
    for (const id of unitIds) {
      const k = toHex(id);
      this.#pending.delete(k);
      this.#held.delete(k);
      const m = this.#merged.get(k);
      if (m !== undefined) {
        hashes.push(m.hash);
        this.#merged.delete(k);
      }
    }
    if (hashes.length === 0) return Object.freeze({ objects: [], pending: [], released: [] });
    const heldBefore = new Set(this.#held.keys());
    const { replica, result } = this.#replica.rebuildWithout(hashes);
    this.#replica = replica;
    const pending: DataUnitId[] = [];
    for (const [k, m] of [...this.#merged])
      if (!replica.hasChange(m.hash)) {
        this.#merged.delete(k);
        this.#pending.set(k, m);
        pending.push(m.unitId);
      }
    const settled = this.#settle(result, "rebuild", true);
    return Object.freeze({
      objects: settled.objects,
      pending: Object.freeze(pending),
      released: Object.freeze(settled.merged.filter((id) => heldBefore.has(toHex(id)))),
    });
  }

  has(unitId: DataUnitId): boolean {
    const k = toHex(unitId);
    return this.#merged.has(k) || this.#pending.has(k) || this.#held.has(k);
  }

  /** Forgets the whole state, to rebuild it from accepted units (SNAP-EP). */
  reset(): void {
    this.#replica = ServiceControlReplica.empty(this.#options);
    this.#merged.clear();
    this.#pending.clear();
    this.#held.clear();
    this.#refresh("rebuild");
  }

  /**
   * How a sync client commits this writer's records (structurally the
   * client's CommitBinding): `stage` writes the intents as one change and
   * admits it here (ServiceControlReplica.write), so a change §4 refuses
   * throws before any unit exists ("Couldn't send", §11). `signerClass` is
   * the writer's class at the head it writes on: `root` or `personal` for a
   * managing client, `service-device` for the base installation.
   */
  commitBinding(principal: PrincipalId, signerClass: ServiceControlSignerClass) {
    const codec = serviceControlCodecFor({ resourceId: this.#options.resource, actor: principal });
    return {
      codec,
      stage: (intents: readonly unknown[]): ServiceControlStagedOperation | null => {
        const list = intents as readonly ServiceControlIntent[];
        if (list.length === 0) return null;
        // SC0 holds the initial change to unit 1 (§2.2); no other change depends on it.
        const actorSeq = list.some((i) => i.intent === "initialize") ? 1 : 2;
        const change = this.#replica.write({ signer: principal, actorSeq, signerClass }, list);
        if (change === null) return null;
        const before = this.#prints;
        const after = fingerprints(this.#replica.validate());
        const keys = changedKeys(before, after);
        return {
          values: [change],
          affectedNodeIds: keys,
          modelRevision: this.#replica.heads().join(","),
          apply: () => {},
          revert: () => {
            this.#replica = this.#replica.rebuildWithout([change.hash]).replica;
          },
          writes: () => [],
          committed: (unitIds) => {
            const unitId = unitIds[0];
            if (unitId !== undefined)
              this.#merged.set(toHex(unitId), { unitId, hash: change.hash });
            this.#refresh("local");
          },
        };
      },
    };
  }

  /**
   * The Snapshot binding of a sync client: publishes the full save (SOP
   * §13); it has no `load`, so an offered Snapshot of C is not loaded and
   * the units are replayed instead (§2.2).
   */
  snapshotBinding() {
    return {
      codec: serviceControlSnapshotCodec,
      current: (): Uint8Array => this.#replica.save(),
    };
  }
}
