import {
  type ActorSequence,
  actorSequence,
  bytesEqual,
  type DataEpoch,
  type DataUnitId,
  dataUnitId,
  fromHex,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { decryptDataUnit, deriveActorDataKey, type ResourceDEK } from "@openlfcp/crypto";
import type {
  DataUnitRow,
  DataUnitStatus,
  LfcpStorage,
  StorageWrite,
  StoredDataUnit,
} from "@openlfcp/storage";
import {
  beyondCutoff,
  type ControlView,
  canonicalFrontierFromCbor,
  checkDataUnit,
  classifyDataUnit,
  type DataProfileCodec,
  type DataUnitCheckOptions,
  type DataUnitEquivocation,
  type DataUnitQuarantined,
  dataUnitAad,
  parseDataUnit,
  type ReceivedDataUnit,
  receiveDataUnit,
} from "@openlfcp/wire";
import { decodeDeterministic } from "@openlfcp/wire/cbor";
import { EngineGuard, isEngineTrap, unitItem } from "./engine-guard.js";
import { dataUnitRow, StoredSeenUnits } from "./storage.js";

/**
 * Applying received Data Units to the Resource's Data Profile (LFCP-033).
 *
 * This is where LFCP security ends and application semantics begin. The
 * LFCP side is receiveDataUnit (LFCP-025), unchanged and in its order:
 * structure → actor → signature → equivocation → referenced head →
 * data/write at that head → epoch and cutoff → DEK → AEAD → profile
 * decode → actor hash chain (accepted or held). Only an accepted unit
 * reaches the profile, and only once: the Data Unit ID is the idempotency
 * boundary.
 *
 * The profile side is a DataProfileHandler, selected by the Resource's
 * Genesis data_profile. The applier knows no profile: the Shared Objects
 * handler lives in @openlfcp/shared-objects. A Resource whose profile has
 * no handler is PROFILE_UNSUPPORTED: its units are verified without a DEK
 * and kept, and their plaintext is never decrypted or applied.
 *
 * Three ways a valid unit can wait, kept apart:
 * - held (§26.2, G-DP1): its actor chain does not link yet; retried here
 *   when the actor's previous unit is accepted;
 * - profile-pending: LFCP-accepted, but the profile cannot merge it until
 *   other units' content arrives (Automerge dependencies); the handler
 *   buffers it and merges it when they do;
 * - quarantined (STALE_DATA_EPOCH): never merged automatically.
 *
 * Crash-loop breaker (EngineGuard): every engine call on received units
 * (decode and apply, also when replaying) runs with a durable record of
 * the units it covers. After a crash those units are suspects, received
 * and replayed alone; a unit that crashes the engine again by itself is
 * quarantined locally (status local-failure, INVALID_AUTOMERGE_BYTES) and
 * never given to the engine again. Exclusion and rebuild (G-EP7) work on
 * units already merged once and are not guarded.
 */

/** An LFCP-accepted unit as the profile sees it. */
export interface ProfileUnit {
  readonly unitId: DataUnitId;
  readonly resourceId: ResourceId;
  readonly actor: PrincipalId;
  readonly seq: ActorSequence;
  readonly epoch: DataEpoch;
}

/** A profile-level finding about the state after a merge (e.g. a PROFILE_INVALID object). */
export interface ProfileDiagnostic {
  readonly objectId?: string;
  readonly code: string;
  readonly diagnostic?: string;
  readonly pointer?: string;
  readonly message: string;
}

export interface ProfileApplyResult {
  /** Units merged by this call: the unit itself when it merged now, and buffered units it unblocked. */
  readonly merged: readonly DataUnitId[];
  /** Objects whose state changed. */
  readonly objects: readonly string[];
  /** Findings about the merged state; they never undo the merge (profile §77 isolation). */
  readonly diagnostics: readonly ProfileDiagnostic[];
  /** Why the unit is buffered by the profile when it did not merge now. */
  readonly pending?: string;
  /**
   * Why the profile holds the unit (SHARED-OBJECTS-PROFILE-01 §14.1): a
   * different change has its actor and sequence number. Never merged until
   * a rebuild frees them.
   */
  readonly held?: string;
}

/** What a handler's applyBatch reports: per unit merged, pending or rejected, and the objects once. */
export interface ProfileBatchResult {
  /** Units merged now: the batch's and buffered units it unblocked. */
  readonly merged: readonly DataUnitId[];
  /** Units buffered by the profile (the batch's, and earlier ones still waiting). */
  readonly pending: readonly DataUnitId[];
  /** Units the profile holds (§14.1): a different change has their actor and sequence number. */
  readonly held?: readonly DataUnitId[];
  /** Units the profile refused, with the code and message apply would have thrown. */
  readonly rejected: readonly {
    readonly unitId: DataUnitId;
    readonly code: string;
    readonly message: string;
  }[];
  readonly objects: readonly string[];
  readonly diagnostics: readonly ProfileDiagnostic[];
}

export interface ProfileExcludeResult {
  /** Objects whose state changed. */
  readonly objects: readonly string[];
  /** Merged units that now wait for an excluded unit's content (profile-pending). */
  readonly pending: readonly DataUnitId[];
  /** Held units (§14.1) that merged after the rebuild freed their actor sequence. */
  readonly released?: readonly DataUnitId[];
}

/** The application side of one Data Profile. Implemented by profile packages. */
export interface DataProfileHandler<T> {
  /** The Genesis data_profile it implements (§15, §27). */
  readonly dataProfile: string;
  /**
   * The codec for one unit's plaintext. The unit's Resource and signing
   * actor are known before its plaintext is decoded, so the codec can bind
   * the content to them; decode throws to reject (local-failure, never
   * merged, never marked accepted).
   */
  codecFor(unit: {
    readonly resourceId: ResourceId;
    readonly actor: PrincipalId;
  }): DataProfileCodec<T>;
  /** Merges one accepted unit's decoded value. Throws when the profile refuses it. */
  apply(unit: ProfileUnit, value: T): ProfileApplyResult;
  /**
   * Merges many accepted units at once, as apply would one by one (a
   * refusal rejects only its unit). Optional: with it, receiveBatch and
   * replayStored hand the profile a whole catch-up at once, which an engine
   * such as Automerge applies far faster than unit by unit.
   */
  applyBatch?(
    units: readonly { readonly unit: ProfileUnit; readonly value: T }[],
  ): ProfileBatchResult;
  /**
   * LFCP-WIRE-01 §19.1 (G-EP7): takes merged or buffered units out again, so that
   * the state equals the state built from the remaining accepted units.
   */
  exclude(unitIds: readonly DataUnitId[]): ProfileExcludeResult;
  /**
   * Whether the profile state holds this unit's content. With it, units
   * merged after the last persisted checkpoint can be replayed from storage
   * after a restart (DataUnitApplier.replayStored).
   */
  has?(unitId: DataUnitId): boolean;
  /** Forgets the whole profile state, to rebuild it from accepted units (SNAP-EP). */
  reset?(): void;
}

interface Applied {
  readonly unitId: DataUnitId;
  readonly dataProfile: string;
  readonly actor: PrincipalId;
  readonly seq: ActorSequence;
  readonly epoch: DataEpoch;
  /**
   * Whether the unit may be advertised in Haves. Always false here: a unit
   * is advertised only once the sync layer knows its storage is durable
   * (LFCP-036).
   */
  readonly haveEligible: false;
  /** Buffered units this one unblocked, merged now. */
  readonly alsoMerged: readonly DataUnitId[];
  /** Held units of the same actor that were retried after this one, with their outcomes. */
  readonly released: readonly ApplyOutcome[];
}

/**
 * Two or more signature-valid units for one (resource, actor, seq).
 * LFCP-WIRE-01 §26.2 (G-DP5): no unit of the set stays merged, since keeping the
 * first one would choose by arrival order (§26.2 forbids choosing). Every
 * unit is marked "equivocation" and un-accepted; merged ones were taken out
 * of the profile state.
 */
export type EquivocationOutcome = DataUnitEquivocation & {
  /** Units of the set that were merged and are now excluded from the profile state. */
  readonly excluded: readonly DataUnitId[];
  /** Objects whose state changed through the exclusion. */
  readonly objects: readonly string[];
  /** Merged units that now wait in the profile for an excluded unit's content. */
  readonly pending: readonly DataUnitId[];
  /** Held units of the actor retried after the exclusion (§26.2, G-DP1-GAP). */
  readonly released: readonly ApplyOutcome[];
};

/** The outcome of one received Data Unit. */
export type ApplyOutcome =
  /** Accepted by LFCP and merged into the profile state. */
  | (Applied & {
      readonly kind: "applied";
      readonly objects: readonly string[];
      readonly diagnostics: readonly ProfileDiagnostic[];
    })
  /** Accepted by LFCP; the profile buffers it until the content it builds on arrives. */
  | (Applied & { readonly kind: "profile-pending"; readonly detail: string })
  /**
   * Accepted by LFCP and kept (a holding: advertised and relayed); the
   * profile holds it because a different change has its actor and sequence
   * number (SHARED-OBJECTS-PROFILE-01 §14.1, POST-001). It is retried after
   * every rebuild that removes changes, and reported as applied then.
   */
  | (Applied & { readonly kind: "profile-held"; readonly detail: string })
  /** Accepted by LFCP, refused by the profile when merging: never merged. */
  | {
      readonly kind: "profile-rejected";
      readonly unitId: DataUnitId;
      readonly dataProfile: string;
      readonly code: string;
      readonly message: string;
    }
  /** The Resource's Data Profile has no handler (§62 PROFILE_UNSUPPORTED): verified and kept, never decrypted. */
  | {
      readonly kind: "profile-unsupported";
      readonly code: "PROFILE_UNSUPPORTED";
      readonly unitId: DataUnitId;
      readonly dataProfile: string;
    }
  /**
   * A unit whose content a loaded Snapshot already holds: verified without
   * a DEK and accepted, never decrypted or merged again (acceptCovered).
   */
  | {
      readonly kind: "covered";
      readonly unitId: DataUnitId;
      readonly dataProfile: string;
      /** Held units of the same actor that were retried after this one, with their outcomes. */
      readonly released: readonly ApplyOutcome[];
    }
  /**
   * The unit crashed the profile engine twice by itself (EngineGuard): it
   * is quarantined on this device and never applied again. Local only: no
   * wire code; the unit may be valid elsewhere.
   */
  | {
      readonly kind: "engine-crash";
      readonly code: "INVALID_AUTOMERGE_BYTES";
      readonly unitId: DataUnitId;
      readonly message: string;
    }
  | EquivocationOutcome
  | Exclude<ReceivedDataUnit<unknown>, { readonly kind: "accepted" | "equivocation" }>;

/** A merged unit that a newly known Key Epoch puts beyond its cutoff (G-EP7). */
export interface ExcludedUnit {
  readonly unitId: DataUnitId;
  readonly quarantine: Omit<DataUnitQuarantined, "kind" | "unitId">;
}

export interface EpochReconciliation {
  /** Units taken out of the profile state and now quarantined. */
  readonly excluded: readonly ExcludedUnit[];
  /** Objects whose state changed. */
  readonly objects: readonly string[];
  /** Merged units that now wait in the profile for an excluded unit's content. */
  readonly pending: readonly DataUnitId[];
  /**
   * The Key Epoch cut off units a loaded Snapshot covered: the Snapshot
   * state was dropped and rebuilt from accepted units (SNAP-EP); the units
   * it covered must be fetched again.
   */
  readonly snapshotDropped: boolean;
  /**
   * Held units retried once the excluded units stopped being their actors'
   * latest accepted ones (§26.2, G-DP1-GAP), with their outcomes.
   */
  readonly released: readonly ApplyOutcome[];
}

export interface DataUnitApplierOptions extends DataUnitCheckOptions {
  /**
   * Where verified units, their exact bytes, statuses and the accepted
   * marks live (the wire SeenUnits runs on it). InMemoryLfcpStorage for
   * tests and development only.
   */
  readonly storage: Pick<LfcpStorage, "dataUnits" | "snapshots" | "commit" | "localMarks">;
  /** The DEK of a Data Epoch, if this client holds it (e.g. dekResolver). */
  readonly dek: (epoch: DataEpoch) => ResourceDEK | undefined | Promise<ResourceDEK | undefined>;
  /** The profiles this client implements. */
  readonly handlers: readonly DataProfileHandler<unknown>[];
}

/** A codec for bytes that do not parse: receiveDataUnit rejects them before any decode. */
const unreachableCodec = (dataProfile: string): DataProfileCodec<never> => ({
  dataProfile,
  encode: () => {
    throw new Error("no codec for a malformed unit");
  },
  decode: () => {
    throw new Error("no codec for a malformed unit");
  },
});

const LFCP_ACCEPTED: readonly DataUnitStatus[] = ["merged", "profile-pending", "profile-held"];

const HELD =
  "held: a different change has its actor and sequence number (SHARED-OBJECTS-PROFILE-01 §14.1)";

const CRASHED =
  "this unit crashed the profile engine twice, applied alone; it is not applied again on this device (local only)";

type Accepted = Extract<ReceivedDataUnit<unknown>, { kind: "accepted" }>;

const profileUnit = (view: ControlView, r: Accepted): ProfileUnit => ({
  unitId: r.unitId,
  resourceId: view.state.resourceId,
  actor: r.actor,
  seq: r.seq,
  epoch: r.epoch,
});

export class DataUnitApplier {
  readonly #options: DataUnitApplierOptions;
  readonly #handlers: ReadonlyMap<string, DataProfileHandler<unknown>>;
  readonly #storage: Pick<LfcpStorage, "dataUnits" | "snapshots" | "commit" | "localMarks">;
  readonly #seen: StoredSeenUnits;
  readonly #guard: EngineGuard;
  /** Units quarantined by the crash-loop breaker at this start, not yet reported. */
  #crashed: DataUnitId[] = [];

  constructor(options: DataUnitApplierOptions) {
    this.#options = options;
    this.#handlers = new Map(options.handlers.map((h) => [h.dataProfile, h]));
    this.#storage = options.storage;
    this.#seen = new StoredSeenUnits(options.storage);
    this.#guard = new EngineGuard(options.storage, "units");
  }

  /** Once per Resource: a leftover apply record becomes suspects; second-time crashers are quarantined. */
  async #recover(resource: ResourceId): Promise<void> {
    const crashed = await this.#guard.recover(resource);
    const writes: StorageWrite[] = [];
    for (const item of crashed) {
      const unitId = dataUnitId(fromHex(item.slice("unit:".length)));
      if ((await this.#storage.dataUnits.get(unitId)) === undefined) continue;
      writes.push({
        op: "set-data-unit-status",
        unitId,
        status: "local-failure",
        detail: `INVALID_AUTOMERGE_BYTES: ${CRASHED}`,
      });
      this.#crashed.push(unitId);
    }
    await this.#write(writes);
  }

  /** The unit's ID from its bytes, or undefined when they do not parse (reported by the LFCP checks). */
  #idOf(bytes: Uint8Array): DataUnitId | undefined {
    try {
      return parseDataUnit(bytes).signed.id as unknown as DataUnitId;
    } catch {
      return undefined;
    }
  }

  #crashOutcome(unitId: DataUnitId): ApplyOutcome {
    return Object.freeze({
      kind: "engine-crash",
      code: "INVALID_AUTOMERGE_BYTES",
      unitId,
      message: CRASHED,
    });
  }

  async #write(writes: readonly StorageWrite[]): Promise<void> {
    if (writes.length === 0) return;
    const r = await this.#storage.commit(writes);
    if (!r.ok) throw new Error(`unexpected storage precondition failure: ${r.reason}`);
  }

  /**
   * Receives one Data Unit of the Resource `view` describes. Never creates
   * a Data Unit: received content is applied, not re-sent as local work.
   */
  async receive(view: ControlView, bytes: Uint8Array): Promise<ApplyOutcome> {
    const R = view.state.resourceId;
    await this.#recover(R);
    const id = this.#idOf(bytes);
    if (id !== undefined && this.#guard.suspicion(R, unitItem(id)) === 2)
      return this.#crashOutcome(id);
    return this.#guard.run(R, id === undefined ? [] : [unitItem(id)], async () => {
      const v = await this.#verify(view, bytes);
      if ("outcome" in v) return v.outcome;
      return v.r.kind === "accepted"
        ? this.#apply(view, v.handler, v.r)
        : this.#settle(view, v.handler, v.r);
    });
  }

  /**
   * Receives the units of one DATA_BATCH (or any run of units) of the
   * Resource `view` describes: each passes the LFCP checks of receive in
   * order, unchanged, and the accepted ones reach the profile together
   * through the handler's applyBatch, when it has one. Outcomes come in the
   * order of `units`. An applied unit's objects and diagnostics are those
   * of the whole batch, reported on the last unit merged; the units
   * buffered before that the batch unblocked count as merged by the first.
   * Before an equivocation is handled, the units accepted so far are
   * applied, so its exclusion sees them.
   */
  async receiveBatch(view: ControlView, units: readonly Uint8Array[]): Promise<ApplyOutcome[]> {
    const handler = this.#handlers.get(view.state.dataProfile);
    const outcomes: ApplyOutcome[] = [];
    if (handler?.applyBatch === undefined) {
      for (const bytes of units) outcomes.push(await this.receive(view, bytes));
      return outcomes;
    }
    // Units that crashed the engine before go alone (receive), after the batch.
    const R = view.state.resourceId;
    await this.#recover(R);
    const batch: { index: number; bytes: Uint8Array }[] = [];
    const alone: { index: number; bytes: Uint8Array }[] = [];
    for (const [index, bytes] of units.entries()) {
      const id = this.#idOf(bytes);
      if (id !== undefined && this.#guard.suspicion(R, unitItem(id)) > 0)
        alone.push({ index, bytes });
      else batch.push({ index, bytes });
    }
    const items = batch.flatMap(({ bytes }) => {
      const id = this.#idOf(bytes);
      return id === undefined ? [] : [unitItem(id)];
    });
    const done = await this.#guard.run(R, items, () =>
      this.#receiveBatch(
        view,
        handler,
        batch.map((b) => b.bytes),
      ),
    );
    for (const [k, { index }] of batch.entries()) outcomes[index] = done[k] as ApplyOutcome;
    for (const { index, bytes } of alone) outcomes[index] = await this.receive(view, bytes);
    return outcomes;
  }

  async #receiveBatch(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
    units: readonly Uint8Array[],
  ): Promise<ApplyOutcome[]> {
    const outcomes: ApplyOutcome[] = [];
    let staged: { index: number; r: Accepted }[] = [];
    const flush = async () => {
      const batch = staged;
      staged = [];
      for (const [index, outcome] of await this.#applyStaged(view, handler, batch))
        outcomes[index] = outcome;
    };
    for (const [index, bytes] of units.entries()) {
      const v = await this.#verify(view, bytes);
      if ("outcome" in v) outcomes[index] = v.outcome;
      else if (v.r.kind === "accepted") staged.push({ index, r: v.r });
      else {
        if (v.r.kind === "equivocation") await flush();
        outcomes[index] = await this.#settle(view, v.handler, v.r);
      }
    }
    await flush();
    return outcomes;
  }

  /** The LFCP checks of one unit (receiveDataUnit), or the outcome when there is no handler. */
  async #verify(
    view: ControlView,
    bytes: Uint8Array,
  ): Promise<
    | { readonly outcome: ApplyOutcome }
    | { readonly handler: DataProfileHandler<unknown>; readonly r: ReceivedDataUnit<unknown> }
  > {
    const dataProfile = view.state.dataProfile;
    let row: DataUnitRow | undefined;
    try {
      row = dataUnitRow(bytes);
      this.#seen.expect(row);
    } catch {
      row = undefined; // receiveDataUnit reports it as MALFORMED_MESSAGE
    }
    const handler = this.#handlers.get(dataProfile);
    if (handler === undefined)
      return { outcome: await this.#unsupported(view, bytes, dataProfile) };

    const codec =
      row === undefined
        ? unreachableCodec(dataProfile)
        : handler.codecFor({ resourceId: row.resourceId, actor: row.actor });
    const r = await receiveDataUnit(view, bytes, {
      ...this.#options,
      seen: this.#seen,
      profile: codec,
    });
    // A decode that trapped the engine is not this unit's local failure.
    if (r.kind === "local-failure" && isEngineTrap(r.error)) throw r.error;
    return { handler, r };
  }

  /** A unit LFCP did not accept for merging: held, quarantined, failed locally, equivocating, … */
  async #settle(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
    r: Exclude<ReceivedDataUnit<unknown>, { kind: "accepted" }>,
  ): Promise<ApplyOutcome> {
    const status = (unitId: DataUnitId, s: DataUnitStatus, detail?: string): StorageWrite => ({
      op: "set-data-unit-status",
      unitId,
      status: s,
      ...(detail === undefined ? {} : { detail }),
    });

    switch (r.kind) {
      case "held":
        await this.#write([status(r.unitId, "held", r.reason)]);
        return r;
      case "quarantined":
        await this.#write([status(r.unitId, "quarantined", r.reason)]);
        return r;
      case "local-failure":
        await this.#write([status(r.unitId, "local-failure", `${r.reason}: ${r.message}`)]);
        return r;
      case "equivocation":
        return this.#equivocation(view, handler, r);
      default:
        return r; // duplicate (harmless replay) or rejected (never stored)
    }
  }

  async #apply(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
    r: Accepted,
  ): Promise<ApplyOutcome> {
    let result: ProfileApplyResult;
    try {
      result = handler.apply(profileUnit(view, r), r.value);
    } catch (e) {
      if (isEngineTrap(e)) throw e; // the engine is gone: not the unit's refusal
      const code = (e as { code?: unknown }).code;
      return this.#rejected(
        r,
        handler.dataProfile,
        typeof code === "string" ? code : "PROFILE_REJECTED",
        e instanceof Error ? e.message : String(e),
      );
    }
    return this.#merged(view, handler, r, result);
  }

  /** The staged accepted units through the handler's applyBatch, as #apply would one by one. */
  async #applyStaged(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
    staged: readonly { readonly index: number; readonly r: Accepted }[],
  ): Promise<[number, ApplyOutcome][]> {
    if (staged.length === 0 || handler.applyBatch === undefined) return [];
    let batch: ProfileBatchResult;
    try {
      batch = handler.applyBatch(
        staged.map(({ r }) => ({ unit: profileUnit(view, r), value: r.value })),
      );
    } catch (e) {
      if (isEngineTrap(e)) throw e;
      // The handler failed as a whole: apply one by one, which isolates the failing unit.
      const out: [number, ApplyOutcome][] = [];
      for (const { index, r } of staged) out.push([index, await this.#apply(view, handler, r)]);
      return out;
    }
    const merged = new Set(batch.merged.map((id) => toHex(id)));
    const heldNow = new Set((batch.held ?? []).map((id) => toHex(id)));
    const rejected = new Map(batch.rejected.map((x) => [toHex(x.unitId), x]));
    const inBatch = new Set(staged.map(({ r }) => toHex(r.unitId)));
    const unblocked = batch.merged.filter((id) => !inBatch.has(toHex(id)));
    let last = -1;
    staged.forEach(({ r }, k) => {
      if (merged.has(toHex(r.unitId))) last = k;
    });
    const out: [number, ApplyOutcome][] = [];
    for (const [k, { index, r }] of staged.entries()) {
      const key = toHex(r.unitId);
      const refused = rejected.get(key);
      if (refused !== undefined) {
        out.push([
          index,
          await this.#rejected(r, handler.dataProfile, refused.code, refused.message),
        ]);
        continue;
      }
      const now = merged.has(key);
      out.push([
        index,
        await this.#merged(
          view,
          handler,
          r,
          {
            merged: [...(now ? [r.unitId] : []), ...(k === 0 ? unblocked : [])],
            objects: k === last ? batch.objects : [],
            diagnostics: k === last ? batch.diagnostics : [],
            ...(now
              ? {}
              : heldNow.has(key)
                ? { held: HELD }
                : { pending: "buffered by the profile" }),
          },
          false,
        ),
      ]);
    }
    // §26.2 (G-DP1-GAP): held units whose previous names a unit of the batch
    // may link now. One scan for the whole batch keeps it linear; each
    // released unit is reported with the unit it links to.
    const byPrevious = new Map(staged.map(({ index, r }) => [toHex(r.unitId), index]));
    const held = await this.#storage.dataUnits.withStatus(view.state.resourceId, "held");
    const releasedFor = new Map<number, ApplyOutcome[]>();
    for (const h of held) {
      const previous = parseDataUnit(h.bytes).payload.prevDataUnitId;
      const owner = previous === null ? undefined : byPrevious.get(toHex(previous));
      if (owner === undefined) continue;
      if ((await this.#storage.dataUnits.get(h.unitId))?.status !== "held") continue;
      releasedFor.set(owner, [
        ...(releasedFor.get(owner) ?? []),
        await this.receive(view, h.bytes),
      ]);
    }
    return out.map(([index, outcome]) => {
      const extra = releasedFor.get(index);
      if (extra === undefined || !("released" in outcome)) return [index, outcome];
      return [
        index,
        Object.freeze({ ...outcome, released: Object.freeze([...outcome.released, ...extra]) }),
      ];
    });
  }

  /** An accepted unit the profile refused: never merged. */
  async #rejected(
    r: Accepted,
    dataProfile: string,
    code: string,
    message: string,
  ): Promise<ApplyOutcome> {
    await this.#write([
      { op: "set-data-unit-status", unitId: r.unitId, status: "profile-rejected", detail: message },
    ]);
    return Object.freeze({
      kind: "profile-rejected",
      unitId: r.unitId,
      dataProfile,
      code,
      message,
    });
  }

  /** An accepted unit the profile merged or buffered: its statuses, then held units it releases. */
  async #merged(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
    r: Accepted,
    result: ProfileApplyResult,
    releaseHeld = true,
  ): Promise<ApplyOutcome> {
    const dataProfile = handler.dataProfile;
    const mergedNow = result.merged.some((id) => bytesEqual(id, r.unitId));
    const alsoMerged = result.merged.filter((id) => !bytesEqual(id, r.unitId));
    const held = !mergedNow && result.held !== undefined;
    await this.#write([
      mergedNow
        ? { op: "set-data-unit-status", unitId: r.unitId, status: "merged" }
        : held
          ? {
              op: "set-data-unit-status",
              unitId: r.unitId,
              status: "profile-held",
              detail: result.held ?? null,
            }
          : {
              op: "set-data-unit-status",
              unitId: r.unitId,
              status: "profile-pending",
              detail: result.pending ?? "buffered by the profile",
            },
      ...alsoMerged.map(
        (unitId): StorageWrite => ({ op: "set-data-unit-status", unitId, status: "merged" }),
      ),
    ]);
    // §26.2 (G-DP1, G-DP1-GAP): a held unit of this actor above it may link now, across a gap.
    // A batch releases its held units once, at its end (#applyStaged).
    const next = releaseHeld
      ? await this.#storage.dataUnits.range(
          view.state.resourceId,
          r.actor,
          actorSequence(r.seq + 1n),
          actorSequence(2n ** 64n - 1n),
        )
      : [];
    const released: ApplyOutcome[] = [];
    // Only a held unit whose previous names the unit just accepted can link now.
    for (const held of next.filter((u) => u.status === "held")) {
      const previous = parseDataUnit(held.bytes).payload.prevDataUnitId;
      if (previous === null || !bytesEqual(previous, r.unitId)) continue;
      // A retry above may already have released it.
      if ((await this.#storage.dataUnits.get(held.unitId))?.status !== "held") continue;
      released.push(await this.receive(view, held.bytes));
    }
    const base = {
      unitId: r.unitId,
      dataProfile,
      actor: r.actor,
      seq: r.seq,
      epoch: r.epoch,
      haveEligible: false as const,
      alsoMerged: Object.freeze(alsoMerged),
      released: Object.freeze(released),
    };
    if (held)
      return Object.freeze({ ...base, kind: "profile-held", detail: result.held as string });
    return Object.freeze(
      mergedNow
        ? {
            ...base,
            kind: "applied",
            objects: result.objects,
            diagnostics: result.diagnostics,
          }
        : {
            ...base,
            kind: "profile-pending",
            detail: result.pending ?? "buffered by the profile",
          },
    );
  }

  // §26.2 (G-DP5): exclude every merged unit of an equivocating set.
  async #equivocation(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
    r: DataUnitEquivocation,
  ): Promise<EquivocationOutcome> {
    const stored = (
      await Promise.all(r.unitIds.map((id) => this.#storage.dataUnits.get(id)))
    ).filter((u) => u !== undefined);
    const merged = stored.filter((u) => LFCP_ACCEPTED.includes(u.status)).map((u) => u.unitId);
    const result: ProfileExcludeResult =
      merged.length > 0 ? handler.exclude(merged) : { objects: [], pending: [] };
    await this.#write([
      ...stored.flatMap((u): StorageWrite[] => [
        {
          op: "set-data-unit-status",
          unitId: u.unitId,
          status: "equivocation",
          detail: "ACTOR_EQUIVOCATION (G-DP5)",
        },
        { op: "set-accepted", unitId: u.unitId, accepted: false },
      ]),
      ...result.pending.map(
        (unitId): StorageWrite => ({
          op: "set-data-unit-status",
          unitId,
          status: "profile-pending",
          detail: "builds on an equivocating unit",
        }),
      ),
      ...this.#freedWrites(result),
    ]);
    // The actor's latest accepted unit may now be lower: held units can link (G-DP1-GAP).
    const released = [
      ...(merged.length > 0 ? await this.#retryHeld(view, [r.actor]) : []),
      ...(await this.#freed(handler, result)),
    ];
    return Object.freeze({
      ...r,
      excluded: Object.freeze(merged),
      objects: result.objects,
      pending: result.pending,
      released,
    });
  }

  /**
   * After a restart: the stored, LFCP-accepted units (merged or buffered by
   * the profile) whose content the restored profile state does not hold
   * (merged after its last checkpoint), decrypted again from their exact
   * stored bytes and applied, in (actor, seq) order. Units covered by a
   * Snapshot are not replayed (their content came with it). Needs the
   * handler's has(); returns what was replayed and what could not be (no
   * DEK, refused). LFCP checks are not repeated: the units passed them when
   * they were accepted.
   */
  async replayStored(view: ControlView): Promise<{
    readonly replayed: readonly DataUnitId[];
    readonly skipped: readonly { readonly unitId: DataUnitId; readonly reason: string }[];
    /** Units quarantined at this start: they crashed the engine twice by themselves. */
    readonly crashed: readonly DataUnitId[];
  }> {
    const handler = this.#handlers.get(view.state.dataProfile);
    const replayed: DataUnitId[] = [];
    const skipped: { unitId: DataUnitId; reason: string }[] = [];
    if (handler?.has === undefined) {
      await this.#recover(view.state.resourceId);
      const crashed = this.#crashed;
      this.#crashed = [];
      return { replayed, skipped, crashed };
    }
    const resource = view.state.resourceId;
    // A crash during an earlier apply: suspects, or units quarantined now.
    await this.#recover(resource);
    const crashed = this.#crashed;
    this.#crashed = [];
    // Also units accepted by LFCP whose merge was never recorded (a crash
    // between the accepted mark and the status write leaves them "seen" or "held").
    const stored = [
      ...(await this.#storage.dataUnits.withStatus(resource, "merged")),
      ...(await this.#storage.dataUnits.withStatus(resource, "profile-pending")),
      ...(await this.#storage.dataUnits.withStatus(resource, "profile-held")),
      ...(await this.#storage.dataUnits.withStatus(resource, "seen")),
      ...(await this.#storage.dataUnits.withStatus(resource, "held")),
    ]
      .filter((u) => u.accepted && u.detail !== "covered by a Snapshot" && !handler.has?.(u.unitId))
      .sort((a, b) => (a.actorSeq < b.actorSeq ? -1 : a.actorSeq > b.actorSeq ? 1 : 0));
    const merged: DataUnitId[] = [];
    const pendingNow: DataUnitId[] = [];
    const heldNow: DataUnitId[] = [];
    // Suspects of an earlier crash replay alone, each under its own record.
    const suspect = (u: { unitId: DataUnitId }) =>
      this.#guard.suspicion(resource, unitItem(u.unitId)) > 0;
    const groups = [...stored.filter(suspect).map((u) => [u]), stored.filter((u) => !suspect(u))];
    for (const group of groups)
      if (group.length > 0)
        await this.#guard.run(
          resource,
          group.map((u) => unitItem(u.unitId)),
          () =>
            this.#replayGroup(handler, group, { merged, pendingNow, heldNow, replayed, skipped }),
        );
    const isHeld = (id: DataUnitId) => heldNow.some((h) => bytesEqual(h, id));
    await this.#write([
      ...heldNow
        .filter((id) => !merged.some((m) => bytesEqual(m, id)))
        .map(
          (unitId): StorageWrite => ({
            op: "set-data-unit-status",
            unitId,
            status: "profile-held",
            detail: HELD,
          }),
        ),
      ...pendingNow
        .filter((id) => !merged.some((m) => bytesEqual(m, id)) && !isHeld(id))
        .map(
          (unitId): StorageWrite => ({
            op: "set-data-unit-status",
            unitId,
            status: "profile-pending",
            detail: "replayed; waiting for content it builds on",
          }),
        ),
      ...merged.map(
        (unitId): StorageWrite => ({ op: "set-data-unit-status", unitId, status: "merged" }),
      ),
    ]);
    return {
      replayed: Object.freeze(replayed),
      skipped: Object.freeze(skipped),
      crashed: Object.freeze(crashed),
    };
  }
  /** Decrypts, decodes and applies replayed units (replayStored), adding to `acc`. */
  async #replayGroup(
    handler: DataProfileHandler<unknown>,
    group: readonly StoredDataUnit[],
    acc: {
      readonly merged: DataUnitId[];
      readonly pendingNow: DataUnitId[];
      readonly heldNow: DataUnitId[];
      readonly replayed: DataUnitId[];
      readonly skipped: { unitId: DataUnitId; reason: string }[];
    },
  ): Promise<void> {
    const { merged, pendingNow, heldNow, replayed, skipped } = acc;
    const decoded: { readonly unit: ProfileUnit; readonly value: unknown }[] = [];
    for (const u of group) {
      const dek = await this.#options.dek(u.dataEpoch);
      if (dek === undefined) {
        skipped.push({ unitId: u.unitId, reason: `no DEK for epoch ${u.dataEpoch}` });
        continue;
      }
      try {
        const p = parseDataUnit(u.bytes).payload;
        const key = deriveActorDataKey(dek, p.resourceId, p.dataEpoch, p.actor);
        const plaintext = decryptDataUnit(key, p.actorSeq, dataUnitAad(p), p.ciphertext);
        const value = handler
          .codecFor({ resourceId: p.resourceId, actor: p.actor })
          .decode(plaintext);
        decoded.push({
          unit: {
            unitId: u.unitId,
            resourceId: p.resourceId,
            actor: p.actor,
            seq: p.actorSeq,
            epoch: p.dataEpoch,
          },
          value,
        });
      } catch (e) {
        if (isEngineTrap(e)) throw e;
        skipped.push({ unitId: u.unitId, reason: e instanceof Error ? e.message : String(e) });
      }
    }
    if (handler.applyBatch !== undefined && decoded.length > 0) {
      // One profile call for the whole replay (a restart after many changes).
      const batch = handler.applyBatch(decoded);
      const refused = new Map(batch.rejected.map((x) => [toHex(x.unitId), x]));
      merged.push(...batch.merged);
      heldNow.push(...(batch.held ?? []));
      for (const { unit } of decoded) {
        const no = refused.get(toHex(unit.unitId));
        if (no !== undefined) {
          skipped.push({ unitId: unit.unitId, reason: `${no.code}: ${no.message}` });
          continue;
        }
        if (!batch.merged.some((id) => bytesEqual(id, unit.unitId))) pendingNow.push(unit.unitId);
        replayed.push(unit.unitId);
      }
    } else
      for (const { unit, value } of decoded) {
        try {
          const r = handler.apply(unit, value);
          merged.push(...r.merged);
          if (r.held !== undefined) heldNow.push(unit.unitId);
          if (!r.merged.some((id) => bytesEqual(id, unit.unitId))) pendingNow.push(unit.unitId);
          replayed.push(unit.unitId);
        } catch (e) {
          if (isEngineTrap(e)) throw e;
          skipped.push({ unitId: unit.unitId, reason: e instanceof Error ? e.message : String(e) });
        }
      }
  }

  /**
   * A unit inside the frontier of a Snapshot this client loaded (§29, §66
   * step 3): its content is in the Snapshot, so it is not decrypted or
   * merged again. It gets the DEK-free LFCP checks (structure, signature,
   * equivocation, data/write at its head, epoch cutoff) and is then marked
   * accepted, so the actor's next unit links to it (§26.2). Its own link to
   * the previous unit is not checked: that unit is attested by the signed,
   * authorized Snapshot and was never received. A replay is a duplicate.
   */
  async acceptCovered(view: ControlView, bytes: Uint8Array): Promise<ApplyOutcome> {
    const dataProfile = view.state.dataProfile;
    try {
      this.#seen.expect(dataUnitRow(bytes));
    } catch {
      // checkDataUnit reports it as MALFORMED_MESSAGE
    }
    const c = await checkDataUnit(view, bytes, this.#seen, this.#options);
    if (c.kind === "equivocation") {
      const handler = this.#handlers.get(dataProfile);
      return handler === undefined
        ? Object.freeze({ ...c, excluded: [], objects: [], pending: [], released: [] })
        : this.#equivocation(view, handler, c);
    }
    if (c.kind !== "valid") {
      if (c.kind === "quarantined")
        await this.#write([
          { op: "set-data-unit-status", unitId: c.unitId, status: "quarantined", detail: c.reason },
        ]);
      return c;
    }
    const p = c.parsed.payload;
    if ((await this.#storage.dataUnits.acceptedAt(p.resourceId, p.actor, p.actorSeq)) !== undefined)
      return Object.freeze({ kind: "duplicate", unitId: c.unitId });
    await this.#write([
      {
        op: "set-data-unit-status",
        unitId: c.unitId,
        status: "merged",
        detail: "covered by a Snapshot",
      },
      { op: "set-accepted", unitId: c.unitId, accepted: true },
    ]);
    // §26.2 (G-DP1, G-DP1-GAP): a held unit of this actor above it may link now, across a gap.
    const next = await this.#storage.dataUnits.range(
      p.resourceId,
      p.actor,
      actorSequence(p.actorSeq + 1n),
      actorSequence(2n ** 64n - 1n),
    );
    const released: ApplyOutcome[] = [];
    // Only a held unit whose previous names the unit just accepted can link now.
    for (const held of next.filter((u) => u.status === "held")) {
      const previous = parseDataUnit(held.bytes).payload.prevDataUnitId;
      if (previous === null || !bytesEqual(previous, c.unitId)) continue;
      // A retry above may already have released it.
      if ((await this.#storage.dataUnits.get(held.unitId))?.status !== "held") continue;
      released.push(await this.receive(view, held.bytes));
    }
    return Object.freeze({
      kind: "covered",
      unitId: c.unitId,
      dataProfile,
      released: Object.freeze(released),
    });
  }

  async #unsupported(
    view: ControlView,
    bytes: Uint8Array,
    dataProfile: string,
  ): Promise<ApplyOutcome> {
    // DEK-free checks only: the plaintext of an unknown profile is never decrypted.
    const c = await checkDataUnit(view, bytes, this.#seen, this.#options);
    if (c.kind === "equivocation")
      return Object.freeze({ ...c, excluded: [], objects: [], pending: [], released: [] });
    if (c.kind !== "valid") return c;
    await this.#write([
      { op: "set-data-unit-status", unitId: c.unitId, status: "profile-unsupported" },
    ]);
    return Object.freeze({
      kind: "profile-unsupported",
      code: "PROFILE_UNSUPPORTED",
      unitId: c.unitId,
      dataProfile,
    });
  }

  /**
   * LFCP-WIRE-01 §19.1 (G-EP7): the single entry point the sync engine calls with
   * every newly validated Control view that may carry a new Key Epoch.
   * Merged (or profile-buffered) units that the view now puts beyond an
   * epoch cutoff are taken out of the profile state, which is rebuilt from
   * the remaining accepted units; they are quarantined (STALE_DATA_EPOCH)
   * and un-accepted.
   */
  // PROVISIONAL (SNAP-EP): a Key Epoch learned after a Snapshot was loaded
  // that puts any unit the Snapshot covers beyond its cutoff drops the
  // Snapshot-derived state: the profile is rebuilt from accepted units only,
  // the covered units are fetched again, and G-EP7 then applies normally.
  async #dropCutSnapshots(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
  ): Promise<boolean> {
    const resource = view.state.resourceId;
    const snapshots = await this.#storage.snapshots.list(resource);
    if (snapshots.length === 0 || handler.reset === undefined) return false;
    const covered = (await this.#storage.dataUnits.withStatus(resource, "merged")).filter(
      (u) => u.accepted && u.detail === "covered by a Snapshot",
    );
    const cut =
      snapshots.some(
        (x) =>
          beyondCutoff(
            view,
            x.dataEpoch,
            canonicalFrontierFromCbor(decodeDeterministic(x.frontier)),
          ) !== undefined,
      ) || covered.some((u) => classifyDataUnit(view, u).kind === "quarantine");
    if (!cut) return false;
    await this.#write([
      ...snapshots.map((x): StorageWrite => ({ op: "delete-snapshot", snapshotId: x.snapshotId })),
      ...covered.flatMap((u): StorageWrite[] => [
        { op: "set-accepted", unitId: u.unitId, accepted: false },
        {
          op: "set-data-unit-status",
          unitId: u.unitId,
          status: "seen",
          detail: "Snapshot dropped (SNAP-EP)",
        },
      ]),
    ]);
    handler.reset();
    await this.replayStored(view);
    return true;
  }

  /** The distinct actors of stored units. */
  async #actorsOf(unitIds: readonly DataUnitId[]): Promise<PrincipalId[]> {
    const byHex = new Map<string, PrincipalId>();
    for (const id of unitIds) {
      const u = await this.#storage.dataUnits.get(id);
      if (u !== undefined) byHex.set(toHex(u.actor), u.actor);
    }
    return [...byHex.values()];
  }

  /** Status writes for the held units (§14.1) a rebuild merged. */
  #freedWrites(result: ProfileExcludeResult): StorageWrite[] {
    return (result.released ?? []).map(
      (unitId): StorageWrite => ({ op: "set-data-unit-status", unitId, status: "merged" }),
    );
  }

  /** The held units (§14.1) a rebuild merged, reported as applied. */
  async #freed(
    handler: DataProfileHandler<unknown>,
    result: ProfileExcludeResult,
  ): Promise<ApplyOutcome[]> {
    const out: ApplyOutcome[] = [];
    for (const unitId of result.released ?? []) {
      const u = await this.#storage.dataUnits.get(unitId);
      if (u === undefined) continue;
      out.push(
        Object.freeze({
          kind: "applied",
          unitId,
          dataProfile: handler.dataProfile,
          actor: u.actor,
          seq: u.actorSeq,
          epoch: u.dataEpoch,
          haveEligible: false as const,
          alsoMerged: Object.freeze([]),
          released: Object.freeze([]),
          objects: Object.freeze([]),
          diagnostics: Object.freeze([]),
        }),
      );
    }
    return out;
  }

  /**
   * §26.2 (G-DP1-GAP): after units of `actors` stopped being accepted, a
   * held unit may now name the actor's latest accepted unit. Every held
   * unit of those actors is received again, lowest sequence first.
   */
  async #retryHeld(view: ControlView, actors: readonly PrincipalId[]): Promise<ApplyOutcome[]> {
    const released: ApplyOutcome[] = [];
    for (const actor of actors) {
      const held = (
        await this.#storage.dataUnits.range(
          view.state.resourceId,
          actor,
          actorSequence(1n),
          actorSequence(2n ** 64n - 1n),
        )
      ).filter((u) => u.status === "held");
      for (const u of held) {
        if ((await this.#storage.dataUnits.get(u.unitId))?.status !== "held") continue;
        released.push(await this.receive(view, u.bytes));
      }
    }
    return released;
  }

  async reconcileEpochs(view: ControlView): Promise<EpochReconciliation> {
    const handler = this.#handlers.get(view.state.dataProfile);
    if (handler === undefined)
      return Object.freeze({
        excluded: [],
        objects: [],
        pending: [],
        snapshotDropped: false,
        released: [],
      });
    const resource = view.state.resourceId;
    const snapshotDropped = await this.#dropCutSnapshots(view, handler);
    const empty: EpochReconciliation = Object.freeze({
      excluded: [],
      objects: [],
      pending: [],
      snapshotDropped,
      released: [],
    });
    const candidates = [
      ...(await this.#storage.dataUnits.withStatus(resource, "merged")),
      ...(await this.#storage.dataUnits.withStatus(resource, "profile-pending")),
      ...(await this.#storage.dataUnits.withStatus(resource, "profile-held")),
    ].filter((u) => u.accepted);
    const excluded: ExcludedUnit[] = [];
    for (const u of candidates) {
      const c = classifyDataUnit(view, u);
      if (c.kind === "quarantine")
        excluded.push({
          unitId: u.unitId,
          quarantine: { code: c.code, reason: c.reason, epoch: c.epoch, closedBy: c.closedBy },
        });
    }
    if (excluded.length === 0) return empty;
    const result = handler.exclude(excluded.map((e) => e.unitId));
    await this.#write([
      ...excluded.flatMap((e): StorageWrite[] => [
        {
          op: "set-data-unit-status",
          unitId: e.unitId,
          status: "quarantined",
          detail: e.quarantine.reason,
        },
        { op: "set-accepted", unitId: e.unitId, accepted: false },
      ]),
      ...result.pending.map(
        (unitId): StorageWrite => ({
          op: "set-data-unit-status",
          unitId,
          status: "profile-pending",
          detail: "builds on an excluded unit",
        }),
      ),
      ...this.#freedWrites(result),
    ]);
    const actors = await this.#actorsOf(excluded.map((e) => e.unitId));
    const released = [
      ...(await this.#retryHeld(view, actors)),
      ...(await this.#freed(handler, result)),
    ];
    return Object.freeze({
      snapshotDropped,
      excluded: Object.freeze(excluded),
      objects: result.objects,
      pending: result.pending,
      released,
    });
  }
}
