import {
  type ActorSequence,
  actorSequence,
  bytesEqual,
  type DataEpoch,
  type DataUnitId,
  type PrincipalId,
  type ResourceId,
} from "@openlfcp/core";
import { decryptDataUnit, deriveActorDataKey, type ResourceDEK } from "@openlfcp/crypto";
import type { DataUnitRow, DataUnitStatus, LfcpStorage, StorageWrite } from "@openlfcp/storage";
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
}

export interface ProfileExcludeResult {
  /** Objects whose state changed. */
  readonly objects: readonly string[];
  /** Merged units that now wait for an excluded unit's content (profile-pending). */
  readonly pending: readonly DataUnitId[];
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
}

export interface DataUnitApplierOptions extends DataUnitCheckOptions {
  /**
   * Where verified units, their exact bytes, statuses and the accepted
   * marks live (the wire SeenUnits runs on it). InMemoryLfcpStorage for
   * tests and development only.
   */
  readonly storage: Pick<LfcpStorage, "dataUnits" | "snapshots" | "commit">;
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

const LFCP_ACCEPTED: readonly DataUnitStatus[] = ["merged", "profile-pending"];

export class DataUnitApplier {
  readonly #options: DataUnitApplierOptions;
  readonly #handlers: ReadonlyMap<string, DataProfileHandler<unknown>>;
  readonly #storage: Pick<LfcpStorage, "dataUnits" | "snapshots" | "commit">;
  readonly #seen: StoredSeenUnits;

  constructor(options: DataUnitApplierOptions) {
    this.#options = options;
    this.#handlers = new Map(options.handlers.map((h) => [h.dataProfile, h]));
    this.#storage = options.storage;
    this.#seen = new StoredSeenUnits(options.storage);
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
    const dataProfile = view.state.dataProfile;
    let row: DataUnitRow | undefined;
    try {
      row = dataUnitRow(bytes);
      this.#seen.expect(row);
    } catch {
      row = undefined; // receiveDataUnit reports it as MALFORMED_MESSAGE
    }
    const handler = this.#handlers.get(dataProfile);
    if (handler === undefined) return this.#unsupported(view, bytes, dataProfile);

    const codec =
      row === undefined
        ? unreachableCodec(dataProfile)
        : handler.codecFor({ resourceId: row.resourceId, actor: row.actor });
    const r = await receiveDataUnit(view, bytes, {
      ...this.#options,
      seen: this.#seen,
      profile: codec,
    });
    const status = (unitId: DataUnitId, s: DataUnitStatus, detail?: string): StorageWrite => ({
      op: "set-data-unit-status",
      unitId,
      status: s,
      ...(detail === undefined ? {} : { detail }),
    });

    switch (r.kind) {
      case "accepted":
        return this.#apply(view, handler, r);
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
        return this.#equivocation(handler, r);
      default:
        return r; // duplicate (harmless replay) or rejected (never stored)
    }
  }

  async #apply(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
    r: Extract<ReceivedDataUnit<unknown>, { kind: "accepted" }>,
  ): Promise<ApplyOutcome> {
    const dataProfile = handler.dataProfile;
    let result: ProfileApplyResult;
    try {
      result = handler.apply(
        {
          unitId: r.unitId,
          resourceId: view.state.resourceId,
          actor: r.actor,
          seq: r.seq,
          epoch: r.epoch,
        },
        r.value,
      );
    } catch (e) {
      const code = (e as { code?: unknown }).code;
      const message = e instanceof Error ? e.message : String(e);
      await this.#write([
        {
          op: "set-data-unit-status",
          unitId: r.unitId,
          status: "profile-rejected",
          detail: message,
        },
      ]);
      return Object.freeze({
        kind: "profile-rejected",
        unitId: r.unitId,
        dataProfile,
        code: typeof code === "string" ? code : "PROFILE_REJECTED",
        message,
      });
    }
    const mergedNow = result.merged.some((id) => bytesEqual(id, r.unitId));
    const alsoMerged = result.merged.filter((id) => !bytesEqual(id, r.unitId));
    await this.#write([
      mergedNow
        ? { op: "set-data-unit-status", unitId: r.unitId, status: "merged" }
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
    const next = await this.#storage.dataUnits.range(
      view.state.resourceId,
      r.actor,
      actorSequence(r.seq + 1n),
      actorSequence(2n ** 64n - 1n),
    );
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
    ]);
    return Object.freeze({
      ...r,
      excluded: Object.freeze(merged),
      objects: result.objects,
      pending: result.pending,
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
  }> {
    const handler = this.#handlers.get(view.state.dataProfile);
    const replayed: DataUnitId[] = [];
    const skipped: { unitId: DataUnitId; reason: string }[] = [];
    if (handler?.has === undefined) return { replayed, skipped };
    const resource = view.state.resourceId;
    // Also units accepted by LFCP whose merge was never recorded (a crash
    // between the accepted mark and the status write leaves them "seen" or "held").
    const stored = [
      ...(await this.#storage.dataUnits.withStatus(resource, "merged")),
      ...(await this.#storage.dataUnits.withStatus(resource, "profile-pending")),
      ...(await this.#storage.dataUnits.withStatus(resource, "seen")),
      ...(await this.#storage.dataUnits.withStatus(resource, "held")),
    ]
      .filter((u) => u.accepted && u.detail !== "covered by a Snapshot" && !handler.has?.(u.unitId))
      .sort((a, b) => (a.actorSeq < b.actorSeq ? -1 : a.actorSeq > b.actorSeq ? 1 : 0));
    const merged: DataUnitId[] = [];
    const pendingNow: DataUnitId[] = [];
    for (const u of stored) {
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
        const r = handler.apply(
          {
            unitId: u.unitId,
            resourceId: p.resourceId,
            actor: p.actor,
            seq: p.actorSeq,
            epoch: p.dataEpoch,
          },
          value,
        );
        merged.push(...r.merged);
        if (!r.merged.some((id) => bytesEqual(id, u.unitId))) pendingNow.push(u.unitId);
        replayed.push(u.unitId);
      } catch (e) {
        skipped.push({ unitId: u.unitId, reason: e instanceof Error ? e.message : String(e) });
      }
    }
    await this.#write([
      ...pendingNow
        .filter((id) => !merged.some((m) => bytesEqual(m, id)))
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
    return { replayed: Object.freeze(replayed), skipped: Object.freeze(skipped) };
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
        ? Object.freeze({ ...c, excluded: [], objects: [], pending: [] })
        : this.#equivocation(handler, c);
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
      return Object.freeze({ ...c, excluded: [], objects: [], pending: [] });
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

  async reconcileEpochs(view: ControlView): Promise<EpochReconciliation> {
    const handler = this.#handlers.get(view.state.dataProfile);
    if (handler === undefined)
      return Object.freeze({ excluded: [], objects: [], pending: [], snapshotDropped: false });
    const resource = view.state.resourceId;
    const snapshotDropped = await this.#dropCutSnapshots(view, handler);
    const empty: EpochReconciliation = Object.freeze({
      excluded: [],
      objects: [],
      pending: [],
      snapshotDropped,
    });
    const candidates = [
      ...(await this.#storage.dataUnits.withStatus(resource, "merged")),
      ...(await this.#storage.dataUnits.withStatus(resource, "profile-pending")),
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
    ]);
    return Object.freeze({
      snapshotDropped,
      excluded: Object.freeze(excluded),
      objects: result.objects,
      pending: result.pending,
    });
  }
}
