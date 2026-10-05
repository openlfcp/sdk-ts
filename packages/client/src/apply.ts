import {
  type ActorSequence,
  actorSequence,
  bytesEqual,
  type DataEpoch,
  type DataUnitId,
  dataUnitId,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import type { ResourceDEK } from "@openlfcp/crypto";
import {
  type ControlView,
  checkDataUnit,
  classifyDataUnit,
  type DataProfileCodec,
  type DataUnitCheckOptions,
  type DataUnitHeader,
  type DataUnitPayload,
  type DataUnitQuarantined,
  parseDataUnit,
  type ReceivedDataUnit,
  receiveDataUnit,
  type SeenUnits,
} from "@openlfcp/wire";

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
   * PROVISIONAL (G-EP7): takes merged or buffered units out again, so that
   * the state equals the state built from the remaining accepted units.
   */
  exclude(unitIds: readonly DataUnitId[]): ProfileExcludeResult;
}

/** Where a unit stands for this receiver. */
export type UnitStatus =
  | "merged"
  | "profile-pending"
  | "held"
  | "quarantined"
  | "equivocation"
  | "local-failure"
  | "profile-rejected"
  | "profile-unsupported";

/** One signature-valid unit: its exact bytes, header and status. */
export interface UnitRecord {
  readonly unitId: DataUnitId;
  /** The exact signed bytes, kept whatever the profile state (§10.6). */
  readonly bytes: Uint8Array;
  readonly header: DataUnitHeader;
  readonly dataProfile: string;
  readonly status: UnitStatus;
  readonly detail?: string;
}

/**
 * The receiver's record of the units it verified. Durable implementations
 * are storage work (LFCP-034 to LFCP-036).
 */
export interface UnitLedger {
  /** Records a unit or changes its status; the bytes of a unit never change. */
  put(record: UnitRecord): Promise<void>;
  get(unitId: DataUnitId): Promise<UnitRecord | undefined>;
  withStatus(status: UnitStatus): Promise<UnitRecord[]>;
  /** Held units of (resource, actor, seq). */
  heldAt(resource: ResourceId, actor: PrincipalId, seq: ActorSequence): Promise<UnitRecord[]>;
}

/**
 * FOR TESTS AND DEVELOPMENT ONLY: everything is lost on restart, including
 * the exact bytes of held and quarantined units.
 */
export class InMemoryUnitLedger implements UnitLedger {
  readonly #records = new Map<string, UnitRecord>();

  put(record: UnitRecord): Promise<void> {
    const old = this.#records.get(toHex(record.unitId));
    const bytes = old?.bytes ?? Uint8Array.from(record.bytes);
    this.#records.set(toHex(record.unitId), Object.freeze({ ...record, bytes }));
    return Promise.resolve();
  }

  get(unitId: DataUnitId): Promise<UnitRecord | undefined> {
    return Promise.resolve(this.#records.get(toHex(unitId)));
  }

  withStatus(status: UnitStatus): Promise<UnitRecord[]> {
    return Promise.resolve([...this.#records.values()].filter((r) => r.status === status));
  }

  heldAt(resource: ResourceId, actor: PrincipalId, seq: ActorSequence): Promise<UnitRecord[]> {
    return Promise.resolve(
      [...this.#records.values()].filter(
        (r) =>
          r.status === "held" &&
          r.header.actorSeq === seq &&
          bytesEqual(r.header.actor, actor) &&
          bytesEqual(r.header.resourceId, resource),
      ),
    );
  }
}

interface Applied {
  readonly unitId: DataUnitId;
  readonly dataProfile: string;
  readonly actor: PrincipalId;
  readonly seq: ActorSequence;
  readonly epoch: DataEpoch;
  /**
   * Whether the unit may be advertised in Haves. Always false here: a unit
   * is advertised only once durable storage keeps it (LFCP-036).
   */
  readonly haveEligible: false;
  /** Buffered units this one unblocked, merged now. */
  readonly alsoMerged: readonly DataUnitId[];
  /** Held units of the same actor that were retried after this one, with their outcomes. */
  readonly released: readonly ApplyOutcome[];
}

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
  | Exclude<ReceivedDataUnit<unknown>, { readonly kind: "accepted" }>;

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
}

export interface DataUnitApplierOptions extends DataUnitCheckOptions {
  readonly seen: SeenUnits;
  /** The DEK of a Data Epoch, if this client holds it (from a Key Package, LFCP-024). */
  readonly dek: (epoch: DataEpoch) => ResourceDEK | undefined | Promise<ResourceDEK | undefined>;
  /** The profiles this client implements. */
  readonly handlers: readonly DataProfileHandler<unknown>[];
  /** Defaults to an InMemoryUnitLedger (tests and development only). */
  readonly ledger?: UnitLedger;
}

const headerOf = (p: DataUnitPayload): DataUnitHeader => ({
  resourceId: p.resourceId,
  dataEpoch: p.dataEpoch,
  actor: p.actor,
  actorSeq: p.actorSeq,
  controlHead: p.controlHead,
});

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

export class DataUnitApplier {
  readonly #options: DataUnitApplierOptions;
  readonly #handlers: ReadonlyMap<string, DataProfileHandler<unknown>>;
  readonly ledger: UnitLedger;

  constructor(options: DataUnitApplierOptions) {
    this.#options = options;
    this.#handlers = new Map(options.handlers.map((h) => [h.dataProfile, h]));
    this.ledger = options.ledger ?? new InMemoryUnitLedger();
  }

  /**
   * Receives one Data Unit of the Resource `view` describes. Never creates
   * a Data Unit: received content is applied, not re-sent as local work.
   */
  async receive(view: ControlView, bytes: Uint8Array): Promise<ApplyOutcome> {
    const dataProfile = view.state.dataProfile;
    const handler = this.#handlers.get(dataProfile);
    if (handler === undefined) return this.#unsupported(view, bytes, dataProfile);

    let payload: DataUnitPayload | undefined;
    try {
      payload = parseDataUnit(bytes).payload;
    } catch {
      payload = undefined; // receiveDataUnit reports it as MALFORMED_MESSAGE
    }
    const codec =
      payload === undefined
        ? unreachableCodec(dataProfile)
        : handler.codecFor({ resourceId: payload.resourceId, actor: payload.actor });
    const r = await receiveDataUnit(view, bytes, { ...this.#options, profile: codec });
    const record = (status: UnitStatus, detail?: string) =>
      payload === undefined || !("unitId" in r)
        ? Promise.resolve()
        : this.ledger.put({
            unitId: r.unitId as DataUnitId,
            bytes,
            header: headerOf(payload),
            dataProfile,
            status,
            ...(detail === undefined ? {} : { detail }),
          });

    switch (r.kind) {
      case "accepted":
        return this.#apply(view, handler, r, record);
      case "held":
        await record("held", r.reason);
        return r;
      case "quarantined":
        await record("quarantined", r.reason);
        return r;
      case "local-failure":
        await record("local-failure", `${r.reason}: ${r.message}`);
        return r;
      case "equivocation":
        // Never merged and no winner chosen: this unit is kept as evidence,
        // and every ID (and the one merged earlier, if any) is surfaced.
        if (payload !== undefined)
          await this.ledger.put({
            unitId: parseDataUnitId(bytes),
            bytes,
            header: headerOf(payload),
            dataProfile,
            status: "equivocation",
          });
        return r;
      default:
        return r; // duplicate (harmless replay) or rejected (not kept)
    }
  }

  async #apply(
    view: ControlView,
    handler: DataProfileHandler<unknown>,
    r: Extract<ReceivedDataUnit<unknown>, { kind: "accepted" }>,
    record: (status: UnitStatus, detail?: string) => Promise<void>,
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
      await record("profile-rejected", message);
      return Object.freeze({
        kind: "profile-rejected",
        unitId: r.unitId,
        dataProfile,
        code: typeof code === "string" ? code : "PROFILE_REJECTED",
        message,
      });
    }
    const mergedNow = result.merged.some((id) => bytesEqual(id, r.unitId));
    await record(mergedNow ? "merged" : "profile-pending", result.pending);
    const alsoMerged = result.merged.filter((id) => !bytesEqual(id, r.unitId));
    for (const id of alsoMerged) {
      const other = await this.ledger.get(id);
      if (other !== undefined) await this.ledger.put({ ...other, status: "merged" });
    }
    // §26.2, G-DP1: a held unit of this actor at seq + 1 may link now.
    const released: ApplyOutcome[] = [];
    for (const held of await this.ledger.heldAt(
      view.state.resourceId,
      r.actor,
      actorSequence(r.seq + 1n),
    ))
      released.push(await this.receive(view, held.bytes));
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
        ? { ...base, kind: "applied", objects: result.objects, diagnostics: result.diagnostics }
        : { ...base, kind: "profile-pending", detail: result.pending ?? "buffered by the profile" },
    );
  }

  async #unsupported(
    view: ControlView,
    bytes: Uint8Array,
    dataProfile: string,
  ): Promise<ApplyOutcome> {
    // DEK-free checks only: the plaintext of an unknown profile is never decrypted.
    const c = await checkDataUnit(view, bytes, this.#options.seen, this.#options);
    if (c.kind !== "valid") return c;
    await this.ledger.put({
      unitId: c.unitId,
      bytes,
      header: headerOf(c.parsed.payload),
      dataProfile,
      status: "profile-unsupported",
    });
    return Object.freeze({
      kind: "profile-unsupported",
      code: "PROFILE_UNSUPPORTED",
      unitId: c.unitId,
      dataProfile,
    });
  }

  /**
   * PROVISIONAL (G-EP7): the single entry point the sync engine calls with
   * every newly validated Control view that may carry a new Key Epoch.
   * Merged (or profile-buffered) units that the view now puts beyond an
   * epoch cutoff are taken out of the profile state, which is rebuilt from
   * the remaining accepted units, and are quarantined (STALE_DATA_EPOCH).
   */
  async reconcileEpochs(view: ControlView): Promise<EpochReconciliation> {
    const handler = this.#handlers.get(view.state.dataProfile);
    const empty: EpochReconciliation = Object.freeze({ excluded: [], objects: [], pending: [] });
    if (handler === undefined) return empty;
    const candidates = [
      ...(await this.ledger.withStatus("merged")),
      ...(await this.ledger.withStatus("profile-pending")),
    ].filter((u) => bytesEqual(u.header.resourceId, view.state.resourceId));
    const excluded: ExcludedUnit[] = [];
    for (const u of candidates) {
      const c = classifyDataUnit(view, u.header);
      if (c.kind === "quarantine")
        excluded.push({
          unitId: u.unitId,
          quarantine: { code: c.code, reason: c.reason, epoch: c.epoch, closedBy: c.closedBy },
        });
    }
    if (excluded.length === 0) return empty;
    const result = handler.exclude(excluded.map((e) => e.unitId));
    for (const e of excluded) {
      const u = (await this.ledger.get(e.unitId)) as UnitRecord;
      await this.ledger.put({ ...u, status: "quarantined", detail: e.quarantine.reason });
    }
    for (const id of result.pending) {
      const u = await this.ledger.get(id);
      if (u !== undefined && u.status === "merged")
        await this.ledger.put({
          ...u,
          status: "profile-pending",
          detail: "builds on an excluded unit",
        });
    }
    return Object.freeze({
      excluded: Object.freeze(excluded),
      objects: result.objects,
      pending: result.pending,
    });
  }
}

const parseDataUnitId = (bytes: Uint8Array): DataUnitId =>
  dataUnitId(parseDataUnit(bytes).signed.id);
