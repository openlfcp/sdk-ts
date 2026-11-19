import {
  bytesEqual,
  dataEpoch,
  fromHex,
  generateResourceId,
  type PrincipalId,
  type ResourceId,
  resourceId,
  secureRandom,
  toHex,
} from "@openlfcp/core";
import { dekCommitment, generateResourceDEK } from "@openlfcp/crypto";
import {
  activeDevice,
  type ControlState,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { createResourceAsDevice, type DeviceCreateResult } from "./identity/accept.js";
import { storeDek, syncChain } from "./identity/context.js";
import type {
  ServiceControlCommitOutcome,
  ServiceControlPort,
  ServiceControlStateView,
} from "./identity/control-approval.js";
import { newOperationId, OperationJournal, phaseOf } from "./identity/journal.js";
import { ChannelPool, IdentityRefused, IdentityUnavailable } from "./identity/network.js";
import { type IdentityFlowOptions, identityTarget } from "./identity/resource.js";
import { addToRoster } from "./identity/roster.js";
import type { SyncClient } from "./sync-client.js";

/**
 * The control Resource `C` of SERVICE-CONTROL-PROFILE-01 on the client
 * side: the signer facts its admission needs (§2.3) and its creation by a
 * managing client (§1). The document itself (admission, records, state,
 * subscriptions) is @openlfcp/shared-objects' ServiceControlDataProfile,
 * opened in a SyncClient like any Resource: its units reach the profile
 * with the Control state at their control_ref (ProfileUnit.control).
 */

/** SERVICE-CONTROL-PROFILE-01's Data Profile identifier. */
export const SERVICE_CONTROL_PROFILE = "org.openlfcp.service-control.v1";

/**
 * §11: the roster name the creating client writes, which explains the
 * entry to a client whose SDK does not implement the profile; a client
 * that implements it shows `service.label` instead.
 */
export const serviceControlRosterName = (mac: string): string =>
  `Reminders bridge · ${mac} (needs Shared Tasks 0.8)`;

/** What C's verified Control state says of a signer at a unit's control_ref (W §80.1). */
export interface ServiceControlSignerFacts {
  readonly owner: PrincipalId;
  readonly signer: PrincipalId;
  readonly device?: {
    readonly kind: number;
    readonly root: PrincipalId;
    readonly boundInC: boolean;
    readonly active: boolean;
  };
}

/**
 * §2.3 at control_ref: the facts shared-objects' serviceControlSignerClass
 * decides the signer class from. A device is bound when C's chain binds it
 * (registered, suspended or revoked), active by W §17.5 `activeDevice`.
 */
export function serviceControlSignerFacts(
  state: ControlState,
  signer: PrincipalId,
): ServiceControlSignerFacts {
  const d = state.devices.get(toHex(signer));
  return Object.freeze({
    owner: state.owner.principalId,
    signer,
    ...(d === undefined
      ? {}
      : {
          device: Object.freeze({
            kind: Number(d.kind),
            root: d.root,
            boundInC: true,
            active: activeDevice(state, signer) !== undefined,
          }),
        }),
  });
}

export interface CreateServiceControlOptions extends IdentityFlowOptions {
  /** Route and coordinator of C: the root's default server. */
  readonly url: string;
  /** The Mac's name, for the roster entry (§11). */
  readonly mac: string;
  /** Resume this operation. */
  readonly operation?: string;
}

/** The initial change's intent (§2.2), for the shared-objects commit binding. */
export interface ServiceControlInitialize {
  readonly intent: "initialize";
  readonly attemptId: string;
  readonly createdAt: string;
}

export type CreatedServiceControl =
  | {
      readonly kind: "created";
      readonly operation: string;
      readonly resource: ResourceId;
      /**
       * The first write of this installation in C, committed through its
       * SyncClient with operation ID `<operation>:initialize`: the Genesis
       * signer's unit 1 carries it (§2.2).
       */
      readonly initialize: ServiceControlInitialize;
    }
  | Exclude<DeviceCreateResult, { readonly kind: "created" }>;

const isoSeconds = (ms: number) => `${new Date(ms).toISOString().slice(0, 19)}Z`;

/**
 * §1: a managing client creates C, owned by the root, and lists it in the
 * roster as "Reminders bridge · <Mac> (needs Shared Tasks 0.8)". From a
 * personal device with `13` this is IDENTITY §7.3 (createResourceAsDevice:
 * the root keyed, its other devices registered); from the root itself, its
 * own Genesis, hosted, then the roster entry. Journaled: an interrupted run
 * resumes with `operation`. The initial change is the caller's next write.
 */
export async function createServiceControl(
  o: CreateServiceControlOptions,
): Promise<CreatedServiceControl> {
  const journal = new OperationJournal(o.storage);
  const name = serviceControlRosterName(o.mac);
  const known = o.operation === undefined ? undefined : await journal.get(o.operation);
  const done = (operation: string, resource: ResourceId, meta: Record<string, unknown>) => ({
    kind: "created" as const,
    operation,
    resource,
    initialize: Object.freeze({
      intent: "initialize" as const,
      attemptId: String(meta.attemptId),
      createdAt: String(meta.createdAt),
    }),
  });
  const meta = async (operation: string): Promise<Record<string, unknown>> => {
    const key = `service-control:${operation}`;
    const stored = await o.storage.localMarks.get(key);
    if (stored !== undefined) return JSON.parse(stored) as Record<string, unknown>;
    const fresh = {
      attemptId: toHex(secureRandom(16)),
      createdAt: isoSeconds(o.now()),
    };
    const r = await o.storage.commit([{ op: "put-local-mark", key, value: JSON.stringify(fresh) }]);
    if (!r.ok) throw new Error(`the attempt was not recorded: ${r.reason}`);
    return fresh;
  };

  if (known?.kind !== "create-service-control") {
    const target = await identityTarget(o);
    const iChain = await (async () => {
      const pool = new ChannelPool(o.network);
      try {
        return await syncChain(
          o.storage,
          await pool.get(o.installation.signer, target.url),
          target.resource,
        );
      } catch (e) {
        if (e instanceof IdentityUnavailable || e instanceof IdentityRefused) return undefined;
        throw e;
      } finally {
        pool.closeAll();
      }
    })();
    if (iChain === undefined)
      return { kind: "unavailable", reason: "the Identity Resource is unreachable" };
    const isRoot = bytesEqual(
      iChain.state.owner.principalId,
      o.installation.signer.descriptor.principalId,
    );
    if (!isRoot) {
      const r = await createResourceAsDevice({
        ...o,
        dataProfile: SERVICE_CONTROL_PROFILE,
        name,
        ...(o.operation === undefined ? {} : { operation: o.operation }),
      });
      return r.kind === "created" ? done(r.operation, r.resource, await meta(r.operation)) : r;
    }
  }
  return createAsRoot(o, journal, name, known?.id, meta, done);
}

/** The root's own C: Genesis (no field 5), hosted, then the roster entry. */
async function createAsRoot(
  o: CreateServiceControlOptions,
  journal: OperationJournal,
  name: string,
  resume: string | undefined,
  meta: (operation: string) => Promise<Record<string, unknown>>,
  done: (
    operation: string,
    resource: ResourceId,
    meta: Record<string, unknown>,
  ) => CreatedServiceControl,
): Promise<CreatedServiceControl> {
  const me = o.installation.signer;
  let operation = resume;
  if (operation === undefined) {
    const C = generateResourceId();
    const dek = generateResourceDEK();
    const genesis = signControlRecord(
      { resourceId: C, controlSeq: 0n, prevControlId: null },
      {
        type: "GENESIS",
        dataProfile: SERVICE_CONTROL_PROFILE,
        owner: me.descriptor,
        dekCommitment: dekCommitment(C, dataEpoch(0n), dek),
        endpoints: [{ url: o.url, priority: 0n }],
        coordinatorUrl: o.url,
      },
      me,
    );
    const chain = validateControlChain([genesis.bytes]);
    if (chain.kind !== "linear") throw new Error("the Genesis of C does not validate");
    // The DEK first, then the journal that names the Genesis (§9.1).
    await storeDek(o.storage, o.secrets, chain, dataEpoch(0n), dek);
    operation = newOperationId("create-service-control", secureRandom(8));
    await journal.begin({
      id: operation,
      kind: "create-service-control",
      createdAt: o.now(),
      intent: { resource: toHex(C), url: o.url, name },
      phases: [
        {
          id: "host",
          kind: "host",
          resource: toHex(C),
          state: "pending",
          bytes: toHex(genesis.bytes),
        },
      ],
    });
  }
  const op = await journal.load(operation);
  const C = resourceId(fromHex(op.intent.resource as string));
  const host = phaseOf(op, "host");
  if (host !== undefined && host.state !== "committed-own") {
    const pool = new ChannelPool(o.network);
    try {
      const answer = await (await pool.get(me, op.intent.url as string)).host(
        fromHex(host.bytes as string),
      );
      if (answer.kind === "nack") {
        await journal.putPhase(op.id, { ...host, state: "refused", code: answer.code });
        await journal.setStatus(op.id, "abandoned");
        return { kind: "refused", operation: op.id, code: answer.code };
      }
      await journal.putPhase(op.id, { ...host, state: "committed-own" });
    } catch (e) {
      if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
        return { kind: "unavailable", operation: op.id, reason: e.message };
      throw e;
    } finally {
      pool.closeAll();
    }
  }
  const listed = await addToRoster({
    ...o,
    resource: C,
    name,
    url: op.intent.url as string,
    operation: `${op.id}:roster`,
  });
  if (listed.kind === "added" || listed.kind === "present") {
    await journal.setStatus(op.id, "done");
    return done(op.id, C, await meta(op.id));
  }
  if (listed.kind === "conflict") return listed;
  if (listed.kind === "unavailable")
    return { kind: "unavailable", operation: op.id, reason: listed.reason };
  if (listed.kind === "needs-writer") return { kind: "not-owner-acting" };
  return {
    kind: "incomplete",
    operation: op.id,
    resource: C,
    rootKeys: { sent: [], complete: 0, skipped: [] },
    siblings: [],
    roster: false,
  };
}

/**
 * A ServiceControlPort over a SyncClient that has `C` open with
 * shared-objects' ServiceControlDataProfile: the state readers see, who
 * created an entry (ServiceControlReplica.creatorsOf), and commits with
 * receipts. A committed change is `acknowledged` once its batch is
 * accepted, or acknowledged by a server without acceptance evidence
 * (`evidence-unavailable`); a change admission refuses before anything is
 * queued (§4) is `rejected` with its diagnostic.
 */
export function serviceControlPort(o: {
  readonly client: Pick<SyncClient, "commit" | "statusSnapshot">;
  readonly profile: {
    state(): ServiceControlStateView & { readonly usable?: boolean };
    readonly replica: Pick<ServiceControlPort, "creatorsOf">;
  };
  readonly resource: ResourceId;
  /** Whether `C` is synchronised (e.g. resourceState(C) === "LIVE"); always, by default. */
  readonly synchronised?: () => boolean;
}): ServiceControlPort {
  return Object.freeze({
    resource: o.resource,
    state: () => {
      if (o.synchronised?.() === false) return undefined;
      const s = o.profile.state();
      return s.usable === false ? undefined : s;
    },
    creatorsOf: (container: Parameters<ServiceControlPort["creatorsOf"]>[0], key: string) =>
      o.profile.replica.creatorsOf(container, key),
    commit: async (
      intents: readonly unknown[],
      operationId: string,
    ): Promise<ServiceControlCommitOutcome> => {
      try {
        await o.client.commit(o.resource, intents, { operationId });
      } catch (e) {
        const diagnostic = (e as { diagnostic?: unknown } | null)?.diagnostic;
        if (typeof diagnostic === "string") return { kind: "rejected", code: diagnostic };
        throw e;
      }
      const batch = (await o.client.statusSnapshot(o.resource)).batches.find(
        (b) => b.operationId === operationId,
      );
      if (batch?.status === "rejected")
        return { kind: "rejected", code: batch.rejection?.code ?? "rejected" };
      return batch?.status === "accepted" || batch?.status === "evidence-unavailable"
        ? { kind: "acknowledged" }
        : { kind: "queued" };
    },
  });
}
