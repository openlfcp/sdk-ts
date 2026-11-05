import {
  fromHex,
  LfcpError,
  type ResourceId,
  resourceId,
  secureRandom,
  toHex,
} from "@openlfcp/core";
import { ABILITY, hasAbility } from "@openlfcp/wire";
import { loadControlChain } from "../storage.js";
import {
  fetchDeks,
  genesisOwner,
  IdentityConflict,
  loadIdentityDocument,
  runUnitPhase,
  sealIdentityUnit,
  syncChain,
} from "./context.js";
import { type RosterEntryValue, resourceRef } from "./document.js";
import { newOperationId, OperationJournal } from "./journal.js";
import {
  ChannelPool,
  type IdentityChannel,
  IdentityRefused,
  IdentityUnavailable,
} from "./network.js";
import type { LinearChain } from "./phases.js";
import { type IdentityFlowOptions, identityTarget } from "./resource.js";

/**
 * The roster of the Identity Resource (IDENTITY-PROFILE-01 §2.1): how the
 * human's other installations learn a Resource (§6). An entry is written as
 * its own durable phase of an operation (§9.1): a unit refused as stale
 * after a rotation of `I` is written again in the current epoch (W §19.1),
 * and an entry already present, by this installation or another writer,
 * is not written again.
 */
export type RosterWrite =
  /** This installation's unit carrying the entry was accepted. */
  | { readonly state: "written" }
  /** The roster already held an entry for the Resource. */
  | { readonly state: "present" }
  /** The coordinator refused the unit for another reason; the phase stays open. */
  | { readonly state: "refused"; readonly code: string };

/** Writes `roster[ref(resource)] = entry` in `I` as the phase `roster` of `operation`. */
export async function writeRosterEntry(
  o: IdentityFlowOptions,
  channel: IdentityChannel,
  journal: OperationJournal,
  operation: string,
  identity: ResourceId,
  resource: ResourceId,
  entry: RosterEntryValue,
): Promise<RosterWrite> {
  const me = o.installation.signer;
  const openI = async () => {
    const chain = await syncChain(o.storage, channel, identity);
    const doc = o.document(identity, genesisOwner(chain));
    const deks = await fetchDeks(o.storage, o.secrets, channel, chain, o.installation);
    const load = await loadIdentityDocument({ channel, chain, deks, doc });
    return { chain, doc, deks, load };
  };
  if ((await openI()).doc.roster().has(resourceRef(resource))) return { state: "present" };
  const r = await runUnitPhase(channel, journal, operation, {
    id: "roster",
    resource: identity,
    // A unit refused after a rotation of I is written again in the new epoch (W §19.1).
    rebuildOn: ["STALE_DATA_EPOCH"],
    // A resumed operation whose unit was refused writes the entry again on the
    // current document, previous unit and actor sequence: the refused bytes may
    // name a previous unit this actor has since moved past (W §26.2). Exact
    // bytes are re-sent only after an unknown outcome (§9.1).
    rebuildRefused: true,
    build: async () => {
      const { chain, doc, deks, load } = await openI();
      return sealIdentityUnit({
        storage: o.storage,
        chain,
        deks,
        signer: me,
        doc,
        latest: load.latest,
        intents: [{ intent: "roster.put", key: resourceRef(resource), entry }],
      });
    },
  });
  return r.state === "committed-own"
    ? { state: "written" }
    : { state: "refused", code: r.code ?? "refused" };
}

export interface AddToRosterOptions extends IdentityFlowOptions {
  /** The Resource to list (a Resource of the human: created or joined here). */
  readonly resource: ResourceId;
  /** A display name for the roster entry. */
  readonly name?: string;
  /**
   * The entry's fields; by default taken from the Resource's Control Chain:
   * its Data Profile, route endpoints and coordinator (stored here, or read
   * from `url`).
   */
  readonly entry?: RosterEntryValue;
  /** The Resource's coordinator, when its chain is not stored here. */
  readonly url?: string;
  /** Resume this operation. */
  readonly operation?: string;
}

export type AddToRosterResult =
  /** This installation wrote the entry. */
  | { readonly kind: "added"; readonly operation: string; readonly resource: ResourceId }
  /** The roster already lists the Resource (written earlier, or by another device). */
  | { readonly kind: "present"; readonly operation: string; readonly resource: ResourceId }
  /** This installation cannot write `I` (`holds(D, 2)` is false, e.g. a Read device, §7.2). */
  | { readonly kind: "needs-writer" }
  /** The coordinator refused the unit: the operation stays open; resume it with `operation`. */
  | {
      readonly kind: "document-incomplete";
      readonly operation: string;
      readonly resource: ResourceId;
      readonly code: string;
    }
  | { readonly kind: "conflict" }
  | { readonly kind: "unavailable"; readonly operation?: string; readonly reason: string };

/**
 * Adds a Resource to the roster of the Identity Resource as one durable
 * operation (IDENTITY-PROFILE-01 §2.1, §6, §9): the entry the human's other
 * installations read to reach the Resource (pairing step 10, reconciliation
 * §7.1). For a Resource created or joined after `I` was filled (§5.1), for
 * example a section created later on any personal device. Idempotent: an
 * entry already present is not written again; a unit refused as stale
 * after a rotation of `I` is written again in the current epoch; any other
 * refusal leaves the operation open. Only a writer of `I` (the root or a
 * personal device holding data/write there) may add entries (§3 AI4: a
 * pairing or service device never writes the roster).
 */
export async function addToRoster(o: AddToRosterOptions): Promise<AddToRosterResult> {
  const target = await identityTarget(o);
  const me = o.installation.signer;
  const journal = new OperationJournal(o.storage);
  const pool = new ChannelPool(o.network);
  let operation = o.operation;
  try {
    const channel = await pool.get(me, target.url);
    const I = await syncChain(o.storage, channel, target.resource);
    if (!hasAbility(I.state, me.descriptor.principalId, ABILITY.DATA_WRITE))
      return { kind: "needs-writer" };
    if (operation === undefined || (await journal.get(operation)) === undefined) {
      const entry = o.entry ?? (await entryOf(o, pool, o.resource));
      operation = operation ?? newOperationId("add-to-roster", secureRandom(8));
      await journal.begin({
        id: operation,
        kind: "add-to-roster",
        createdAt: o.now(),
        intent: {
          identity: toHex(target.resource),
          resource: toHex(o.resource),
          entry: { ...entry, ...(o.name === undefined ? {} : { name: o.name }) },
        },
      });
    }
    const op = await journal.load(operation);
    const resource = resourceId(fromHex(op.intent.resource as string));
    const written = await writeRosterEntry(
      o,
      channel,
      journal,
      op.id,
      target.resource,
      resource,
      op.intent.entry as RosterEntryValue,
    );
    if (written.state === "refused")
      return { kind: "document-incomplete", operation: op.id, resource, code: written.code };
    await journal.setStatus(op.id, "done");
    return { kind: written.state === "written" ? "added" : "present", operation: op.id, resource };
  } catch (e) {
    if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
      return {
        kind: "unavailable",
        ...(operation === undefined ? {} : { operation }),
        reason: e.message,
      };
    if (e instanceof IdentityConflict) return { kind: "conflict" };
    throw e;
  } finally {
    pool.closeAll();
  }
}

/** The roster entry of a Resource from its Control Chain (W §15, §20): profile, routes, coordinator. */
async function entryOf(
  o: AddToRosterOptions,
  pool: ChannelPool,
  resource: ResourceId,
): Promise<RosterEntryValue> {
  const stored = await loadControlChain(o.storage, resource);
  let chain: LinearChain;
  if (stored?.kind === "linear") chain = stored;
  else if (o.url !== undefined)
    chain = await syncChain(o.storage, await pool.get(o.installation.signer, o.url), resource);
  else
    throw new LfcpError(
      "MISSING_DEPENDENCY",
      "the Resource's chain is not stored here: give its entry or its coordinator URL",
    );
  return {
    profile: chain.state.dataProfile,
    endpoints: chain.state.route.endpoints.map((e) => e.url),
    coordinator: chain.state.route.coordinatorUrl,
  };
}
