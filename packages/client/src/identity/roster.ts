import type { ResourceId } from "@openlfcp/core";
import {
  fetchDeks,
  genesisOwner,
  loadIdentityDocument,
  runUnitPhase,
  sealIdentityUnit,
  syncChain,
} from "./context.js";
import { type RosterEntryValue, resourceRef } from "./document.js";
import type { OperationJournal } from "./journal.js";
import type { IdentityChannel } from "./network.js";
import type { IdentityFlowOptions } from "./resource.js";

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
