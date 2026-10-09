import type { DataUnitId, ResourceId } from "@openlfcp/core";
import type { LfcpStorage } from "@openlfcp/storage";
import type { BatchStatus } from "./batch-status.js";
import type { AccessState } from "./write-access.js";

/**
 * The status stream of a Resource (SDK-SECTIONS-INTEGRATION-01 §4, §5,
 * LFCP-02-026): what an editor adapter shows as saved, waiting, accepted
 * or not, and what it knows about units received from others. Every fact
 * comes from evidence the SDK holds; none is derived from a sent frame.
 */

/** §4.2: the signal that showed the server lost units it had acknowledged. */
export type ReofferReason = "unknown-previous" | "have-gap" | "rehost";

/** §4.3: what became of a unit received from others. */
export type ReceivedFact = "held" | "waiting" | "refused";

/**
 * LFCP-02-028: how far this session caught up with the Resource.
 * "current-at-checkpoint" only once the Resource was live (Control, keys
 * and every offered unit received and applied), at `checkedAt`; it stays
 * so offline, as of that check. "unknown" while a Control conflict or a
 * missing key blocks the catch-up.
 */
export type CatchUp = "not-started" | "receiving" | "current-at-checkpoint" | "unknown";

/** §4.3: a section without `ready` is importing. */
export type SectionState = "ready" | "importing";

/**
 * §5: one event of a Resource's status stream. `revision` grows by one with
 * each event of that Resource in this SDK session; a consumer that sees a
 * revision other than the next one asks for statusSnapshot.
 */
export type StatusEvent = { readonly revision: number } & (
  | ({ readonly kind: "batch" } & BatchStatus)
  | {
      readonly kind: "reoffered";
      readonly unitIds: readonly DataUnitId[];
      readonly reason: ReofferReason;
    }
  | {
      readonly kind: "received";
      readonly fact: ReceivedFact;
      readonly unitIds: readonly DataUnitId[];
      /** The admission or merge diagnostic, when refused. */
      readonly diagnostic?: string;
    }
  | { readonly kind: "section-state"; readonly state: SectionState }
  | { readonly kind: "access"; readonly access: AccessState }
  | {
      readonly kind: "catch-up";
      readonly state: CatchUp;
      /** The local time the Resource was last live; null before. */
      readonly checkedAt: number | null;
    }
  /** The Resource was hosted again on this route (§41.1). */
  | { readonly kind: "rehost"; readonly route: string }
);

/** The body of a status event, before its revision is assigned. */
export type StatusEventBody = StatusEvent extends infer E
  ? E extends { readonly revision: number }
    ? Omit<E, "revision">
    : never
  : never;

/** §4.3: the received units that are not merged, as stored. */
export interface ReceivedState {
  readonly held: readonly DataUnitId[];
  readonly waiting: readonly DataUnitId[];
  readonly refused: readonly { readonly unitId: DataUnitId; readonly diagnostic: string }[];
}

/** §5: the complete state of a Resource's status, at `revision`. */
export interface StatusSnapshot {
  readonly revision: number;
  readonly batches: readonly BatchStatus[];
  readonly received: ReceivedState;
  /** Unknown without a section binding, or before the section exists. */
  readonly section: SectionState | "unknown";
  readonly access: AccessState;
  readonly catchUp: { readonly state: CatchUp; readonly checkedAt: number | null };
}

/**
 * The received units of `resource` that wait or were refused: held behind
 * a change with their actor and sequence (SOP §14.1), waiting for a
 * dependency (the profile's, or the previous unit of their actor, §26.2),
 * refused when merging. Units of this client are never among them.
 */
export async function receivedState(
  storage: Pick<LfcpStorage, "dataUnits">,
  resource: ResourceId,
): Promise<ReceivedState> {
  const ids = async (status: "profile-held" | "profile-pending" | "held") =>
    (await storage.dataUnits.withStatus(resource, status)).map((u) => u.unitId);
  const refused = (await storage.dataUnits.withStatus(resource, "profile-rejected")).map((u) =>
    Object.freeze({ unitId: u.unitId, diagnostic: u.detail ?? "" }),
  );
  return Object.freeze({
    held: Object.freeze(await ids("profile-held")),
    waiting: Object.freeze([...(await ids("profile-pending")), ...(await ids("held"))]),
    refused: Object.freeze(refused),
  });
}
