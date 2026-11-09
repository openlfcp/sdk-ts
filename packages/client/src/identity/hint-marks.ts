import { type DataEpoch, type PrincipalId, type ResourceId, toHex } from "@openlfcp/core";
import type { IdentityStorage } from "./context.js";

/**
 * When a managing installation last answered a device's key hint
 * (IDENTITY-PROFILE-01 §7.1 step 3; review 419 round 2, P2-1): the epoch set
 * it re-sealed for that device in that Resource, and when. A hint is answered
 * once: reconciliation re-seals its epochs again only when the hint changes,
 * or after HINT_RESEND_BACKOFF_MS (a package lost again, a device that never
 * came back). Without this, a hint nobody clears (a device left unused, an
 * older version, a refusal for good) made every reconciliation seal and
 * upload a new package. Local marks, public values only.
 */
export const HINT_RESEND_BACKOFF_MS = 24 * 60 * 60 * 1000;

const PREFIX = "identity-hint-answered:";
const keyOf = (resource: ResourceId, device: PrincipalId) =>
  `${PREFIX}${toHex(resource)}:${toHex(device)}`;

const setOf = (epochs: Iterable<bigint | number | string>) =>
  [...new Set([...epochs].map((e) => String(e)))].sort();

type MarkStorage = Pick<IdentityStorage, "localMarks" | "commit">;

/** Whether `epochs` of `device`'s hint in `resource` were answered recently enough to wait. */
export async function hintAnswered(
  storage: MarkStorage,
  resource: ResourceId,
  device: PrincipalId,
  epochs: Iterable<bigint | number | string | DataEpoch>,
  now: number,
): Promise<boolean> {
  const raw = await storage.localMarks.get(keyOf(resource, device));
  if (raw === undefined) return false;
  try {
    const mark = JSON.parse(raw) as { epochs?: unknown; at?: unknown };
    if (!Array.isArray(mark.epochs) || typeof mark.at !== "number") return false;
    const was = setOf(mark.epochs as string[]);
    const is = setOf(epochs);
    return (
      was.length === is.length &&
      was.every((e, i) => e === is[i]) &&
      now - mark.at < HINT_RESEND_BACKOFF_MS
    );
  } catch {
    return false;
  }
}

/** Records that `epochs` of `device`'s hint in `resource` were answered (re-sealed or refused) at `now`. */
export async function recordHintAnswered(
  storage: MarkStorage,
  resource: ResourceId,
  device: PrincipalId,
  epochs: Iterable<bigint | number | string>,
  now: number,
): Promise<void> {
  const r = await storage.commit([
    {
      op: "put-local-mark",
      key: keyOf(resource, device),
      value: JSON.stringify({ epochs: setOf(epochs), at: now }),
    },
  ]);
  if (!r.ok) throw new Error(`the hint mark was not stored: ${r.reason}`);
}
