import { bytesEqual, type ControlRecordId, type ResourceId, toHex } from "@openlfcp/core";
import { ABILITY, hasAbility, revokedReaderPrefix, validateControlChain } from "@openlfcp/wire";
import { setWriteBarrier } from "../storage.js";
import type { FlowOptions } from "./devices.js";
import { ChannelPool, IdentityRefused, IdentityUnavailable } from "./network.js";

/**
 * What a device that may have been revoked shows for a Resource
 * (IDENTITY-PROFILE-01 §8.6). The device distinguishes, from evidence
 * only:
 *
 * - `access-refused`: the coordinator refuses its reads
 *   (`NACK(AUTHORIZATION_FAILED)`) and proves nothing: "This device no
 *   longer has access to this section; it may have been removed from your
 *   identity". A server without `identity-01`, or a device that never
 *   read, stays here.
 * - `revocation-proven`: the Control prefix through the revoking record,
 *   obtained through the revoked-reader read of W §41 and verified here
 *   (the record revokes this device, which held `data/read` just before
 *   it and holds nothing after): "This device was removed from your
 *   identity".
 *
 * In both states the device must not create Data Units for the Resource,
 * and it is never re-paired under the same Principal (N5). A timeout is
 * `unreachable`, never a decision.
 */
export type RevocationStatus =
  | { readonly kind: "active" }
  | { readonly kind: "access-refused"; readonly code: string }
  | {
      readonly kind: "revocation-proven";
      /** The revoking DEVICE_REVOKE. */
      readonly record: ControlRecordId;
      readonly reason: bigint;
      /** The verified prefix, through the revoking record. */
      readonly prefix: readonly Uint8Array[];
    }
  | { readonly kind: "unreachable"; readonly reason: string };

export async function revocationStatus(
  o: FlowOptions & { readonly resource: ResourceId; readonly url: string },
): Promise<RevocationStatus> {
  const status = await observe(o);
  // §8.6: in both states the device creates no Data Unit for the Resource; the
  // barrier is durable, so a restart on an old chain cannot write either.
  if (status.kind === "access-refused")
    await setWriteBarrier(o.storage, o.resource, { state: "access-refused", reason: status.code });
  else if (status.kind === "revocation-proven")
    await setWriteBarrier(o.storage, o.resource, {
      state: "revocation-proven",
      record: toHex(status.record),
      reason: String(status.reason),
    });
  else if (status.kind === "active") await setWriteBarrier(o.storage, o.resource, null);
  return status;
}

async function observe(
  o: FlowOptions & { readonly resource: ResourceId; readonly url: string },
): Promise<RevocationStatus> {
  const me = o.installation.signer;
  const pool = new ChannelPool(o.network);
  try {
    const channel = await pool.get(me, o.url);
    const opened = await channel.open(o.resource);
    if (opened.kind === "nack") return { kind: "access-refused", code: opened.code };
    // The whole readable chain, never merged into a longer local one: a prefix proves only itself.
    const records = await channel.control(o.resource, 0n);
    const chain = validateControlChain([...records]);
    if (chain.kind !== "linear" || !bytesEqual(chain.state.resourceId, o.resource))
      return { kind: "access-refused", code: "INVALID_CONTROL_CHAIN" };
    const p = me.descriptor.principalId;
    if (hasAbility(chain.state, p, ABILITY.DATA_READ)) return { kind: "active" };
    const prefix = revokedReaderPrefix(chain, p);
    // The prefix ends at the revoking record (W §41); anything else proves nothing.
    if (prefix === undefined || prefix.index !== chain.records.length - 1)
      return { kind: "access-refused", code: "AUTHORIZATION_FAILED" };
    return {
      kind: "revocation-proven",
      record: prefix.recordId,
      reason: prefix.reason,
      prefix: Object.freeze([...records]),
    };
  } catch (e) {
    if (e instanceof IdentityRefused) return { kind: "access-refused", code: e.code };
    if (e instanceof IdentityUnavailable) return { kind: "unreachable", reason: e.message };
    throw e;
  } finally {
    pool.closeAll();
  }
}
