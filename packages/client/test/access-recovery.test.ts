import { type ControlRecordId, dataEpoch, resourceId } from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import {
  type ControlBody,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import {
  afterAccepted,
  afterMismatch,
  RECOVERY_TRANSIENT_ATTEMPTS,
  RECOVERY_TRANSIENT_CODES,
  startRecovery,
} from "../src/access-recovery.js";

// LFCP-02-106: the decisions of access recovery after a server restore,
// on a synthetic chain (Genesis, a grant to MEMBER, a grant to OTHER, and a
// revocation of OTHER).

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const MEMBER = signer(33);
const OTHER = signer(65);
const STRANGER = signer(97);
const R = resourceId(bytes32(200));

const signed: Uint8Array[] = [];
const ids: ControlRecordId[] = [];
function add(body: ControlBody) {
  const s = signControlRecord(
    { resourceId: R, controlSeq: BigInt(signed.length), prevControlId: ids.at(-1) ?? null },
    body,
    OWNER,
  );
  signed.push(s.bytes);
  ids.push(s.recordId);
}
add({
  type: "GENESIS",
  dataProfile: "org.example.custom.v1",
  owner: OWNER.descriptor,
  dekCommitment: dekCommitment(R, dataEpoch(0n), importResourceDEK(bytes32(90))),
  endpoints: [{ url: "wss://a.example.test", priority: 0n }],
  coordinatorUrl: "wss://a.example.test",
});
add({ type: "CAPABILITY_GRANT", subject: MEMBER.descriptor, abilities: [1n, 2n], delegable: [] });
add({ type: "CAPABILITY_GRANT", subject: OTHER.descriptor, abilities: [1n], delegable: [] });
add({ type: "CAPABILITY_REVOKE", grantId: ids[2] as ControlRecordId });

const chain = validateControlChain(signed);
if (chain.kind !== "linear") throw new Error(chain.kind);
const { state, records } = chain;
const principal = (s: Signer) => s.descriptor.principalId;

describe("access recovery decisions (LFCP-02-106)", () => {
  it("starts by pushing the head when the chain grants data/read", () => {
    expect(startRecovery(state, records, principal(MEMBER))).toEqual({ kind: "push", index: 3 });
    expect(startRecovery(state, records, principal(OWNER))).toEqual({ kind: "push", index: 3 });
  });

  it("never starts for a revoked member or a stranger", () => {
    expect(startRecovery(state, records, principal(OTHER))).toEqual({
      kind: "final",
      reason: "not-granted",
    });
    expect(startRecovery(state, records, principal(STRANGER))).toEqual({
      kind: "final",
      reason: "not-granted",
    });
  });

  it("has nothing to push above a Genesis alone", () => {
    const genesisOnly = validateControlChain(signed.slice(0, 1));
    if (genesisOnly.kind !== "linear") throw new Error(genesisOnly.kind);
    expect(startRecovery(genesisOnly.state, genesisOnly.records, principal(OWNER))).toEqual({
      kind: "final",
      reason: "server-current",
    });
  });

  it("continues above the server's head after a mismatch", () => {
    expect(afterMismatch(records, ids[0])).toEqual({ kind: "push", index: 1 });
    expect(afterMismatch(records, ids[2])).toEqual({ kind: "push", index: 3 });
  });

  it("reopens at our head and stops at a head we do not know", () => {
    // The server holds our head: another holder re-supplied it; open once more.
    expect(afterMismatch(records, ids[3])).toEqual({ kind: "reopen" });
    expect(afterMismatch(records, bytes32(7))).toEqual({ kind: "final", reason: "unknown-head" });
    expect(afterMismatch(records, undefined)).toEqual({ kind: "final", reason: "refused" });
  });

  it("pushes in order and reopens after the head", () => {
    expect(afterAccepted(records, 1)).toEqual({ kind: "push", index: 2 });
    expect(afterAccepted(records, 3)).toEqual({ kind: "reopen" });
  });

  it("bounds transient refusals", () => {
    expect(RECOVERY_TRANSIENT_ATTEMPTS).toBe(3);
    expect([...RECOVERY_TRANSIENT_CODES].sort()).toEqual(["INTERNAL_ERROR", "RATE_LIMITED"]);
  });
});
