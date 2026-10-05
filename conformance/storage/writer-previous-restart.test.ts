// §26.2 (G-DP1-GAP) on the Node adapter: the unit a writer's next unit
// names as `previous` (its latest own unit still accepted) is read from
// storage, so after the process "dies" and the SQLite file is reopened the
// same unit is chosen: across an abandoned sequence and a unit a cutoff
// excluded.
//
// Cross-package (client + storage-node), so it lives under conformance/.

import { createQueuedDataUnit, latestAcceptedOwnUnit } from "@openlfcp/client";
import { dataEpoch, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  type DataProfileCodec,
  parseDataUnit,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { inDir, makeTempDir, removeTempDir } from "./temp-dir.mjs";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const OWNER: Signer = (() => {
  const key = importSigningKey(bytes32(1));
  return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(101))) };
})();
const R = resourceId(bytes32(200));
const DEK0 = importResourceDEK(bytes32(90));
const TEXT: DataProfileCodec<string> = {
  dataProfile: "org.example.text.v1",
  encode: (s) => Uint8Array.from(s, (c) => c.charCodeAt(0)),
  decode: (p) => String.fromCharCode(...p),
};
const genesis = signControlRecord(
  { resourceId: R, controlSeq: 0n, prevControlId: null },
  {
    type: "GENESIS",
    dataProfile: TEXT.dataProfile,
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  },
  OWNER,
);
const chain = validateControlChain([genesis.bytes]);
if (chain.kind !== "linear") throw new Error(chain.kind);
const VIEW = chain;
const prevOf = (bytes: Uint8Array) => {
  const p = parseDataUnit(bytes).payload.prevDataUnitId;
  return p === null ? null : toHex(p);
};

describe("the writer's previous unit survives a restart (§26.2, G-DP1-GAP)", () => {
  it("chooses the same latest own unit still accepted after reopening SQLite", async () => {
    const dir = makeTempDir("lfcp-writer-previous-");
    const path = inDir(dir, "lfcp.sqlite");
    try {
      const base = {
        view: VIEW,
        controlHead: VIEW.state.head,
        actor: OWNER,
        dek: DEK0,
        profile: TEXT,
      };
      let storage = SqliteLfcpStorage.open(path);
      const u1 = await createQueuedDataUnit(storage, { ...base, value: "one" });
      const u2 = await createQueuedDataUnit(storage, { ...base, value: "two" });
      await storage.actorSequences.reserveNext(R, OWNER.descriptor.principalId); // 3, abandoned
      const u4 = await createQueuedDataUnit(storage, { ...base, value: "four" });
      // A cutoff excluded 4.
      await storage.commit([
        { op: "set-data-unit-status", unitId: u4.unitId, status: "quarantined", detail: "STALE" },
        { op: "set-accepted", unitId: u4.unitId, accepted: false },
      ]);
      const before = await latestAcceptedOwnUnit(storage, R, OWNER.descriptor.principalId);
      storage.close();

      storage = SqliteLfcpStorage.open(path);
      const after = await latestAcceptedOwnUnit(storage, R, OWNER.descriptor.principalId);
      expect(toHex(after as Uint8Array)).toBe(toHex(before as Uint8Array));
      expect(toHex(after as Uint8Array)).toBe(toHex(u2.unitId));
      const u5 = await createQueuedDataUnit(storage, { ...base, value: "five" });
      expect([u5.seq, prevOf(u5.bytes)]).toEqual([5n, toHex(u2.unitId)]);
      expect([prevOf(u1.bytes), prevOf(u2.bytes), prevOf(u4.bytes)]).toEqual([
        null,
        toHex(u1.unitId),
        toHex(u2.unitId),
      ]);
      storage.close();
    } finally {
      removeTempDir(dir);
    }
  });
});
