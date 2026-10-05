// LFCP-036 on the Node adapter: a client queues units, sends them, and
// "dies" before any ACK (the store is closed without one, and every
// in-memory object is dropped). After reopening the SQLite file, a new
// queue resends the very same bytes in new messages, and the next sequence
// continues after the queued ones: nothing is created or reserved again.
//
// Cross-package (client + storage-node), so it lives under conformance/.

import { createQueuedDataUnit, OutboundQueue } from "@openlfcp/client";
import {
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  type DataProfileCodec,
  decodeMessage,
  MESSAGE_TYPE,
  principalDescriptorFromKeys,
  replyTo,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { inDir, makeTempDir, removeTempDir } from "./temp-dir.mjs";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const WRITER = signer(33);
const R = resourceId(bytes32(200));
const DEK0 = importResourceDEK(bytes32(90));
const PROFILE = "org.example.text.v1";
const TEXT: DataProfileCodec<string> = {
  dataProfile: PROFILE,
  encode: (s) => Uint8Array.from(s, (c) => c.charCodeAt(0)),
  decode: (p) => String.fromCharCode(...p),
};

const records: Uint8Array[] = [];
let head: ControlRecordId | null = null;
for (const body of [
  {
    type: "GENESIS" as const,
    dataProfile: PROFILE,
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  },
  {
    type: "CAPABILITY_GRANT" as const,
    subject: WRITER.descriptor,
    abilities: [1n, 2n],
    delegable: [],
  },
]) {
  const s = signControlRecord(
    { resourceId: R, controlSeq: BigInt(records.length), prevControlId: head },
    body,
    OWNER,
  );
  records.push(s.bytes);
  head = s.recordId;
}
const chain = validateControlChain(records);
if (chain.kind !== "linear") throw new Error(chain.kind);
const view = chain;

describe("outbound queue across a restart (SQLite)", () => {
  it("resends the same bytes with new message IDs and never regenerates a unit or a sequence", async () => {
    const dir = makeTempDir("lfcp-outbound-restart-");
    const path = inDir(dir, "lfcp.sqlite");
    try {
      // Before the crash: two units created, queued and sent; no ACK arrives.
      let storage = SqliteLfcpStorage.open(path);
      const units: { bytes: Uint8Array; unitId: DataUnitId }[] = [];
      for (const value of ["one", "two"])
        units.push(
          await createQueuedDataUnit(storage, {
            view,
            controlHead: view.state.head,
            actor: WRITER,
            dek: DEK0,
            profile: TEXT,
            previousUnitId: units.at(-1)?.unitId ?? null,
            value,
          }),
        );
      const [before] = await new OutboundQueue({ storage }).next(R, "2026-10-05T12:00:00Z");
      storage.close();

      // After the restart.
      storage = SqliteLfcpStorage.open(path);
      const q = new OutboundQueue({ storage });
      const [after] = await q.next(R, "2026-10-05T12:05:00Z");
      expect(toHex(after?.message.messageId as Uint8Array)).not.toBe(
        toHex(before?.message.messageId as Uint8Array),
      );
      const a = decodeMessage(after?.bytes as Uint8Array);
      const b = decodeMessage(before?.bytes as Uint8Array);
      expect(a.type === "DATA_PUT" && a.body.objects.map(toHex)).toEqual(
        units.map((u) => toHex(u.bytes)),
      );
      expect(b.type === "DATA_PUT" && b.body.objects.map(toHex)).toEqual(
        units.map((u) => toHex(u.bytes)),
      );
      expect((await storage.outbound.list(R)).map((o) => o.attempts)).toEqual([2, 2]);
      expect(await storage.actorSequences.reserveNext(R, WRITER.descriptor.principalId)).toBe(3n);
      // The ACK, after the restart, clears exactly the named units.
      const r = await q.onAck(
        replyTo(after?.message as never, "ACK", {
          requestType: MESSAGE_TYPE.DATA_PUT,
          objectIds: after?.itemIds ?? [],
        }),
        "2026-10-05T12:05:01Z",
      );
      expect(r.acked).toHaveLength(2);
      storage.close();
      storage = SqliteLfcpStorage.open(path);
      expect(await storage.outbound.list(R)).toEqual([]);
      expect((await storage.syncState.get(R))?.recentlyAcked).toHaveLength(2);
      storage.close();
    } finally {
      removeTempDir(dir);
    }
  });
});
