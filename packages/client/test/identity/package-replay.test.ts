import { dataEpoch, generateResourceId, type ResourceId, toHex } from "@openlfcp/core";
import { dekCommitment, generateResourceDEK, sha256 } from "@openlfcp/crypto";
import { signControlRecord } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { deliverKeys } from "../../src/identity/context.js";
import { PackageLedger } from "../../src/identity/journal.js";
import { MemoryCoordinator } from "./memory-coordinator.js";
import { device, party, URL } from "./support.js";

const OWNER = party(1);
function raw() {
  const R: ResourceId = generateResourceId();
  const dek = generateResourceDEK();
  const records: Uint8Array[] = [];
  const add = (
    body: Parameters<typeof signControlRecord>[1],
    prev: Uint8Array | null,
    seq: bigint,
  ) => {
    const s = signControlRecord(
      { resourceId: R, controlSeq: seq, prevControlId: prev as never },
      body,
      OWNER.signer,
    );
    return s;
  };
  const g = add(
    {
      type: "GENESIS",
      dataProfile: "org.example.v1",
      owner: OWNER.signer.descriptor,
      dekCommitment: dekCommitment(R, dataEpoch(0n), dek),
      endpoints: [{ url: URL, priority: 0n }],
      coordinatorUrl: URL,
    },
    null,
    0n,
  );
  records.push(g.bytes);
  const grant = (n: number, prev: Uint8Array, seq: bigint) =>
    add(
      {
        type: "CAPABILITY_GRANT",
        subject: party(n).signer.descriptor,
        abilities: [1n],
        delegable: [],
      },
      prev,
      seq,
    );
  return { R, dek, g, grant };
}

describe("deliverKeys after a lost answer (§9.1, §9.5)", () => {
  test("the same package bytes are sent again and the ledger records the accepted one", async () => {
    const { R, dek, g, grant } = raw();
    const g5 = grant(5, g.recordId, 1n);
    const server = new MemoryCoordinator();
    server.seed([g.bytes, g5.bytes]);
    const chain = server.chain(R);
    const local = device();
    const channel = await server.network().connect(OWNER.signer, URL);
    const ledger = new PackageLedger(local.storage);
    const send = () =>
      deliverKeys({
        channel,
        ledger,
        chain,
        sender: OWNER.signer,
        recipients: [party(5).signer.descriptor],
        deks: new Map([["0", dek]]),
      });
    server.fault = (e) => (e.op === "key-package" ? "drop-answer" : undefined);
    await expect(send()).rejects.toThrow();
    server.fault = () => undefined;
    await send();
    const uploads = server.uploads.filter((u) => u.op === "key-package").map((u) => toHex(u.bytes));
    expect(uploads.length).toBe(2);
    expect(uploads[0]).toBe(uploads[1]);
    expect(server.packagesOf(R).length).toBe(1);
    const [entry] = await ledger.list(R);
    expect(toHex(entry?.packageId as Uint8Array)).toBe(
      toHex(sha256(server.uploads[0]?.bytes as Uint8Array)),
    );
  });
});
