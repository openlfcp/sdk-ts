import { dataEpoch, generateResourceId, type ResourceId } from "@openlfcp/core";
import { dekCommitment, generateResourceDEK } from "@openlfcp/crypto";
import { signControlRecord, validateControlChain } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { IdentityConflict, syncChain } from "../../src/identity/context.js";
import { saveControlChain } from "../../src/storage.js";
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

describe("syncChain and forks (IDENTITY-PROFILE-01 §9.7)", () => {
  test("a server branch that does not extend the stored one is a conflict, and stays one", async () => {
    const { R, g, grant } = raw();
    const a1 = grant(5, g.recordId, 1n);
    const b1 = grant(6, g.recordId, 1n);
    const b2 = grant(7, b1.recordId, 2n);
    const local = device();
    const mine = validateControlChain([g.bytes, a1.bytes]);
    if (mine.kind !== "linear") throw new Error(mine.kind);
    await saveControlChain(local.storage, mine, null);
    const server = new MemoryCoordinator();
    server.seed([g.bytes, b1.bytes, b2.bytes]);
    const channel = await server.network().connect(OWNER.signer, URL);
    await expect(syncChain(local.storage, channel, R)).rejects.toBeInstanceOf(IdentityConflict);
    expect(await local.storage.control.conflict(R)).toBeDefined();
    // Known forks block later opens too, whatever one server shows.
    const other = new MemoryCoordinator();
    other.seed([g.bytes]);
    const c2 = await other.network().connect(OWNER.signer, URL);
    await expect(syncChain(local.storage, c2, R)).rejects.toBeInstanceOf(IdentityConflict);
  });
});
