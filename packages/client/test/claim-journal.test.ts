import { dataEpoch, hash32, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { dekSecretRef, InMemoryLfcpStorage, InMemorySecretStore } from "@openlfcp/storage";
import {
  type AnyMessage,
  ERROR_CODE,
  parseControlRecord,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import {
  abandonInvitationClaim,
  acceptInvitation,
  createInvitation,
  loadControlChain,
  pendingInvitationClaims,
  resumeInvitationClaim,
  saveControlChain,
} from "../src/index.js";
import { FakeServer } from "./fake-server.js";

// LFCP-02-110: a claim whose CONTROL_PUT answer is lost is journaled and
// settled by sending the same record again (LFCP-WIRE-01 §47, §70), so the
// one-time invitation is never spent twice and never lost.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const party = (seed: number) => ({
  signer: signer(seed),
  agreement: importAgreementKey(bytes32(seed + 100)),
});
const OWNER = signer(1);
const R = resourceId(bytes32(210));
const DEK = importResourceDEK(bytes32(91));
const URL = "wss://sync.example.test/v1/ws";
const CONTROL_PUT = 23n;

/**
 * A coordinator holding the owner's chain with an invitation, and its Key
 * Package. `lose` decides, per claim, whether its answer is lost after the
 * commit ("after"), the request itself is lost ("before"), or neither.
 */
async function coordinator() {
  const owner = new InMemoryLfcpStorage();
  const genesis = signControlRecord(
    { resourceId: R, controlSeq: 0n, prevControlId: null },
    {
      type: "GENESIS",
      dataProfile: "org.example.custom.v1",
      owner: OWNER.descriptor,
      dekCommitment: dekCommitment(R, dataEpoch(0n), DEK),
      endpoints: [{ url: URL, priority: 0n }],
      coordinatorUrl: URL,
    },
    OWNER,
  );
  const start = validateControlChain([genesis.bytes]);
  if (start.kind !== "linear") throw new Error(start.kind);
  await saveControlChain(owner, start, null);
  const invitation = await createInvitation({
    storage: owner,
    resourceId: R,
    inviter: OWNER,
    dek: DEK,
    endpoints: [URL],
  });
  const queued = await owner.outbound.list(R);
  const records = [genesis.bytes, queued[0]?.bytes as Uint8Array];
  const packages = [queued[1]?.bytes as Uint8Array];
  const server = new FakeServer();
  const state = { lose: null as "before" | "after" | null, puts: 0, committed: 0 };
  const chain = () => {
    const c = validateControlChain(records);
    if (c.kind !== "linear") throw new Error(c.kind);
    return c;
  };
  server.onMessage = (m: AnyMessage, s) => {
    const reply = (type: AnyMessage["type"], body: unknown) =>
      s.reply(m, type as never, body as never);
    const v = chain();
    switch (m.type) {
      case "RESOURCE_OPEN":
        reply("RESOURCE_OPENED", {
          resourceId: R,
          heads: [{ seq: v.state.seq, recordId: v.state.head }],
          haves: [],
        });
        break;
      case "CONTROL_GET":
        reply("CONTROL_BATCH", {
          resourceId: R,
          objects: records.slice(Number(m.body.start), Number(m.body.end) + 1),
        });
        break;
      case "KEY_PACKAGE_GET":
        reply("KEY_PACKAGE_BATCH", { resourceId: R, objects: packages });
        break;
      case "CONTROL_PUT": {
        state.puts++;
        const record = m.body.record;
        const id = parseControlRecord(record).signed.id;
        const ack = () => reply("ACK", { requestType: CONTROL_PUT, objectIds: [hash32(id)] });
        // §47: a record already committed is acknowledged again.
        if (records.some((r) => toHex(parseControlRecord(r).signed.id) === toHex(id))) {
          ack();
          break;
        }
        if (toHex(m.body.expectedHead) !== toHex(v.state.head)) {
          reply("NACK", { code: ERROR_CODE.CONTROL_HEAD_MISMATCH, details: v.state.head });
          break;
        }
        if (validateControlChain([...records, record]).kind !== "linear") {
          reply("NACK", { code: ERROR_CODE.AUTHORIZATION_FAILED });
          break;
        }
        const lose = state.lose;
        state.lose = null;
        if (lose === "before") break; // neither committed nor answered
        records.push(record);
        state.committed++; // only joiners' claims come through CONTROL_PUT here
        if (lose !== "after") ack();
        break;
      }
    }
    return [];
  };
  /** The owner appends a record, moving the head. */
  const moveHead = () => {
    const c = chain();
    const grant = signControlRecord(
      { resourceId: R, controlSeq: c.state.seq + 1n, prevControlId: c.state.head },
      {
        type: "CAPABILITY_GRANT",
        subject: signer(77).descriptor,
        abilities: [1n],
        delegable: [],
      },
      OWNER,
    );
    records.push(grant.bytes);
  };
  const claims = () => state.committed;
  return { server, state, invitation, moveHead, claims };
}

/** A promise settled once `ms` ms passed: the attempt's give-up timer. */
const after = (ms: number) => new Promise((r) => setTimeout(r, ms));

function joiner(seed: number) {
  return {
    claimant: party(seed),
    storage: new InMemoryLfcpStorage(),
    secrets: new InMemorySecretStore(),
  };
}

describe("the claim journal (LFCP-02-110)", () => {
  it("a claim committed whose answer is lost is completed from the journal, spending the link once", async () => {
    const c = await coordinator();
    const j = joiner(50);
    const accept = () =>
      acceptInvitation({
        link: c.invitation.link,
        ...j,
        now: Date.now,
        webSocket: c.server.factory,
        timeout: after(300),
      });
    c.state.lose = "after";
    const first = await accept();
    expect(first.kind).toBe("unavailable");
    expect(c.claims()).toBe(1); // the coordinator committed it
    expect(await loadControlChain(j.storage, R)).toBeUndefined();
    const pending = await pendingInvitationClaims(j.storage);
    expect(pending.map((p) => p.resourceId)).toEqual([toHex(R)]);
    // The DEK went to the SecretStore before the journal.
    expect(await j.secrets.get(dekSecretRef(R, dataEpoch(0n)))).toBeDefined();

    const again = await accept();
    expect(again).toMatchObject({ kind: "claimed", resumed: true, attempts: ["ACK"] });
    expect(c.claims()).toBe(1);
    const chain = await loadControlChain(j.storage, R);
    expect(chain?.kind === "linear" && chain.state.seq).toBe(2n);
    expect(await pendingInvitationClaims(j.storage)).toEqual([]);
  });

  it("a claim lost before the coordinator committed it is sent again, or claimed anew when the head moved", async () => {
    const c = await coordinator();
    const j = joiner(51);
    const accept = () =>
      acceptInvitation({
        link: c.invitation.link,
        ...j,
        now: Date.now,
        webSocket: c.server.factory,
        timeout: after(300),
      });
    c.state.lose = "before";
    expect((await accept()).kind).toBe("unavailable");
    expect(c.claims()).toBe(0);
    c.moveHead(); // the journaled claim's expected head is stale now
    const again = await accept();
    expect(again).toMatchObject({ kind: "claimed", resumed: false, attempts: ["ACK"] });
    expect(c.claims()).toBe(1);
    expect(await pendingInvitationClaims(j.storage)).toEqual([]);
  });

  it("settles a journaled claim after a restart, without the link", async () => {
    const c = await coordinator();
    const j = joiner(52);
    c.state.lose = "after";
    const first = await acceptInvitation({
      link: c.invitation.link,
      ...j,
      now: Date.now,
      webSocket: c.server.factory,
      timeout: after(300),
    });
    expect(first.kind).toBe("unavailable");
    const resumed = await resumeInvitationClaim({
      resourceId: R,
      claimant: { signer: j.claimant.signer },
      storage: j.storage,
      secrets: j.secrets,
      url: URL,
      now: Date.now,
      webSocket: c.server.factory,
      timeout: after(300),
    });
    expect(resumed).toMatchObject({ kind: "claimed", resumed: true });
    expect(c.claims()).toBe(1);
    expect(
      await resumeInvitationClaim({
        resourceId: R,
        claimant: { signer: j.claimant.signer },
        storage: j.storage,
        secrets: j.secrets,
        url: URL,
        now: Date.now,
        webSocket: c.server.factory,
      }),
    ).toEqual({ kind: "none", resourceId: R });
  });

  it("a claim another claimant won meanwhile is refused, and its journal is removed", async () => {
    const c = await coordinator();
    const j = joiner(53);
    c.state.lose = "before";
    const first = await acceptInvitation({
      link: c.invitation.link,
      ...j,
      now: Date.now,
      webSocket: c.server.factory,
      timeout: after(300),
    });
    expect(first.kind).toBe("unavailable");
    // Someone else uses the link first.
    const other = joiner(54);
    expect(
      await acceptInvitation({
        link: c.invitation.link,
        ...other,
        now: Date.now,
        webSocket: c.server.factory,
      }),
    ).toMatchObject({ kind: "claimed", resumed: false });
    const again = await acceptInvitation({
      link: c.invitation.link,
      ...j,
      now: Date.now,
      webSocket: c.server.factory,
      timeout: after(300),
    });
    expect(again).toMatchObject({ kind: "refused", code: "AUTHORIZATION_FAILED" });
    expect(c.claims()).toBe(1);
    expect(await pendingInvitationClaims(j.storage)).toEqual([]);
  });

  it("abandons a journaled claim on request", async () => {
    const c = await coordinator();
    const j = joiner(55);
    c.state.lose = "after";
    await acceptInvitation({
      link: c.invitation.link,
      ...j,
      now: Date.now,
      webSocket: c.server.factory,
      timeout: after(300),
    });
    expect(await pendingInvitationClaims(j.storage)).toHaveLength(1);
    await abandonInvitationClaim(j.storage, R);
    expect(await pendingInvitationClaims(j.storage)).toEqual([]);
  });
});
