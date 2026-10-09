// LFCP-02-110, live: a claim whose CONTROL_PUT answer is lost, against the
// Rust reference server at server.lock. The claimant journals the claim
// before sending it; accepting the same link again sends the same record,
// which the coordinator acknowledges as already committed (LFCP-WIRE-01
// §47, §70): the claimant joins and the one-time invitation is spent once.
// When the request itself is lost, the same record commits on the retry.

import {
  acceptInvitation,
  createInvitation,
  type InvitationLink,
  loadControlChain,
  pendingInvitationClaims,
} from "@openlfcp/client";
import { resourceId } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import { SharedObjectsDataProfile, SharedObjectsReplica } from "@openlfcp/shared-objects";
import { InMemoryLfcpStorage, InMemorySecretStore } from "@openlfcp/storage";
import { ABILITY, hasAbility, MESSAGE_TYPE } from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { bytes32, createResource, party, Side, sleep, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";
import { WireTap } from "./wire-tap.js";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(17);
const DEK0 = importResourceDEK(bytes32(97));

async function withServer(
  ctx: { skip(): void },
  body: (server: RunningRustServer) => Promise<void>,
): Promise<void> {
  const started = await startRustServer();
  if ("skip" in started) {
    console.warn(`SKIPPED: claim journal interop (${started.skip})`);
    ctx.skip();
    return;
  }
  try {
    await body(started);
  } catch (e) {
    throw new Error(
      `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${started.log().slice(-4000)}`,
    );
  } finally {
    await started.stop();
  }
}

/** OWNER hosts a Resource and creates a one-time invitation to it. */
async function invitation(server: RunningRustServer, seed: number) {
  const R = resourceId(bytes32(seed));
  const { replica, change: init } = SharedObjectsReplica.create({
    resource: R,
    principal: OWNER.signer.descriptor.principalId,
  });
  const owner = new Side({
    url: server.url,
    resource: R,
    who: OWNER,
    profile: new SharedObjectsDataProfile(replica),
  });
  const genesis = await createResource(owner, server.url, DEK0);
  owner.start({ open: false });
  await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
  await owner.client.host(genesis.bytes);
  owner.open();
  await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
  await owner.write(init);
  const created = await createInvitation({
    storage: owner.storage,
    resourceId: R,
    inviter: OWNER.signer,
    dek: DEK0,
    endpoints: [server.url],
  });
  owner.client.flush();
  await waitFor("OWNER settled at the grant", () => owner.controlSettled(1n), 30_000);
  return { R, owner, link: created.link as InvitationLink };
}

/** BOB's acceptInvitation through `tap`, with a short give-up timer. */
const bob = (link: InvitationLink, tap: WireTap) => {
  const who = party(58);
  const storage = new InMemoryLfcpStorage();
  const secrets = new InMemorySecretStore();
  return {
    who,
    storage,
    secrets,
    accept: () =>
      acceptInvitation({
        link,
        claimant: who,
        storage,
        secrets,
        now: () => Date.now(),
        webSocket: tap.factory,
        timeout: sleep(4_000),
      }),
  };
};

const isClaimPut = (f: { message?: { type: string } | undefined }) =>
  f.message?.type === "CONTROL_PUT";
const isClaimAck = (f: { message?: unknown }) => {
  const m = f.message as { type?: string; body?: { requestType?: bigint } } | undefined;
  return m?.type === "ACK" && m.body?.requestType === MESSAGE_TYPE.CONTROL_PUT;
};

describe("the claim journal ↔ Rust reference server (live, LFCP-02-110)", () => {
  it(
    "a claim committed whose answer is lost joins on the retry, spending the link once",
    (ctx) =>
      withServer(ctx, async (server) => {
        const { R, owner, link } = await invitation(server, 221);
        const tap = new WireTap();
        let dropped = false;
        tap.rule((f) => {
          if (!dropped && f.direction === "in" && isClaimAck(f)) {
            dropped = true;
            return { kind: "drop" };
          }
          return undefined;
        });
        const b = bob(link, tap);
        expect((await b.accept()).kind).toBe("unavailable");
        expect(dropped).toBe(true);
        expect(await pendingInvitationClaims(b.storage)).toHaveLength(1);
        // The coordinator committed it: OWNER learns the claim.
        owner.client.flush();
        await waitFor("OWNER sees the claim", () => owner.controlSettled(2n), 30_000);

        const again = await b.accept();
        expect(again).toMatchObject({ kind: "claimed", resumed: true, attempts: ["ACK"] });
        expect(await pendingInvitationClaims(b.storage)).toEqual([]);
        const chain = await loadControlChain(b.storage, R);
        if (chain?.kind !== "linear") throw new Error("no chain");
        expect(chain.state.seq).toBe(2n);
        expect(
          hasAbility(chain.state, b.who.signer.descriptor.principalId, ABILITY.DATA_READ),
        ).toBe(true);
        // Exactly one claim on the server: OWNER's chain still ends at it.
        await sleep(500);
        expect((await owner.storage.control.head(R))?.controlSeq).toBe(2n);
        const claimPuts = tap.messages("CONTROL_PUT", "out");
        expect(claimPuts).toHaveLength(2);
        await owner.stop();
      }),
    120_000,
  );

  it(
    "a claim lost on its way commits when the journal sends it again",
    (ctx) =>
      withServer(ctx, async (server) => {
        const { R, owner, link } = await invitation(server, 222);
        const tap = new WireTap();
        let dropped = false;
        tap.rule((f) => {
          if (!dropped && f.direction === "out" && isClaimPut(f)) {
            dropped = true;
            return { kind: "drop" };
          }
          return undefined;
        });
        const b = bob(link, tap);
        expect((await b.accept()).kind).toBe("unavailable");
        expect((await owner.storage.control.head(R))?.controlSeq).toBe(1n);
        const again = await b.accept();
        expect(again).toMatchObject({ kind: "claimed", resumed: true });
        owner.client.flush();
        await waitFor("OWNER sees the claim", () => owner.controlSettled(2n), 30_000);
        await owner.stop();
      }),
    120_000,
  );
});
