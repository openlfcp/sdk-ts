// LFCP-02-106, live: a member refused on RESOURCE_OPEN because a restored
// server lost its grant re-supplies its own Control Chain with CONTROL_PUT
// and opens again (design: .github docs/devel/design/
// member-recovery-after-restore.md; LFCP-WIRE-01 §47, §68.1, §84), against
// the Rust reference server at server.lock.

import { loadControlChain, queueControlRecord, saveControlChain } from "@openlfcp/client";
import { type ObjectId, resourceId, toHex } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  type Task,
} from "@openlfcp/shared-objects";
import { signControlRecord } from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { bytes32, createResource, grantAndKey, party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(16);
const BOB = party(56);
const CAROL = party(76);
const DEK0 = importResourceDEK(bytes32(96));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c0739a1" as ObjectId;

const sideOf = (url: string, R: ReturnType<typeof resourceId>, who: typeof OWNER) =>
  new Side({
    url,
    resource: R,
    who,
    profile: new SharedObjectsDataProfile(
      SharedObjectsReplica.empty({ resource: R, principal: who.signer.descriptor.principalId }),
    ),
  });

const recovery = (side: Side) =>
  side.events.flatMap((e) =>
    e.type === "access-recovery" ? [`${e.outcome}${e.reason ? `:${e.reason}` : ""}`] : [],
  );
const title = (side: Side) => (side.profile.replica.task(TASK)?.task as Task | undefined)?.title;

async function withServer(
  ctx: { skip(): void },
  body: (server: RunningRustServer) => Promise<void>,
): Promise<void> {
  const started = await startRustServer();
  if ("skip" in started) {
    console.warn(`SKIPPED: access recovery interop (${started.skip})`);
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

/**
 * OWNER hosts `R` and writes a Task; the store is copied (`backup`); OWNER
 * grants BOB, who joins and converges. Both sessions are stopped.
 */
async function joinedAfterBackup(server: RunningRustServer, seed: number) {
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
  await owner.write(
    owner.profile.replica.apply(
      createTask({ id: TASK, title: "Before", createdBy: OWNER.signer.descriptor.principalId })
        .intent,
    ) as LocalChange,
  );
  await waitFor("OWNER queue empty", () => owner.queueEmpty());
  const backup = server.files(); // the grant is not in it
  await grantAndKey(owner, BOB, DEK0);
  await waitFor("grant acknowledged", () => owner.queueEmpty());
  const bob = sideOf(server.url, R, BOB);
  bob.start();
  await waitFor("BOB LIVE", () => bob.client.resourceState(R) === "LIVE", 30_000);
  await waitFor("BOB has the Task", () => title(bob) === "Before", 30_000);
  await bob.stop();
  await owner.stop();
  return { R, owner, backup, bob };
}

/** BOB again, on the storage, secrets and replica of an earlier session. */
const again = (server: RunningRustServer, bob: Side) =>
  new Side({
    url: server.url,
    resource: bob.resource,
    who: BOB,
    storage: bob.storage,
    secrets: bob.secrets,
    profile: bob.profile,
  });

/** OWNER revokes BOB's grant (queued and flushed). */
async function revokeBob(owner: Side) {
  const chain = await loadControlChain(owner.storage, owner.resource);
  if (chain?.kind !== "linear") throw new Error("no chain");
  const grant = [...chain.state.grants.values()].find(
    (g) => toHex(g.subject) === toHex(BOB.signer.descriptor.principalId),
  );
  if (grant === undefined) throw new Error("no grant of BOB");
  const revoke = signControlRecord(
    {
      resourceId: owner.resource,
      controlSeq: chain.state.seq + 1n,
      prevControlId: chain.state.head,
    },
    { type: "CAPABILITY_REVOKE", grantId: grant.id as never },
    owner.who.signer,
  );
  await queueControlRecord(owner.storage, revoke.bytes);
  owner.client.flush();
}

describe("access recovery after a restore ↔ Rust reference server (live, LFCP-02-106)", () => {
  it(
    "a member whose grant the server lost re-supplies it and reaches LIVE without the owner",
    (ctx) =>
      withServer(ctx, async (server) => {
        const { R, backup, bob: joined } = await joinedAfterBackup(server, 211);
        await server.restore(backup);
        const bob = again(server, joined);
        bob.start();
        await waitFor("BOB LIVE again", () => bob.client.resourceState(R) === "LIVE", 30_000);
        expect(recovery(bob)).toEqual(["started", "recovered"]);
        expect(bob.client.resourceRefusal(R)).toBeNull();
        await bob.stop();
      }),
    120_000,
  );

  it(
    "member and owner reconnecting together end with one chain",
    (ctx) =>
      withServer(ctx, async (server) => {
        const { R, owner, backup, bob: joined } = await joinedAfterBackup(server, 212);
        await server.restore(backup);
        const bob = again(server, joined);
        owner.start();
        bob.start();
        await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE", 30_000);
        await waitFor("BOB LIVE", () => bob.client.resourceState(R) === "LIVE", 30_000);
        await waitFor("OWNER queue empty", () => owner.queueEmpty(), 30_000);
        // Both hold the same chain: Genesis and the grant, no fork.
        expect((await bob.storage.control.head(R))?.controlSeq).toBe(1n);
        expect((await owner.storage.control.head(R))?.controlSeq).toBe(1n);
        expect(recovery(bob).filter((r) => r.startsWith("ended"))).toEqual([]);
        await bob.stop();
        await owner.stop();
      }),
    120_000,
  );

  it(
    "no recovery runs when the owner re-supplied first",
    (ctx) =>
      withServer(ctx, async (server) => {
        const { R, owner, backup, bob: joined } = await joinedAfterBackup(server, 213);
        await server.restore(backup);
        owner.start();
        await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE", 30_000);
        await waitFor("OWNER queue empty", () => owner.queueEmpty(), 30_000);
        // The owner's CONTROL_PUT is asynchronous (§68.1): wait until BOB's
        // open is not refused any more, without recovery.
        await waitFor(
          "server holds the grant",
          async () => {
            const probe = sideOf(server.url, R, BOB);
            probe.start();
            await waitFor(
              "probe answered",
              () =>
                probe.client.resourceState(R) === "LIVE" ||
                probe.client.resourceRefusal(R) !== null,
              10_000,
            );
            const ok = probe.client.resourceState(R) === "LIVE";
            await probe.stop();
            return ok;
          },
          30_000,
        );
        const member = again(server, joined);
        member.start();
        await waitFor("BOB LIVE", () => member.client.resourceState(R) === "LIVE", 30_000);
        expect(recovery(member)).toEqual([]);
        await member.stop();
        await owner.stop();
      }),
    120_000,
  );

  it(
    "a member whose own chain revokes it sends nothing and stays refused",
    (ctx) =>
      withServer(ctx, async (server) => {
        const { R, owner, bob: joined } = await joinedAfterBackup(server, 214);
        const bob = again(server, joined);
        owner.start();
        bob.start();
        await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE", 30_000);
        await waitFor("BOB LIVE", () => bob.client.resourceState(R) === "LIVE", 30_000);
        await revokeBob(owner);
        await waitFor("revocation acknowledged", () => owner.queueEmpty(), 30_000);
        // The server stops serving BOB once he is revoked, so he would not
        // receive it live; store the revocation in his chain as if he had.
        const full = await loadControlChain(owner.storage, R);
        if (full?.kind !== "linear") throw new Error("no chain");
        const bobHead = await bob.storage.control.head(R);
        const saved = await saveControlChain(bob.storage, full, bobHead?.head ?? null);
        expect(saved.ok).toBe(true);
        await bob.stop();
        const revoked = again(server, bob);
        revoked.start();
        await waitFor("BOB refused", () => revoked.client.resourceRefusal(R) !== null, 30_000);
        expect(revoked.client.resourceRefusal(R)?.code).toBe("AUTHORIZATION_FAILED");
        expect(recovery(revoked)).toEqual(["ended:not-granted"]);
        await revoked.stop();
        await owner.stop();
      }),
    120_000,
  );

  it(
    "a member revoked on the server only is refused after one more open",
    (ctx) =>
      withServer(ctx, async (server) => {
        const { R, owner, bob: joined } = await joinedAfterBackup(server, 215);
        // BOB is offline while OWNER revokes him.
        owner.start();
        await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE", 30_000);
        await revokeBob(owner);
        await waitFor("revocation acknowledged", () => owner.queueEmpty(), 30_000);
        // BOB returns with his chain, which still grants him.
        const bob = again(server, joined);
        bob.start();
        await waitFor("BOB refused", () => bob.client.resourceRefusal(R) !== null, 30_000);
        expect(bob.client.resourceRefusal(R)?.code).toBe("AUTHORIZATION_FAILED");
        // BOB's head is on the server: re-sending it is acknowledged (a
        // repeat), BOB opens once more and the refusal is final.
        expect(recovery(bob)).toEqual(["started", "ended:still-refused"]);
        await bob.stop();
        await owner.stop();
      }),
    120_000,
  );

  it(
    "a session without a chain that grants it is refused as before",
    (ctx) =>
      withServer(ctx, async (server) => {
        const { R } = await joinedAfterBackup(server, 216);
        const carol = sideOf(server.url, R, CAROL);
        carol.start();
        await waitFor("CAROL refused", () => carol.client.resourceRefusal(R) !== null, 30_000);
        expect(carol.client.resourceRefusal(R)?.code).toBe("AUTHORIZATION_FAILED");
        expect(recovery(carol)).toEqual([]);
        await carol.stop();
      }),
    120_000,
  );
});
