// LFCP-WIRE-01 §26.2 against the Rust reference server, live: an actor
// whose first unit went stale names no previous unit for its next one.
// OWNER grants BOB and CAROL. CAROL, offline, writes her first unit
// (sequence 1). OWNER revokes BOB: the Key Epoch closes epoch 0 without a
// CAROL entry (§19.1), so CAROL's unit is stale. Back online, CAROL writes
// again: her unit at sequence 2 has a null `previous` (she holds no own
// unit as accepted), the server accepts it, and OWNER, who accepted nothing
// of CAROL, links and merges it. Up to 0.2.0-beta.7 createDataUnit refused
// any null `previous` after sequence 1, so CAROL could never write again.

import { hash32, type ObjectId, resourceId } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytes32, createResource, grantAndKey, party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(14);
const BOB = party(54);
const CAROL = party(64);
const R = resourceId(bytes32(191));
const DEK0 = importResourceDEK(bytes32(95));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c073991" as ObjectId;

let server: RunningRustServer | undefined;
let skip: string | undefined;

beforeAll(async () => {
  const started = await startRustServer();
  if ("skip" in started) skip = started.skip;
  else server = started;
}, 600_000);

afterAll(async () => {
  await server?.stop();
});

describe("a first unit gone stale ↔ Rust reference server (live, §26.2)", () => {
  it("the next unit, at sequence 2, names no previous unit; the server and the owner take it", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: stale first unit (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    try {
      const { replica, change: init } = SharedObjectsReplica.create({
        resource: R,
        principal: OWNER.signer.descriptor.principalId,
      });
      const owner = new Side({
        url,
        resource: R,
        who: OWNER,
        profile: new SharedObjectsDataProfile(replica),
      });
      const genesis = await createResource(owner, url, DEK0);
      await owner.write(init);
      owner.start({ open: false });
      await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
      await owner.client.host(genesis.bytes);
      owner.open();
      await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
      await grantAndKey(owner, BOB, DEK0);
      await waitFor("BOB granted", () => owner.controlSettled(1n), 30_000);
      await grantAndKey(owner, CAROL, DEK0);
      await waitFor("CAROL granted", () => owner.controlSettled(2n), 30_000);
      const task = (side: Side) => side.profile.replica.task(TASK)?.task as Task;
      await owner.write(
        owner.profile.replica.apply(
          createTask({ id: TASK, title: "Before", createdBy: OWNER.signer.descriptor.principalId })
            .intent,
        ) as LocalChange,
      );
      await waitFor("OWNER edit ACKed", () => owner.queueEmpty(), 30_000);

      // CAROL syncs once (her chain and DEK), then goes offline.
      const carol = new Side({
        url,
        resource: R,
        who: CAROL,
        profile: new SharedObjectsDataProfile(
          SharedObjectsReplica.empty({
            resource: R,
            principal: CAROL.signer.descriptor.principalId,
          }),
        ),
      });
      carol.start();
      await waitFor("CAROL has the Task", () => task(carol)?.title === "Before", 30_000);
      await carol.stop();
      // Offline, her first unit: sequence 1, previous null, queued.
      await carol.write(
        carol.profile.replica.apply(setTitle(task(carol), "Carol offline").intent) as LocalChange,
      );
      const first = (
        await carol.storage.dataUnits.range(
          R,
          CAROL.signer.descriptor.principalId,
          1n as never,
          1n as never,
        )
      )[0];
      expect(first?.actorSeq).toBe(1n);
      expect(first?.prevDataUnitId).toBeNull();

      // OWNER revokes BOB: the Key Epoch closes epoch 0, with no CAROL entry.
      const result = await owner.client.revokeAccess(R, BOB.signer.descriptor.principalId);
      expect(result).toMatchObject({ kind: "queued", epoch: 1n });
      await waitFor("OWNER at the new epoch", () => owner.controlSettled(4n), 30_000);

      // CAROL back, on the same store: her first unit is stale (quarantined).
      const back = new Side({
        url,
        resource: R,
        who: CAROL,
        profile: carol.profile,
        storage: carol.storage,
        secrets: carol.secrets,
      });
      back.start();
      await waitFor(
        "CAROL's first unit cut off",
        async () =>
          (await back.storage.dataUnits.withStatus(R, "quarantined")).some(
            (u) => u.actorSeq === 1n && u.actor !== undefined,
          ),
        30_000,
      );
      await waitFor(
        "CAROL at the new epoch",
        async () => (await back.storage.control.head(R))?.controlSeq === 4n,
        30_000,
      );
      expect(task(back)?.title).toBe("Before");

      // Her next unit: sequence 2, previous null (§26.2), accepted by the server.
      const after = back.profile.replica.apply(
        setTitle(task(back), "Carol after").intent,
      ) as LocalChange;
      // The new epoch's DEK reaches CAROL in a Key Package: written once it is there.
      let id: Awaited<ReturnType<typeof back.write>> | undefined;
      await waitFor(
        "CAROL writes in the new epoch",
        async () => {
          try {
            id = await back.write(after);
            return true;
          } catch (e) {
            if (String(e).includes("no DEK")) return false;
            throw e;
          }
        },
        30_000,
      );
      if (id === undefined) throw new Error("not written");
      const unitId = id;
      const second = await back.storage.dataUnits.get(unitId);
      expect(second?.actorSeq).toBe(2n);
      expect(second?.prevDataUnitId).toBeNull();
      expect(second?.dataEpoch).toBe(1n);
      // ACKed: its outbound item is gone (the stale unit's own item stays, blocked).
      await waitFor(
        "CAROL's unit ACKed",
        async () => (await back.storage.outbound.get(hash32(unitId))) === undefined,
        30_000,
      );
      const stale = await back.storage.outbound.get(hash32(first?.unitId as never));
      expect(stale?.blocked?.reason).toBe("stale-epoch");
      // OWNER accepted nothing of CAROL: it links, and merges.
      await waitFor(
        "OWNER merges CAROL's unit",
        () => task(owner)?.title === "Carol after",
        30_000,
      );
      expect((await owner.storage.dataUnits.get(unitId))?.status).toBe("merged");
      await owner.stop();
      await back.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    }
  }, 180_000);
});
