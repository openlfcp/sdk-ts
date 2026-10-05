// LFCP-038, live: a client process killed mid-sync and restarted, against
// the Rust reference server. BOB runs in a child process on SQLite and a
// file secret store (client-proc.mjs); OWNER runs here.
//
// 1. OWNER hosts a Resource, writes a Task and twelve edits, grants BOB.
// 2. BOB #1 starts catching up and is SIGKILLed after three units.
// 3. BOB #2 restarts from disk, reaches LIVE, writes two edits and is
//    SIGKILLed right after the second write (before its ACK may arrive).
// 4. OWNER writes more while BOB is down.
// 5. BOB #3 restarts and converges with OWNER.
//
// Checked: BOB's sequences are 1 and 2, each on the server exactly once (no
// reuse); no unit is applied as new twice across the restarts (replays from
// disk are reported apart); the final replicas are identical.

import { type DataUnitId, type ObjectId, resourceId, toHex } from "@openlfcp/core";
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
import { inDir, makeTempDir, removeTempDir } from "../storage/temp-dir.mjs";
import { type ClientEvent, type ClientProc, startClientProc } from "./client-proc-control.mjs";
import { bytes32, createResource, grantAndKey, party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(13);
const BOB_SEED = 53;
const BOB = party(BOB_SEED);
const R = resourceId(bytes32(190));
const DEK0 = importResourceDEK(bytes32(93));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;

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

const applied = (p: ClientProc) =>
  p.events.filter((e) => e.t === "unit" && e.kind === "applied").map((e) => String(e.unitId));
const last = (p: ClientProc, t: string): ClientEvent | undefined =>
  p.events.filter((e) => e.t === t).at(-1);

describe("restart mid-sync ↔ Rust reference server (live, child processes)", () => {
  it("converges after kills with no sequence reuse and no duplicate apply", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: TS↔Rust restart interop (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    const dir = makeTempDir("lfcp-038-live-");
    const procs: ClientProc[] = [];
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
      owner.start({ open: false });
      await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
      await owner.client.host(genesis.bytes);
      owner.open();
      await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
      const task = () => owner.profile.replica.task(TASK)?.task as Task;
      const edit = (title: string) =>
        owner.write(owner.profile.replica.apply(setTitle(task(), title).intent) as LocalChange);
      await owner.write(init);
      await owner.write(
        owner.profile.replica.apply(
          createTask({ id: TASK, title: "Draft", createdBy: OWNER.signer.descriptor.principalId })
            .intent,
        ) as LocalChange,
      );
      for (let i = 1; i <= 12; i++) await edit(`owner ${i}`);
      await grantAndKey(owner, BOB, DEK0);
      await waitFor("OWNER queue empty", () => owner.queueEmpty(), 30_000);

      const args = [inDir(dir, "bob"), url, toHex(R), String(BOB_SEED)];
      // 2. Killed mid catch-up.
      const bob1 = startClientProc(args);
      procs.push(bob1);
      await waitFor("BOB #1 applied three units", () => applied(bob1).length >= 3, 30_000);
      await bob1.kill();

      // 3. Restarted from disk; LIVE; two writes; killed right after the second.
      const bob2 = startClientProc(args);
      procs.push(bob2);
      await waitFor("BOB #2 LIVE", () => last(bob2, "state")?.state === "LIVE", 30_000);
      // What BOB #1 merged is on disk: restored from a checkpoint, or replayed from stored units.
      expect(
        bob2.events.find((e) => e.t === "started")?.restored === true ||
          bob2.events.some((e) => e.t === "replayed" && Number(e.n) > 0),
      ).toBe(true);
      bob2.send("write bob one");
      await waitFor(
        "BOB #2 first write",
        () => bob2.events.filter((e) => e.t === "wrote").length === 1,
      );
      bob2.send("write bob two");
      await waitFor(
        "BOB #2 second write",
        () => bob2.events.filter((e) => e.t === "wrote").length === 2,
      );
      await bob2.kill();
      const wrote = bob2.events
        .filter((e) => e.t === "wrote")
        .map((e): [string, string] => [String(e.seq), String(e.unitId)]);
      expect(wrote.map(([seq]) => seq)).toEqual(["1", "2"]);

      // 4. OWNER keeps writing while BOB is down.
      await edit("owner while bob is down");
      await waitFor("OWNER queue empty again", () => owner.queueEmpty());

      // 5. Restarted again: converges.
      const bob3 = startClientProc(args);
      procs.push(bob3);
      await waitFor("BOB #3 LIVE", () => last(bob3, "state")?.state === "LIVE", 30_000);
      await waitFor(
        "OWNER has BOB's two units",
        async () => {
          for (const [seq] of wrote)
            if (
              (
                await owner.storage.dataUnits.at(
                  R,
                  BOB.signer.descriptor.principalId,
                  BigInt(seq) as never,
                )
              ).length !== 1
            )
              return false;
          return true;
        },
        30_000,
      );
      await waitFor(
        "convergence",
        () => {
          bob3.send("root");
          const root = last(bob3, "root")?.root;
          return JSON.stringify(root) === JSON.stringify(owner.profile.replica.root());
        },
        30_000,
      );

      // No sequence reuse: BOB's units on OWNER's side are exactly the two written, one per sequence.
      for (const [seq, unitId] of wrote) {
        const at = await owner.storage.dataUnits.at(
          R,
          BOB.signer.descriptor.principalId,
          BigInt(seq) as never,
        );
        expect(at.map((u) => toHex(u.unitId as DataUnitId))).toEqual([unitId]);
      }
      expect(last(bob3, "root")?.actorSeq).toBe(2);
      // No duplicate apply: a unit applied as new before a restart is never applied as new again.
      const before = new Set([...applied(bob1), ...applied(bob2)]);
      expect(applied(bob3).filter((id) => before.has(id))).toEqual([]);
      for (const p of procs) expect(p.events.filter((e) => e.t === "error")).toEqual([]);
      expect(owner.errors()).toEqual([]);
      await owner.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- client events ---\n${procs.map((p, i) => `#${i + 1} ${JSON.stringify(p.events.slice(-30))}`).join("\n")}\n--- client stderr ---\n${procs.map((p) => p.stderr().slice(-1500)).join("\n")}\n--- server log (tail) ---\n${server.log().slice(-3000)}`,
      );
    } finally {
      for (const p of procs) if (p.alive()) await p.kill();
      removeTempDir(dir);
    }
  }, 180_000);
});
