// LFCP-02-028: section Snapshot catch-up against the Rust reference server,
// live. OWNER commits a section in three batches, publishes a Snapshot of
// it (SNAPSHOT_PUT), commits two more batches, and grants CAROL. CAROL, a
// fresh client, loads the offered Snapshot through the section admission,
// accepts the frontier's last unit as covered, fetches only the units
// beyond it, ends in OWNER's exact state, and writes on with her own actor.

import { resourceId } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  type SectionIntent,
  SectionReplica,
  SharedSectionsDataProfile,
} from "@openlfcp/shared-objects/sections";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytes32, createResource, grantAndKey, party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(14);
const CAROL = party(73);
const R = resourceId(bytes32(185));
const DEK0 = importResourceDEK(bytes32(93));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);

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

const sectionSide = (url: string, who: typeof OWNER) => {
  const profile = new SharedSectionsDataProfile(
    SectionReplica.empty({ resource: R, principal: who.signer.descriptor.principalId }),
  );
  return new Side({
    url,
    resource: R,
    who,
    profile,
    commit: profile.commitBinding(who.signer.descriptor.principalId) as never,
  });
};

describe("section Snapshot catch-up ↔ Rust reference server (live, LFCP-02-028)", () => {
  it("a fresh client loads the published section Snapshot and fetches only the tail", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: section Snapshot interop (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    try {
      const owner = sectionSide(url, OWNER);
      const me = OWNER.signer.descriptor.principalId;
      const genesis = await createResource(owner, url, DEK0);
      owner.start({ open: false });
      await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
      await owner.client.host(genesis.bytes);
      owner.open();
      await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");

      const item = (n: number, text: string, by = me): SectionIntent => ({
        intent: "item.create",
        id: id(n),
        parent: SECTION,
        after: null,
        text,
        createdBy: by,
      });
      const commit = (op: string, intents: SectionIntent[]) =>
        owner.client.commit(R, intents, { operationId: op });
      await commit("op-1", [
        { intent: "section.create", sectionId: SECTION, title: "Plan", createdBy: me },
      ]);
      await commit("op-2", [item(10, "one")]);
      await commit("op-3", [item(11, "two")]);
      await waitFor("three units ACKed", () => owner.queueEmpty());
      await owner.client.publishSnapshot(R);
      await waitFor("Snapshot ACKed", () => owner.queueEmpty());
      await commit("op-4", [{ intent: "section.set_title", title: "Final plan" }]);
      await commit("op-5", [item(12, "three")]);
      await grantAndKey(owner, CAROL, DEK0);
      await waitFor("tail, grant and Key Package ACKed", () => owner.queueEmpty());

      const carol = sectionSide(url, CAROL);
      carol.start();
      await waitFor("CAROL LIVE", () => carol.client.resourceState(R) === "LIVE");
      await waitFor(
        "CAROL converged",
        () =>
          JSON.stringify(carol.profile.replica.snapshot()) ===
          JSON.stringify(owner.profile.replica.snapshot()),
      );
      const loaded = carol.events.find((e) => e.type === "snapshot-loaded");
      expect(loaded?.type === "snapshot-loaded" && loaded.frontier).toEqual([
        { principalId: me, contiguous: 3n, extras: [] },
      ]);
      const units = carol.events
        .filter((e) => e.type === "unit")
        .map((e) => (e.type === "unit" ? e.outcome.kind : ""));
      expect(units).toEqual(["covered", "applied", "applied"]);
      expect(carol.profile.replica.snapshot().title.value).toBe("Final plan");

      // CAROL writes on with her own actor, and OWNER admits it.
      await carol.client.commit(R, [item(20, "carol's", CAROL.signer.descriptor.principalId)], {
        operationId: "carol-1",
      });
      await waitFor(
        "OWNER has CAROL's item",
        () => owner.profile.replica.snapshot().nodes[id(20)]?.text === "carol's",
        30_000,
      );
      expect(owner.errors()).toEqual([]);
      expect(carol.errors()).toEqual([]);
      await owner.stop();
      await carol.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    }
  }, 120_000);
});
