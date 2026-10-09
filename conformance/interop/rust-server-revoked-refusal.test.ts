// LFCP-02-115: a member revoked while offline learns the refusal and
// reports it honestly, against the Rust reference server, live. B joins a
// section, goes offline and commits a batch; OWNER revokes B. When B
// reconnects the server refuses RESOURCE_OPEN with AUTHORIZATION_FAILED;
// the access recovery (LFCP-02-106) cannot help: the server already holds
// B's chain (it answers B's head as committed) and refuses the reopen too. B's status then says the server refuses it (not
// "revoked": the server does not say why), its offline batch is blocked
// with the work kept, and how current B is is unknown.

import type { StatusEvent, SyncEvent } from "@openlfcp/client";
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

const OWNER = party(15);
const B = party(55);
const R = resourceId(bytes32(195));
const DEK0 = importResourceDEK(bytes32(95));
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

const statusOf = (events: readonly SyncEvent[]): StatusEvent[] =>
  events.flatMap((e) => (e.type === "status" ? [e.event] : []));

describe("a revoked member's refusal (live, LFCP-02-115)", () => {
  it("reports server-refused access, a blocked batch and unknown catch-up", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: revoked refusal interop (${skip})`);
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
      await owner.client.commit(
        R,
        [{ intent: "section.create", sectionId: SECTION, title: "Plan", createdBy: me }],
        { operationId: "create" },
      );
      await grantAndKey(owner, B, DEK0);
      await waitFor("B granted", () => owner.controlSettled(1n), 30_000);

      const b = sectionSide(url, B);
      b.start();
      await waitFor("B LIVE", () => b.client.resourceState(R) === "LIVE", 30_000);
      await waitFor(
        "B has the section",
        () => b.profile.replica.sectionState() === "ready",
        30_000,
      );

      // B goes offline and writes; OWNER revokes B meanwhile.
      await b.stop();
      const item: SectionIntent = {
        intent: "item.create",
        id: id(10),
        parent: SECTION,
        after: null,
        text: "from B, offline",
        createdBy: B.signer.descriptor.principalId,
      };
      await b.client.commit(R, [item], { operationId: "b-stale" });
      const queued = await b.storage.outbound.list(R);
      expect(queued.length).toBeGreaterThan(0);
      expect(await owner.client.revokeAccess(R, B.signer.descriptor.principalId)).toMatchObject({
        kind: "queued",
      });
      await waitFor("OWNER at the new epoch", () => owner.controlSettled(3n), 30_000);

      // B reconnects: refused.
      const from = b.events.length;
      b.start();
      await waitFor(
        "B refused",
        () => b.client.resourceRefusal(R)?.code === "AUTHORIZATION_FAILED",
        30_000,
      );
      await waitFor(
        "B reports the refusal",
        () =>
          statusOf(b.events.slice(from)).some(
            (e) => e.kind === "batch" && e.operationId === "b-stale" && e.status === "blocked",
          ),
        30_000,
      );
      const recovery = b.events
        .slice(from)
        .filter((e) => e.type === "access-recovery")
        .map((e) => (e.type === "access-recovery" ? `${e.outcome}:${e.reason ?? ""}` : ""));
      // B pushes its head; the server answers it as committed (§47) and the
      // reopen is refused again: the server holds B's chain and still refuses.
      expect(recovery).toEqual(["started:", "ended:still-refused"]);

      const access = statusOf(b.events.slice(from))
        .filter((e) => e.kind === "access")
        .at(-1);
      expect(access).toMatchObject({
        kind: "access",
        access: {
          allowed: false,
          reason: "server-refused",
          current: false,
          serverRefusal: { code: "AUTHORIZATION_FAILED", recovery: "still-refused" },
        },
      });
      const snap = await b.client.statusSnapshot(R);
      expect(snap.batches.find((x) => x.operationId === "b-stale")?.status).toBe("blocked");
      expect(snap.catchUp.state).toBe("unknown");
      expect(snap.access).toMatchObject({ allowed: false, reason: "server-refused" });
      // The work is kept: the queued unit and the receipt stay.
      expect(await b.storage.outbound.list(R)).toEqual(queued);
      // A new commit is refused locally with the same reason.
      await expect(
        b.client.commit(R, [{ ...item, id: id(11) }], { operationId: "b-next" }),
      ).rejects.toMatchObject({ code: "NOT_WRITABLE", access: { reason: "server-refused" } });
      await owner.stop();
      await b.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    }
  }, 180_000);
});
