// E-014 (SERVICE-CONTROL-PROFILE-01) against the Rust reference server,
// live (L1). A plugin client, the root R, creates the control Resource C
// and writes its initial change, binds the bridge's base installation B (a
// kind-1 device of R with scope [C]) and writes its base approval (A3).
// B then writes service and status; the plugin sends a request, B answers
// it with events, asks a question, the plugin answers, and B settles and
// cleans up by the deletion rules. Both sides follow the other through
// subscriptions. A record over its §4 size is refused before anything is
// queued, and the busiest minute the A§3.5 pacing allows is admitted under
// the server's default write quotas and message rate.

import {
  leafPayload,
  loadControlChain,
  queueControlRecord,
  queueKeyPackage,
  serviceControlSignerFacts,
  signChain,
} from "@openlfcp/client";
import { dataEpoch, type PrincipalId, resourceId, toBase64url } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  type ServiceControlChanged,
  ServiceControlDataProfile,
  type ServiceControlIntent,
  type ServiceControlSignerClass,
  serviceControlSignerClass,
} from "@openlfcp/shared-objects/service-control";
import { type ControlState, sealKeyPackage, signControlRecord } from "@openlfcp/wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytes32, createResource, type Party, party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const PLUGIN = party(31);
const BRIDGE = party(32);
const C = resourceId(bytes32(201));
const DEK0 = importResourceDEK(bytes32(97));
const T0 = "2026-11-19T10:00:00Z";
const T1 = "2026-11-19T10:30:00Z";
const uid = (n: number) => `0196f2a0-0000-7000-8000-${String(n).padStart(12, "0")}`;
const idOf = (p: Party): PrincipalId => p.signer.descriptor.principalId;
const ref = (p: Party) => `p:${toBase64url(idOf(p))}`;

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

/** §2.3 from C's Control state at the unit's control_ref (the applier's ProfileUnit.control). */
const signerClassOf = (u: { actor: PrincipalId; control?: unknown }): ServiceControlSignerClass =>
  u.control === undefined
    ? "other"
    : serviceControlSignerClass(serviceControlSignerFacts(u.control as ControlState, u.actor));

function controlSide(url: string, who: Party, cls: ServiceControlSignerClass) {
  const profile = new ServiceControlDataProfile({
    resource: C,
    root: idOf(PLUGIN),
    genesisSigner: idOf(PLUGIN),
    signerClassOf,
  });
  const side = new Side({
    url,
    resource: C,
    who,
    profile,
    commit: profile.commitBinding(idOf(who), cls) as never,
  });
  const seen: ServiceControlChanged[] = [];
  profile.onChanged((e) => seen.push(e));
  return { side, profile, seen };
}

let ops = 0;
const commit = async (side: Side<ServiceControlDataProfile>, intents: ServiceControlIntent[]) => {
  const op = `op-${++ops}`;
  try {
    return await side.client.commit(C, intents, { operationId: op });
  } catch (e) {
    throw Object.assign(e as object, { op, intents: intents.map((i) => i.intent) });
  }
};

describe("control Resource C ↔ Rust reference server (live, E-014)", () => {
  it("a plugin client and a service client exchange a request, events, a question and an answer", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: service-control interop (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    try {
      // The plugin (root R) creates C and writes the initial change (its unit 1).
      const plugin = controlSide(url, PLUGIN, "root");
      const genesis = await createResource(plugin.side, url, DEK0);
      plugin.side.start({ open: false });
      await waitFor("plugin READY", () => plugin.side.client.connectionState === "READY");
      await plugin.side.client.host(genesis.bytes);
      plugin.side.open();
      await waitFor("plugin LIVE", () => plugin.side.client.resourceState(C) === "LIVE");
      await commit(plugin.side, [{ intent: "initialize", attemptId: "attempt-1", createdAt: T0 }]);

      // B, the base installation: a kind-1 device of R with scope [C], keyed, then A3.
      const chain = await loadControlChain(plugin.side.storage, C);
      if (chain?.kind !== "linear") throw new Error("no chain");
      const certificates = signChain(
        chain.state,
        PLUGIN.signer,
        leafPayload(idOf(PLUGIN), BRIDGE.signer.descriptor, 1, [1n, 2n], [C]),
      );
      const grant = signControlRecord(
        { resourceId: C, controlSeq: chain.state.seq + 1n, prevControlId: chain.state.head },
        { type: "DEVICE_GRANT", root: idOf(PLUGIN), chain: certificates },
        PLUGIN.signer,
      );
      await queueControlRecord(plugin.side.storage, grant.bytes);
      const kp = await sealKeyPackage({
        resourceId: C,
        epoch: dataEpoch(0n),
        controlHead: grant.recordId,
        recipient: BRIDGE.signer.descriptor,
        dek: DEK0,
        signer: PLUGIN.signer,
      });
      await queueKeyPackage(plugin.side.storage, kp.bytes);
      plugin.side.client.flush();
      await waitFor("grant ACKed", () => plugin.side.controlSettled(chain.state.seq + 1n), 30_000);
      await commit(plugin.side, [
        {
          intent: "approval.create",
          approval: {
            role: "base",
            resource: toBase64url(C),
            principal: ref(BRIDGE),
            certDigest: toBase64url(certificates.leaf.payloadDigest),
            certId: toBase64url(certificates.leaf.id),
            generation: 0,
            origin: "attempt-1",
            at: T0,
          },
        },
      ]);

      const bridge = controlSide(url, BRIDGE, "service-device");
      bridge.side.start();
      await waitFor("bridge LIVE", () => bridge.side.client.resourceState(C) === "LIVE", 30_000);
      await waitFor(
        "bridge sees its approval",
        () => bridge.profile.state().approvals[ref(BRIDGE)]?.role === "base",
        30_000,
      );
      await commit(bridge.side, [
        {
          intent: "service.put",
          fields: {
            instance: "inst-1",
            kind: "apple-reminders",
            label: "MacBook Air",
            platform: "macos",
            app: "0.6.0",
            protocol: { v: 1, ops: ["check", "turn-off"], questionKinds: ["mass-delete"] },
            artifactSliceId: "arm64",
            macos: "15.1",
            cert: { state: "certified", manifestSeq: 1, certTestMode: false },
            capacity: { sections: 1, max: 8, devicesFree: 20 },
          },
        },
        { intent: "status.put", fields: { state: "running", since: T0, heartbeatAt: T0 } },
      ]);
      await waitFor("plugin hears from the bridge", () =>
        plugin.seen.some((e) => e.origin === "remote" && e.keys.includes("status")),
      );
      expect(plugin.profile.state().service?.label).toBe("MacBook Air");

      // The bridge executes what it is asked, from its subscription (§3.4).
      const rid = uid(1);
      const qid = uid(2);
      const aid = uid(3);
      const handled = new Set<string>();
      bridge.profile.onChanged((e) => {
        if (e.origin !== "remote") return;
        if (e.keys.includes(`requests/${rid}`) && !handled.has(rid)) {
          handled.add(rid);
          void (async () => {
            await commit(bridge.side, [
              { intent: "event.put", id: rid, state: "received", at: T0 },
            ]);
            await commit(bridge.side, [
              { intent: "event.put", id: rid, state: "executing", at: T0 },
              {
                intent: "question.create",
                qid,
                question: {
                  binding: toBase64url(bytes32(5)),
                  generation: 1,
                  kind: "mass-delete",
                  anomalyId: "anomaly-1",
                  snapshotHash: "h-1",
                  items: ["Milk", "Eggs"],
                  counts: { delete: 12 },
                  options: ["accept", "keep"],
                  at: T0,
                },
              },
            ]);
          })();
        }
        if (e.keys.includes(`answers/${aid}`) && !handled.has(aid)) {
          handled.add(aid);
          void commit(bridge.side, [
            { intent: "event.put", id: aid, state: "applied", at: T0 },
            {
              intent: "question.resolve",
              qid,
              resolved: { answerId: aid, choice: "accept", at: T0 },
            },
            { intent: "event.put", id: rid, state: "applied", at: T0 },
          ]);
        }
      });

      await commit(plugin.side, [
        {
          intent: "request.create",
          rid,
          request: {
            op: "check",
            args: {},
            client: { app: "0.8.0", protocol: 1 },
            at: T0,
          },
        },
      ]);
      await waitFor("the question reaches the plugin", () =>
        Boolean(plugin.profile.state().questions[qid]),
      );
      expect(plugin.profile.state().events[rid]?.state).toBe("executing");
      await commit(plugin.side, [
        {
          intent: "answer.create",
          aid,
          answer: { qid, snapshotHash: "h-1", choice: "accept", at: T0 },
        },
      ]);
      await waitFor(
        "the plugin sees the request applied",
        () => plugin.profile.state().events[rid]?.state === "applied",
        30_000,
      );
      const states = plugin.seen
        .filter((e) => e.origin === "remote" && e.keys.includes(`events/${rid}`))
        .map((e) => e.state.events[rid]?.state);
      expect(states[0]).toBe("received");
      expect(states.at(-1)).toBe("applied");
      expect(plugin.profile.state().questions[qid]?.resolved?.choice).toBe("accept");
      expect(plugin.profile.state().events[aid]?.state).toBe("applied");

      // §9: the bridge deletes what is settled; the plugin sees the maps cleared.
      await commit(bridge.side, [
        { intent: "delete", container: "requests", key: rid },
        { intent: "delete", container: "events", key: rid },
        { intent: "delete", container: "answers", key: aid },
        { intent: "delete", container: "events", key: aid },
        { intent: "delete", container: "questions", key: qid },
      ]);
      await waitFor("the plugin sees the cleanup", () => {
        const s = plugin.profile.state();
        return !s.requests[rid] && !s.questions[qid] && !s.answers[aid];
      });

      // §4 sizes: refused before anything is queued ("Couldn't send").
      const queued = (await plugin.side.storage.outbound.list(C)).length;
      await expect(
        commit(plugin.side, [
          {
            intent: "request.create",
            rid: uid(4),
            request: {
              op: "check",
              args: { note: "x".repeat(4096) },
              client: { app: "0.8.0", protocol: 1 },
              at: T0,
            },
          },
        ]),
      ).rejects.toMatchObject({ diagnostic: "LIMIT_EXCEEDED" });
      expect((await plugin.side.storage.outbound.list(C)).length).toBe(queued);

      // A§3.5 pacing at its busiest: a heartbeat and one transition for each of the
      // 8 bindings in one minute, sent back to back. The server's default quotas
      // and its message rate (50/s, burst 200) admit it.
      const bindings = Array.from({ length: 8 }, (_, n) => toBase64url(bytes32(40 + n)));
      const minute = [
        commit(bridge.side, [{ intent: "status.put", fields: { heartbeatAt: T1 } }]),
        ...bindings.map((X) =>
          commit(bridge.side, [
            {
              intent: "binding.put",
              binding: X,
              fields: {
                state: "on",
                generation: 1,
                list: "Groceries",
                filter: "all",
                lastCompleteCheckAt: T0,
                pending: { toApple: 0, toLfcp: 0 },
                refused: 0,
                unconfirmed: 0,
              },
            },
          ]),
        ),
      ];
      await Promise.all(minute);
      await waitFor("the minute ACKed", () => bridge.side.queueEmpty(), 30_000);
      await waitFor(
        "the plugin has every binding",
        () => Object.keys(plugin.profile.state().bindings).length === 8,
        30_000,
      );

      // §9 Snapshots are published by the human's clients.
      await plugin.side.client.publishSnapshot(C);
      await waitFor("Snapshot ACKed", () => plugin.side.queueEmpty(), 30_000);

      const refusals = [...plugin.side.errors(), ...bridge.side.errors()];
      expect(refusals).toEqual([]);
      expect(server.log()).not.toMatch(/QUOTA_EXCEEDED|RATE_LIMITED/);
      await plugin.side.stop();
      await bridge.side.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? `${e.message} ${JSON.stringify(e)}` : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    }
  }, 180_000);
});
