// E-015 (A§4.3–4.4, SERVICE-CONTROL-PROFILE-01 §7.1, §8.1) against the Rust
// reference server at server.lock, live (L1). The root P (a plugin client)
// has an Identity Resource I over sections X1…X4 and a control Resource C
// whose base installation B is approved. For each section P creates J,
// writes requests[rid] = pair-section in C; the section device D writes its
// kind-1 request in I as J, B writes pairing[rid]; P approves without the
// human through autoApproveSection: A1 consume, A2 grant (I), A3 approval
// record (C, through serviceControlPort over P's SyncClient), A4
// registration (X). Each section loses one boundary's answer: the record
// is committed but the client never hears it (A1, A2, A4), or the client
// crashes right after committing A3. The next re-check recovers: one of
// each record, A3 before A4, D ready in its section.
//
// Skipped (saying why) without a server checkout or cargo, unless
// LFCP_REQUIRE_LIVE=1; LFCP_SERVER_BIN runs a prebuilt server instead.

import {
  autoApproveSection,
  completePairing,
  createIdentityResource,
  createPairingSession,
  type IdentityChannel,
  type IdentityNetwork,
  IdentityUnavailable,
  leafPayload,
  loadControlChain,
  OperationJournal,
  queueControlRecord,
  queueKeyPackage,
  requestPairing,
  type SectionApprovalResult,
  type ServiceControlPort,
  serviceControlPort,
  serviceControlSignerFacts,
  signChain,
} from "@openlfcp/client";
import {
  dataEpoch,
  generateResourceId,
  type PrincipalId,
  type ResourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import { generateResourceDEK } from "@openlfcp/crypto";
import {
  ServiceControlDataProfile,
  type ServiceControlIntent,
  type ServiceControlSignerClass,
  serviceControlSignerClass,
} from "@openlfcp/shared-objects/service-control";
import {
  type ControlState,
  deviceFingerprint,
  encodePrincipalDescriptor,
  parseControlRecord,
  sealKeyPackage,
  signControlRecord,
} from "@openlfcp/wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createResource, Side, sleep, waitFor } from "./harness.js";
import { chainOf, hostResource, installation, type Node } from "./identity-live.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

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

const T0 = "2026-11-19T10:00:00Z";
const uid = (n: number) => `0196f2a0-0000-7000-8000-${String(n).padStart(12, "0")}`;
const idOf = (n: Node): PrincipalId => n.installation.signer.descriptor.principalId;
const ref = (p: PrincipalId) => `p:${toBase64url(p)}`;
const type = (bytes: Uint8Array) => {
  const t = parseControlRecord(bytes).payload.controlType;
  return t === 9n ? "DEVICE_GRANT" : t === 10n ? "DEVICE_REVOKE" : String(t);
};

/** §2.3 from C's Control state at the unit's control_ref. */
const signerClassOf = (u: { actor: PrincipalId; control?: unknown }): ServiceControlSignerClass =>
  u.control === undefined
    ? "other"
    : serviceControlSignerClass(serviceControlSignerFacts(u.control as ControlState, u.actor));

function controlSide(
  url: string,
  C: ResourceId,
  root: Node,
  who: Node,
  cls: ServiceControlSignerClass,
) {
  const profile = new ServiceControlDataProfile({
    resource: C,
    root: idOf(root),
    genesisSigner: idOf(root),
    signerClassOf,
  });
  const side = new Side({
    url,
    resource: C,
    who: who.installation,
    profile,
    commit: profile.commitBinding(idOf(who), cls) as never,
  });
  return { side, profile };
}

/**
 * The network of a client whose answer to one Control Record is lost: the
 * coordinator commits it, the client sees the session end (a crash, or a
 * dropped connection, before the ACK reached the journal).
 */
function losing(
  net: IdentityNetwork,
  lose: (resource: ResourceId, bytes: Uint8Array) => boolean,
): IdentityNetwork {
  let lost = false;
  return {
    connect: async (signer, url) => {
      const channel = await net.connect(signer, url);
      return new Proxy(channel, {
        get(target, key) {
          if (key === "putControl")
            return async (...args: Parameters<IdentityChannel["putControl"]>) => {
              const answer = await target.putControl(...args);
              if (!lost && lose(args[0], args[2])) {
                lost = true;
                throw new IdentityUnavailable("the answer was lost");
              }
              return answer;
            };
          const v = Reflect.get(target, key) as unknown;
          return typeof v === "function" ? v.bind(target) : v;
        },
      });
    },
    ...(net.close === undefined ? {} : { close: () => net.close?.() }),
  };
}

/** A port whose client crashes once right after its A3 commit is durable. */
function crashingAfterCommit(port: ServiceControlPort): ServiceControlPort {
  let crashed = false;
  return {
    resource: port.resource,
    state: () => port.state(),
    creatorsOf: (c, k) => port.creatorsOf(c, k),
    commit: async (intents, operation) => {
      const r = await port.commit(intents, operation);
      if (
        !crashed &&
        (intents as ServiceControlIntent[]).some((i) => i.intent === "approval.create")
      ) {
        crashed = true;
        throw new Error("crashed after the A3 commit");
      }
      return r;
    },
  };
}

describe("section auto-approval ↔ Rust reference server (live, E-015)", () => {
  it("a crash at each ACK boundary A1–A4 recovers: one of each record, A3 before A4", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: section auto-approval interop (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    const P = installation(61);
    const B = installation(62);
    const sides: Side<ServiceControlDataProfile>[] = [];
    try {
      const sections = [];
      for (let n = 1; n <= 4; n++) sections.push(await hostResource(P, url, `X${n}`));
      const created = await createIdentityResource({
        ...P,
        url,
        label: "laptop",
        roster: sections,
      });
      if (created.kind !== "created") throw new Error(JSON.stringify(created));
      const I = created.identity;

      // C, created and initialized by the root; B approved as its base installation (A§4.1).
      const C = generateResourceId();
      const dek = generateResourceDEK();
      const plugin = controlSide(url, C, P, P, "root");
      sides.push(plugin.side);
      const genesis = await createResource(plugin.side, url, dek);
      plugin.side.start({ open: false });
      await waitFor("plugin READY", () => plugin.side.client.connectionState === "READY");
      await plugin.side.client.host(genesis.bytes);
      plugin.side.open();
      await waitFor("plugin LIVE", () => plugin.side.client.resourceState(C) === "LIVE");
      let ops = 0;
      const commit = (side: Side<ServiceControlDataProfile>, intents: ServiceControlIntent[]) =>
        side.client.commit(C, intents, { operationId: `op-${++ops}` });
      await commit(plugin.side, [{ intent: "initialize", attemptId: "attempt-1", createdAt: T0 }]);
      const chainC = await loadControlChain(plugin.side.storage, C);
      if (chainC?.kind !== "linear") throw new Error("no chain of C");
      const certB = signChain(
        chainC.state,
        P.installation.signer,
        leafPayload(idOf(P), B.installation.signer.descriptor, 1, [1n, 2n], [C]),
      );
      const grant = signControlRecord(
        { resourceId: C, controlSeq: chainC.state.seq + 1n, prevControlId: chainC.state.head },
        { type: "DEVICE_GRANT", root: idOf(P), chain: certB },
        P.installation.signer,
      );
      await queueControlRecord(plugin.side.storage, grant.bytes);
      await queueKeyPackage(
        plugin.side.storage,
        (
          await sealKeyPackage({
            resourceId: C,
            epoch: dataEpoch(0n),
            controlHead: grant.recordId,
            recipient: B.installation.signer.descriptor,
            dek,
            signer: P.installation.signer,
          })
        ).bytes,
      );
      plugin.side.client.flush();
      await waitFor(
        "B bound in C",
        () => plugin.side.controlSettled(chainC.state.seq + 1n),
        30_000,
      );
      await commit(plugin.side, [
        {
          intent: "approval.create",
          approval: {
            role: "base",
            resource: toBase64url(C),
            principal: ref(idOf(B)),
            certDigest: toBase64url(certB.leaf.payloadDigest),
            certId: toBase64url(certB.leaf.id),
            generation: 0,
            origin: "attempt-1",
            at: T0,
          },
        },
      ]);
      const bridge = controlSide(url, C, P, B, "service-device");
      sides.push(bridge.side);
      bridge.side.start();
      await waitFor(
        "B sees its approval",
        () => bridge.profile.state().approvals[ref(idOf(B))] !== undefined,
        30_000,
      );

      const port = serviceControlPort({
        client: plugin.side.client,
        profile: plugin.profile,
        resource: C,
        synchronised: () => plugin.side.client.resourceState(C) === "LIVE",
      });
      const order: string[] = [];

      const boundaries = ["A1", "A2", "A3", "A4"] as const;
      for (const [i, boundary] of boundaries.entries()) {
        const X = (sections[i] as { resource: ResourceId }).resource;
        const label = (r: ResourceId) =>
          toHex(r) === toHex(I) ? "I" : toHex(r) === toHex(X) ? "X" : "?";
        const D = installation(70 + i);
        const s = await createPairingSession(P);
        if (s.kind !== "created") throw new Error(`${boundary} session: ${JSON.stringify(s)}`);
        const rid = uid(i + 1);
        await commit(plugin.side, [
          {
            intent: "request.create",
            rid,
            request: {
              op: "pair-section",
              binding: toBase64url(X),
              generation: 1,
              args: { link: s.link.reveal() },
              client: { app: "0.8.0", protocol: 1 },
              at: T0,
            },
          },
        ]);
        const req = await requestPairing({
          ...D,
          link: s.link,
          label: `Reminders · X${i + 1}`,
          kind: 1,
          scope: [X],
        });
        if (req.kind !== "requested")
          throw new Error(`${boundary} request: ${JSON.stringify(req)}`);
        await waitFor(
          `${boundary}: B sees requests[rid]`,
          () => bridge.profile.state().requests[rid] !== undefined,
          30_000,
        );
        await commit(bridge.side, [
          {
            intent: "pairing.create",
            rid,
            pairing: {
              descriptor: toBase64url(encodePrincipalDescriptor(D.installation.signer.descriptor)),
              principal: ref(idOf(D)),
              fp: deviceFingerprint(idOf(D)),
            },
          },
          { intent: "event.put", id: rid, state: "request-ready", at: T0 },
        ]);
        await waitFor(
          `${boundary}: P sees pairing[rid]`,
          () => plugin.profile.state().pairing[rid] !== undefined,
          30_000,
        );

        // The first run loses the boundary's answer.
        const lose =
          boundary === "A1"
            ? (r: ResourceId, b: Uint8Array) => label(r) === "I" && type(b) === "DEVICE_REVOKE"
            : boundary === "A2"
              ? (r: ResourceId, b: Uint8Array) => label(r) === "I" && type(b) === "DEVICE_GRANT"
              : boundary === "A4"
                ? (r: ResourceId) => label(r) === "X"
                : () => false;
        // Every Control Record P sends, in one log with its writes to C.
        const tapped: IdentityNetwork = {
          connect: async (signer, u) => {
            const ch = await P.network.connect(signer, u);
            return new Proxy(ch, {
              get(target, key) {
                if (key === "putControl")
                  return async (...a: Parameters<IdentityChannel["putControl"]>) => {
                    order.push(`${boundary}:${label(a[0])}:${type(a[2])}`);
                    return target.putControl(...a);
                  };
                const v = Reflect.get(target, key) as unknown;
                return typeof v === "function" ? v.bind(target) : v;
              },
            });
          },
        };
        const loggingPort: ServiceControlPort = {
          ...port,
          state: () => port.state(),
          creatorsOf: (c, k) => port.creatorsOf(c, k),
          commit: async (intents, operation) => {
            order.push(
              `${boundary}:C:${(intents as ServiceControlIntent[]).map((x) => x.intent).join(",")}`,
            );
            return port.commit(intents, operation);
          },
        };
        const first = await autoApproveSection({
          ...P,
          network: losing(tapped, lose),
          session: s.session,
          rid,
          control: boundary === "A3" ? crashingAfterCommit(loggingPort) : loggingPort,
        }).catch((e: unknown) => ({ crashed: String(e) }));
        expect(first, boundary).not.toMatchObject({
          kind: "approval",
          approval: { kind: "approved", registrations: [{ status: "registered" }] },
        });

        // The next re-check (a push of I or C): until the approval is done.
        let result: SectionApprovalResult | undefined;
        const deadline = Date.now() + 60_000;
        while (Date.now() < deadline) {
          result = await autoApproveSection({
            ...P,
            network: tapped,
            session: s.session,
            rid,
            control: loggingPort,
          });
          if (result.kind === "approval" && result.approval.kind === "approved") break;
          await sleep(200);
        }
        if (result?.kind !== "approval" || result.approval.kind !== "approved")
          throw new Error(`${boundary}: ${JSON.stringify(result)}`);
        expect(
          result.approval.registrations.map((r) => r.status),
          boundary,
        ).toEqual(["registered"]);

        // One of each record.
        const chainI = await chainOf(P, url, I);
        const chainX = await chainOf(P, url, X);
        const isD = (r: (typeof chainI.records)[number]) =>
          r.body.type === "DEVICE_GRANT" &&
          toHex(r.body.chain.leaf.payload.device.principalId) === toHex(idOf(D));
        expect(
          chainI.records
            .filter(
              (r) =>
                r.body.type === "DEVICE_REVOKE" && toHex(r.body.device) === toHex(s.pairingDevice),
            )
            .map((r) => r.body.type === "DEVICE_REVOKE" && r.body.reason),
          boundary,
        ).toEqual([3n]);
        expect(chainI.records.filter(isD).length, boundary).toBe(1);
        expect(chainX.records.filter(isD).length, boundary).toBe(1);
        const approval = plugin.profile.state().approvals[ref(idOf(D))];
        expect(approval, boundary).toMatchObject({
          role: "section",
          resource: toBase64url(X),
          generation: 1,
          origin: rid,
          certDigest: toBase64url(result.approval.chain.leaf.payloadDigest),
          revoked: false,
        });
        expect(plugin.profile.replica.creatorsOf("approvals", ref(idOf(D))).length, boundary).toBe(
          1,
        );
        // A3 before A4.
        const a3 = order.findIndex((o) => o.startsWith(`${boundary}:C:approval.create`));
        const a4 = order.findIndex((o) => o === `${boundary}:X:DEVICE_GRANT`);
        expect(a3, boundary).toBeGreaterThanOrEqual(0);
        expect(a4, `${boundary} ${order.join(" ")}`).toBeGreaterThan(a3);
        const journal = new OperationJournal(P.storage);
        const op = (await journal.list({ kind: "pairing-approval" })).find(
          (o) => o.intent.session === s.session,
        );
        expect(op?.intent.approvedBy, boundary).toBe("pre-authorised");

        const done = await completePairing({ ...D, operation: req.operation });
        expect(done.kind === "approved" && done.candidates.map((c) => c.status), boundary).toEqual([
          "ready",
        ]);
        // The service completes the request (§8.1 step 4): the next pair-section may open (SC7).
        await commit(bridge.side, [{ intent: "event.put", id: rid, state: "applied", at: T0 }]);
        await waitFor(
          `${boundary}: P sees applied`,
          () => plugin.profile.state().events[rid]?.state === "applied",
          30_000,
        );
      }
      const refusals = sides.flatMap((x) => x.errors());
      expect(refusals).toEqual([]);
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? `${e.message}\n${e.stack}` : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    } finally {
      for (const s of sides) await s.stop();
      P.network.close?.();
    }
  }, 300_000);
});
