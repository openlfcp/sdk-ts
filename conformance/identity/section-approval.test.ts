// E-015 (A§4.3–4.4, SERVICE-CONTROL-PROFILE-01 §7.1, §8.1; IDENTITY-PROFILE-01
// §5.3 step 4, §9): a section installation paired through the control
// Resource C. The managing client P created J_X and wrote requests[rid];
// the bridge's section device D writes its kind-1 request in I as J_X and
// the base installation B writes pairing[rid]. P approves without the human
// in phases A1 consume, A2 grant, A3 approval record in C, A4 registration
// in X; a crash at each ACK boundary resumes without losing or doubling a
// phase. An established mismatch cancels J_X and writes cancels{mismatch};
// a cancel that finds the session consumed carries the phases on.
//
// The identity flows run on the client's MemoryCoordinator; C is a real
// ServiceControlReplica, admission included (control-port.ts). The client API
// is imported from its sources, as the MemoryCoordinator is (one
// IdentityUnavailable class).

import { type PrincipalId, type ResourceId, toBase64url, toHex } from "@openlfcp/core";
import {
  type ControlRecord,
  type ControlState,
  type DeviceCertificate,
  deviceFingerprint,
  encodePrincipalDescriptor,
  parseControlRecord,
} from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import {
  type ApprovalResult,
  approvePairing,
  autoApproveSection,
  type ControlRevocationCause,
  cancelPairing,
  completePairing,
  controlNames,
  controlRevocationTargets,
  createIdentityResource,
  createPairingSession,
  OperationJournal,
  type PairingRequestValue,
  pairingRequests,
  reconcileDevices,
  requestPairing,
  resumeApproval,
  SERVICE_CONTROL_PROFILE_ID,
  type SectionApprovalInput,
  type ServiceControlPort,
  sectionApprovalDecision,
} from "../../packages/client/src/index.js";
import type { Fault, UploadEvent } from "../../packages/client/test/identity/memory-coordinator.js";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { party, pid, URL } from "../../packages/client/test/identity/support.js";
import {
  addToRoster,
  hostResource,
  node,
  pair,
  world,
} from "../../packages/client/test/identity/world.js";
import { type CommitFault, T0, TestControl } from "./control-port.js";

const uid = (n: number) => `0196f2a0-0000-7000-8000-${String(n).padStart(12, "0")}`;
const ref = (p: PrincipalId) => `p:${toBase64url(p)}`;
const R = pid(1);
const BASE = pid(30);
const D_N = 7;
const D = pid(D_N);

async function setup(o: { readonly controlInRoster?: boolean; readonly archived?: boolean } = {}) {
  const w = await world(2);
  const [X, Y] = w.resources as unknown as [ResourceId, ResourceId];
  // C hosted and listed in the roster (§1), for the reconciliation order of §7.4.
  let hosted: ResourceId | undefined;
  if (o.controlInRoster === true) {
    const h = await hostResource(w.server, w.P, SERVICE_CONTROL_PROFILE_ID);
    // An archived entry stays in the roster (IDENTITY §4 rule 6).
    const entry = {
      ...h.entry,
      endpoints: [...h.entry.endpoints],
      ...(o.archived === true ? { archived: true } : {}),
    };
    await addToRoster(w.P, w.I, h.resource, entry);
    hosted = h.resource;
  }
  const control = new TestControl(R, hosted);
  // B, the base installation, approved by fingerprint before (A§4.1).
  control.write(R, "root", [
    {
      intent: "approval.create",
      approval: {
        role: "base",
        resource: toBase64url(control.resource),
        principal: ref(BASE),
        certDigest: toBase64url(new Uint8Array(32).fill(3)),
        certId: toBase64url(new Uint8Array(32).fill(4)),
        generation: 0,
        origin: "attempt-1",
        at: T0,
      },
    },
  ]);
  const s = await createPairingSession(w.P);
  if (s.kind !== "created") throw new Error(s.kind);
  const rid = uid(1);
  control.write(R, "root", [
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
  const bridge = node(w.server, party(D_N));
  // Every Control Record a coordinator accepts, by Resource, in one log with C's writes.
  const tap = (e: UploadEvent) => {
    if (e.op === "control") control.events.push(`${label(e.resource)}:${type(e.bytes)}`);
  };
  const label = (r: ResourceId) =>
    toHex(r) === toHex(w.I) ? "I" : toHex(r) === toHex(X) ? "X" : "Y";
  w.server.fault = (e) => {
    tap(e);
    return undefined;
  };
  const faultOn = (pred: (e: UploadEvent) => boolean, f: Fault) => {
    let fired = false;
    w.server.fault = (e) => {
      tap(e);
      if (!fired && pred(e)) {
        fired = true;
        return f;
      }
      return undefined;
    };
  };
  return { w, X, Y, control, s, rid, bridge, faultOn, label };
}
type T = Awaited<ReturnType<typeof setup>>;

function type(bytes: Uint8Array): string {
  const t = parseControlRecord(bytes).payload.controlType;
  return t === 9n ? "DEVICE_GRANT" : t === 10n ? "DEVICE_REVOKE" : String(t);
}

/** D writes its kind-1 request in I as J_X (§8.1 step 2). */
async function bridgeRequests(t: T, scope: readonly ResourceId[] = [t.X], kind: 0 | 1 = 1) {
  const r = await requestPairing({
    ...t.bridge,
    link: t.s.link,
    label: "Reminders · Groceries",
    kind,
    ...(kind === 1 ? { scope } : {}),
  });
  if (r.kind !== "requested") throw new Error(r.kind);
  return r;
}

/** B writes pairing[rid] with the descriptor it wrote in I, then request-ready. */
function servicePairs(t: T, who = D_N) {
  const descriptor = toBase64url(encodePrincipalDescriptor(party(who).signer.descriptor));
  t.control.write(BASE, "service-device", [
    {
      intent: "pairing.create",
      rid: t.rid,
      pairing: { descriptor, principal: ref(pid(who)), fp: deviceFingerprint(pid(who)) },
    },
    { intent: "event.put", id: t.rid, state: "request-ready", at: T0 },
  ]);
}

const approve = (t: T, port: ServiceControlPort) =>
  autoApproveSection({ ...t.w.P, session: t.s.session, rid: t.rid, control: port });

const records = (t: T, r: ResourceId): readonly ControlRecord[] => t.w.server.chain(r).records;
const consumes = (t: T) =>
  records(t, t.w.I).filter(
    (r) =>
      r.body.type === "DEVICE_REVOKE" &&
      toHex(r.body.device) === toHex(t.s.pairingDevice) &&
      r.body.reason === 3n,
  ).length;
const grantsOf = (t: T, r: ResourceId) =>
  records(t, r).filter(
    (x) =>
      x.body.type === "DEVICE_GRANT" &&
      toHex(x.body.chain.leaf.payload.device.principalId) === toHex(D),
  ).length;
const approvalWrites = (t: T) =>
  t.control.log.filter((l) => l.intents.includes("approval.create")).length;

/** The end state of every recovery: one of each phase, A3 before A4, D ready in X. */
async function expectOneOfEach(t: T, result: ApprovalResult) {
  if (result.kind !== "approved") throw new Error(JSON.stringify(result));
  expect(consumes(t)).toBe(1);
  expect(grantsOf(t, t.w.I)).toBe(1);
  expect(grantsOf(t, t.X)).toBe(1);
  expect(grantsOf(t, t.Y)).toBe(0);
  expect(approvalWrites(t)).toBe(1);
  const a = t.control.replica.validate().approvals[ref(D)];
  expect(a).toMatchObject({
    role: "section",
    resource: toBase64url(t.X),
    principal: ref(D),
    certDigest: toBase64url(result.chain.leaf.payloadDigest),
    certId: toBase64url(result.chain.leaf.id),
    generation: 1,
    origin: t.rid,
    revoked: false,
  });
  expect(t.control.replica.creatorsOf("approvals", ref(D)).map((c) => c.writerClass)).toEqual([
    "root",
  ]);
  // A3 precedes A4 (§7.1): the approval record before the grant in X.
  const a3 = t.control.events.indexOf("C:approval.create");
  const a4 = t.control.events.indexOf("X:DEVICE_GRANT");
  expect(a3).toBeGreaterThanOrEqual(0);
  expect(a4).toBeGreaterThan(a3);
  const op = (await new OperationJournal(t.w.P.storage).list({ kind: "pairing-approval" }))[0];
  expect(op?.intent.approvedBy).toBe("pre-authorised");
  expect(op?.intent.fingerprint).toBe(deviceFingerprint(D));
  expect(JSON.stringify(op)).not.toContain("lfcp://");
}

describe("section auto-approval through C (E-015, A§4.3–4.4)", { timeout: 120_000 }, () => {
  test("the push of I first, then pairing[rid]: waiting, then A1–A4 without the human", async () => {
    const t = await setup();
    const port = t.control.port(R, "root");
    expect(await approve(t, port)).toMatchObject({ kind: "waiting" });
    await bridgeRequests(t);
    expect(await approve(t, port)).toMatchObject({ kind: "waiting" });
    expect(consumes(t)).toBe(0);
    servicePairs(t);
    const r = await approve(t, port);
    if (r.kind !== "approval") throw new Error(JSON.stringify(r));
    await expectOneOfEach(t, r.approval);
    const done = await completePairing({ ...t.bridge, operation: (await bridgeOp(t)) as string });
    expect(done.kind === "approved" && done.candidates.map((c) => c.status)).toEqual(["ready"]);
  });

  test("pairing[rid] first, the request in I not yet delivered: waiting, never a mismatch", async () => {
    const t = await setup();
    const port = t.control.port(R, "root");
    servicePairs(t);
    expect(await approve(t, port)).toMatchObject({ kind: "waiting" });
    expect(t.control.replica.validate().cancels).toEqual({});
    await bridgeRequests(t);
    const r = await approve(t, port);
    if (r.kind !== "approval") throw new Error(JSON.stringify(r));
    await expectOneOfEach(t, r.approval);
  });

  test("C not synchronised: waiting; A3 not acknowledged yet: nothing registered (A4 waits)", async () => {
    const t = await setup();
    await bridgeRequests(t);
    servicePairs(t);
    t.control.synchronised = false;
    expect(await approve(t, t.control.port(R, "root"))).toMatchObject({ kind: "waiting" });
    t.control.synchronised = true;
    let fault: CommitFault = "queued";
    const port = t.control.port(R, "root", () => fault);
    const first = await approve(t, port);
    expect(first).toMatchObject({
      kind: "approval",
      approval: { kind: "approval-record-pending" },
    });
    expect(grantsOf(t, t.X)).toBe(0);
    fault = undefined;
    const again = await approve(t, port);
    if (again.kind !== "approval") throw new Error(JSON.stringify(again));
    await expectOneOfEach(t, again.approval);
  });
});

describe("a crash at each ACK boundary of A1–A4 (A§4.4, IDENTITY §9)", { timeout: 120_000 }, () => {
  const boundaries: {
    readonly name: string;
    readonly arm: (t: T) => (() => CommitFault) | undefined;
  }[] = [
    {
      name: "A1 consume",
      arm: (t) => {
        t.faultOn(
          (e) =>
            e.op === "control" && t.label(e.resource) === "I" && type(e.bytes) === "DEVICE_REVOKE",
          "drop-answer",
        );
        return undefined;
      },
    },
    {
      name: "A2 grant",
      arm: (t) => {
        t.faultOn(
          (e) =>
            e.op === "control" && t.label(e.resource) === "I" && type(e.bytes) === "DEVICE_GRANT",
          "drop-answer",
        );
        return undefined;
      },
    },
    {
      name: "A3 approval record",
      arm: () => {
        let crashed = false;
        return () => {
          if (crashed) return undefined;
          crashed = true;
          return "crash-after-commit";
        };
      },
    },
    {
      name: "A4 registration",
      arm: (t) => {
        t.faultOn((e) => e.op === "control" && t.label(e.resource) === "X", "drop-answer");
        return undefined;
      },
    },
  ];
  for (const b of boundaries)
    test(`${b.name}: the answer is lost, the next re-check recovers it, nothing twice`, async () => {
      const t = await setup();
      await bridgeRequests(t);
      servicePairs(t);
      const fault = b.arm(t);
      const port = t.control.port(R, "root", fault);
      // The crash: the call ends without its answer (or throws); the journal stays.
      const first = await approve(t, port).catch((e: unknown) => ({ crashed: String(e) }));
      expect(first).not.toMatchObject({
        kind: "approval",
        approval: { kind: "approved", registrations: [{ status: "registered" }] },
      });
      // A fresh client on the same storage: the next push or open re-checks.
      const restarted = { ...t.w.P, network: t.w.server.network() };
      const again = await autoApproveSection({
        ...restarted,
        session: t.s.session,
        rid: t.rid,
        control: port,
      });
      if (again.kind !== "approval") throw new Error(`${b.name}: ${JSON.stringify(again)}`);
      await expectOneOfEach(t, again.approval);
      expect(
        again.approval.kind === "approved" && again.approval.registrations.map((r) => r.status),
      ).toEqual(["registered"]);
    });

  test("a cancel that finds the session consumed carries the phases on (A§4.1)", async () => {
    const t = await setup();
    await bridgeRequests(t);
    servicePairs(t);
    t.faultOn(
      (e) => e.op === "control" && t.label(e.resource) === "I" && type(e.bytes) === "DEVICE_REVOKE",
      "drop-answer",
    );
    const port = t.control.port(R, "root");
    const first = await approve(t, port);
    expect(first).toMatchObject({ kind: "approval", approval: { kind: "unavailable" } });
    // The human (or the local deadline) cancels: the consume is already in I.
    const cancelled = await cancelPairing({ ...t.w.P, session: t.s.session });
    if (cancelled.kind !== "consumed" || cancelled.operation === undefined)
      throw new Error(JSON.stringify(cancelled));
    expect(
      records(t, t.w.I).filter((r) => r.body.type === "DEVICE_REVOKE" && r.body.reason === 0n),
    ).toEqual([]);
    const resumed = await resumeApproval({ ...t.w.P, control: port }, cancelled.operation);
    await expectOneOfEach(t, resumed);
  });
});

describe("an established mismatch cancels J_X with cancels{mismatch} (§8.1 step 3)", {
  timeout: 120_000,
}, () => {
  const cases: { name: string; run: (t: T) => Promise<void> }[] = [
    {
      name: "the descriptor in C differs from the request in I",
      run: async (t) => {
        await bridgeRequests(t);
        servicePairs(t, 8);
      },
    },
    {
      name: "the request asks for scope [X, Y]",
      run: async (t) => {
        await bridgeRequests(t, [t.X, t.Y]);
        servicePairs(t);
      },
    },
    {
      name: "the request asks for scope [Y]",
      run: async (t) => {
        await bridgeRequests(t, [t.Y]);
        servicePairs(t);
      },
    },
    {
      name: "a personal request (kind 0) with an equal descriptor",
      run: async (t) => {
        await bridgeRequests(t, [], 0);
        servicePairs(t);
      },
    },
  ];
  for (const c of cases)
    test(c.name, async () => {
      const t = await setup();
      await c.run(t);
      const r = await approve(t, t.control.port(R, "root"));
      expect(r).toMatchObject({
        kind: "cancelled",
        reason: "mismatch",
        written: { kind: "acknowledged" },
      });
      expect(consumes(t)).toBe(0);
      const cancel = records(t, t.w.I).filter(
        (x) => x.body.type === "DEVICE_REVOKE" && toHex(x.body.device) === toHex(t.s.pairingDevice),
      );
      expect(cancel.map((x) => x.body.type === "DEVICE_REVOKE" && x.body.reason)).toEqual([0n]);
      expect(t.control.replica.validate().cancels[t.rid]?.reason).toBe("mismatch");
      expect(approvalWrites(t)).toBe(0);
      // Re-checked after that: closed, nothing new is cancelled or written.
      expect(await approve(t, t.control.port(R, "root"))).toMatchObject({ kind: "cancelled" });
      expect(t.control.log.filter((l) => l.intents.includes("cancel.create")).length).toBe(1);
    });

  test("the local deadline passed while waiting: cancels{expired}", async () => {
    const t = await setup();
    await bridgeRequests(t);
    const r = await autoApproveSection({
      ...t.w.P,
      session: t.s.session,
      rid: t.rid,
      control: t.control.port(R, "root"),
      expired: true,
    });
    expect(r).toMatchObject({ kind: "cancelled", reason: "expired" });
    expect(t.control.replica.validate().cancels[t.rid]?.reason).toBe("expired");
    expect(consumes(t)).toBe(0);
  });

  test("another installation's session: not approved, nothing cancelled", async () => {
    const t = await setup();
    await bridgeRequests(t);
    servicePairs(t);
    const other = { ...node(t.w.server, party(1)), storage: t.w.P.storage };
    // The same root on another installation that did not write requests[rid]: its port writes as personal.
    const port = t.control.port(pid(2), "personal");
    const r = await autoApproveSection({
      ...other,
      session: "pairing-session:unknown",
      rid: t.rid,
      control: port,
    });
    expect(r).toMatchObject({ kind: "not-own" });
    expect(consumes(t)).toBe(0);
    expect(t.control.replica.validate().cancels).toEqual({});
  });
});

async function bridgeOp(t: T) {
  return (await new OperationJournal(t.bridge.storage).list({ kind: "pairing-request" }))[0]?.id;
}

describe("revocation through C only by approval records (R2-1, §7.2, A§5.3)", {
  timeout: 120_000,
}, () => {
  /** D approved for X at generation 1; a personal device A; S, another bridge's section device for Y. */
  async function approved() {
    const t = await setup();
    await bridgeRequests(t);
    servicePairs(t);
    const r = await approve(t, t.control.port(R, "root"));
    if (r.kind !== "approval" || r.approval.kind !== "approved") throw new Error(JSON.stringify(r));
    const A = await pair(t.w, t.w.P, 2, "full");
    const S = await pair(t.w, t.w.P, 40, "service", { kind: 1, scope: [t.Y] });
    // S's approval lives in the other bridge's C.
    const otherC = new TestControl(R);
    const sLeaf = t.w.server.chain(t.w.I).state.devices.get(toHex(pid(40)))?.chain?.leaf;
    otherC.write(R, "root", [
      { intent: "approval.create", approval: forged(pid(40), t.Y, sLeaf?.payloadDigest) },
    ]);
    return { t, A, S, I: () => t.w.server.chain(t.w.I).state };
  }
  const forged = (P: PrincipalId, X: ResourceId, digest?: Uint8Array, generation = 1) => ({
    role: "section" as const,
    resource: toBase64url(X),
    principal: ref(P),
    certDigest: toBase64url(digest ?? new Uint8Array(32).fill(9)),
    certId: toBase64url(new Uint8Array(32).fill(8)),
    generation,
    origin: uid(99),
    at: T0,
  });
  const lifecycle = (t: T, bindings: { binding: string; generation: number }[], op = "remove") =>
    t.control.write(BASE, "service-device", [
      { intent: "lifecycle.put", fields: { op, bindings, at: T0 } },
    ]);
  const targets = (t: T, I: ControlState, cause: ControlRevocationCause) =>
    controlRevocationTargets({ root: R, identity: I, control: t.control.port(R, "root"), cause });

  test("lifecycle names {X, 1}: only D, whose approval this C holds", async () => {
    const { t, I } = await approved();
    lifecycle(t, [{ binding: toBase64url(t.X), generation: 1 }]);
    const r = targets(t, I(), { kind: "lifecycle" });
    expect(r.targets.map(ref)).toEqual([ref(D)]);
    expect(targets(t, I(), { kind: "human", principal: D }).targets.map(ref)).toEqual([ref(D)]);
  });

  test("a personal device, a pairing device, another bridge's installation, a stale generation, another root, a 0.5 installation: nothing", async () => {
    const { t, A, S, I } = await approved();
    const a = A.installation.signer.descriptor.principalId;
    const aLeaf = I().devices.get(toHex(a))?.chain?.leaf;
    // Approvals the root wrote for what must never be revoked through C.
    t.control.write(R, "root", [
      { intent: "approval.create", approval: forged(a, t.X, aLeaf?.payloadDigest) },
      { intent: "approval.create", approval: forged(t.s.pairingDevice, t.X) },
      { intent: "approval.create", approval: forged(pid(50), t.X) },
    ]);
    // Forged binding fields name A; lifecycle names X at a stale generation.
    t.control.write(BASE, "service-device", [
      {
        intent: "binding.put",
        binding: toBase64url(t.X),
        fields: {
          state: "on",
          generation: 2,
          list: "Groceries",
          filter: "all",
          pending: { toApple: 0, toLfcp: 0 },
          refused: 0,
          unconfirmed: 0,
          principal: ref(a),
        },
      },
    ]);
    lifecycle(t, [{ binding: toBase64url(t.X), generation: 2 }]);
    expect(targets(t, I(), { kind: "lifecycle" })).toEqual({ targets: [], refused: [] });
    // Another bridge's section (its approval is in the other C) and a 0.5 installation alike.
    lifecycle(t, [{ binding: toBase64url(t.Y), generation: 1 }]);
    expect(targets(t, I(), { kind: "lifecycle" }).targets).toEqual([]);
    const s = S.installation.signer.descriptor.principalId;
    expect(targets(t, I(), { kind: "human", principal: s })).toEqual({
      targets: [],
      refused: [{ principal: ref(s), reason: "C holds no approval for it" }],
    });
    // Named one by one, each fails its own condition of §7.2.
    const why = (P: PrincipalId) =>
      targets(t, I(), { kind: "human", principal: P }).refused[0]?.reason;
    expect(why(a)).toBe("not a service device (kind 1)");
    expect(why(t.s.pairingDevice)).toBe("not a service device (kind 1)");
    expect(why(pid(50))).toBe("not bound in I");
    // The same X at generation 1 still names D alone: the forged approvals are refused.
    lifecycle(t, [{ binding: toBase64url(t.X), generation: 1 }]);
    const r = targets(t, I(), { kind: "lifecycle" });
    expect(r.targets.map(ref)).toEqual([ref(D)]);
    expect(r.refused.map((x) => x.principal).sort()).toEqual(
      [ref(a), ref(t.s.pairingDevice), ref(pid(50))].sort(),
    );
  });

  test("the cascade check: a service that issued a certificate is not revoked through C", async () => {
    const { t, I } = await approved();
    const state = I();
    const devices = new Map(state.devices);
    const [k, other] = [...devices].find(([key]) => key !== toHex(D) && key !== toHex(R)) ?? [];
    if (k === undefined || other === undefined) throw new Error("no other device");
    devices.set(k, { ...other, issuers: [D] });
    const r = targets(t, { ...state, devices } as ControlState, { kind: "human", principal: D });
    expect(r).toEqual({
      targets: [],
      refused: [{ principal: ref(D), reason: "it has issued a certificate" }],
    });
    // Revoking D touches no other device: no device of I was issued by D.
    expect(
      [...state.devices.values()].some((d) => d.issuers.some((e) => toHex(e) === toHex(D))),
    ).toBe(false);
  });

  test("uninstall names every approval of this C without revoked, the base last", async () => {
    const { t, I } = await approved();
    lifecycle(t, [], "uninstall");
    const r = targets(t, I(), { kind: "lifecycle" });
    // B of this test world is not a device of I: its base approval is refused, D stays.
    expect(r.targets.map(ref)).toEqual([ref(D)]);
    expect(r.refused).toEqual([{ principal: ref(BASE), reason: "not bound in I" }]);
    t.control.write(R, "root", [{ intent: "approval.revoke", principal: ref(D), at: T0 }]);
    expect(targets(t, I(), { kind: "lifecycle" }).targets).toEqual([]);
  });
});

describe("sectionApprovalDecision: every substitution of §5.3 step 4 (T§3)", {
  timeout: 60_000,
}, () => {
  async function facts() {
    const t = await setup();
    const J = t.s.pairingDevice;
    const descriptor = toBase64url(encodePrincipalDescriptor(party(D_N).signer.descriptor));
    const entry: PairingRequestValue = {
      descriptor,
      pairing: ref(J),
      label: "Reminders · Groceries",
      kind: 1 as 0 | 1,
      scope: [toBase64url(t.X)] as readonly string[],
    };
    const input: SectionApprovalInput = {
      root: R,
      identity: t.w.server.chain(t.w.I).state,
      pairingDevice: J,
      ownSession: true,
      binding: t.X,
      requests: [{ key: ref(D), entry, signers: [J] }],
      pairing: {
        descriptor,
        principal: ref(D),
        creators: [{ signer: BASE, writerClass: "service" }],
      },
    };
    return { t, input, entry };
  }

  test("each substitution is a mismatch, a wait, or not this installation's", async () => {
    const { t, input, entry } = await facts();
    const pairing = input.pairing as NonNullable<SectionApprovalInput["pairing"]>;
    const kind = (patch: Partial<SectionApprovalInput>) =>
      sectionApprovalDecision({ ...input, ...patch }).kind;
    const withEntry = (e: Partial<PairingRequestValue>, signers = [input.pairingDevice]) =>
      kind({ requests: [{ key: ref(D), entry: { ...entry, ...e }, signers }] });
    const withCreators = (writerClass: "root" | "personal" | "other") =>
      kind({
        pairing: { ...pairing, creators: [{ signer: pid(60), writerClass }] },
      });
    expect(kind({})).toBe("approve");
    // A missing record is never a mismatch.
    expect(kind({ requests: [] })).toBe("wait");
    const { pairing: _p, ...noPairing } = input;
    expect(sectionApprovalDecision(noPairing).kind).toBe("wait");
    // An entry naming J but signed by another writer (OWNER) is ignored: still waiting.
    expect(withEntry({}, [R])).toBe("wait");
    expect(withEntry({}, [input.pairingDevice, R])).toBe("wait");
    // The descriptor, the scope, the kind.
    expect(
      withEntry({ descriptor: toBase64url(encodePrincipalDescriptor(party(8).signer.descriptor)) }),
    ).toBe("mismatch");
    expect(withEntry({ scope: [toBase64url(t.X), toBase64url(t.Y)] })).toBe("mismatch");
    expect(withEntry({ scope: [toBase64url(t.Y)] })).toBe("mismatch");
    expect(withEntry({ scope: [toBase64url(t.X), toBase64url(t.w.I)] })).toBe("mismatch");
    expect(withEntry({ kind: 0, scope: [] })).toBe("mismatch");
    // pairing[rid] not admitted from the service class: a section installation, a
    // pairing device (kind 2), another root's Principal are all of class `other`.
    expect(withCreators("other")).toBe("mismatch");
    expect(withCreators("personal")).toBe("mismatch");
    expect(kind({ pairing: { ...pairing, creators: [] } })).toBe("mismatch");
    expect(kind({ pairing: { ...pairing, principal: ref(pid(8)) } })).toBe("mismatch");
    // Two requests written by J.
    expect(
      kind({
        requests: [
          ...input.requests,
          {
            key: ref(pid(8)),
            entry: {
              ...entry,
              descriptor: toBase64url(encodePrincipalDescriptor(party(8).signer.descriptor)),
            },
            signers: [input.pairingDevice],
          },
        ],
      }),
    ).toBe("mismatch");
    // Another installation's J_X: left to the one that created it.
    expect(kind({ ownSession: false })).toBe("not-own");
  });

  test("J_X already cancelled: closed, nothing approved or cancelled again", async () => {
    const { t, input } = await facts();
    const c = await cancelPairing({ ...t.w.P, session: t.s.session });
    expect(c.kind).toBe("cancelled");
    expect(sectionApprovalDecision({ ...input, identity: t.w.server.chain(t.w.I).state })).toEqual({
      kind: "closed",
      consumed: false,
    });
  });
});

describe("the base installation's approval record (A§4.1, §7.1)", { timeout: 60_000 }, () => {
  test("approved by the human with scope [C]: A3 writes role base, generation 0, origin attemptId", async () => {
    // C hosted and listed in the roster, so the base installation may ask for it (§5.3 step 3).
    const server = new MemoryCoordinator();
    const P = node(server, party(1));
    const hosted = await hostResource(server, P, "org.openlfcp.service-control.v1");
    const created = await createIdentityResource({
      ...P,
      url: URL,
      label: "laptop",
      roster: [hosted],
    });
    if (created.kind !== "created") throw new Error(created.kind);
    const w = { server, P };
    const control = new TestControl(R, hosted.resource);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    const base = node(w.server, party(31));
    const req = await requestPairing({
      ...base,
      link: s.link,
      label: "MacBook Air",
      kind: 1,
      scope: [control.resource],
    });
    if (req.kind !== "requested") throw new Error(req.kind);
    const [review] = await pairingRequests({ ...w.P, session: s.session });
    if (review === undefined) throw new Error("no request");
    const port = control.port(R, "root");
    // A section role on a base scope, or a base generation, is refused before anything is signed.
    expect(
      await approvePairing({
        ...w.P,
        review,
        preset: "service",
        control: port,
        approvalRecord: { role: "base", origin: "attempt-1", generation: 1 },
      }),
    ).toMatchObject({ kind: "infeasible" });
    const r = await approvePairing({
      ...w.P,
      review,
      preset: "service",
      control: port,
      approvalRecord: { role: "base", origin: "attempt-1" },
    });
    if (r.kind !== "approved") throw new Error(JSON.stringify(r));
    expect(control.replica.validate().approvals[ref(pid(31))]).toMatchObject({
      role: "base",
      resource: toBase64url(control.resource),
      generation: 0,
      origin: "attempt-1",
      certDigest: toBase64url(r.chain.leaf.payloadDigest),
    });
    const op = (await new OperationJournal(w.P.storage).list({ kind: "pairing-approval" }))[0];
    expect(op?.intent.approvedBy).toBe("human");
    expect(op?.intent.fingerprint).toBe(deviceFingerprint(pid(31)));
  });
});

describe("a cancel interrupted at each step is finished from the journal (A§4.3, §8.2)", {
  timeout: 120_000,
}, () => {
  const cancelsOf = (t: T) =>
    t.control.log.filter((l) => l.intents.includes("cancel.create")).length;
  const revokes0 = (t: T) =>
    records(t, t.w.I).filter(
      (x) =>
        x.body.type === "DEVICE_REVOKE" &&
        toHex(x.body.device) === toHex(t.s.pairingDevice) &&
        x.body.reason === 0n,
    ).length;

  test("the answer to J's revocation is lost: the next re-check rotates I and writes cancels{mismatch}", async () => {
    const t = await setup();
    await bridgeRequests(t, [t.Y]);
    servicePairs(t);
    t.faultOn(
      (e) => e.op === "control" && t.label(e.resource) === "I" && type(e.bytes) === "DEVICE_REVOKE",
      "drop-answer",
    );
    const port = t.control.port(R, "root");
    expect(await approve(t, port)).toMatchObject({ kind: "unavailable" });
    // The server revoked J; the client never heard it, and C holds no cancel yet.
    expect(revokes0(t)).toBe(1);
    expect(t.control.replica.validate().cancels).toEqual({});
    const journal = await new OperationJournal(t.w.P.storage).load(t.s.session);
    expect(journal.intent.cancelReason).toBe("mismatch");
    const r = await approve(t, port);
    expect(r).toMatchObject({
      kind: "cancelled",
      reason: "mismatch",
      cancel: { kind: "cancelled", rotation: { status: "rotated" } },
      written: { kind: "acknowledged" },
    });
    expect(revokes0(t)).toBe(1);
    expect(records(t, t.w.I).at(-1)?.body.type).toBe("KEY_EPOCH");
    expect(t.control.replica.validate().cancels[t.rid]?.reason).toBe("mismatch");
    expect(cancelsOf(t)).toBe(1);
    expect(consumes(t)).toBe(0);
  });

  test("a crash after J is cancelled, before cancels[rid] is written: written by the next re-check", async () => {
    const t = await setup();
    await bridgeRequests(t);
    servicePairs(t, 8);
    let fault: CommitFault = "crash-before-commit";
    const port = t.control.port(R, "root", () => fault);
    await expect(approve(t, port)).rejects.toThrow("crashed before the commit");
    expect(revokes0(t)).toBe(1);
    expect(t.control.replica.validate().cancels).toEqual({});
    fault = undefined;
    expect(await approve(t, port)).toMatchObject({
      kind: "cancelled",
      reason: "mismatch",
      written: { kind: "acknowledged" },
    });
    expect(revokes0(t)).toBe(1);
    expect(cancelsOf(t)).toBe(1);
    // Re-checked once more: the same operation, nothing new.
    await approve(t, port);
    expect(cancelsOf(t)).toBe(1);
  });

  test("a queued cancels[rid] is committed again under the same operation until acknowledged", async () => {
    const t = await setup();
    await bridgeRequests(t);
    servicePairs(t, 8);
    let fault: CommitFault = "queued";
    const port = t.control.port(R, "root", () => fault);
    expect(await approve(t, port)).toMatchObject({
      kind: "cancelled",
      written: { kind: "queued" },
    });
    fault = undefined;
    expect(await approve(t, port)).toMatchObject({
      kind: "cancelled",
      written: { kind: "acknowledged" },
    });
    expect(cancelsOf(t)).toBe(1);
  });
});

describe("the reconciliation order of a client that implements the profile (§7.4)", {
  timeout: 120_000,
}, () => {
  /** D consumed and bound in I (A1, A2), A3 not written: C was not synchronised for it. */
  async function boundWithoutApproval(o: { readonly archived?: boolean } = {}) {
    const t = await setup({ controlInRoster: true, ...o });
    await bridgeRequests(t);
    servicePairs(t);
    const [review] = await pairingRequests({ ...t.w.P, session: t.s.session });
    if (review === undefined) throw new Error("no request");
    const port = t.control.port(R, "root");
    const r = await approvePairing({
      ...t.w.P,
      review,
      preset: "service",
      scope: [t.X],
      control: { ...port, state: () => undefined },
      approvalRecord: { role: "section", origin: t.rid, generation: 1 },
    });
    expect(r.kind).toBe("approval-record-pending");
    expect(grantsOf(t, t.X)).toBe(0);
    return { t, port };
  }
  type View = Pick<ServiceControlPort, "state" | "requestHistory" | "acknowledged">;
  const reconcile = (
    t: T,
    view: (r: ResourceId) => View | undefined,
    only?: readonly ResourceId[],
  ) =>
    reconcileDevices({ ...t.w.P, controlResources: view, ...(only === undefined ? {} : { only }) });
  const viewOf = (t: T, port: View) => (r: ResourceId) =>
    toHex(r) === toHex(t.control.resource) ? port : undefined;
  const forX = (t: T, r: Awaited<ReturnType<typeof reconcileDevices>>) =>
    r.targets.find((x) => toHex(x.resource) === toHex(t.X));
  const deferredIn = (t: T, r: Awaited<ReturnType<typeof reconcileDevices>>) =>
    forX(t, r)?.deferred?.map((d) => ref(d.device));
  const reasonsIn = (t: T, r: Awaited<ReturnType<typeof reconcileDevices>>) =>
    forX(t, r)?.deferred?.map((d) => d.reason);
  const names = (t: T, port: Pick<ServiceControlPort, "requestHistory">, I = chainI(t)) => [
    ...controlNames(I, t.control.resource, port.requestHistory()),
  ];
  const chainI = (t: T) => t.w.server.chain(t.w.I);
  const noApproval = (t: T) =>
    `the control Resource ${toHex(t.control.resource)} names it and holds no approval for it yet`;
  /** The approval A3 would have written, by another managing client (here: the root, by hand). */
  function writeApproval(t: T) {
    const leaf = chainI(t).state.devices.get(toHex(D))?.chain?.leaf;
    if (leaf === undefined) throw new Error("D is not bound in I");
    t.control.write(R, "root", [
      {
        intent: "approval.create",
        approval: {
          role: "section",
          resource: toBase64url(t.X),
          principal: ref(D),
          certDigest: toBase64url(leaf.payloadDigest),
          certId: toBase64url(leaf.id),
          generation: 1,
          origin: t.rid,
          at: T0,
        },
      },
    ]);
  }

  test("C names D without an approval: deferred; once approvals[D] is present: registered", async () => {
    const { t, port } = await boundWithoutApproval();
    expect(names(t, port)).toEqual([toHex(D)]);
    const first = await reconcile(t, viewOf(t, port));
    expect(deferredIn(t, first)).toEqual([ref(D)]);
    expect(reasonsIn(t, first)).toEqual([noApproval(t)]);
    expect(grantsOf(t, t.X)).toBe(0);
    writeApproval(t);
    const second = await reconcile(t, viewOf(t, port));
    expect(forX(t, second)?.deferred).toBeUndefined();
    expect(grantsOf(t, t.X)).toBe(1);
  });

  test("a control Resource not synchronised, or not open here: every kind-1 registration waits", async () => {
    const { t, port } = await boundWithoutApproval();
    t.control.synchronised = false;
    const r = await reconcile(t, () => port);
    expect(forX(t, r)?.deferred?.map((d) => [ref(d.device), d.reason])).toEqual([
      [ref(D), `the control Resource ${toHex(t.control.resource)} is not synchronised`],
    ]);
    t.control.synchronised = true;
    const closed = await reconcile(t, () => undefined);
    expect(deferredIn(t, closed)).toEqual([ref(D)]);
    expect(grantsOf(t, t.X)).toBe(0);
  });

  test("without controlResources (a client that does not implement the profile) D is registered", async () => {
    const { t } = await boundWithoutApproval();
    const r = await reconcileDevices(t.w.P);
    expect(forX(t, r)?.deferred).toBeUndefined();
    expect(grantsOf(t, t.X)).toBe(1);
  });

  // R1: every control Resource of the roster, archived or not, whatever `only` selects.
  test("an archived C still gates: not open, D waits; synchronised and naming D without an approval, D waits", async () => {
    const { t, port } = await boundWithoutApproval({ archived: true });
    const closed = await reconcile(t, () => undefined);
    expect(reasonsIn(t, closed)).toEqual([
      `the control Resource ${toHex(t.control.resource)} is not synchronised`,
    ]);
    const open = await reconcile(t, viewOf(t, port));
    expect(reasonsIn(t, open)).toEqual([noApproval(t)]);
    expect(grantsOf(t, t.X)).toBe(0);
    writeApproval(t);
    expect(forX(t, await reconcile(t, viewOf(t, port)))?.deferred).toBeUndefined();
    expect(grantsOf(t, t.X)).toBe(1);
  });

  test("`only` without C reconciles X alone, and C still gates D's registration there", async () => {
    const { t, port } = await boundWithoutApproval();
    const r = await reconcile(t, viewOf(t, port), [t.X]);
    expect(r.targets.map((x) => toHex(x.resource))).toEqual([toHex(t.X)]);
    expect(reasonsIn(t, r)).toEqual([noApproval(t)]);
    const closed = await reconcile(t, () => undefined, [t.X]);
    expect(deferredIn(t, closed)).toEqual([ref(D)]);
    expect(grantsOf(t, t.X)).toBe(0);
  });

  // R2: the requests of C's history, by their creator; the Principal from I's chain only.
  test("A3 missing, the service writes a final failed and deletes requests[rid]: D still waits", async () => {
    const { t, port } = await boundWithoutApproval();
    t.control.write(BASE, "service-device", [
      { intent: "event.put", id: t.rid, state: "failed", code: "not_permitted", at: T0 },
    ]);
    t.control.write(BASE, "service-device", [
      { intent: "delete", container: "requests", key: t.rid },
    ]);
    const state = t.control.replica.validate();
    expect(state.requests[t.rid]).toBeUndefined();
    expect(state.pairing[t.rid]?.principal).toBe(ref(D));
    expect(port.requestHistory().map((h) => [h.rid, h.present])).toEqual([[t.rid, false]]);
    expect(names(t, port)).toEqual([toHex(D)]);
    const r = await reconcile(t, viewOf(t, port));
    expect(reasonsIn(t, r)).toEqual([noApproval(t)]);
    expect(grantsOf(t, t.X)).toBe(0);
  });

  test("a request not created by root or personal names nothing: D is registered", async () => {
    const { t, port } = await boundWithoutApproval();
    for (const writerClass of ["service", "other"] as const) {
      const forged: View = {
        ...port,
        requestHistory: () =>
          port
            .requestHistory()
            .map((h) => ({ ...h, creators: h.creators.map((c) => ({ ...c, writerClass })) })),
      };
      expect(names(t, forged), writerClass).toEqual([]);
    }
    const forged: View = {
      ...port,
      requestHistory: () =>
        port.requestHistory().map((h) => ({
          ...h,
          creators: h.creators.map((c) => ({ ...c, writerClass: "service" as const })),
        })),
    };
    const r = await reconcile(t, viewOf(t, forged));
    expect(forX(t, r)?.deferred).toBeUndefined();
    expect(grantsOf(t, t.X)).toBe(1);
  });

  test("pairing[rid] naming a device the chain does not prove for rid defers nothing (ignored)", async () => {
    const t = await setup({ controlInRoster: true });
    // D pairs through another session J2, which no request of C names; pairing[rid] (whose
    // request links the J of t.s, never consumed) names D all the same.
    const s2 = await createPairingSession(t.w.P);
    if (s2.kind !== "created") throw new Error(s2.kind);
    const asked = await requestPairing({
      ...t.bridge,
      link: s2.link,
      label: "Reminders · Groceries",
      kind: 1,
      scope: [t.X],
    });
    if (asked.kind !== "requested") throw new Error(asked.kind);
    servicePairs(t);
    const [review] = await pairingRequests({ ...t.w.P, session: s2.session });
    if (review === undefined) throw new Error("no request");
    const port = t.control.port(R, "root");
    const r = await approvePairing({
      ...t.w.P,
      review,
      preset: "service",
      scope: [t.X],
      control: { ...port, state: () => undefined },
      approvalRecord: { role: "section", origin: t.rid, generation: 1 },
    });
    expect(r.kind).toBe("approval-record-pending");
    expect(t.control.replica.validate().pairing[t.rid]?.principal).toBe(ref(D));
    expect(chainI(t).state.devices.has(toHex(D))).toBe(true);
    expect(names(t, port)).toEqual([]);
    const done = await reconcile(t, viewOf(t, port));
    expect(forX(t, done)?.deferred).toBeUndefined();
    expect(grantsOf(t, t.X)).toBe(1);
  });

  // R3: A3 counts once the server accepted it.
  test("this client's A3 queued: D deferred, no DEVICE_GRANT in X; once acknowledged: registered", async () => {
    const t = await setup({ controlInRoster: true });
    await bridgeRequests(t);
    servicePairs(t);
    const port = t.control.port(R, "root", () => "queued");
    expect(await approve(t, port)).toMatchObject({
      kind: "approval",
      approval: { kind: "approval-record-pending" },
    });
    // Present in this client's state, not accepted by the coordinator.
    expect(t.control.replica.validate().approvals[ref(D)]).toBeDefined();
    expect(await port.acknowledged("approvals", ref(D))).toBe(false);
    const queued = await reconcile(t, viewOf(t, port));
    expect(reasonsIn(t, queued)).toEqual([
      `the control Resource ${toHex(t.control.resource)} names it and its approval for it is not accepted by the server yet`,
    ]);
    expect(grantsOf(t, t.X)).toBe(0);
    t.control.acknowledge();
    expect(await port.acknowledged("approvals", ref(D))).toBe(true);
    const acked = await reconcile(t, viewOf(t, port));
    expect(forX(t, acked)?.deferred).toBeUndefined();
    expect(grantsOf(t, t.X)).toBe(1);
  });

  // Conditions 2 and 3 of the Section rule, each broken in I's chain as the reconciler reads it.
  test("C does not name D when the chain breaks condition 2 or 3", async () => {
    const { t, port } = await boundWithoutApproval();
    const I = chainI(t);
    expect(names(t, port, I)).toEqual([toHex(D)]);
    const J = t.s.pairingDevice;
    type Leaf = DeviceCertificate;
    const withLeaf = (patch: (leaf: Leaf) => Leaf): typeof I => ({
      ...I,
      records: I.records.map((r) =>
        r.body.type === "DEVICE_GRANT" &&
        r.body.pairingDevice !== undefined &&
        r.body.pairingDevice !== null &&
        toHex(r.body.pairingDevice) === toHex(J)
          ? ({
              ...r,
              body: { ...r.body, chain: { ...r.body.chain, leaf: patch(r.body.chain.leaf) } },
            } as typeof r)
          : r,
      ),
    });
    const withConsume = (
      patch: (v: NonNullable<ReturnType<typeof I.state.revoked.get>>) => unknown,
    ): typeof I => ({
      ...I,
      state: {
        ...I.state,
        revoked: new Map(
          [...I.state.revoked].map(([k, v]) => [k, k.endsWith(toHex(J)) ? patch(v) : v]),
        ) as typeof I.state.revoked,
      },
    });
    const other = new Uint8Array(32).fill(0xee);
    const cases: [string, typeof I][] = [
      ["J revoked with reason 0, not consumed", withConsume((v) => ({ ...v, reason: 0n }))],
      ["the consume carries another digest", withConsume((v) => ({ ...v, approval: other }))],
      [
        "the granted leaf has another digest",
        withLeaf((l) => ({ ...l, payloadDigest: other as typeof l.payloadDigest })),
      ],
      [
        "scope is not [X]",
        withLeaf((l) => ({ ...l, payload: { ...l.payload, scope: [t.X, t.Y] } })),
      ],
      ["scope is [Y]", withLeaf((l) => ({ ...l, payload: { ...l.payload, scope: [t.Y] } }))],
      ["kind is not 1", withLeaf((l) => ({ ...l, payload: { ...l.payload, kind: 0 } }))],
      ["another mask", withLeaf((l) => ({ ...l, payload: { ...l.payload, mask: [1n] } }))],
      [
        "mask {1, 2, 3}",
        withLeaf((l) => ({ ...l, payload: { ...l.payload, mask: [1n, 2n, 3n] } })),
      ],
      [
        "another root",
        withLeaf((l) => ({
          ...l,
          payload: { ...l.payload, root: other as typeof l.payload.root },
        })),
      ],
    ];
    for (const [why, chain] of cases) expect(names(t, port, chain), why).toEqual([]);
    // Condition 1: the request's binding is not the granted scope, or it is not pair-section.
    for (const [why, patch] of [
      ["binding = Y", { binding: toBase64url(t.Y) }],
      ["op = preview", { op: "preview" }],
      ["a link without a pairing device", { args: { link: "lfcp-pair:nothing" } }],
    ] as const) {
      const history = port
        .requestHistory()
        .map((h) => ({ ...h, request: { ...h.request, ...patch } }));
      expect([...controlNames(I, t.control.resource, history)], why).toEqual([]);
    }
  });
});
