import type { PrincipalId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  deviceFingerprint,
  ServiceControlAdmissionError,
  type ServiceControlIntent,
  ServiceControlReplica,
  type ServiceControlSignerClass,
  type ServiceControlWriter,
  serviceControlCleanup,
} from "../src/service-control/index.js";
import {
  approval,
  B,
  personal,
  principalRef,
  request,
  resource,
  root,
  SERVICE,
  STATUS,
  serviceDevice,
  T0,
  uid,
  X,
} from "./support/service-control.js";

const options = { resource, root, genesisSigner: root };
const writer = (
  signer: PrincipalId,
  signerClass: ServiceControlSignerClass,
  actorSeq = 2,
): ServiceControlWriter => ({ signer, signerClass, actorSeq });
const R = writer(root, "root");
const P = writer(personal, "personal");
const S = writer(B, "service-device");
const PAUSED = { ...STATUS, state: "paused" };

/** C initialized by root, B's base approval written, B's first service and status. */
function ready(): ServiceControlReplica {
  const c = ServiceControlReplica.empty(options);
  c.write({ ...R, actorSeq: 1 }, [{ intent: "initialize", attemptId: "attempt-1", createdAt: T0 }]);
  c.write(R, [{ intent: "approval.create", approval: approval(B) as never }]);
  c.write(S, [
    { intent: "service.put", fields: SERVICE },
    { intent: "status.put", fields: STATUS },
  ]);
  return c;
}

const diagnosticOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    if (e instanceof ServiceControlAdmissionError) return e.diagnostic;
    throw e;
  }
  return "admitted";
};

const req = (rid: string, op = "turn-off", extra: Record<string, unknown> = {}) =>
  ({ intent: "request.create", rid, request: request(op, extra) }) as ServiceControlIntent;

describe("SERVICE-CONTROL-PROFILE-01 §3: writing C", () => {
  it("writes the initial change and the records of each writer class", () => {
    const c = ready();
    c.write(P, [req(uid(1))]);
    c.write(S, [
      { intent: "event.put", id: uid(1), state: "received", at: T0 },
      {
        intent: "binding.put",
        binding: X,
        fields: {
          state: "on",
          generation: 1,
          list: "Groceries",
          filter: "all",
          pending: { toApple: 0, toLfcp: 0 },
          refused: 0,
          unconfirmed: 0,
        },
      },
    ]);
    c.write(S, [{ intent: "event.put", id: uid(1), state: "executing", code: "network", at: T0 }]);
    c.write(S, [{ intent: "event.put", id: uid(1), state: "applied", at: T0 }]);
    const v = c.validate();
    expect(v.usable).toBe(true);
    expect(v.problems).toEqual([]);
    expect(v.requests[uid(1)]?.op).toBe("turn-off");
    // The retryable code does not outlive its state.
    expect(v.events[uid(1)]).toEqual({ state: "applied", at: T0 });
    expect(v.service?.label).toBe("MacBook Air");
    expect(v.status?.state).toBe("running");
    expect(v.bindings[X]?.state).toBe("on");
    expect(v.approvals[principalRef(B)]?.role).toBe("base");
  });

  it("answers a question, resolves it, and deletes both once settled", () => {
    const c = ready();
    const question = {
      binding: X,
      generation: 1,
      kind: "mass-delete",
      anomalyId: "a-1",
      snapshotHash: "h-1",
      items: ["Milk", "Eggs"],
      counts: { delete: 12 },
      options: ["accept", "keep"],
      at: T0,
    };
    c.write(S, [{ intent: "question.create", qid: uid(5), question }]);
    const answer = { qid: uid(5), snapshotHash: "h-1", choice: "accept", at: T0 };
    c.write(R, [{ intent: "answer.create", aid: uid(6), answer }]);
    // Not yet: the question holds neither resolved nor superseded.
    expect(
      diagnosticOf(() => c.write(S, [{ intent: "delete", container: "answers", key: uid(6) }])),
    ).toBe("FORBIDDEN_MUTATION");
    c.write(S, [
      { intent: "event.put", id: uid(6), state: "applied", at: T0 },
      {
        intent: "question.resolve",
        qid: uid(5),
        resolved: { answerId: uid(6), choice: "accept", at: T0 },
      },
    ]);
    c.write(S, [
      { intent: "delete", container: "answers", key: uid(6) },
      { intent: "delete", container: "events", key: uid(6) },
      { intent: "delete", container: "questions", key: uid(5) },
    ]);
    const v = c.validate();
    expect(Object.keys(v.questions)).toEqual([]);
    expect(Object.keys(v.answers)).toEqual([]);
    expect(Object.keys(v.events)).toEqual([]);
  });

  it("deletes a request with its event and cancel only once the event is final (§9)", () => {
    const c = ready();
    c.write(P, [req(uid(2))]);
    c.write(R, [{ intent: "cancel.create", rid: uid(2), cancel: { reason: "user", at: T0 } }]);
    const cleanup: ServiceControlIntent[] = [
      { intent: "delete", container: "requests", key: uid(2) },
      { intent: "delete", container: "cancels", key: uid(2) },
    ];
    expect(diagnosticOf(() => c.write(S, cleanup))).toBe("FORBIDDEN_MUTATION");
    c.write(S, [{ intent: "event.put", id: uid(2), state: "cancelled", at: T0 }]);
    c.write(S, [...cleanup, { intent: "delete", container: "events", key: uid(2) }]);
    const v = c.validate();
    expect([v.requests, v.cancels, v.events].map((m) => Object.keys(m).length)).toEqual([0, 0, 0]);
  });

  it("refuses a write outside the writer's row and leaves the replica as it was", () => {
    const c = ready();
    const heads = c.heads();
    expect(diagnosticOf(() => c.write(P, [{ intent: "status.put", fields: PAUSED }]))).toBe(
      "UNAUTHORIZED_WRITER",
    );
    expect(diagnosticOf(() => c.write(S, [req(uid(3))]))).toBe("FORBIDDEN_MUTATION");
    expect(
      diagnosticOf(() => c.write(writer(B, "other"), [{ intent: "status.put", fields: PAUSED }])),
    ).toBe("UNAUTHORIZED_WRITER");
    // Events only forward; nothing once final.
    c.write(P, [req(uid(4))]);
    c.write(S, [{ intent: "event.put", id: uid(4), state: "executing", at: T0 }]);
    expect(
      diagnosticOf(() =>
        c.write(S, [{ intent: "event.put", id: uid(4), state: "received", at: T0 }]),
      ),
    ).toBe("FORBIDDEN_MUTATION");
    expect(c.validate().events[uid(4)]?.state).toBe("executing");
    expect(c.heads()).not.toEqual(heads);
    // A refused write consumed nothing: the next one is admitted on the same heads.
    const before = c.heads();
    expect(diagnosticOf(() => c.write(P, [{ intent: "status.put", fields: PAUSED }]))).toBe(
      "UNAUTHORIZED_WRITER",
    );
    expect(c.heads()).toEqual(before);
    c.write(P, [req(uid(7))]);
  });
});

describe("SERVICE-CONTROL-PROFILE-01 §3: a write of the current values", () => {
  it("makes no change and nothing to send", () => {
    const c = ready();
    const heads = c.heads();
    expect(c.write(S, [{ intent: "status.put", fields: STATUS }])).toBeNull();
    expect(c.heads()).toEqual(heads);
    expect(c.write(S, [{ intent: "status.put", fields: PAUSED }])).not.toBeNull();
  });
});

describe("SERVICE-CONTROL-PROFILE-01 §4 sizes (A§3.2): records over their limits are refused", () => {
  it("refuses an entry over 4 KiB and a pairing entry over 8 KiB, and admits smaller ones", () => {
    const c = ready();
    expect(
      diagnosticOf(() => c.write(P, [req(uid(10), "check", { args: { note: "x".repeat(4096) } })])),
    ).toBe("LIMIT_EXCEEDED");
    expect(
      diagnosticOf(() =>
        c.write(S, [{ intent: "status.put", fields: { message: "m".repeat(4096) } }]),
      ),
    ).toBe("LIMIT_EXCEEDED");
    c.write(P, [req(uid(11), "check", { args: { note: "x".repeat(3000) } })]);
    c.write(P, [
      {
        intent: "request.create",
        rid: uid(12),
        request: request("pair-section", { args: { link: "l" } }),
      },
    ]);
    // An unknown field is admitted (§2.1) but counts towards the size.
    const pairing = (n: number) => ({
      intent: "pairing.create" as const,
      rid: uid(12),
      pairing: {
        descriptor: serviceDevice.text,
        principal: principalRef(B),
        fp: deviceFingerprint(B),
        note: "n".repeat(n),
      },
    });
    expect(diagnosticOf(() => c.write(S, [pairing(8192)]))).toBe("LIMIT_EXCEEDED");
    c.write(S, [pairing(6000)]);
    expect(c.validate().pairing[uid(12)]?.principal).toBe(principalRef(B));
  });

  it("refuses an Example over 80 characters and more than 5 items", () => {
    const c = ready();
    const question = (items: string[]) => ({
      intent: "question.create" as const,
      qid: uid(20),
      question: {
        binding: X,
        generation: 1,
        kind: "mass-delete",
        anomalyId: "a",
        snapshotHash: "h",
        items,
        counts: {},
        options: ["accept"],
        at: T0,
      },
    });
    expect(diagnosticOf(() => c.write(S, [question(["t".repeat(81)])]))).toBe("LIMIT_EXCEEDED");
    expect(diagnosticOf(() => c.write(S, [question(["a", "b", "c", "d", "e", "f"])]))).toBe(
      "LIMIT_EXCEEDED",
    );
    c.write(S, [question(["t".repeat(80), "b", "c", "d", "e"])]);
  });

  it("refuses a 33rd open request and a second open pair-section", () => {
    const c = ready();
    for (let n = 0; n < 31; n++) c.write(P, [req(uid(100 + n))]);
    c.write(P, [
      {
        intent: "request.create",
        rid: uid(200),
        request: request("pair-section", { args: { link: "l" } }),
      },
    ]);
    expect(diagnosticOf(() => c.write(P, [req(uid(201))]))).toBe("LIMIT_EXCEEDED");
    // A final event closes a request: there is room again.
    c.write(S, [{ intent: "event.put", id: uid(100), state: "applied", at: T0 }]);
    expect(
      diagnosticOf(() =>
        c.write(P, [
          {
            intent: "request.create",
            rid: uid(202),
            request: request("pair-section", { args: { link: "l" } }),
          },
        ]),
      ),
    ).toBe("LIMIT_EXCEEDED");
    c.write(P, [req(uid(203))]);
    expect(Object.keys(c.validate().requests)).toHaveLength(33);
  });
});

describe("SERVICE-CONTROL-PROFILE-01 §9: deletion for display", () => {
  const T8 = Date.parse(T0) + 8 * 24 * 60 * 60 * 1000;
  it("deletes what has been final for 7 days, each change admitted by §3", () => {
    const c = ready();
    c.write(P, [req(uid(30)), req(uid(31))]);
    c.write(R, [{ intent: "cancel.create", rid: uid(30), cancel: { reason: "user", at: T0 } }]);
    c.write(S, [
      { intent: "event.put", id: uid(30), state: "cancelled", at: T0 },
      { intent: "event.put", id: uid(31), state: "executing", at: T0 },
      {
        intent: "question.create",
        qid: uid(32),
        question: {
          binding: X,
          generation: 1,
          kind: "mass-delete",
          anomalyId: "a",
          snapshotHash: "h",
          items: [],
          counts: {},
          options: ["accept"],
          at: T0,
        },
      },
    ]);
    c.write(R, [
      {
        intent: "answer.create",
        aid: uid(33),
        answer: { qid: uid(32), snapshotHash: "h", choice: "accept", at: T0 },
      },
    ]);
    c.write(S, [
      { intent: "event.put", id: uid(33), state: "applied", at: T0 },
      {
        intent: "question.resolve",
        qid: uid(32),
        resolved: { answerId: uid(33), choice: "accept", at: T0 },
      },
    ]);
    expect(serviceControlCleanup(c.validate(), Date.parse(T0))).toEqual([]);
    const changes = serviceControlCleanup(c.validate(), T8);
    expect(changes).toHaveLength(2);
    for (const change of changes) c.write(S, change);
    const v = c.validate();
    expect(Object.keys(v.requests)).toEqual([uid(31)]);
    expect(Object.keys(v.events)).toEqual([uid(31)]);
    expect([v.cancels, v.questions, v.answers].map((m) => Object.keys(m).length)).toEqual([
      0, 0, 0,
    ]);
  });
});

describe("SERVICE-CONTROL-PROFILE-01 §9: 7 days from becoming final, not from creation", () => {
  const DAY = 24 * 60 * 60 * 1000;
  const at = (days: number) =>
    new Date(Date.parse(T0) + days * DAY).toISOString().replace(/\.\d{3}Z$/, "Z");
  const question = (qid: string) =>
    ({
      intent: "question.create",
      qid,
      question: {
        binding: X,
        generation: 1,
        kind: "mass-delete",
        anomalyId: "a",
        snapshotHash: "h",
        items: [],
        counts: {},
        options: ["accept"],
        at: at(0),
      },
    }) as ServiceControlIntent;
  const answer = (aid: string, qid: string, day: number) =>
    ({
      intent: "answer.create",
      aid,
      answer: { qid, snapshotHash: "h", choice: "accept", at: at(day) },
    }) as ServiceControlIntent;

  it("a question created on day 0 and superseded on day 18 stays until day 25", () => {
    const c = ready();
    c.write(S, [question(uid(40))]);
    c.write(S, [{ intent: "question.supersede", qid: uid(40), by: uid(41) }]);
    const now = Date.parse(at(18));
    // Without the service's record of when it superseded the question: kept.
    expect(serviceControlCleanup(c.validate(), now)).toEqual([]);
    const supersededAt = () => at(18);
    expect(serviceControlCleanup(c.validate(), now, { supersededAt })).toEqual([]);
    expect(serviceControlCleanup(c.validate(), Date.parse(at(24)), { supersededAt })).toEqual([]);
    const changes = serviceControlCleanup(c.validate(), Date.parse(at(25)), { supersededAt });
    expect(changes).toEqual([[{ intent: "delete", container: "questions", key: uid(40) }]]);
    for (const change of changes) c.write(S, change);
    expect(c.validate().questions).toEqual({});
  });

  it("a request created on day 0 and final on day 10 stays until day 17", () => {
    const c = ready();
    c.write(P, [req(uid(42))]);
    c.write(S, [{ intent: "event.put", id: uid(42), state: "applied", at: at(10) }]);
    expect(serviceControlCleanup(c.validate(), Date.parse(at(16)))).toEqual([]);
    expect(serviceControlCleanup(c.validate(), Date.parse(at(17)))).toHaveLength(1);
  });

  it("an answer without a final event holds its question until its own event is final (PB-33)", () => {
    const c = ready();
    c.write(S, [question(uid(46))]);
    c.write(R, [answer(uid(47), uid(46), 0)]);
    c.write(S, [
      { intent: "event.put", id: uid(47), state: "applied", at: at(0) },
      {
        intent: "question.resolve",
        qid: uid(46),
        resolved: { answerId: uid(47), choice: "accept", at: at(0) },
      },
    ]);
    // A second answer on day 1 the service has not handled yet: no event at all.
    c.write(R, [answer(uid(48), uid(46), 1)]);
    expect(serviceControlCleanup(c.validate(), Date.parse(at(30)))).toEqual([]);
    // Rejected on day 20: the question and both answers go 7 days later, not before.
    c.write(S, [
      { intent: "event.put", id: uid(48), state: "rejected", code: "already_answered", at: at(20) },
    ]);
    expect(serviceControlCleanup(c.validate(), Date.parse(at(26)))).toEqual([]);
    const changes = serviceControlCleanup(c.validate(), Date.parse(at(27)));
    expect(changes).toHaveLength(1);
    for (const change of changes) c.write(S, change);
    const v = c.validate();
    expect([v.questions, v.answers, v.events].map((m) => Object.keys(m).length)).toEqual([0, 0, 0]);
  });

  it("an old resolved question waits for a later answer to settle and age", () => {
    const c = ready();
    c.write(S, [question(uid(43))]);
    c.write(R, [answer(uid(44), uid(43), 0)]);
    c.write(S, [
      { intent: "event.put", id: uid(44), state: "applied", at: at(0) },
      {
        intent: "question.resolve",
        qid: uid(43),
        resolved: { answerId: uid(44), choice: "accept", at: at(0) },
      },
    ]);
    // A second answer on day 9, still being handled, then rejected on day 12.
    c.write(R, [answer(uid(45), uid(43), 9)]);
    c.write(S, [{ intent: "event.put", id: uid(45), state: "received", at: at(9) }]);
    expect(serviceControlCleanup(c.validate(), Date.parse(at(30)))).toEqual([]);
    c.write(S, [
      {
        intent: "event.put",
        id: uid(45),
        state: "rejected",
        code: "already_answered",
        at: at(12),
      },
    ]);
    expect(serviceControlCleanup(c.validate(), Date.parse(at(18)))).toEqual([]);
    const changes = serviceControlCleanup(c.validate(), Date.parse(at(19)));
    expect(changes).toHaveLength(1);
    for (const change of changes) c.write(S, change);
    const v = c.validate();
    expect([v.questions, v.answers, v.events].map((m) => Object.keys(m).length)).toEqual([0, 0, 0]);
  });
});
