import type * as A from "@automerge/automerge";
import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import {
  ServiceControlReplica,
  type ServiceControlSignerClass,
  type ServiceControlUnit,
  serviceControlCodecFor,
} from "../src/service-control/index.js";
import {
  approval,
  B,
  B2,
  type Doc,
  edit,
  initial,
  last,
  personal,
  principalRef,
  put,
  request,
  resource,
  root,
  SERVICE,
  STATUS,
  uid,
} from "./support/service-control.js";

const options = { resource, root, genesisSigner: root };
const unit = (
  doc: A.Doc<Doc>,
  signer: typeof root,
  signerClass: ServiceControlSignerClass,
  actorSeq = 1,
): ServiceControlUnit => ({ bytes: last(doc), signer, signerClass, actorSeq });

/** init (R), base approval (personal), the service's fill (B), a request (personal). */
function history() {
  const init = initial();
  const base = edit(init, personal, (d) => put(d.approvals, principalRef(B), approval(B)));
  const fill = edit(base, B, (d) => {
    for (const [k, v] of Object.entries(SERVICE)) put(d.service, k, v);
    for (const [k, v] of Object.entries(STATUS)) put(d.status, k, v);
  });
  const asked = edit(fill, personal, (d) => put(d.requests, uid(1), request("check")));
  return [
    unit(init, root, "root"),
    unit(base, personal, "personal"),
    unit(fill, B, "service-device"),
    unit(asked, personal, "personal", 2),
  ];
}

describe("ServiceControlReplica", () => {
  it("admits a history in any delivery order and reads the same state", () => {
    const units = history();
    const forward = ServiceControlReplica.fromChanges(units, options);
    const backward = ServiceControlReplica.fromChanges([...units].reverse(), options);
    expect(forward.result.refused).toEqual([]);
    expect(backward.result.refused).toEqual([]);
    expect(backward.replica.heads()).toEqual(forward.replica.heads());
    const state = backward.replica.validate();
    expect(state.status?.state).toBe("running");
    expect(Object.keys(state.requests)).toEqual([uid(1)]);
  });

  it("keeps a change waiting for its dependencies", () => {
    const units = history();
    const replica = ServiceControlReplica.empty(options);
    const first = replica.receiveChanges([
      units[0] as ServiceControlUnit,
      units[2] as ServiceControlUnit,
    ]);
    expect(first.waiting).toHaveLength(1);
    const rest = replica.receiveChanges([units[1] as ServiceControlUnit]);
    expect(rest.admitted).toHaveLength(2);
    expect(replica.validate().service?.label).toBe("MacBook Air");
  });

  it("names a change's author by its signer and class, never by a field (§2.4)", () => {
    const units = history();
    const { replica } = ServiceControlReplica.fromChanges(units, options);
    const hashes = replica.heads();
    expect(replica.authorOf(hashes[0] as string)).toEqual({
      signer: personal,
      writerClass: "personal",
    });
    const fill = ServiceControlReplica.fromChanges(units.slice(0, 3), options).replica.heads()[0];
    expect(replica.authorOf(fill as string)?.writerClass).toBe("service");
    expect(replica.authorOf("00".repeat(32))).toBeUndefined();
    expect(replica.writerClassAt({ signer: B, signerClass: "service-device", actorSeq: 2 })).toBe(
      "service",
    );
  });

  it("refuses a change of a writer whose class the pre-state does not give, and its dependants", () => {
    const [init] = history();
    const base = initial();
    const status = edit(base, B, (d) => put(d.status, "state", "running"));
    const { result } = ServiceControlReplica.fromChanges(
      [init as ServiceControlUnit, unit(status, B, "service-device")],
      options,
    );
    expect(result.refused.map((r) => r.diagnostic)).toEqual(["UNAUTHORIZED_WRITER"]);
  });

  it("reopens from a Snapshot only against the verified units of every change", () => {
    const units = history();
    const { replica } = ServiceControlReplica.fromChanges(units, options);
    const reopened = ServiceControlReplica.fromSnapshot(replica.snapshot(), options, units);
    expect(reopened.heads()).toEqual(replica.heads());
    expect(() =>
      ServiceControlReplica.fromSnapshot(replica.snapshot(), options, units.slice(0, 3)),
    ).toThrow(/verified carrying unit/);
  });

  it("binds a unit's codec to its signer's actor", () => {
    const [init] = history();
    const codec = serviceControlCodecFor({ resourceId: resource, actor: root });
    const framed = codec.encode({ ...codec.decode(codec.encode(asChange(init))) });
    expect(codec.decode(framed).seq).toBe(1);
    expect(() =>
      serviceControlCodecFor({ resourceId: resource, actor: personal }).decode(framed),
    ).toThrow(/actor/);
  });
});

const asChange = (u: ServiceControlUnit | undefined) =>
  checkChange((u as ServiceControlUnit).bytes);

describe("ServiceControlReplica §5 sizes on the merged state", () => {
  it("leaves out a status that two admitted branches make larger than 4096 bytes, in both orders", () => {
    const init = initial();
    // Two managing clients approve different base installations concurrently.
    const baseB = edit(init, personal, (d) => put(d.approvals, principalRef(B), approval(B)));
    const baseB2 = edit(init, root, (d) => put(d.approvals, principalRef(B2), approval(B2)));
    // Each installation is the only base in its own causal history and fills status.
    const fill = (doc: A.Doc<Doc>, who: typeof B, field: string) =>
      edit(doc, who, (d) => {
        for (const [k, v] of Object.entries(STATUS)) put(d.status, k, v);
        put(d.status, field, "x".repeat(2300));
      });
    const units = [
      unit(init, root, "root"),
      unit(baseB, personal, "personal"),
      unit(baseB2, root, "root", 2),
      unit(fill(baseB, B, "noteB"), B, "service-device"),
      unit(fill(baseB2, B2, "noteB2"), B2, "service-device"),
    ];
    for (const order of [units, [...units.slice(0, 3), ...units.slice(3).reverse()]]) {
      const { replica, result } = ServiceControlReplica.fromChanges(order, options);
      expect(result.refused).toEqual([]);
      const state = replica.validate();
      expect(state.status).toBeUndefined();
      expect(state.problems.map((p) => [p.pointer, p.diagnostic])).toEqual([
        ["/status", "LIMIT_EXCEEDED"],
      ]);
    }
  });
});
