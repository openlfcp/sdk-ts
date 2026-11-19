import * as A from "@automerge/automerge";
import { principalId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import {
  checkServiceControlUnit,
  ServiceControlAdmission,
  type ServiceControlSignerClass,
  type ServiceControlWriter,
  serviceControlSignerClass,
  serviceControlWriterClass,
} from "../src/service-control/index.js";
import {
  approval,
  B,
  B2,
  type Doc,
  edit,
  initial,
  last,
  other,
  personal,
  principalRef,
  put,
  request,
  resource,
  root,
  SERVICE,
  STATUS,
  T0,
  uid,
  X,
} from "./support/service-control.js";

const options = { resource, root, genesisSigner: root };
const writer = (
  signer: typeof root,
  signerClass: ServiceControlSignerClass,
  actorSeq = 1,
): ServiceControlWriter => ({ signer, signerClass, actorSeq });
const R = writer(root, "root");
const personalWriter = (seq = 1) => writer(personal, "personal", seq);
const serviceWriter = (seq = 1, signer = B) => writer(signer, "service-device", seq);

/** Admits `doc`'s last change as `w`'s; returns the class or the diagnostic. */
function admit(admission: ServiceControlAdmission, doc: A.Doc<Doc>, w: ServiceControlWriter) {
  const change = checkChange(last(doc));
  try {
    checkServiceControlUnit(change, w, options);
    return admission.accept(change, w);
  } catch (e) {
    return (e as { diagnostic: string }).diagnostic;
  }
}

describe("SERVICE-CONTROL-PROFILE-01 §2.3 writer classes at control_ref", () => {
  const device = (
    kind: number,
    extra: Partial<{ root: typeof root; boundInC: boolean; active: boolean }> = {},
  ) => ({
    kind,
    root,
    boundInC: true,
    active: true,
    ...extra,
  });

  it("gives root to C's Genesis owner, personal to its bound kind-0 devices", () => {
    expect(serviceControlSignerClass({ owner: root, signer: root })).toBe("root");
    expect(serviceControlSignerClass({ owner: root, signer: personal, device: device(0) })).toBe(
      "personal",
    );
  });

  it("makes a bound and active kind-1 device of R a service candidate only", () => {
    expect(serviceControlSignerClass({ owner: root, signer: B, device: device(1) })).toBe(
      "service-device",
    );
  });

  it("gives other to everybody else", () => {
    const cases = [
      // a section installation: scope [X], not bound in C
      device(1, { boundInC: false }),
      // revoked or suspended at control_ref
      device(1, { active: false }),
      device(0, { active: false }),
      // a pairing device
      device(2),
      // another root's personal device
      device(0, { root: other }),
    ];
    for (const d of cases)
      expect(serviceControlSignerClass({ owner: root, signer: B, device: d })).toBe("other");
    // a non-device member, such as another root
    expect(serviceControlSignerClass({ owner: root, signer: other })).toBe("other");
  });

  it("gives service to exactly the Principal of the only unrevoked base approval", () => {
    expect(serviceControlWriterClass("service-device", B, [principalRef(B)])).toBe("service");
    expect(serviceControlWriterClass("service-device", B, [])).toBe("other");
    expect(serviceControlWriterClass("service-device", B, [principalRef(B2)])).toBe("other");
    expect(
      serviceControlWriterClass("service-device", B, [principalRef(B), principalRef(B2)]),
    ).toBe("other");
    expect(serviceControlWriterClass("personal", personal, [principalRef(B)])).toBe("personal");
    expect(serviceControlWriterClass("other", B, [principalRef(B)])).toBe("other");
  });
});

describe("SERVICE-CONTROL-PROFILE-01 §2.3 the class on the change's causal history", () => {
  function approved() {
    const admission = new ServiceControlAdmission(options);
    const init = initial();
    expect(admit(admission, init, R)).toBe("root");
    const base = edit(init, personal, (d) => put(d.approvals, principalRef(B), approval(B)));
    expect(admit(admission, base, personalWriter())).toBe("personal");
    return { admission, init, base };
  }
  const fill = (doc: A.Doc<Doc>) =>
    edit(doc, B, (d) => {
      for (const [k, v] of Object.entries(SERVICE)) put(d.service, k, v);
      for (const [k, v] of Object.entries(STATUS)) put(d.status, k, v);
    });

  it("refuses a service device without its approval in the change's causal history", () => {
    const { admission, init } = approved();
    // The approval is admitted, but the change was made on the initial change only.
    expect(admit(admission, fill(init), serviceWriter())).toBe("UNAUTHORIZED_WRITER");
  });

  it("admits the service device whose base approval is in its pre-state", () => {
    const { admission, base } = approved();
    expect(admit(admission, fill(base), serviceWriter())).toBe("service");
  });

  it("refuses the approved device when it is revoked at control_ref", () => {
    const { admission, base } = approved();
    expect(admit(admission, fill(base), writer(B, "other"))).toBe("UNAUTHORIZED_WRITER");
  });

  it("keeps a decision made before a revocation, and refuses writes made on it", () => {
    const { admission, base } = approved();
    const filled = fill(base);
    expect(admit(admission, filled, serviceWriter())).toBe("service");
    const revoked = edit(filled, personal, (d) =>
      put(d.approvals[principalRef(B)], "revoked", { at: T0 }),
    );
    // Made on `filled`, concurrently with the revocation: its pre-state holds the approval.
    const concurrent = edit(filled, B, (d) => put(d.status, "message", "syncing"));
    expect(admit(admission, revoked, personalWriter(2))).toBe("personal");
    expect(admit(admission, concurrent, serviceWriter(2))).toBe("service");
    const after = edit(A.merge(A.clone(concurrent), revoked), B, (d) =>
      put(d.status, "message", "again"),
    );
    expect(admit(admission, after, serviceWriter(3))).toBe("UNAUTHORIZED_WRITER");
  });

  it("gives the class to nobody with two unrevoked base approvals (§7.3)", () => {
    const { admission, base } = approved();
    const second = edit(base, root, (d) => put(d.approvals, principalRef(B2), approval(B2)));
    expect(admit(admission, second, writer(root, "root", 2))).toBe("root");
    expect(admission.writerClassAt(A.getHeads(second), serviceWriter())).toBe("other");
    expect(admission.writerClassAt(A.getHeads(second), serviceWriter(1, B2))).toBe("other");
    const revoked = edit(second, personal, (d) =>
      put(d.approvals[principalRef(B2)], "revoked", { at: T0 }),
    );
    expect(admit(admission, revoked, personalWriter(2))).toBe("personal");
    expect(admission.writerClassAt(A.getHeads(revoked), serviceWriter())).toBe("service");
    expect(admission.writerClassAt(A.getHeads(revoked), serviceWriter(1, B2))).toBe("other");
  });

  it("reads two equal concurrent approvals as one base approval (§5 rule 3)", () => {
    const { admission, init, base } = approved();
    const repeated = edit(init, root, (d) => put(d.approvals, principalRef(B), approval(B)));
    expect(admit(admission, repeated, writer(root, "root", 2))).toBe("root");
    const heads = [...A.getHeads(base), ...A.getHeads(repeated)];
    expect(admission.writerClassAt(heads, serviceWriter())).toBe("service");
  });

  it("refuses the initial change of anybody but C's Genesis signer (SC0)", () => {
    const admission = new ServiceControlAdmission(options);
    expect(admit(admission, initial(personal), personalWriter())).toBe("INVALID_ROOT");
    const byDevice = { ...options, genesisSigner: personal };
    const change = checkChange(last(initial(personal)));
    checkServiceControlUnit(change, personalWriter(), byDevice);
    expect(new ServiceControlAdmission(byDevice).accept(change, personalWriter())).toBe("personal");
  });

  it("admits a request of root or personal, and refuses one of the service (§3)", () => {
    const { admission, base } = approved();
    const asked = edit(base, personal, (d) => put(d.requests, uid(1), request("check")));
    expect(admit(admission, asked, personalWriter(2))).toBe("personal");
    const byService = edit(base, B, (d) => put(d.requests, uid(2), request("check")));
    expect(admit(admission, byService, serviceWriter())).toBe("FORBIDDEN_MUTATION");
    const byOther = edit(base, principalId(new Uint8Array(32).fill(12)), (d) =>
      put(d.requests, uid(3), request("check")),
    );
    expect(
      admit(admission, byOther, writer(principalId(new Uint8Array(32).fill(12)), "other")),
    ).toBe("UNAUTHORIZED_WRITER");
  });
});

describe("SERVICE-CONTROL-PROFILE-01 §2.1 field types in SC0, SC4 and SC7", () => {
  const meta = (fn: (d: Doc) => void) => initial(root, fn);

  it("refuses an initial change whose meta has the wrong types (SC0 is not exempt from SC4)", () => {
    const cases: [string, (d: Doc) => void][] = [
      ["INVALID_FIELD_TYPE", (d) => put(d.meta, "attemptId", 123)],
      ["INVALID_TIMESTAMP", (d) => put(d.meta, "createdAt", "bad timestamp")],
      ["INVALID_FIELD_TYPE", (d) => put(d.meta, "createdAt", 5)],
      // A plain string is collaborative Text in Automerge 3.
      [
        "INVALID_FIELD_TYPE",
        (d) => {
          d.meta.attemptId = "attempt-1";
        },
      ],
    ];
    for (const [want, fn] of cases)
      expect(admit(new ServiceControlAdmission(options), meta(fn), R)).toBe(want);
    expect(admit(new ServiceControlAdmission(options), initial(), R)).toBe("root");
  });

  it("checks a binding's preview and a question's counts (§2.1, SC4, SC7)", () => {
    const approvedDoc = () => {
      const admission = new ServiceControlAdmission(options);
      const init = initial();
      admit(admission, init, R);
      const base = edit(init, personal, (d) => put(d.approvals, principalRef(B), approval(B)));
      admit(admission, base, personalWriter());
      return { admission, base };
    };
    const binding = (preview: unknown) => ({
      state: "preview",
      generation: 1,
      list: "Groceries",
      filter: "all",
      pending: { toApple: 0, toLfcp: 0 },
      refused: 0,
      unconfirmed: 0,
      preview,
    });
    const preview = { id: "p-1", planHash: "h-1", filter: "all", list: "Groceries" };
    const write = (value: unknown) => {
      const { admission, base } = approvedDoc();
      const doc = edit(base, B, (d) => put(d.bindings, X, value));
      return admit(admission, doc, serviceWriter());
    };
    expect(write(binding({ ...preview, items: ["Milk"], counts: { add: 2 } }))).toBe("service");
    expect(write(binding({ id: 123, items: ["1"] }))).toBe("MISSING_REQUIRED_FIELD");
    expect(write(binding({ ...preview, id: 123 }))).toBe("INVALID_FIELD_TYPE");
    expect(write(binding({ ...preview, counts: { bad: "string" } }))).toBe("INVALID_FIELD_TYPE");
    expect(write(binding({ ...preview, items: ["1", "2", "3", "4", "5", "6"] }))).toBe(
      "LIMIT_EXCEEDED",
    );
    expect(write(binding({ ...preview, items: ["x".repeat(81)] }))).toBe("LIMIT_EXCEEDED");
    const question = (counts: unknown) => ({
      binding: X,
      generation: 1,
      kind: "mass-delete",
      anomalyId: "an-1",
      snapshotHash: "sh-1",
      items: [],
      counts,
      options: ["apply"],
      at: T0,
    });
    const ask = (counts: unknown) => {
      const { admission, base } = approvedDoc();
      return admit(
        admission,
        edit(base, B, (d) => put(d.questions, uid(11), question(counts))),
        serviceWriter(),
      );
    };
    expect(ask({ deleted: 12 })).toBe("service");
    expect(ask({ deleted: "12" })).toBe("INVALID_FIELD_TYPE");
  });
});
