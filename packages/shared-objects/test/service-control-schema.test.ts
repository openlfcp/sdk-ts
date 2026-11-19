import * as A from "@automerge/automerge";
import { principalId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { deviceFingerprint, validateServiceControl } from "../src/service-control/index.js";
import {
  approval,
  B,
  B2,
  C,
  type Doc,
  edit,
  initial,
  personal,
  principalRef,
  put,
  request,
  root,
  SERVICE,
  STATUS,
  serviceDevice,
  T0,
  uid,
  X,
} from "./support/service-control.js";

const v = (doc: A.Doc<Doc>) => validateServiceControl(doc, C);
const diagnostics = (doc: A.Doc<Doc>) => v(doc).problems.map((p) => [p.pointer, p.diagnostic]);

describe("SERVICE-CONTROL-PROFILE-01 §5 state validation", () => {
  it("reads the initial change as a usable, empty C (§5 rule 1)", () => {
    const s = v(initial());
    expect(s.usable).toBe(true);
    expect(s.problems).toEqual([]);
    expect(s.service).toBeUndefined();
    expect(s.status).toBeUndefined();
    expect(s.requests).toEqual({});
  });

  it("makes C unusable when a root key is missing or profile differs", () => {
    const missing = A.change(initial(), (d) => {
      delete d.lifecycle;
    });
    expect(v(missing).usable).toBe(false);
    expect(diagnostics(missing)).toEqual([["", "INVALID_ROOT"]]);
    const other = A.change(initial(), (d) => {
      put(d, "profile", "org.openlfcp.service-control.v2");
    });
    expect(v(other).usable).toBe(false);
  });

  it("reports a meta whose fields have the wrong types (§2.1)", () => {
    const doc = initial(root, (d) => put(d.meta, "createdAt", "bad timestamp"));
    expect(v(doc).usable).toBe(true);
    expect(diagnostics(doc)).toEqual([["/meta", "INVALID_TIMESTAMP"]]);
  });

  it("reads valid entries with unknown fields and leaves invalid ones out (§2.1, §5 rule 1)", () => {
    const doc = edit(initial(), personal, (d) => {
      put(d.requests, uid(1), request("turn-off", { priority: "high" }));
      put(d.requests, uid(2), request("Turn-Off"));
      put(d.requests, "r-1", request("check"));
      put(d.cancels, uid(1), { reason: "oops", at: T0 });
    });
    const s = v(doc);
    expect(Object.keys(s.requests)).toEqual([uid(1)]);
    expect(s.requests[uid(1)]?.priority).toBe("high");
    expect(s.requests[uid(1)]?.generation).toBe(1);
    expect(diagnostics(doc)).toEqual([
      [`/requests/${uid(2)}`, "INVALID_ENUM_VALUE"],
      ["/requests/r-1", "INVALID_KEY"],
      [`/cancels/${uid(1)}`, "INVALID_ENUM_VALUE"],
    ]);
  });

  it("checks service and status as wholes, once the service writes them", () => {
    const filled = edit(initial(), B, (d) => {
      put(d, "service", SERVICE);
      put(d, "status", { state: "running", since: T0 });
    });
    expect(diagnostics(filled)).toEqual([["/status", "MISSING_REQUIRED_FIELD"]]);
    const ok = edit(initial(), B, (d) => {
      put(d, "service", SERVICE);
      put(d, "status", STATUS);
    });
    expect(v(ok).status).toEqual(STATUS);
    expect((v(ok).service as { protocol: { ops: string[] } }).protocol.ops).toEqual(["check"]);
  });

  it("limits examples to 80 Unicode scalar values and items to 5", () => {
    const question = (items: string[]) => ({
      binding: X,
      generation: 1,
      kind: "mass-delete",
      anomalyId: "an-1",
      snapshotHash: "sh-1",
      items,
      counts: {},
      options: ["apply"],
      at: T0,
    });
    const doc = edit(initial(), B, (d) => {
      put(d.questions, uid(1), question(["é".repeat(80)]));
      put(d.questions, uid(2), question(["é".repeat(81)]));
      put(d.questions, uid(3), question(["1", "2", "3", "4", "5", "6"]));
    });
    expect(diagnostics(doc)).toEqual([
      [`/questions/${uid(2)}`, "LIMIT_EXCEEDED"],
      [`/questions/${uid(3)}`, "LIMIT_EXCEEDED"],
    ]);
  });

  it("checks an approval's key, and that a base approval names C", () => {
    const doc = edit(initial(), personal, (d) => {
      put(d.approvals, principalRef(B), approval(B2));
      put(d.approvals, principalRef(B2), approval(B2, "base", X));
    });
    expect(diagnostics(doc)).toEqual([
      [`/approvals/${principalRef(B)}`, "INVALID_KEY"],
      [`/approvals/${principalRef(B2)}`, "INVALID_ENUM_VALUE"],
    ]);
  });

  it("reads two equal concurrent approval maps as one, and differing ones as invalid (§5 rule 3)", () => {
    const base = initial();
    const a = edit(base, personal, (d) => put(d.approvals, principalRef(B), approval(B)));
    const same = edit(base, root, (d) => put(d.approvals, principalRef(B), approval(B)));
    const merged = A.merge(A.clone(a), same);
    expect(v(merged).approvals[principalRef(B)]?.revoked).toBe(false);
    const differ = edit(base, root, (d) =>
      put(d.approvals, principalRef(B), approval(B, "base", C, "z")),
    );
    const conflicting = A.merge(A.clone(a), differ);
    expect(v(conflicting).approvals).toEqual({});
    // A revoked value in one of the equal maps means revoked.
    const revoked = edit(merged, personal, (d) => {
      put(d.approvals[principalRef(B)], "revoked", { at: T0 });
    });
    expect(v(revoked).approvals[principalRef(B)]?.revoked).toBe(true);
  });

  it("refuses a request whose field holds concurrent values (§5 rule 3)", () => {
    const base = edit(initial(), personal, (d) => put(d.requests, uid(1), request("check")));
    const one = edit(base, personal, (d) => put(d.requests[uid(1)], "at", "2026-11-19T10:30:00Z"));
    const two = edit(base, root, (d) => put(d.requests[uid(1)], "at", "2026-11-19T11:00:00Z"));
    expect(diagnostics(A.merge(A.clone(one), two))).toEqual([
      [`/requests/${uid(1)}`, "INVALID_FIELD_TYPE"],
    ]);
  });

  it("reads an event's highest concurrent state, and two final ones as invalid (§5 rule 3)", () => {
    const base = edit(
      edit(initial(), personal, (d) => put(d.requests, uid(1), request("check"))),
      B,
      (d) => put(d.events, uid(1), { state: "received", at: T0 }),
    );
    const executing = edit(base, B, (d) => put(d.events[uid(1)], "state", "executing"));
    const applied = edit(base, B2, (d) => put(d.events[uid(1)], "state", "applied"));
    expect(v(A.merge(A.clone(executing), applied)).events[uid(1)]?.state).toBe("applied");
    const failed = edit(base, B, (d) => put(d.events[uid(1)], "state", "failed"));
    const both = A.merge(A.clone(failed), applied);
    expect(v(both).events).toEqual({});
    expect(diagnostics(both)).toEqual([[`/events/${uid(1)}`, "INVALID_ENUM_VALUE"]]);
  });

  it("checks a pairing entry's descriptor, principal and fingerprint", () => {
    const fp = deviceFingerprint(B);
    const doc = edit(initial(), B, (d) => {
      put(d.pairing, uid(3), { descriptor: serviceDevice.text, principal: principalRef(B), fp });
      put(d.pairing, uid(4), {
        descriptor: serviceDevice.text,
        principal: principalRef(B),
        fp: deviceFingerprint(principalId(new Uint8Array(32))),
      });
    });
    expect(Object.keys(v(doc).pairing)).toEqual([uid(3)]);
    expect(diagnostics(doc)).toEqual([[`/pairing/${uid(4)}`, "INVALID_DESCRIPTOR"]]);
    expect(fp).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/);
  });
});
