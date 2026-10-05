// Self-tests for the conformance runner (LFCP-017). Every suite here is
// synthetic, built in memory from synthetic keys; none is an official vector.

import { toHex } from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import {
  encodePrincipalDescriptor,
  objectId,
  principalDescriptorFromKeys,
  signObject,
} from "@openlfcp/wire";
import { cborMap, encode } from "@openlfcp/wire/cbor";
import { describe, expect, it } from "vitest";
import { bytesCheck, outcomeCheck } from "./checks.js";
import {
  type CaseResult,
  describeFailure,
  type Handler,
  type PendingFile,
  runSuite,
  type VectorCase,
  type VectorSuite,
} from "./runner.js";
import { WIRE_HANDLERS } from "./wire/handlers.js";

const SUITE_ID = "SYNTHETIC-01";
const seq = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const hx = (b: Uint8Array) => ({ hex: toHex(b) });

// A synthetic Principal (not a fixture of any published suite).
const SEED = seq(1);
const X25519 = seq(101);
const KEY = importSigningKey(SEED);
const DESCRIPTOR = principalDescriptorFromKeys(KEY, importAgreementKey(X25519));
const SIGNER = { key: KEY, descriptor: DESCRIPTOR };

function principalCase(id = "principal_synthetic"): VectorCase {
  return {
    id,
    type: "bytes",
    kind: "principal",
    inputs: { ed25519_seed: hx(SEED), x25519_private: hx(X25519) },
    expected: {
      ed25519_public: hx(KEY.publicKey),
      x25519_public: hx(DESCRIPTOR.x25519PublicKey),
      principal_id: hx(DESCRIPTOR.principalId),
      descriptor_cbor: hx(encodePrincipalDescriptor(DESCRIPTOR)),
    },
  };
}

/** A synthetic Data Unit signed by the synthetic Principal. */
function dataUnit(actorSeq: number) {
  const payload = encode(
    cborMap([
      [0, seq(50)],
      [1, 0],
      [2, DESCRIPTOR.principalId],
      [3, actorSeq],
      [4, null],
      [5, seq(60)],
      [6, seq(70)],
    ]),
  );
  return signObject(payload, SIGNER);
}

function negativeCase(id: string, cose: Uint8Array, code: string): VectorCase {
  return {
    id,
    type: "validation",
    kind: "data_unit",
    inputs: { cose_sign1: hx(cose) },
    expected: { valid: false, disposition: "reject", error: { code } },
  };
}

const suiteOf = (...cases: VectorCase[]): VectorSuite => ({
  format: "lfcp-vector-format/1",
  suite: { id: SUITE_ID, version: "01" },
  cases,
});
const noPending: PendingFile = { suite: SUITE_ID, cases: {} };
const run = (suite: VectorSuite, pending: PendingFile = noPending, handlers = WIRE_HANDLERS) =>
  runSuite(suite, handlers, pending);
const only = (suite: VectorSuite, pending?: PendingFile): CaseResult => {
  const r = run(suite, pending).cases[0];
  if (r === undefined) throw new Error("no result");
  return r;
};
const flip = (hex: string, at: number): string => {
  const b = Uint8Array.from(hex.match(/../g) ?? [], (x) => Number.parseInt(x, 16));
  b[at] = (b[at] as number) ^ 0x01;
  return toHex(b);
};

describe("runner self-tests", () => {
  it("passes a correct synthetic principal case", () => {
    const r = only(suiteOf(principalCase()));
    expect(r.status).toBe("passed");
    expect(r.checks.length).toBeGreaterThan(0);
  });

  it("detects wrong exact bytes, reporting the vector ID, offset and both sides", () => {
    const c = principalCase();
    const bad = flip((c.expected.descriptor_cbor as { hex: string }).hex, 40);
    const r = only(suiteOf({ ...c, expected: { ...c.expected, descriptor_cbor: { hex: bad } } }));
    expect(r.status).toBe("failed");
    const text = describeFailure(r);
    expect(text).toContain("principal_synthetic descriptor_cbor: bytes differ at offset 40");
    expect(text).toMatch(/expected: …[0-9a-f]+…\n {6}actual: {3}…[0-9a-f]+…/);
  });

  it("detects a wrong expected hash (Principal ID and object ID)", () => {
    const c = principalCase();
    const bad = flip((c.expected.principal_id as { hex: string }).hex, 0);
    const r = only(suiteOf({ ...c, expected: { ...c.expected, principal_id: { hex: bad } } }));
    expect(r.status).toBe("failed");
    expect(describeFailure(r)).toContain("principal_id: bytes differ at offset 0");

    const unit = dataUnit(1);
    const wrongId = bytesCheck("unit_id", objectId(dataUnit(2).bytes), objectId(unit.bytes));
    expect(wrongId.ok).toBe(false);
  });

  it("detects the unexpected success of a negative vector", () => {
    // An implemented layer accepts it, and no task claims the outcome: unclassified.
    const r = only(
      suiteOf(negativeCase("neg", dataUnit(1).bytes, "MALFORMED_MESSAGE"), principalCase()),
    );
    expect(r.status).toBe("failed");
    expect(r.problems.join("\n")).toContain('unclassified part "outcome"');
    // The outcome check itself names the problem.
    expect(outcomeCheck("outcome", "MALFORMED_MESSAGE", null)).toEqual({
      name: "outcome",
      ok: false,
      message: "expected MALFORMED_MESSAGE, got unexpected success",
    });
  });

  it("detects a wrong error class", () => {
    // Actor sequence 0 fails as MALFORMED_MESSAGE, not INVALID_SIGNATURE.
    const r = only(
      suiteOf(negativeCase("seq0", dataUnit(0).bytes, "INVALID_SIGNATURE"), principalCase()),
    );
    expect(r.status).toBe("failed");
    expect(describeFailure(r)).toContain(
      "seq0 outcome: expected INVALID_SIGNATURE, actual MALFORMED_MESSAGE",
    );
  });

  it("passes a negative that fails with the expected class", () => {
    const r = only(
      suiteOf(negativeCase("seq0", dataUnit(0).bytes, "MALFORMED_MESSAGE"), principalCase()),
    );
    expect(r.status).toBe("passed");
  });

  it("fails an unknown type or kind as an unclassified vector", () => {
    for (const [type, kind] of [
      ["bytes", "mystery"],
      ["behavioral", "principal"],
    ]) {
      const r = only(
        suiteOf({ id: "x", type: type as string, kind: kind as string, expected: {} }),
      );
      expect(r.status).toBe("failed");
      expect(r.problems).toEqual([
        `unclassified vector: no handler for ${type}/${kind} and no pending entry`,
      ]);
    }
  });

  it("reports pending as pending, never as passed", () => {
    const pending: PendingFile = {
      suite: SUITE_ID,
      cases: { x: { task: "LFCP-999", reason: "synthetic" } },
    };
    const result = run(suiteOf({ id: "x", type: "bytes", kind: "mystery", expected: {} }), pending);
    expect(result.cases[0]?.status).toBe("pending");
    expect(result.summary).toMatchObject({ total: 1, passed: 0, pending: 1, failed: 0 });
  });

  it("fails a stale whole-case pending entry", () => {
    const pending: PendingFile = {
      suite: SUITE_ID,
      cases: { principal_synthetic: { task: "LFCP-999", reason: "synthetic" } },
    };
    const r = only(suiteOf(principalCase()), pending);
    expect(r.status).toBe("failed");
    expect(r.problems[0]).toContain("pending but now handled by bytes/principal");
  });

  it("fails a stale pending part and an unclassified part", () => {
    const handler: Handler = () => ({ checks: [{ name: "a", ok: true }], pending: ["b/later"] });
    const c: VectorCase = { id: "p", type: "bytes", kind: "split", expected: { a: 1, b: 2 } };
    const handlers = { "bytes/split": handler };
    const listed = (parts: Record<string, string>): PendingFile => ({
      suite: SUITE_ID,
      cases: { p: { reason: "synthetic", parts } },
    });
    const ok = runSuite(suiteOf(c), handlers, listed({ "b/later": "LFCP-999" })).cases[0];
    expect(ok?.status).toBe("partial");
    expect(ok?.pending).toEqual([{ part: "b/later", task: "LFCP-999" }]);

    const stale = runSuite(suiteOf(c), handlers, listed({ "b/later": "LFCP-999", "a/x": "LFCP-1" }))
      .cases[0];
    expect(stale?.problems).toEqual([
      'stale pending part "a/x": now handled, remove it from pending',
    ]);

    const unlisted = runSuite(suiteOf(c), handlers, noPending).cases[0];
    expect(unlisted?.problems).toEqual([
      'unclassified part "b/later": the handler cannot run it and it is not pending',
    ]);
  });

  it("fails an expected field that is neither checked nor pending", () => {
    const handler: Handler = () => ({ checks: [{ name: "a", ok: true }] });
    const c: VectorCase = { id: "p", type: "bytes", kind: "split", expected: { a: 1, b: 2 } };
    const r = runSuite(suiteOf(c), { "bytes/split": handler }, noPending).cases[0];
    expect(r?.problems).toEqual(['expected field "b" is neither checked nor pending']);
  });

  it("fails invalid vector data instead of crashing", () => {
    const c = principalCase();
    const r = only(suiteOf({ ...c, inputs: { ed25519_seed: "not-hex-wrapped" } }));
    expect(r.status).toBe("failed");
    expect(r.problems[0]).toContain("handler bytes/principal threw");
  });

  it("fails pending entries for unknown cases and a suite mismatch", () => {
    const result = run(suiteOf(principalCase()), {
      suite: "OTHER-01",
      cases: { ghost: { task: "LFCP-999", reason: "synthetic" } },
    });
    expect(result.summary.problems).toEqual([
      `pending file is for suite OTHER-01, but the suite is ${SUITE_ID}`,
      "pending entry for ghost, which is not in the suite",
    ]);
  });
});
