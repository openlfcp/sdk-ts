import { type ControlRecordId, resourceId, toHex } from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, encode } from "../src/cbor/index.js";
import {
  type ControlBody,
  type ControlState,
  decodeControlPutBody,
  principalDescriptorFromKeys,
  proposeControlPut,
  proposeControlTransition,
  type Signer,
  signControlRecord,
  type TransitionResult,
  validateControlChain,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic keys; the published stale_control_head_put runs in the conformance runner.

const signer = (seed: number): Signer => {
  const key = importSigningKey(seq32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(seed + 100))),
  };
};
const INVITE = signer(97);
const DORA = signer(129);
const EVE = signer(161);
const R = resourceId(seq32(200));

const genesis = signControlRecord(
  { resourceId: R, controlSeq: 0n, prevControlId: null },
  {
    type: "GENESIS",
    dataProfile: "org.example.custom.v1",
    owner: ALICE.descriptor,
    dekCommitment: seq32(10) as never,
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  },
  ALICE,
);
const grantBruno = signControlRecord(
  { resourceId: R, controlSeq: 1n, prevControlId: genesis.recordId },
  { type: "CAPABILITY_GRANT", subject: BRUNO.descriptor, abilities: [1n, 2n], delegable: [] },
  ALICE,
);
const inviteGrant = signControlRecord(
  { resourceId: R, controlSeq: 2n, prevControlId: grantBruno.recordId },
  {
    type: "CAPABILITY_GRANT",
    subject: INVITE.descriptor,
    abilities: [1n, 2n, 11n],
    delegable: [],
    claimLimit: 1n,
  },
  ALICE,
);

/** The validated state at H (after the invite grant). */
function stateAtH(): ControlState {
  const r = validateControlChain([genesis.bytes, grantBruno.bytes, inviteGrant.bytes]);
  if (r.kind !== "linear") throw new Error(r.kind);
  return r.state;
}
const H = inviteGrant.recordId;

const next = (
  state: ControlState,
  body: ControlBody,
  by: Signer,
  over: { seq?: bigint; prev?: ControlRecordId } = {},
) =>
  signControlRecord(
    {
      resourceId: R,
      controlSeq: over.seq ?? state.seq + 1n,
      prevControlId: over.prev ?? state.head,
    },
    body,
    by,
  ).bytes;
const claim = (claimant: Signer): ControlBody => ({
  type: "CAPABILITY_CLAIM",
  invitationGrantId: H,
  claimant: claimant.descriptor,
  abilities: [1n, 2n],
});
const grantTo = (who: Signer): ControlBody => ({
  type: "CAPABILITY_GRANT",
  subject: who.descriptor,
  abilities: [1n],
  delegable: [],
});

/** A comparable summary: kinds, codes and heads (no object identity). */
function summary(r: TransitionResult): unknown {
  switch (r.kind) {
    case "accepted":
      return {
        kind: r.kind,
        head: toHex(r.nextState.head),
        seq: String(r.nextState.seq),
        record: toHex(r.record.signed.id),
      };
    case "already-committed":
      return { kind: r.kind, head: toHex(r.head) };
    case "head-mismatch":
      return { kind: r.kind, wire: r.wireCode, current: toHex(r.currentHead) };
    case "invalid":
      return { kind: r.kind, problem: r.problem, wire: r.wireCode };
    default:
      return { kind: r.kind, wire: r.wireCode };
  }
}

/** A deep snapshot of a state (Maps and typed arrays included) to prove it is not mutated. */
function snapshot(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) => {
    if (v instanceof Uint8Array) return `h'${toHex(v)}'`;
    if (v instanceof Map) return [...v.entries()];
    if (typeof v === "bigint") return `${v}n`;
    return v;
  });
}

describe("proposeControlTransition (§21, §47)", () => {
  it("1, 6. accepts an authorized successor when the expected head is current", () => {
    const state = stateAtH();
    const r = proposeControlTransition(state, H, next(state, grantTo(DORA), ALICE));
    if (r.kind !== "accepted") throw new Error(JSON.stringify(summary(r)));
    expect(r.nextState.seq).toBe(3n);
    expect(toHex(r.nextState.head)).toBe(toHex(r.record.signed.id));
    expect(r.nextState.grants.size).toBe(state.grants.size + 1);
  });

  it("2. refuses a stale expected head with CONTROL_HEAD_MISMATCH and the current head", () => {
    const state = stateAtH();
    const r = proposeControlTransition(
      state,
      grantBruno.recordId,
      next(state, grantTo(DORA), ALICE),
    );
    expect(summary(r)).toEqual({
      kind: "head-mismatch",
      wire: "CONTROL_HEAD_MISMATCH",
      current: toHex(H),
    });
  });

  it("3. refuses a candidate whose prev is not the current head", () => {
    const state = stateAtH();
    const r = proposeControlTransition(
      state,
      H,
      next(state, grantTo(DORA), ALICE, { prev: grantBruno.recordId }),
    );
    expect(summary(r)).toEqual({
      kind: "invalid",
      problem: "PREVIOUS",
      wire: "INVALID_CONTROL_CHAIN",
    });
  });

  it("4. refuses a candidate whose seq is not current + 1", () => {
    const state = stateAtH();
    for (const seq of [2n, 4n]) {
      const r = proposeControlTransition(state, H, next(state, grantTo(DORA), ALICE, { seq }));
      expect(summary(r)).toEqual({
        kind: "invalid",
        problem: "SEQUENCE",
        wire: "INVALID_CONTROL_CHAIN",
      });
    }
  });

  it("5. refuses an unauthorized mutation with AUTHORIZATION_FAILED", () => {
    const state = stateAtH();
    const r = proposeControlTransition(state, H, next(state, grantTo(DORA), BRUNO)); // no capability/grant, no parent
    expect(r).toMatchObject({ kind: "unauthorized", wireCode: "AUTHORIZATION_FAILED" });
  });

  it("7. gives the same result for the same inputs", () => {
    const state = stateAtH();
    const candidate = next(state, grantTo(DORA), ALICE);
    expect(summary(proposeControlTransition(state, H, candidate))).toEqual(
      summary(proposeControlTransition(state, H, candidate)),
    );
  });

  it("8-13. two claims from the same head: one succeeds, the other is stale, then exhausted", () => {
    const state = stateAtH();
    const a = next(state, claim(DORA), INVITE); // candidate A, expected H
    const b = next(state, claim(EVE), INVITE); // candidate B, expected H
    // 9, 11. A commits: the head moves to H2, and the one claim is consumed.
    const first = proposeControlTransition(state, H, a);
    if (first.kind !== "accepted") throw new Error(JSON.stringify(summary(first)));
    const h2 = first.nextState.head;
    expect(first.nextState.grants.get(toHex(H))?.claimsUsed).toBe(1n);
    // 10. B, still expecting H, is stale against H2.
    expect(summary(proposeControlTransition(first.nextState, H, b))).toEqual({
      kind: "head-mismatch",
      wire: "CONTROL_HEAD_MISMATCH",
      current: toHex(h2),
    });
    // 12, 13. B's caller refreshes, rebuilds on H2 and is refused: the invitation is used up.
    const rebuilt = next(first.nextState, claim(EVE), INVITE);
    expect(proposeControlTransition(first.nextState, h2, rebuilt)).toMatchObject({
      kind: "claim-exhausted",
      wireCode: "AUTHORIZATION_FAILED",
      code: "INVITE_CLAIM_EXHAUSTED",
    });
    // The same holds for A's claim submitted again on H2: an invitation is consumed once.
    expect(
      proposeControlTransition(first.nextState, h2, next(first.nextState, claim(DORA), INVITE))
        .kind,
    ).toBe("claim-exhausted");
  });

  it("14. the winner is whichever commits first, never chosen by content, time or ID order", () => {
    const state = stateAtH();
    const a = next(state, claim(DORA), INVITE);
    const b = next(state, claim(EVE), INVITE);
    for (const [first, second] of [
      [a, b],
      [b, a],
    ] as const) {
      const r1 = proposeControlTransition(state, H, first);
      if (r1.kind !== "accepted") throw new Error(r1.kind);
      expect(toHex(r1.record.signed.bytes)).toBe(toHex(first));
      expect(proposeControlTransition(r1.nextState, H, second).kind).toBe("head-mismatch");
    }
  });

  it("15. is pure: inputs are not mutated and the result is new state, nothing is written", () => {
    const state = stateAtH();
    const candidate = next(state, grantTo(DORA), ALICE);
    const expected = Uint8Array.from(H);
    const before = [snapshot(state), toHex(candidate), toHex(expected)];
    const r = proposeControlTransition(state, expected, candidate);
    expect([snapshot(state), toHex(candidate), toHex(expected)]).toEqual(before);
    expect(r.kind === "accepted" && r.nextState !== state).toBe(true);
    expect(Object.isFrozen(r)).toBe(true);
  });

  it("refuses Genesis, and a null expected head", () => {
    const state = stateAtH();
    expect(proposeControlTransition(state, H, genesis.bytes)).toMatchObject({
      kind: "genesis",
      wireCode: "MALFORMED_MESSAGE",
    });
    const other = signControlRecord(
      { resourceId: R, controlSeq: 0n, prevControlId: null },
      {
        type: "GENESIS",
        dataProfile: "x.y",
        owner: BRUNO.descriptor,
        dekCommitment: seq32(11) as never,
        endpoints: [{ url: "wss://b.example.test", priority: 0n }],
        coordinatorUrl: "wss://b.example.test",
      },
      BRUNO,
    );
    expect(proposeControlTransition(state, H, other.bytes).kind).toBe("genesis");
    expect(proposeControlTransition(state, null, next(state, grantTo(DORA), ALICE))).toMatchObject({
      kind: "invalid",
      problem: "NULL_EXPECTED_HEAD",
      wireCode: "MALFORMED_MESSAGE",
    });
  });

  it("reports the current head record itself as already committed, whatever head was expected", () => {
    const state = stateAtH();
    for (const expected of [H, grantBruno.recordId]) {
      expect(summary(proposeControlTransition(state, expected, inviteGrant.bytes))).toEqual({
        kind: "already-committed",
        head: toHex(H),
      });
    }
  });

  it("refuses malformed candidate bytes as MALFORMED_MESSAGE", () => {
    expect(summary(proposeControlTransition(stateAtH(), H, Uint8Array.of(0x80)))).toEqual({
      kind: "invalid",
      problem: "MALFORMED",
      wire: "MALFORMED_MESSAGE",
    });
  });
});

describe("CONTROL_PUT bodies (§47)", () => {
  it("decodes the body and proposes its record", () => {
    const state = stateAtH();
    const candidate = next(state, grantTo(DORA), ALICE);
    const body = decodeControlPutBody(
      encode(
        cborMap([
          [0, R],
          [1, H],
          [2, candidate],
        ]),
      ),
    );
    expect(proposeControlPut(state, body).kind).toBe("accepted");
    const stale = decodeControlPutBody(
      encode(
        cborMap([
          [0, R],
          [1, grantBruno.recordId],
          [2, candidate],
        ]),
      ),
    );
    expect(proposeControlPut(state, stale).kind).toBe("head-mismatch");
    const nullHead = decodeControlPutBody(
      encode(
        cborMap([
          [0, R],
          [1, null],
          [2, candidate],
        ]),
      ),
    );
    expect(proposeControlPut(state, nullHead)).toMatchObject({
      kind: "invalid",
      problem: "NULL_EXPECTED_HEAD",
    });
    const otherResource = decodeControlPutBody(
      encode(
        cborMap([
          [0, seq32(9)],
          [1, H],
          [2, candidate],
        ]),
      ),
    );
    expect(proposeControlPut(state, otherResource)).toMatchObject({
      kind: "invalid",
      problem: "RESOURCE",
    });
  });

  it("rejects a malformed body", () => {
    expect(() =>
      decodeControlPutBody(
        encode(
          cborMap([
            [0, R],
            [1, H],
          ]),
        ),
      ),
    ).toThrow();
    expect(() =>
      decodeControlPutBody(
        encode(
          cborMap([
            [0, R],
            [1, seq32(1).subarray(1)],
            [2, Uint8Array.of(0)],
          ]),
        ),
      ),
    ).toThrow();
  });
});
