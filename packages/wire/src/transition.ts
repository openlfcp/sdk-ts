import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  LfcpError,
  type ResourceId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { type Authorization, authorizeControlRecord } from "./capability.js";
import { type CborValue, decodeStrict } from "./cbor/index.js";
import { type ChainProblem, type ControlState, validateControlChain } from "./chain.js";
import { type ControlRecord, decodeControlRecord } from "./control.js";
import { Fields } from "./fields.js";

/**
 * Control transitions with compare-and-swap semantics (LFCP-WIRE-01 §21,
 * §47, §18.1 rule 6). Library logic only: a pure function of the
 * validated current state, the expected head and the candidate's exact
 * bytes. No network, clock, randomness or storage; the caller commits an
 * accepted transition atomically (durable coordinator CAS is server work).
 *
 * One head takes one successor: a candidate is accepted only against the
 * exact current head, so of two candidates built on the same head H, the
 * first accepted moves the head to H2 and the second then fails its
 * expected-head check. A caller that refreshes and rebuilds on H2 is
 * validated again from H2's state, so a one-time invitation already
 * consumed at H2 refuses the second claim (INVITE_CLAIM_EXHAUSTED).
 *
 * Validation reuses validateControlChain from the current state (the
 * `start` path), with the LFCP-021 capability engine and applyRecord:
 * there is no second rule set here.
 */
export type TransitionResult =
  | { readonly kind: "accepted"; readonly nextState: ControlState; readonly record: ControlRecord }
  /**
   * The candidate is the current head record itself (same record ID, so the
   * same exact bytes): it is already committed. A server may answer a
   * repeated put idempotently; how it answers is the server's decision.
   */
  | { readonly kind: "already-committed"; readonly head: ControlRecordId }
  /** §47: NACK(CONTROL_HEAD_MISMATCH) "with the current head". */
  | {
      readonly kind: "head-mismatch";
      readonly wireCode: "CONTROL_HEAD_MISMATCH";
      readonly currentHead: ControlRecordId;
    }
  /** §47: Genesis is created with RESOURCE_HOST, never through a Control transition. */
  | { readonly kind: "genesis"; readonly wireCode: "MALFORMED_MESSAGE"; readonly reason: string }
  | {
      readonly kind: "unauthorized";
      readonly wireCode: "AUTHORIZATION_FAILED";
      readonly reason: string;
    }
  /** §18.1 rule 3 after serialization: the invitation is used up. AUTHORIZATION_FAILED on the wire. */
  | {
      readonly kind: "claim-exhausted";
      readonly wireCode: "AUTHORIZATION_FAILED";
      readonly code: "INVITE_CLAIM_EXHAUSTED";
      readonly reason: string;
    }
  | {
      readonly kind: "invalid";
      readonly problem: ChainProblem | "NULL_EXPECTED_HEAD";
      readonly wireCode: string;
      readonly error: LfcpError;
    };

/**
 * Evaluates one candidate Control Record against the validated current
 * state and the head the submitter expected. Checks, in order: a non-null
 * expected head; the candidate decodes; it is not already the head; it is
 * not a Genesis; the expected head is the current head; then the full
 * successor rules (seq = current + 1, prev = current head, same Resource,
 * signature by the issuer, authority, claim limit) from the current state.
 */
export function proposeControlTransition(
  state: ControlState,
  expectedHead: Uint8Array | null,
  candidate: Uint8Array,
): TransitionResult {
  if (expectedHead === null) {
    // §47: "A CONTROL_PUT always names an expected head; a null expected head is invalid."
    return Object.freeze({
      kind: "invalid",
      problem: "NULL_EXPECTED_HEAD",
      wireCode: "MALFORMED_MESSAGE",
      error: new LfcpError(
        "INVALID_STRUCTURE",
        "an ordinary Control transition needs an expected head",
      ),
    });
  }
  let record: ControlRecord;
  try {
    record = decodeControlRecord(candidate);
  } catch (e) {
    const error = e instanceof LfcpError ? e : new LfcpError("INVALID_STRUCTURE", String(e));
    return Object.freeze({
      kind: "invalid",
      problem:
        error.code === "UNSUPPORTED_VALUE"
          ? "UNSUPPORTED_TYPE"
          : error.code === "INVALID_CONTROL_CHAIN"
            ? "SEQUENCE"
            : "MALFORMED",
      wireCode:
        error.code === "UNSUPPORTED_VALUE" || error.code === "INVALID_CONTROL_CHAIN"
          ? "INVALID_CONTROL_CHAIN"
          : "MALFORMED_MESSAGE",
      error,
    });
  }
  if (bytesEqual(record.signed.id, state.head))
    return Object.freeze({ kind: "already-committed", head: state.head });
  if (record.body.type === "GENESIS")
    return Object.freeze({
      kind: "genesis",
      wireCode: "MALFORMED_MESSAGE",
      reason: "Genesis is created with RESOURCE_HOST, not as a Control transition (§47)",
    });
  if (!bytesEqual(expectedHead, state.head))
    return Object.freeze({
      kind: "head-mismatch",
      wireCode: "CONTROL_HEAD_MISMATCH",
      currentHead: state.head,
    });

  let refusal: Authorization | undefined;
  const result = validateControlChain([candidate], {
    start: state,
    authorize: (r, s) => {
      const decision = authorizeControlRecord(r, s);
      if (!decision.allowed) refusal = decision;
      return decision;
    },
  });
  if (result.kind === "linear") {
    const accepted = result.records[0];
    if (accepted === undefined)
      // The only candidate was the head itself, which is handled above.
      throw new Error("unreachable: an accepted transition without a record");
    return Object.freeze({ kind: "accepted", nextState: result.state, record: accepted });
  }
  if (result.kind === "conflict")
    // One candidate from one head cannot fork; a second Genesis is refused above.
    throw new Error("unreachable: a single candidate produced a conflict");
  if (result.problem === "UNAUTHORIZED" && refusal !== undefined && !refusal.allowed) {
    if (refusal.code === "INVITE_CLAIM_EXHAUSTED")
      return Object.freeze({
        kind: "claim-exhausted",
        wireCode: "AUTHORIZATION_FAILED",
        code: "INVITE_CLAIM_EXHAUSTED",
        reason: refusal.reason,
      });
    return Object.freeze({
      kind: "unauthorized",
      wireCode: "AUTHORIZATION_FAILED",
      reason: refusal.reason,
    });
  }
  return Object.freeze({
    kind: "invalid",
    problem: result.problem,
    wireCode: result.wireCode,
    error: result.error,
  });
}

/** The CONTROL_PUT body (§47). */
export interface ControlPutBody {
  readonly resourceId: ResourceId;
  /** The expected current Control Head (§47: always present). */
  readonly expectedHead: ControlRecordId;
  /** The exact signed Control Record bytes. */
  readonly record: Uint8Array;
}

/**
 * Decodes a control-put-body: {0 resource-id, 1 hash32, 2 bstr} (§47).
 * "A CONTROL_PUT always names an expected head; a null expected head is
 * invalid" (§47): null is INVALID_STRUCTURE (MALFORMED_MESSAGE).
 * Structure only; decodeMessage (message.ts) reads it from a CONTROL_PUT.
 */
export function controlPutBodyFromCbor(value: CborValue): ControlPutBody {
  const f = new Fields(value, "control-put-body", [0, 1, 2]);
  return Object.freeze({
    resourceId: resourceId(f.bytes(0, 32)),
    expectedHead: controlRecordId(f.bytes(1, 32)),
    record: f.bytes(2),
  });
}

/**
 * A CONTROL_PUT against the coordinator's current state: the body's
 * Resource must be the state's, and the record must be of that Resource
 * too; then proposeControlTransition.
 */
export function proposeControlPut(state: ControlState, body: ControlPutBody): TransitionResult {
  if (!bytesEqual(body.resourceId, state.resourceId))
    return Object.freeze({
      kind: "invalid",
      problem: "RESOURCE",
      wireCode: "INVALID_CONTROL_CHAIN",
      error: new LfcpError(
        "INVALID_CONTROL_CHAIN",
        `the put names Resource ${toHex(body.resourceId)}, not this chain's Resource`,
      ),
    });
  return proposeControlTransition(state, body.expectedHead, body.record);
}

/** Decodes a CONTROL_PUT body from its CBOR bytes (a bare body; decodeMessage decodes whole messages). */
export const decodeControlPutBody = (bytes: Uint8Array): ControlPutBody =>
  controlPutBodyFromCbor(decodeStrict(bytes));
