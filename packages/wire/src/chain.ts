import {
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  dataEpoch,
  type Hash32,
  LfcpError,
  type LfcpErrorCode,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  type Authorization,
  applyCapabilities,
  authorizeControlRecord,
  type Grant,
  transferIssuerDescriptor,
} from "./capability.js";
import {
  type ControlRecord,
  controlRecordSigner,
  decodeControlRecord,
  verifyGenesis,
} from "./control.js";
import { objectId, verifySignedObject } from "./cose.js";
import type { Endpoint } from "./endpoint.js";
import type { ActorHave } from "./have.js";
import type { PrincipalDescriptor } from "./principal.js";

/**
 * Control Chain validation (LFCP-WIRE-01 §13, §13.1, §13.2, §15).
 *
 * A pure function over exact signed Control Records: no I/O, clock or
 * randomness. The records may arrive in any order; the chain is ordered by
 * its own links (prev_control_id from Genesis), so every permutation of a
 * set gives the same result. Diagnostics are sorted by sequence and then
 * record ID only to make them reproducible; nothing ever chooses a branch.
 *
 * A fork (two validly signed records naming the same previous record) is a
 * conflict, never resolved by time, ID order, arrival order or server
 * preference (§13.2). A chain containing a Coordinator Recovery (7) or
 * Resource Tombstone (8) record is refused with PROTOCOL_UNSUPPORTED
 * (MVP-0.1-PROTOCOL-SCOPE §4, DV1). Extension records (32 and above) need
 * owner authority (§14) and stay in the chain, since the links run through
 * them, but are not applied to the derived state; they are listed in
 * `unappliedRecords`.
 */

/** The initial and current route (§15, §20). */
export interface ControlRoute {
  readonly endpoints: readonly Endpoint[];
  readonly coordinatorUrl: string;
}

/** A Data Epoch and its DEK commitment (§11, §15, §19). */
export interface ControlEpoch {
  readonly epoch: DataEpoch;
  readonly dekCommitment: Hash32;
}

/**
 * One Data Epoch in the chain's history (§11, §15, §19): opened by Genesis
 * (epoch 0) or a Key Epoch record, and closed by the next Key Epoch record,
 * which records its final frontier (§19.1). Kept for every epoch, so units
 * of any older epoch stay evaluable.
 */
export interface EpochHistory extends ControlEpoch {
  readonly openedBy: ControlRecordId;
  /** The Key Epoch record that closed this epoch, or null while it is current. */
  readonly closedBy: ControlRecordId | null;
  /** The accepted final frontier of this epoch (canonical, G-CP1), or null while it is current. */
  readonly finalFrontier: readonly ActorHave[] | null;
}

/**
 * The validated state of one Resource's Control Chain. This is the single
 * Control state type: LFCP-021 (capabilities) and LFCP-023 (epochs and
 * cutoff) extend it here and in `applyRecord`, never with a parallel type.
 *
 * LFCP-020 fills the chain position and what Genesis establishes;
 * LFCP-021 adds the grants and applies route updates; LFCP-023 applies
 * Key Epoch rotation (`epoch`, `epochs`).
 */
export interface ControlState {
  readonly resourceId: ResourceId;
  readonly genesisId: ControlRecordId;
  /** The current Control Head: the record ID of the last validated record. */
  readonly head: ControlRecordId;
  readonly seq: bigint;
  readonly dataProfile: string;
  /** The owner: the Genesis owner, or the new owner after a verified transfer (§15, §23.3). */
  readonly owner: PrincipalDescriptor;
  readonly route: ControlRoute;
  /** §20 route version of `route`; Genesis implies route version 0 (§15). */
  readonly routeVersion: bigint;
  /** The current Data Epoch. */
  readonly epoch: ControlEpoch;
  /** Every Data Epoch so far, by epoch number (decimal string) (§19, LFCP-023). */
  readonly epochs: ReadonlyMap<string, EpochHistory>;
  /** Grants created through this head (§17.2, §18.1), by grant ID hex; see capability.ts. */
  readonly grants: ReadonlyMap<string, Grant>;
  /**
   * Principal Descriptors carried by applied records (Genesis owner, grant
   * subjects, claimants), by Principal ID hex. Descriptors are
   * self-certifying (§7), so knowing one grants nothing; it only lets later
   * records by that Principal be verified.
   */
  readonly principals: ReadonlyMap<string, PrincipalDescriptor>;
}

/** Why a chain is invalid. */
export type ChainProblem =
  | "MALFORMED"
  | "UNSUPPORTED_TYPE"
  | "NO_GENESIS"
  | "GENESIS_SIGNER"
  | "RESOURCE"
  | "SEQUENCE"
  | "PREVIOUS"
  | "SIGNATURE"
  | "UNRESOLVED_ISSUER"
  | "EPOCH"
  | "UNAUTHORIZED"
  | "DEFERRED_TYPE";

export type ChainResult =
  | {
      readonly kind: "linear";
      readonly state: ControlState;
      /** The validated records in chain order (from the start, Genesis included when no start was given). */
      readonly records: readonly ControlRecord[];
      /** Extension records kept in the chain but not applied (mvpSupported = false), in chain order. */
      readonly unappliedRecords: readonly ControlRecordId[];
      /**
       * The validated state at any head of this chain (from the start, or
       * Genesis), for evaluating authority at an older Control Head. States
       * are kept by immutable head ID; undefined for a head not on the chain.
       */
      readonly stateAt: (head: Uint8Array) => ControlState | undefined;
    }
  | {
      readonly kind: "conflict";
      readonly wireCode: "CONTROL_CONFLICT";
      /** The record both branches name as previous; null when two Genesis records compete. */
      readonly commonHead: ControlRecordId | null;
      /** The contested sequence. */
      readonly seq: bigint;
      /** The competing record IDs, sorted by bytes for reproducible output (not a ranking). */
      readonly competing: readonly ControlRecordId[];
      /** The validated common prefix up to commonHead (null for a Genesis conflict); no branch is applied. */
      readonly prefixState: ControlState | null;
    }
  | {
      readonly kind: "invalid";
      readonly problem: ChainProblem;
      readonly wireCode: string;
      /** Position in the input array of the offending record (null when no record is at fault). */
      readonly index: number | null;
      readonly recordId: ControlRecordId | null;
      readonly error: LfcpError;
    };

export interface ChainOptions {
  /** Continue after an already validated head instead of starting from Genesis. */
  readonly start?: ControlState;
  /**
   * Resolves an issuer that no earlier record in the chain describes.
   * The returned descriptor is checked against the ID like any other.
   */
  readonly resolvePrincipal?: (id: PrincipalId) => PrincipalDescriptor | undefined;
  /**
   * Authorization, called for every non-Genesis record with the state
   * before it (the previous head). Defaults to authorizeControlRecord, the
   * LFCP-021 capability engine; a caller may substitute a policy (tests).
   * A refusal makes the chain invalid (UNAUTHORIZED).
   */
  readonly authorize?: (record: ControlRecord, state: ControlState) => boolean | Authorization;
}

const WIRE: Readonly<Record<ChainProblem, string>> = {
  MALFORMED: "MALFORMED_MESSAGE",
  // §14: "Unknown core Control Record types MUST cause validation failure, with INVALID_CONTROL_CHAIN."
  UNSUPPORTED_TYPE: "INVALID_CONTROL_CHAIN",
  // §13.1: a broken chain structure is INVALID_CONTROL_CHAIN.
  NO_GENESIS: "INVALID_CONTROL_CHAIN",
  // §15: a Genesis whose issuer or kid is not its owner.
  GENESIS_SIGNER: "INVALID_SIGNATURE",
  RESOURCE: "INVALID_CONTROL_CHAIN",
  SEQUENCE: "INVALID_CONTROL_CHAIN",
  PREVIOUS: "INVALID_CONTROL_CHAIN",
  // §13: kid MUST equal the issuer, and the signature must verify; §23.3 transfer signatures.
  SIGNATURE: "INVALID_SIGNATURE",
  // §13.1: an issuer the receiver cannot resolve to a Principal Descriptor.
  UNRESOLVED_ISSUER: "MISSING_DEPENDENCY",
  // PROVISIONAL (G-EP3): a Key Epoch that is not current + 1 breaks the chain.
  EPOCH: "INVALID_CONTROL_CHAIN",
  UNAUTHORIZED: "AUTHORIZATION_FAILED",
  // MVP-0.1-PROTOCOL-SCOPE §4 (DV1): Coordinator Recovery and Resource Tombstone records.
  DEFERRED_TYPE: "PROTOCOL_UNSUPPORTED",
};

const SDK_CODE: Readonly<Record<ChainProblem, LfcpErrorCode>> = {
  MALFORMED: "INVALID_STRUCTURE",
  UNSUPPORTED_TYPE: "UNSUPPORTED_VALUE",
  NO_GENESIS: "INVALID_CONTROL_CHAIN",
  GENESIS_SIGNER: "INVALID_SIGNATURE",
  RESOURCE: "INVALID_CONTROL_CHAIN",
  SEQUENCE: "INVALID_CONTROL_CHAIN",
  PREVIOUS: "INVALID_CONTROL_CHAIN",
  SIGNATURE: "INVALID_SIGNATURE",
  UNRESOLVED_ISSUER: "MISSING_DEPENDENCY",
  EPOCH: "INVALID_CONTROL_CHAIN",
  UNAUTHORIZED: "AUTHORIZATION_FAILED",
  DEFERRED_TYPE: "PROTOCOL_UNSUPPORTED",
};

interface Entry {
  readonly index: number;
  readonly record: ControlRecord;
  readonly key: string;
}

interface Problem {
  readonly problem: ChainProblem;
  readonly index: number | null;
  readonly recordId: ControlRecordId | null;
  readonly seq: bigint;
  readonly error: LfcpError;
}

function problem(
  kind: ChainProblem,
  at: { index: number | null; recordId: ControlRecordId | null; seq: bigint },
  message: string,
  cause?: LfcpError,
): Problem {
  return { problem: kind, ...at, error: cause ?? new LfcpError(SDK_CODE[kind], message) };
}

/** The record ID: SHA-256 of the exact signed bytes (§13), as a ControlRecordId. */
const rid = (record: ControlRecord): ControlRecordId => controlRecordId(record.signed.id);

const at = (e: Entry) => ({
  index: e.index,
  recordId: rid(e.record),
  seq: e.record.payload.controlSeq,
});

/** The first problem by (sequence, record ID): reproducible across input orders. */
function invalid(problems: readonly Problem[]): ChainResult {
  const first = [...problems].sort((a, b) => {
    if (a.seq !== b.seq) return a.seq < b.seq ? -1 : 1;
    const x = a.recordId === null ? "" : toHex(a.recordId);
    const y = b.recordId === null ? "" : toHex(b.recordId);
    return x < y ? -1 : x > y ? 1 : 0;
  })[0] as Problem;
  return Object.freeze({
    kind: "invalid",
    problem: first.problem,
    wireCode: WIRE[first.problem],
    index: first.index,
    recordId: first.recordId,
    error: first.error,
  });
}

const sortedIds = (ids: readonly ControlRecordId[]): readonly ControlRecordId[] =>
  Object.freeze([...ids].sort((a, b) => (toHex(a) < toHex(b) ? -1 : 1)));

function conflict(
  commonHead: ControlRecordId | null,
  seq: bigint,
  competing: readonly ControlRecordId[],
  prefixState: ControlState | null,
): ChainResult {
  return Object.freeze({
    kind: "conflict",
    wireCode: "CONTROL_CONFLICT",
    commonHead,
    seq,
    competing: sortedIds(competing),
    prefixState,
  });
}

function genesisState(record: ControlRecord): ControlState {
  const body = record.body;
  if (body.type !== "GENESIS") throw new Error("not a Genesis record");
  const id = controlRecordId(record.signed.id);
  return Object.freeze({
    resourceId: record.payload.resourceId,
    genesisId: id,
    head: id,
    seq: 0n,
    dataProfile: body.dataProfile,
    owner: body.owner,
    route: Object.freeze({ endpoints: body.endpoints, coordinatorUrl: body.coordinatorUrl }),
    routeVersion: 0n,
    epoch: Object.freeze({ epoch: dataEpoch(0n), dekCommitment: body.dekCommitment }),
    epochs: new Map([
      [
        "0",
        Object.freeze({
          epoch: dataEpoch(0n),
          dekCommitment: body.dekCommitment,
          openedBy: id,
          closedBy: null,
          finalFrontier: null,
        }),
      ],
    ]),
    grants: new Map(),
    principals: new Map([[toHex(body.owner.principalId), body.owner]]),
  });
}

/**
 * The state after a validated record. Applied records (mvpSupported)
 * change derived state: descriptors (LFCP-020), grants, revocations, claims
 * and routes (LFCP-021); LFCP-023 adds epochs here. Unapplied (extension)
 * records move the head and nothing else.
 */
function applyRecord(state: ControlState, record: ControlRecord): ControlState {
  const next = { head: controlRecordId(record.signed.id), seq: record.payload.controlSeq };
  if (!record.mvpSupported) return Object.freeze({ ...state, ...next });
  const principals = new Map(state.principals);
  const body = record.body;
  if (body.type === "CAPABILITY_GRANT")
    principals.set(toHex(body.subject.principalId), body.subject);
  if (body.type === "CAPABILITY_CLAIM")
    principals.set(toHex(body.claimant.principalId), body.claimant);
  // §23.3 "After commit, the accepting Principal becomes the Resource owner"
  // (verified by authorizeControlRecord before this record was accepted).
  const newOwner = transferIssuerDescriptor(record);
  if (newOwner !== undefined) principals.set(toHex(newOwner.principalId), newOwner);
  const route =
    body.type === "ROUTE_UPDATE"
      ? {
          route: Object.freeze({ endpoints: body.endpoints, coordinatorUrl: body.coordinatorUrl }),
          routeVersion: body.routeVersion,
        }
      : {};
  return Object.freeze({
    ...state,
    ...next,
    ...route,
    ...(body.type === "KEY_EPOCH" ? rotate(state, record, body) : {}),
    ...(newOwner !== undefined ? { owner: newOwner } : {}),
    principals,
    grants: applyCapabilities(state.grants, record),
  });
}

/**
 * §19: a committed Key Epoch record closes the current epoch with its final
 * frontier and opens the next one with its DEK commitment. Its succession
 * (new = current + 1) is checked before it is applied (G-EP3).
 */
function rotate(
  state: ControlState,
  record: ControlRecord,
  body: Extract<ControlRecord["body"], { type: "KEY_EPOCH" }>,
): Pick<ControlState, "epoch" | "epochs"> {
  const id = controlRecordId(record.signed.id);
  const epochs = new Map(state.epochs);
  const current = epochs.get(String(state.epoch.epoch));
  if (current !== undefined)
    epochs.set(
      String(current.epoch),
      Object.freeze({ ...current, closedBy: id, finalFrontier: body.finalFrontier }),
    );
  epochs.set(
    String(body.epoch),
    Object.freeze({
      epoch: body.epoch,
      dekCommitment: body.dekCommitment,
      openedBy: id,
      closedBy: null,
      finalFrontier: null,
    }),
  );
  return { epoch: Object.freeze({ epoch: body.epoch, dekCommitment: body.dekCommitment }), epochs };
}

/**
 * Validates a set of exact signed Control Records of one Resource, from
 * Genesis or after `options.start`. Input objects that are already decoded
 * are re-decoded from their exact bytes, never trusted as decoded.
 */
export function validateControlChain(
  inputs: readonly (Uint8Array | ControlRecord)[],
  options: ChainOptions = {},
): ChainResult {
  const entries: Entry[] = [];
  const early: Problem[] = [];
  inputs.forEach((input, index) => {
    const bytes = input instanceof Uint8Array ? input : input.signed.bytes;
    try {
      const record = decodeControlRecord(bytes);
      entries.push({ index, record, key: toHex(record.signed.id) });
    } catch (e) {
      const error = e instanceof LfcpError ? e : new LfcpError("INVALID_STRUCTURE", String(e));
      let recordId: ControlRecordId | null = null;
      try {
        recordId = controlRecordId(objectId(bytes));
      } catch {
        // not bytes at all
      }
      early.push(
        problem(
          error.code === "UNSUPPORTED_VALUE"
            ? "UNSUPPORTED_TYPE"
            : error.code === "INVALID_CONTROL_CHAIN"
              ? "SEQUENCE"
              : "MALFORMED",
          { index, recordId, seq: -1n },
          error.message,
          error,
        ),
      );
    }
  });
  // DV1 (MVP-0.1-PROTOCOL-SCOPE §4): "An MVP 0.1 implementation MUST refuse
  // a Control Chain that contains" a COORDINATOR_RECOVERY (7) or a
  // RESOURCE_TOMBSTONE (8) record, "with PROTOCOL_UNSUPPORTED".
  for (const e of entries) {
    const type = e.record.body.type;
    if (type === "COORDINATOR_RECOVERY" || type === "RESOURCE_TOMBSTONE")
      early.push(
        problem(
          "DEFERRED_TYPE",
          at(e),
          `a ${type} record: MVP 0.1 refuses a chain containing one (scope §4, DV1)`,
        ),
      );
  }
  if (early.length > 0) return invalid(early);

  // The same record delivered twice is one record.
  const unique = new Map<string, Entry>();
  for (const e of entries) if (!unique.has(e.key)) unique.set(e.key, e);
  const all = [...unique.values()];
  const geneses = all.filter((e) => e.record.body.type === "GENESIS");
  let rest = all.filter((e) => e.record.body.type !== "GENESIS");

  let state: ControlState;
  const records: ControlRecord[] = [];
  const start = options.start;
  if (start !== undefined) {
    const others = geneses.filter((g) => g.key !== toHex(start.genesisId));
    if (others.length > 0) {
      if (others.some((g) => toHex(g.record.payload.resourceId) !== toHex(start.resourceId)))
        return invalid(
          others.map((g) => problem("RESOURCE", at(g), "a Genesis of another Resource")),
        );
      // §13.2: "Two different validly signed Genesis Records for one Resource
      // ID are a fork at the root": neither is accepted (CONTROL_CONFLICT).
      return conflict(null, 0n, [start.genesisId, ...others.map((g) => rid(g.record))], null);
    }
    rest = rest.filter((e) => e.key !== toHex(start.head));
    state = start;
  } else {
    if (geneses.length === 0)
      return invalid([
        problem(
          "NO_GENESIS",
          { index: null, recordId: null, seq: -1n },
          "the chain has no Genesis record",
        ),
      ]);
    const bad: Problem[] = [];
    for (const g of geneses) {
      const v = verifyGenesis(g.record);
      if (!v.valid)
        bad.push(
          problem(
            v.reason === "ISSUER_NOT_OWNER" ? "GENESIS_SIGNER" : "SIGNATURE",
            at(g),
            `Genesis is not signed by its owner (${v.reason}, §15)`,
          ),
        );
    }
    if (bad.length > 0) return invalid(bad);
    if (geneses.length > 1) {
      const resource = toHex((geneses[0] as Entry).record.payload.resourceId);
      if (geneses.some((g) => toHex(g.record.payload.resourceId) !== resource))
        return invalid(
          geneses.map((g) => problem("RESOURCE", at(g), "Genesis records of different Resources")),
        );
      // §13.2: "Two different validly signed Genesis Records for one Resource
      // ID are a fork at the root": neither is accepted (CONTROL_CONFLICT).
      return conflict(
        null,
        0n,
        geneses.map((g) => rid(g.record)),
        null,
      );
    }
    const genesis = geneses[0] as Entry;
    state = genesisState(genesis.record);
    records.push(genesis.record);
  }

  const structural: Problem[] = [];
  for (const e of rest) {
    if (toHex(e.record.payload.resourceId) !== toHex(state.resourceId))
      structural.push(problem("RESOURCE", at(e), "the record belongs to another Resource"));
    else if (e.record.payload.prevControlId === null)
      structural.push(
        problem("PREVIOUS", at(e), "a non-Genesis record without a previous record ID (§13.1)"),
      );
  }
  if (structural.length > 0) return invalid(structural);

  const children = new Map<string, Entry[]>();
  for (const e of rest) {
    const prev = toHex(e.record.payload.prevControlId as ControlRecordId);
    children.set(prev, [...(children.get(prev) ?? []), e]);
  }

  const unapplied: ControlRecordId[] = [];
  const states = new Map<string, ControlState>([[toHex(state.head), state]]);
  const visited = new Set<string>();
  const authorize = options.authorize ?? authorizeControlRecord;
  for (;;) {
    const kids = children.get(toHex(state.head)) ?? [];
    if (kids.length === 0) break;
    const problems: Problem[] = [];
    const valid: Entry[] = [];
    for (const k of kids) {
      const p = k.record.payload;
      if (p.controlSeq !== state.seq + 1n) {
        problems.push(
          problem("SEQUENCE", at(k), `control_seq ${p.controlSeq} after ${state.seq} (§13.1)`),
        );
        continue;
      }
      // §13: the issuer signs, and kid MUST equal it (see controlRecordSigner).
      const issuer = controlRecordSigner(k.record);
      const descriptor =
        state.principals.get(toHex(issuer)) ??
        transferIssuerDescriptor(k.record) ??
        options.resolvePrincipal?.(issuer);
      if (descriptor === undefined) {
        problems.push(problem("UNRESOLVED_ISSUER", at(k), "no descriptor is known for the issuer"));
        continue;
      }
      const v = verifySignedObject(k.record.signed, descriptor);
      if (!v.valid) {
        problems.push(
          problem("SIGNATURE", at(k), `the record is not signed by its issuer (${v.reason})`),
        );
        continue;
      }
      // §19: "The new epoch number MUST be exactly the previous Data Epoch plus one."
      if (k.record.body.type === "KEY_EPOCH" && k.record.body.epoch !== state.epoch.epoch + 1n) {
        problems.push(
          problem(
            "EPOCH",
            at(k),
            `Key Epoch ${k.record.body.epoch} after epoch ${state.epoch.epoch}: must be the previous epoch plus one (§19)`,
          ),
        );
        continue;
      }
      const decision = authorize(k.record, state);
      if (decision === false || (typeof decision === "object" && !decision.allowed)) {
        const refusal = typeof decision === "object" && !decision.allowed ? decision : undefined;
        // §23.3: a transfer offer or acceptance whose signature does not verify.
        if (refusal?.code === "INVALID_SIGNATURE")
          problems.push(problem("SIGNATURE", at(k), refusal.reason));
        else
          problems.push(
            problem(
              "UNAUTHORIZED",
              at(k),
              `the record is not authorized: ${refusal?.reason ?? "refused"}`,
            ),
          );
        continue;
      }
      valid.push(k);
    }
    if (problems.length > 0) return invalid(problems);
    if (valid.length > 1)
      return conflict(
        state.head,
        state.seq + 1n,
        valid.map((k) => rid(k.record)),
        state,
      );
    const k = valid[0] as Entry;
    visited.add(k.key);
    records.push(k.record);
    if (!k.record.mvpSupported) unapplied.push(rid(k.record));
    state = applyRecord(state, k.record);
    states.set(toHex(state.head), state);
  }

  const unlinked = rest.filter((e) => !visited.has(e.key));
  if (unlinked.length > 0)
    return invalid(
      unlinked.map((e) =>
        problem(
          "PREVIOUS",
          at(e),
          "the previous record ID does not name the chain's record at the previous sequence (§13.1)",
        ),
      ),
    );
  return Object.freeze({
    kind: "linear",
    state,
    records: Object.freeze(records),
    unappliedRecords: Object.freeze(unapplied),
    stateAt: (head: Uint8Array) => states.get(toHex(head)),
  });
}
