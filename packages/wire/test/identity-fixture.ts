// A Control Chain fixture for the identity authority tests, following
// sdk-rs crates/lfcp/tests/support/identity.rs: Principal n has the seeds
// [n; 32] / [n + 100; 32] (identity.ts), the Resource is [77; 32], Genesis
// is owned and signed by Principal 1 unless said otherwise.

import {
  type ControlRecordId,
  controlRecordId,
  type Hash32,
  hash32,
  type ResourceId,
} from "@openlfcp/core";
import { expect } from "vitest";
import { cborMap, encode } from "../src/cbor/index.js";
import {
  type CertificateChain,
  type ControlBody,
  type ControlState,
  certificateChain,
  DEVICE_KIND,
  type DeviceCertificate,
  type DeviceCertificatePayload,
  type DeviceKind,
  principalDescriptorToCbor,
  proposeControlTransition,
  signControlRecord,
  signDeviceCertificate,
  signObject,
  type TransitionResult,
  validateControlChain,
} from "../src/index.js";
import { id, keys, RESOURCE } from "./identity.js";

export const FULL = [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13];

export function devicePayload(
  root: number,
  device: number,
  kind: DeviceKind,
  mask: readonly (number | bigint)[],
  scope: readonly ResourceId[],
  serial: number,
): DeviceCertificatePayload {
  return {
    root: id(root),
    device: keys(device).descriptor,
    kind,
    mask: mask.map(BigInt),
    scope,
    serial: new Uint8Array(16).fill(serial),
  };
}
export const issue = (p: DeviceCertificatePayload, signer: number) =>
  signDeviceCertificate(p, keys(signer));
/** Rust `personal(root, device, mask, signer, serial)`. */
export const personalCert = (
  root: number,
  device: number,
  mask: readonly (number | bigint)[],
  signer: number,
  serial: number,
): DeviceCertificate =>
  issue(devicePayload(root, device, DEVICE_KIND.PERSONAL, mask, [], serial), signer);
export const chainOf = (certs: readonly DeviceCertificate[]): CertificateChain =>
  certificateChain(certs, (certs[0] as DeviceCertificate).payload.root);

export const deviceGrant = (c: CertificateChain, session?: number): ControlBody => ({
  type: "DEVICE_GRANT",
  root: c.root,
  chain: c,
  ...(session !== undefined ? { pairingDevice: id(session) } : {}),
});
export const revokeDevice = (
  root: number,
  device: number,
  reason: number | bigint,
  approval?: Hash32,
): ControlBody => ({
  type: "DEVICE_REVOKE",
  root: id(root),
  device: id(device),
  reason: BigInt(reason),
  ...(approval !== undefined ? { approval } : {}),
});
export const capabilityGrant = (
  subject: number,
  abilities: readonly (number | bigint)[],
  delegable: readonly (number | bigint)[] = [],
  parentGrantId?: ControlRecordId,
  claimLimit?: number,
): ControlBody => ({
  type: "CAPABILITY_GRANT",
  subject: keys(subject).descriptor,
  abilities: abilities.map(BigInt),
  delegable: delegable.map(BigInt),
  ...(parentGrantId !== undefined ? { parentGrantId } : {}),
  ...(claimLimit !== undefined ? { claimLimit: BigInt(claimLimit) } : {}),
});
export const revokeGrant = (grantId: ControlRecordId): ControlBody => ({
  type: "CAPABILITY_REVOKE",
  grantId,
});
export const genesisBody = (owner: number, deviceChain?: CertificateChain): ControlBody => ({
  type: "GENESIS",
  dataProfile: "org.openlfcp.identity.v1",
  owner: keys(owner).descriptor,
  dekCommitment: hash32(new Uint8Array(32)),
  endpoints: [{ url: "wss://example.test/", priority: 0n }],
  coordinatorUrl: "wss://example.test/",
  ...(deviceChain !== undefined ? { deviceChain } : {}),
});
export const genesis = (owner: number, signer: number, deviceChain?: CertificateChain) =>
  signControlRecord(
    { resourceId: RESOURCE, controlSeq: 0n, prevControlId: null },
    genesisBody(owner, deviceChain),
    keys(signer),
  );
export const recordAt = (state: ControlState, signer: number, body: ControlBody) =>
  signControlRecord(
    { resourceId: state.resourceId, controlSeq: state.seq + 1n, prevControlId: state.head },
    body,
    keys(signer),
  );

/** Rust `transfer(state, new_owner, offer_signer, accept_signer, chain)`. */
export function transferBody(
  state: ControlState,
  newOwner: number,
  offerSigner: number,
  acceptSigner: number,
  deviceChain?: CertificateChain,
): ControlBody {
  const offer = signObject(
    encode(
      cborMap([
        [0, state.resourceId],
        [1, state.head],
        [2, state.seq + 1n],
        [3, principalDescriptorToCbor(keys(newOwner).descriptor)],
        [4, new Uint8Array(16).fill(44)],
      ]),
    ),
    keys(offerSigner),
  );
  const accept = signObject(
    encode(
      cborMap([
        [0, state.resourceId],
        [1, offer.id],
        [2, id(newOwner)],
      ]),
    ),
    keys(acceptSigner),
  );
  return {
    type: "OWNER_TRANSFER_COMMIT",
    offer: offer.bytes,
    accept: accept.bytes,
    ...(deviceChain !== undefined ? { deviceChain } : {}),
  };
}

/** The verdict of a transition: "accepted", or "<wire code>: <reason>". */
export function verdictOf(r: TransitionResult): string {
  switch (r.kind) {
    case "accepted":
      return "accepted";
    case "unauthorized":
    case "claim-exhausted":
      return `${r.wireCode}: ${r.reason}`;
    case "invalid":
      return `${r.wireCode}: ${r.error.message}`;
    default:
      return r.kind;
  }
}

export class Fixture {
  readonly records: Uint8Array[] = [];
  readonly states: ControlState[] = [];

  constructor(g = genesis(1, 1)) {
    const r = validateControlChain([g.bytes]);
    if (r.kind !== "linear") throw new Error(`Genesis must validate: ${JSON.stringify(r)}`);
    this.records.push(g.bytes);
    this.states.push(r.state);
  }

  get state(): ControlState {
    return this.states[this.states.length - 1] as ControlState;
  }

  get head(): ControlRecordId {
    return controlRecordId(this.state.head);
  }

  propose(signer: number, body: ControlBody): TransitionResult {
    return proposeControlTransition(
      this.state,
      this.state.head,
      recordAt(this.state, signer, body).bytes,
    );
  }

  push(signer: number, body: ControlBody): void {
    const record = recordAt(this.state, signer, body);
    const r = proposeControlTransition(this.state, this.state.head, record.bytes);
    if (r.kind !== "accepted") throw new Error(`expected acceptance: ${verdictOf(r)}`);
    this.records.push(record.bytes);
    this.states.push(r.nextState);
  }

  /** Refused with AUTHORIZATION_FAILED, for the rule `why` names. */
  denied(signer: number, body: ControlBody, why: RegExp): void {
    expect(verdictOf(this.propose(signer, body))).toMatch(
      new RegExp(`^AUTHORIZATION_FAILED: .*${why.source}`),
    );
  }

  register(root: number, device: number, mask: readonly (number | bigint)[]): void {
    this.push(root, deviceGrant(chainOf([personalCert(root, device, mask, root, device)])));
  }

  /** The whole chain revalidated from Genesis gives the same states as the transitions. */
  replay(): void {
    const r = validateControlChain(this.records);
    if (r.kind !== "linear") throw new Error(`replay must validate: ${JSON.stringify(r)}`);
    expect(r.records.length).toBe(this.records.length);
    for (const s of this.states) expect(r.stateAt(s.head)).toEqual(s);
  }
}
