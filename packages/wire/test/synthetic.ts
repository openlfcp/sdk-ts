// Synthetic test material for @openlfcp/wire unit tests: keys from counting
// byte sequences, never values of a published vector. Official vectors are
// exercised by the conformance runner (conformance/, LFCP-017).

import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { type CborValue, cborMap, encode } from "../src/cbor/index.js";
import { principalDescriptorFromKeys, type Signer, signObject } from "../src/index.js";

/** 32 bytes counting up from `from` (mod 256). */
export const seq32 = (from: number): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);

function signer(seed: number, x25519: number): Signer {
  const key = importSigningKey(seq32(seed));
  return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(x25519))) };
}

/** Synthetic Principals A and B. */
export const ALICE = signer(1, 101);
export const BRUNO = signer(33, 133);

export const RESOURCE = seq32(200);
export const CONTROL_HEAD = seq32(64);

/** Data Unit payload fields (§26) for ALICE as the actor. */
export function dataUnitFields(actorSeq: number | bigint = 1): [number, CborValue][] {
  return [
    [0, RESOURCE],
    [1, 0],
    [2, ALICE.descriptor.principalId],
    [3, actorSeq],
    [4, null],
    [5, CONTROL_HEAD],
    [6, seq32(150).subarray(0, 24)],
  ];
}

export const DATA_UNIT_PAYLOAD = encode(cborMap(dataUnitFields()));
/** ALICE's signed Data Unit (actor sequence 1). */
export const DATA_UNIT = signObject(DATA_UNIT_PAYLOAD, ALICE);
