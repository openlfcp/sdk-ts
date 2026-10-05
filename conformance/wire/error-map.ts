// SDK error code -> LFCP-WIRE-01 §62 code for a received persistent object
// outside HELLO/AUTH, as decided in ADR 0001 (N1, N4, N6, N7, CB1-CB3, P1,
// P2) and documented on each code in packages/core/src/errors.ts.

import { LfcpError } from "@openlfcp/core";

const WIRE_CODE: Readonly<Record<string, string>> = {
  COSE_MALFORMED: "MALFORMED_MESSAGE",
  INVALID_STRUCTURE: "MALFORMED_MESSAGE",
  UNSUPPORTED_VALUE: "MALFORMED_MESSAGE",
  INVALID_PRINCIPAL_DESCRIPTOR: "MALFORMED_MESSAGE",
  // AUTH_FAILED inside HELLO/AUTH (P2); no vector here is a handshake message.
  PRINCIPAL_ID_MISMATCH: "MALFORMED_MESSAGE",
};

/** A failed verifySignedObject (wrong kid or bad signature): G1/N2. */
export const SIGNATURE_FAILURE = "INVALID_SIGNATURE";

/** The wire code for an error thrown while decoding a received object. Unmapped errors are returned as "UNMAPPED:<detail>" so they never match a vector code. */
export function wireCodeOf(e: unknown): string {
  if (!(e instanceof LfcpError)) return `UNMAPPED:${e instanceof Error ? e.message : String(e)}`;
  if (e.code.startsWith("CBOR_")) return "MALFORMED_MESSAGE";
  return WIRE_CODE[e.code] ?? `UNMAPPED:${e.code}`;
}
