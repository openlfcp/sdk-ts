/**
 * Validation codes raised by the SDK while checking local input.
 *
 * These are SDK-internal codes, not the LFCP-WIRE-01 §62 wire error codes
 * that are sent in NACK and ERROR messages. At the wire boundary, every
 * `CBOR_*` failure of a received persistent object surfaces as
 * `MALFORMED_MESSAGE` (LFCP-WIRE-01 §5.2).
 */
export type LfcpErrorCode =
  | "INVALID_LENGTH"
  | "INVALID_HEX"
  | "INVALID_BASE64URL"
  | "INVALID_UUIDV7"
  | "NO_SECURE_RANDOM"
  /** Valid CBOR, but not the deterministic encoding (non-shortest head, unsorted map keys). */
  | "CBOR_NON_CANONICAL"
  /** A map contains the same key twice. */
  | "CBOR_DUPLICATE_KEY"
  /** An indefinite-length item or a break code. */
  | "CBOR_INDEFINITE_LENGTH"
  /** A type LFCP does not use: tags, floats, undefined, other simple values, reserved encodings, unsupported JS values. */
  | "CBOR_UNSUPPORTED_TYPE"
  /** An integer outside the CBOR range -2^64 .. 2^64-1, or an unsafe JS number. */
  | "CBOR_OUT_OF_RANGE"
  /** The input ends inside an item. */
  | "CBOR_TRUNCATED"
  /** Bytes remain after the single top-level item. */
  | "CBOR_TRAILING_BYTES"
  /** A text string that is not well-formed UTF-8 (or a JS string with lone surrogates). */
  | "CBOR_INVALID_UTF8"
  /** Nesting deeper than the SDK's safety limit. */
  | "CBOR_TOO_DEEP"
  /** A cryptographic operation failed (e.g. a low-order X25519 public key). Never carries key bytes. */
  | "CRYPTO_FAILURE"
  /** A Principal Descriptor has the wrong shape, field set, key lengths or encoding (LFCP-WIRE-01 §7). */
  | "INVALID_PRINCIPAL_DESCRIPTOR"
  /** A Principal Descriptor's ID is not the §7 hash of its public keys. */
  | "PRINCIPAL_ID_MISMATCH"
  /**
   * A signed object is not the canonical LFCP COSE_Sign1 shape (LFCP-WIRE-01 §10):
   * tagged, wrong arity, extra or missing protected parameters, non-empty
   * unprotected header, detached payload or a non-64-byte signature. Surfaces
   * on the wire as MALFORMED_MESSAGE.
   */
  | "COSE_MALFORMED"
  /** The signing key does not belong to the Principal Descriptor it is used with. */
  | "COSE_SIGNER_MISMATCH"
  /**
   * Deterministic CBOR that does not have the structure a Wire rule requires:
   * wrong field set, field type or byte-string length, or a broken structural
   * rule (actor sequence 0 §8, a non-canonical actor-have or frontier §28.1,
   * §28.2, Genesis not at control_seq 0 with a null link §13.1). Surfaces on
   * the wire as MALFORMED_MESSAGE.
   */
  | "INVALID_STRUCTURE"
  /**
   * A well-formed value that LFCP reserves but this version does not define:
   * a core Control Record type 9–31 (§14, "MUST cause validation failure").
   * §14 names no wire code; until the spec does, it surfaces as
   * MALFORMED_MESSAGE.
   */
  | "UNSUPPORTED_VALUE"
  /**
   * An integer outside the range a construction requires: a Data Epoch or
   * uint64 value outside 0..2^64-1, an actor sequence outside 1..2^64-1, or
   * a number that is not a safe integer. Values are never truncated.
   * SDK-local; decoded wire values are range-checked by the decoders.
   */
  | "OUT_OF_RANGE"
  /**
   * A local attempt to use an actor sequence twice for one (Resource,
   * Principal) (LFCP-WIRE-01 §8, §12: nonce reuse). SDK-local; never sent.
   */
  | "SEQUENCE_REUSE"
  /**
   * A Control Chain that is not one valid linear chain (LFCP-WIRE-01 §13,
   * §13.1): no Genesis, a sequence that is not previous + 1, a link that is
   * not the previous record ID, a different Resource, a record that links
   * to nothing, or an issuer whose descriptor cannot be resolved. Surfaces
   * on the wire as INVALID_CONTROL_CHAIN (the unresolved-issuer case
   * provisionally; MISSING_DEPENDENCY is the alternative).
   */
  | "INVALID_CONTROL_CHAIN"
  /** A signed object whose kid or signature is wrong for its expected signer (G1/N2). INVALID_SIGNATURE on the wire. */
  | "INVALID_SIGNATURE"
  /** A record the authorization policy (LFCP-021) refuses. AUTHORIZATION_FAILED on the wire. */
  | "AUTHORIZATION_FAILED";

/** Error with a stable machine-readable `code`; the message is for humans only. */
export class LfcpError extends Error {
  readonly code: LfcpErrorCode;

  constructor(code: LfcpErrorCode, message: string) {
    super(message);
    this.name = "LfcpError";
    this.code = code;
  }
}
