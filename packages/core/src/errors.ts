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
  | "PRINCIPAL_ID_MISMATCH";

/** Error with a stable machine-readable `code`; the message is for humans only. */
export class LfcpError extends Error {
  readonly code: LfcpErrorCode;

  constructor(code: LfcpErrorCode, message: string) {
    super(message);
    this.name = "LfcpError";
    this.code = code;
  }
}
