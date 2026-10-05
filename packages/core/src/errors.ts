/**
 * Validation codes raised by the SDK while checking local input.
 *
 * These are SDK-internal codes, not the LFCP-WIRE-01 §62 wire error codes
 * that are sent in NACK and ERROR messages.
 */
export type LfcpErrorCode =
  | "INVALID_LENGTH"
  | "INVALID_HEX"
  | "INVALID_BASE64URL"
  | "INVALID_UUIDV7"
  | "NO_SECURE_RANDOM";

/** Error with a stable machine-readable `code`; the message is for humans only. */
export class LfcpError extends Error {
  readonly code: LfcpErrorCode;

  constructor(code: LfcpErrorCode, message: string) {
    super(message);
    this.name = "LfcpError";
    this.code = code;
  }
}
