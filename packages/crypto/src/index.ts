/**
 * Cryptographic primitives for LFCP, as a thin wrapper over the audited
 * @noble libraries. No other package imports @noble directly.
 */
export const PACKAGE = "@openlfcp/crypto";

export { sha256 } from "./hash.js";
