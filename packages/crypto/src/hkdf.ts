import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { LfcpError } from "@openlfcp/core";

// HKDF-SHA256 (RFC 5869), the KDF of the LFCP crypto profile (LFCP-WIRE-01 §9).

const MAX_OUTPUT = 255 * 32;

/** HKDF-Extract(salt, IKM) with SHA-256: the 32-byte PRK. The result is secret material. */
export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  if (!(salt instanceof Uint8Array) || !(ikm instanceof Uint8Array))
    throw new LfcpError("INVALID_LENGTH", "HKDF-Extract takes byte strings");
  return extract(nobleSha256, ikm, salt);
}

/** HKDF-Expand(PRK, info, L) with SHA-256. The result is secret material. */
export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (!(prk instanceof Uint8Array) || prk.length < 32 || !(info instanceof Uint8Array))
    throw new LfcpError(
      "INVALID_LENGTH",
      "HKDF-Expand takes a PRK of at least 32 bytes and info bytes",
    );
  if (!Number.isSafeInteger(length) || length < 1 || length > MAX_OUTPUT)
    throw new LfcpError("OUT_OF_RANGE", `HKDF-Expand length must be in 1..${MAX_OUTPUT}`);
  return expand(nobleSha256, prk, info, length);
}
