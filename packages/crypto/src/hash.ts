import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

/** SHA-256 (FIPS 180-4), the `hash32` function of LFCP-WIRE-01 §5.3. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}
