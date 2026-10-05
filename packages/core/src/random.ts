import { LfcpError } from "./errors.js";

/** `length` bytes from the platform CSPRNG (globalThis.crypto.getRandomValues), or NO_SECURE_RANDOM. */
export function secureRandom(length: number): Uint8Array {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (typeof c?.getRandomValues !== "function") {
    throw new LfcpError("NO_SECURE_RANDOM", "globalThis.crypto.getRandomValues is not available");
  }
  return c.getRandomValues(new Uint8Array(length));
}
