import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

interface NodeHashLike {
  hash(algorithm: "sha256", data: Uint8Array, encoding: "buffer"): Uint8Array;
}

/** See ed25519-native.ts: the host's global is reached by a constant key, no `node:` import. */
const HOST_PROCESS_GLOBAL = "process";

/**
 * Node's one-shot hash (`crypto.hash`), when the host has it: it allocates only the digest, where
 * noble builds a hasher (state, block and schedule buffers) per call, which a cold connect to C
 * pays for every change of a year of history. Probed against noble's answer before it is used;
 * browsers and WebViews use noble.
 */
function loadNativeSha256(): ((data: Uint8Array) => Uint8Array) | undefined {
  const proc = (globalThis as Record<string, unknown>)[HOST_PROCESS_GLOBAL] as
    | { getBuiltinModule?: (id: string) => unknown }
    | undefined;
  const mod = proc?.getBuiltinModule?.("node:crypto") as Partial<NodeHashLike> | undefined;
  if (typeof mod?.hash !== "function") return undefined;
  const native = (data: Uint8Array): Uint8Array => {
    const d = (mod as NodeHashLike).hash("sha256", data, "buffer");
    // A view of its own bytes, as noble returns: never a pooled Buffer's slice.
    return new Uint8Array(d.buffer, d.byteOffset, d.byteLength).slice();
  };
  try {
    for (const probe of [new Uint8Array(0), new Uint8Array(200).map((_, i) => i)]) {
      const a = native(probe);
      const b = nobleSha256(probe);
      if (a.length !== 32 || !a.every((x, i) => x === b[i])) return undefined;
    }
  } catch {
    return undefined;
  }
  return native;
}

const nativeSha256 = loadNativeSha256();

/** SHA-256 (FIPS 180-4), the `hash32` function of LFCP-WIRE-01 §5.3. */
export function sha256(data: Uint8Array): Uint8Array {
  return nativeSha256 !== undefined ? nativeSha256(data) : nobleSha256(data);
}
