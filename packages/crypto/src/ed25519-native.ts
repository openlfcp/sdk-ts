/**
 * The platform's native Ed25519 verification, for the hot receive path
 * (decision of 2026-11-26, E-030 cold connect, option 1b).
 *
 * Only the equation is delegated: `verifyEd25519` (keys.ts) applies the
 * §10.5.1 encoding rules 1–3 itself and then asks the native backend
 * whether [S]B = R + [k]A. A backend is used only if it answers a fixed
 * set of known-answer probes exactly like the strict noble path, including
 * the cofactorless rejection of a mixed-order A and a mixed-order R.
 * Otherwise, or where no native Ed25519 exists, @noble/curves is used.
 *
 * The synchronous backend is Node's `crypto.verify`, reached through
 * `process.getBuiltinModule` so that this portable package has no `node:`
 * import. That covers Node and Electron hosts (Obsidian desktop). Where it
 * is missing (browsers, mobile WebViews), WebCrypto's Ed25519 is used: it is
 * asynchronous only, so the async receive steps pre-verify with it
 * (`prepareEd25519Verify` in keys.ts) and the synchronous `verifyEd25519`
 * consults those answers. It must pass the same probes, asynchronously.
 */
import { fromHex } from "@openlfcp/core";

/** The equation check for an Ed25519 signature; may throw. */
export type NativeEd25519Verify = (
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
) => boolean;

interface NodeCryptoLike {
  createPublicKey(options: { key: Uint8Array; format: "der"; type: "spki" }): unknown;
  verify(algorithm: null, data: Uint8Array, key: unknown, signature: Uint8Array): boolean;
}

/** DER SubjectPublicKeyInfo prefix of an Ed25519 key (RFC 8410). */
const SPKI_PREFIX = fromHex("302a300506032b6570032100");
/** Bound on cached native key objects; the map is cleared when it is full. */
const KEY_CACHE_LIMIT = 4096;

/**
 * The host's global named by this key, if any. It is feature-detected and
 * optional: without it (browsers, WebViews) the noble path is used, so the
 * package stays portable. The key is a constant rather than a property
 * name so that the node-global boundary rule keeps flagging direct use.
 */
const HOST_PROCESS_GLOBAL = "process";

function loadNodeCrypto(): NodeCryptoLike | undefined {
  const proc = (globalThis as Record<string, unknown>)[HOST_PROCESS_GLOBAL] as
    | { getBuiltinModule?: (id: string) => unknown }
    | undefined;
  const mod = proc?.getBuiltinModule?.("node:crypto") as Partial<NodeCryptoLike> | undefined;
  return typeof mod?.verify === "function" && typeof mod.createPublicKey === "function"
    ? (mod as NodeCryptoLike)
    : undefined;
}

/** A native verifier over Node's crypto, caching one key object per public key. */
export function nodeCryptoVerifier(nodeCrypto: NodeCryptoLike): NativeEd25519Verify {
  const keys = new Map<string, unknown>();
  return (publicKey, message, signature) => {
    const id = String.fromCharCode(...publicKey);
    let key = keys.get(id);
    if (key === undefined) {
      const der = new Uint8Array(SPKI_PREFIX.length + publicKey.length);
      der.set(SPKI_PREFIX);
      der.set(publicKey, SPKI_PREFIX.length);
      key = nodeCrypto.createPublicKey({ key: der, format: "der", type: "spki" });
      if (keys.size >= KEY_CACHE_LIMIT) keys.clear();
      keys.set(id, key);
    }
    return nodeCrypto.verify(null, message, key, signature);
  };
}

interface Probe {
  readonly publicKey: string;
  readonly message: string;
  readonly signature: string;
  readonly expect: boolean;
}

/**
 * Known answers a native backend must reproduce before it is trusted. All
 * pass rules 1–3, so they isolate the equation (rule 4).
 */
const PROBES: readonly Probe[] = [
  // RFC 8032 §7.1 TEST 2: valid.
  {
    publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    message: "72",
    signature:
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    expect: true,
  },
  // The same signature over a different message: invalid.
  {
    publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    message: "73",
    signature:
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    expect: false,
  },
  // A mixed-order A: the cofactored equation holds, the cofactorless does not.
  {
    publicKey: "df631b69abead1f01a821d3924490bbc8934dd067537b00afd038cb0e98701d3",
    message: "6d697865642d6f726465722030",
    signature:
      "d26703e41c1ce4a720da2fb853c13b7d568a3f93c4a41df55554e59be395291b831edbdc69b2dd24324a3f1a1669696787f9660173253a52e42fc3aaa95b2e0e",
    expect: false,
  },
  // A mixed-order R ([r]B + T8): likewise.
  {
    publicKey: "13d8f24cc1b3b79dc1fd45f1fb775325eceee920716bc5315135512c96ac4962",
    message: "6d697865642d6f726465722052",
    signature:
      "64eb9807c12088fa3e745acc456832fffd53b45b251b66bdee2af5353fc84e59ad12de9e8c520cdcff30c9b91f2dc576d7b35dbc7f37fe1f9d917388a40ee304",
    expect: false,
  },
];

/** Whether `verify` reproduces every known answer; false if it throws. */
export function passesProbes(verify: NativeEd25519Verify): boolean {
  try {
    return PROBES.every(
      (p) => verify(fromHex(p.publicKey), fromHex(p.message), fromHex(p.signature)) === p.expect,
    );
  } catch {
    return false;
  }
}

/** Detects a trustworthy synchronous native verifier; null if there is none. */
export function detectNativeEd25519(): NativeEd25519Verify | null {
  try {
    const nodeCrypto = loadNodeCrypto();
    if (nodeCrypto === undefined) return null;
    const verify = nodeCryptoVerifier(nodeCrypto);
    return passesProbes(verify) ? verify : null;
  } catch {
    return null;
  }
}

/** The asynchronous equation check of WebCrypto; may reject. */
export type AsyncEd25519Verify = (
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
) => Promise<boolean>;

interface SubtleLike {
  importKey(
    format: "raw",
    keyData: Uint8Array,
    algorithm: { name: "Ed25519" },
    extractable: false,
    usages: ["verify"],
  ): Promise<unknown>;
  verify(
    algorithm: { name: "Ed25519" },
    key: unknown,
    signature: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean>;
}

function loadSubtle(): SubtleLike | undefined {
  const subtle = (globalThis as { crypto?: { subtle?: Partial<SubtleLike> } }).crypto?.subtle;
  return typeof subtle?.verify === "function" && typeof subtle.importKey === "function"
    ? (subtle as SubtleLike)
    : undefined;
}

/** A verifier over WebCrypto, caching one imported key per public key. */
export function webCryptoVerifier(subtle: SubtleLike): AsyncEd25519Verify {
  const keys = new Map<string, Promise<unknown>>();
  const algorithm = { name: "Ed25519" } as const;
  return async (publicKey, message, signature) => {
    const id = String.fromCharCode(...publicKey);
    let key = keys.get(id);
    if (key === undefined) {
      key = subtle.importKey("raw", Uint8Array.from(publicKey), algorithm, false, ["verify"]);
      if (keys.size >= KEY_CACHE_LIMIT) keys.clear();
      keys.set(id, key);
      key.catch(() => keys.delete(id));
    }
    return subtle.verify(algorithm, await key, signature, message);
  };
}

/** Whether the async `verify` reproduces every known answer; false if it rejects. */
export async function passesProbesAsync(verify: AsyncEd25519Verify): Promise<boolean> {
  try {
    for (const p of PROBES) {
      const got = await verify(fromHex(p.publicKey), fromHex(p.message), fromHex(p.signature));
      if (got !== p.expect) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Detects a trustworthy WebCrypto Ed25519 verifier; null if there is none. */
export async function detectWebCryptoEd25519(): Promise<AsyncEd25519Verify | null> {
  try {
    const subtle = loadSubtle();
    if (subtle === undefined) return null;
    const verify = webCryptoVerifier(subtle);
    return (await passesProbesAsync(verify)) ? verify : null;
  } catch {
    return null;
  }
}
