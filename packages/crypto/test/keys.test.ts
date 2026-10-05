import { fromHex, LfcpError, toBase64url, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  type AgreementKeyPair,
  exportSecretKeyBytes,
  generateAgreementKeyPair,
  generateSigningKeyPair,
  importAgreementKey,
  importSigningKey,
  type SigningKeyPair,
  verifyEd25519,
} from "../src/index.js";

// Public test fixtures, never use in production:
// LFCP-TEST-VECTORS-01 (spec tag mvp-0.1-baseline) case principal_owner inputs.ed25519_seed / inputs.x25519_private.
const OWNER_ED25519_SEED = "3df1a3457c0fc0d78c89cb4cdcd3c5912322cdc199f7a35a843e0e82ea9aa38b";
const OWNER_X25519_PRIVATE = "792bb0d4a2752e97583e603235b07ece323d2f65f1285907fc20c95da91ed874";

const message = Uint8Array.from("LFCP test message", (c) => c.charCodeAt(0));
const structuredClone = (globalThis as unknown as { structuredClone: (v: unknown) => unknown })
  .structuredClone;
const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : "not-an-LfcpError";
  }
  return undefined;
};

/** Every textual form of the secret that must never appear anywhere. */
function secretForms(secretHex: string): string[] {
  const bytes = fromHex(secretHex);
  const b64url = toBase64url(bytes);
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  return [secretHex, secretHex.toUpperCase(), b64url, b64, bytes.join(","), bytes.join(", ")];
}
function expectNoSecret(text: string, secretHex: string): void {
  for (const form of secretForms(secretHex)) expect(text).not.toContain(form);
}

describe("Ed25519 signing keys", () => {
  it("generated keys sign and verify", () => {
    const key = generateSigningKeyPair();
    const signature = key.sign(message);
    expect(signature).toHaveLength(64);
    expect(key.publicKey).toHaveLength(32);
    expect(verifyEd25519(key.publicKey, message, signature)).toBe(true);
  });

  it("rejects a tampered signature, a tampered message and the wrong key", () => {
    const key = generateSigningKeyPair();
    const signature = key.sign(message);
    const badSig = Uint8Array.from(signature);
    badSig[10] = (badSig[10] as number) ^ 1;
    const badMsg = Uint8Array.from(message);
    badMsg[0] = (badMsg[0] as number) ^ 1;
    expect(verifyEd25519(key.publicKey, message, badSig)).toBe(false);
    expect(verifyEd25519(key.publicKey, badMsg, signature)).toBe(false);
    expect(verifyEd25519(generateSigningKeyPair().publicKey, message, signature)).toBe(false);
    expect(verifyEd25519(key.publicKey, message, signature.subarray(0, 63))).toBe(false);
    expect(verifyEd25519(new Uint8Array(31), message, signature)).toBe(false);
  });

  it("imports and exports the 32-byte seed, copying in both directions", () => {
    const seed = fromHex(OWNER_ED25519_SEED);
    const key = importSigningKey(seed);
    seed.fill(0);
    const exported = exportSecretKeyBytes(key);
    expect(toHex(exported)).toBe(OWNER_ED25519_SEED);
    exported.fill(0);
    expect(toHex(exportSecretKeyBytes(key))).toBe(OWNER_ED25519_SEED);
    expect(toHex(importSigningKey(fromHex(OWNER_ED25519_SEED)).sign(message))).toBe(
      toHex(key.sign(message)),
    );
  });

  it.each([0, 31, 33, 64])("rejects a %i-byte seed", (n) => {
    expect(codeOf(() => importSigningKey(new Uint8Array(n)))).toBe("INVALID_LENGTH");
  });
});

describe("X25519 agreement keys", () => {
  it("two generated pairs agree on a 32-byte shared secret", () => {
    const a = generateAgreementKeyPair();
    const b = generateAgreementKeyPair();
    const ab = a.sharedSecret(b.publicKey);
    expect(ab).toHaveLength(32);
    expect(toHex(ab)).toBe(toHex(b.sharedSecret(a.publicKey)));
    expect(toHex(ab)).not.toBe(toHex(a.sharedSecret(generateAgreementKeyPair().publicKey)));
  });

  it("is generated independently of the signing key", () => {
    const signing = generateSigningKeyPair();
    const agreement = generateAgreementKeyPair();
    expect(toHex(exportSecretKeyBytes(agreement))).not.toBe(toHex(exportSecretKeyBytes(signing)));
    expect(toHex(agreement.publicKey)).not.toBe(toHex(signing.publicKey));
  });

  it("imports and exports the 32-byte secret", () => {
    const key = importAgreementKey(fromHex(OWNER_X25519_PRIVATE));
    expect(toHex(exportSecretKeyBytes(key))).toBe(OWNER_X25519_PRIVATE);
  });

  it("rejects bad lengths and a low-order peer key", () => {
    const key = generateAgreementKeyPair();
    expect(codeOf(() => importAgreementKey(new Uint8Array(31)))).toBe("INVALID_LENGTH");
    expect(codeOf(() => key.sharedSecret(new Uint8Array(31)))).toBe("INVALID_LENGTH");
    expect(codeOf(() => key.sharedSecret(new Uint8Array(32)))).toBe("CRYPTO_FAILURE");
  });
});

describe("secrets stay out of diagnostics", () => {
  const signing = importSigningKey(fromHex(OWNER_ED25519_SEED));
  const agreement = importAgreementKey(fromHex(OWNER_X25519_PRIVATE));
  const cases: [string, SigningKeyPair | AgreementKeyPair, string][] = [
    ["SigningKeyPair", signing, OWNER_ED25519_SEED],
    ["AgreementKeyPair", agreement, OWNER_X25519_PRIVATE],
  ];

  it.each(cases)("%s prints [redacted] through JSON, String and inspect", (_name, key, secret) => {
    expect(JSON.stringify(key)).toBe('"[redacted]"');
    expect(String(key)).toBe("[redacted]");
    expect(`${key}`).toBe("[redacted]");
    const inspect = (key as unknown as Record<symbol, () => string>)[
      Symbol.for("nodejs.util.inspect.custom")
    ];
    expect(inspect?.call(key)).toBe("[redacted]");
    expectNoSecret(JSON.stringify({ wrapped: key, list: [key] }), secret);
  });

  it.each(cases)("%s has no enumerable, own or cloned secret bytes", (_name, key, secret) => {
    const own = [
      ...Object.getOwnPropertyNames(key).map((n) => (key as unknown as Record<string, unknown>)[n]),
      ...Object.getOwnPropertySymbols(key).map(
        (s) => (key as unknown as Record<symbol, unknown>)[s],
      ),
    ];
    for (const value of own) {
      if (value instanceof Uint8Array) expect(toHex(value)).not.toBe(secret);
    }
    expect(Object.keys(key)).toEqual(["publicKey"]);
    const clone = structuredClone(key) as unknown as Record<string, unknown>;
    expectNoSecret(
      JSON.stringify(clone, (_k, v) => (v instanceof Uint8Array ? toHex(v) : v)),
      secret,
    );
  });

  it("errors never contain key bytes", () => {
    const errors: unknown[] = [];
    const capture = (fn: () => unknown) => {
      try {
        fn();
      } catch (e) {
        errors.push(e);
      }
    };
    // A seed that is one byte too long, starting with the real secret.
    capture(() => importSigningKey(Uint8Array.from([...fromHex(OWNER_ED25519_SEED), 0])));
    capture(() => importAgreementKey(fromHex(OWNER_X25519_PRIVATE).subarray(0, 31)));
    capture(() => agreement.sharedSecret(new Uint8Array(32)));
    expect(errors).toHaveLength(3);
    for (const e of errors) {
      expect(e).toBeInstanceOf(LfcpError);
      const error = e as LfcpError & { cause?: unknown };
      expect(error.cause).toBeUndefined();
      const text = [
        error.message,
        String(error),
        error.stack ?? "",
        JSON.stringify(error),
        JSON.stringify(
          Object.getOwnPropertyNames(error).map(
            (n) => (error as unknown as Record<string, unknown>)[n],
          ),
        ),
      ].join("\n");
      expectNoSecret(text, OWNER_ED25519_SEED);
      expectNoSecret(text, OWNER_X25519_PRIVATE);
    }
  });
});
