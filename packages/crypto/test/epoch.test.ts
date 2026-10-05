import {
  actorSequence,
  dataEpoch,
  fromHex,
  LfcpError,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
  toBase64url,
  toHex,
  uint64BE,
} from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  dataUnitNonce,
  dekCommitment,
  deriveActorDataKey,
  deriveSnapshotKey,
  exportSecretKeyBytes,
  generateResourceDEK,
  hkdfExpand,
  hkdfExtract,
  importResourceDEK,
  sha256,
  snapshotNonce,
} from "../src/index.js";

// Synthetic values; the published DEK commitments, actor keys, Snapshot
// keys and nonces are checked by the conformance runner (LFCP-017/018).

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};
const seq32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const cat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => [...p]));

const R: ResourceId = resourceId(seq32(10));
const R2: ResourceId = resourceId(seq32(11));
const A: PrincipalId = principalId(seq32(50));
const B: PrincipalId = principalId(seq32(51));
const DEK_BYTES = seq32(90);
const DEK = importResourceDEK(DEK_BYTES);
const E0 = dataEpoch(0n);
const E1 = dataEpoch(1n);

describe("HKDF-SHA256", () => {
  it("matches RFC 5869 test case 1", () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = fromHex("000102030405060708090a0b0c");
    const info = fromHex("f0f1f2f3f4f5f6f7f8f9");
    const prk = hkdfExtract(salt, ikm);
    expect(toHex(prk)).toBe("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    expect(toHex(hkdfExpand(prk, info, 42))).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("rejects bad lengths", () => {
    expect(codeOf(() => hkdfExpand(new Uint8Array(31), new Uint8Array(0), 32))).toBe(
      "INVALID_LENGTH",
    );
    expect(codeOf(() => hkdfExpand(new Uint8Array(32), new Uint8Array(0), 0))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => hkdfExpand(new Uint8Array(32), new Uint8Array(0), 255 * 32 + 1))).toBe(
      "OUT_OF_RANGE",
    );
  });
});

describe("Resource DEK (§11)", () => {
  it("1. is exactly 32 bytes", () => {
    expect(exportSecretKeyBytes(generateResourceDEK())).toHaveLength(32);
    expect(codeOf(() => importResourceDEK(new Uint8Array(31)))).toBe("INVALID_LENGTH");
    expect(codeOf(() => importResourceDEK(new Uint8Array(33)))).toBe("INVALID_LENGTH");
  });

  it("2. generated DEKs are random, not a fixed constant", () => {
    const seen = new Set(
      Array.from({ length: 8 }, () => toHex(exportSecretKeyBytes(generateResourceDEK()))),
    );
    expect(seen.size).toBe(8);
  });

  it("copies its input on import and on export", () => {
    const bytes = seq32(1);
    const dek = importResourceDEK(bytes);
    bytes.fill(0);
    const out = exportSecretKeyBytes(dek);
    out.fill(0);
    expect(toHex(exportSecretKeyBytes(dek))).toBe(toHex(seq32(1)));
  });
});

describe("DEK commitment (§11)", () => {
  it('3. is SHA-256(ASCII("LFCP-DEK-v1") || resource_id || uint64_be(E) || DEK)', () => {
    const input = cat(ascii("LFCP-DEK-v1"), R, fromHex("0000000000000001"), DEK_BYTES);
    expect(toHex(dekCommitment(R, E1, DEK))).toBe(toHex(sha256(input)));
  });

  it("4, 5, 6. changes with the Resource, the epoch and the DEK", () => {
    const base = toHex(dekCommitment(R, E0, DEK));
    expect(toHex(dekCommitment(R2, E0, DEK))).not.toBe(base);
    expect(toHex(dekCommitment(R, E1, DEK))).not.toBe(base);
    expect(toHex(dekCommitment(R, E0, importResourceDEK(seq32(91))))).not.toBe(base);
  });

  it("uses the raw 32-byte Resource ID, never a text form", () => {
    expect(codeOf(() => dekCommitment(ascii(toBase64url(R)) as ResourceId, E0, DEK))).toBe(
      "INVALID_LENGTH",
    );
  });
});

describe("actor key (§12) and Snapshot key (§29.1.1)", () => {
  const manual = (label: string, epoch: bigint, who: Uint8Array) =>
    toHex(hkdfExpand(hkdfExtract(cat(R, uint64BE(epoch)), DEK_BYTES), cat(ascii(label), who), 32));

  it('7. actor_key = HKDF-Expand(HKDF-Extract(R || uint64_be(E), DEK), "LFCP-DATA-KEY-v1" || A, 32)', () => {
    expect(toHex(exportSecretKeyBytes(deriveActorDataKey(DEK, R, E1, A)))).toBe(
      manual("LFCP-DATA-KEY-v1", 1n, A),
    );
  });

  it('snapshot_key uses the label "LFCP-SNAPSHOT-KEY-v1" and the publisher', () => {
    const key = toHex(exportSecretKeyBytes(deriveSnapshotKey(DEK, R, E1, A)));
    expect(key).toBe(manual("LFCP-SNAPSHOT-KEY-v1", 1n, A));
    expect(key).not.toBe(toHex(exportSecretKeyBytes(deriveActorDataKey(DEK, R, E1, A))));
  });

  it("8. different Principals get different actor keys for the same DEK and epoch", () => {
    expect(toHex(exportSecretKeyBytes(deriveActorDataKey(DEK, R, E0, A)))).not.toBe(
      toHex(exportSecretKeyBytes(deriveActorDataKey(DEK, R, E0, B))),
    );
  });

  it("9. a different epoch gives a different actor key", () => {
    expect(toHex(exportSecretKeyBytes(deriveActorDataKey(DEK, R, E0, A)))).not.toBe(
      toHex(exportSecretKeyBytes(deriveActorDataKey(DEK, R, E1, A))),
    );
  });

  it("uses the raw 32-byte Principal ID, never a text form", () => {
    expect(codeOf(() => deriveActorDataKey(DEK, R, E0, ascii(toHex(A)) as PrincipalId))).toBe(
      "INVALID_LENGTH",
    );
  });
});

describe("nonces (§12, §29.1.2)", () => {
  it.each([
    [1n, "000000000000000000000001"],
    [2n, "000000000000000000000002"],
    [256n, "000000000000000000000100"],
    [2n ** 32n, "000000000000000100000000"],
    [2n ** 53n, "000000000020000000000000"],
    [2n ** 64n - 1n, "00000000ffffffffffffffff"],
  ])("10, 11. Data Unit nonce for seq %s", (seq, hex) => {
    const nonce = dataUnitNonce(actorSequence(seq));
    expect(nonce).toHaveLength(12);
    expect(toHex(nonce)).toBe(hex);
  });

  it("Snapshot nonce has the same layout and allows sequence 0", () => {
    expect(toHex(snapshotNonce(0n))).toBe("000000000000000000000000");
    expect(toHex(snapshotNonce(2n ** 64n - 1n))).toBe("00000000ffffffffffffffff");
  });
});

describe("12. uint64 boundaries", () => {
  it("accepts epochs 0, 1, 2^32, 2^53 and 2^64-1", () => {
    for (const e of [0n, 1n, 2n ** 32n, 2n ** 53n, 2n ** 64n - 1n]) {
      expect(dekCommitment(R, dataEpoch(e), DEK)).toHaveLength(32);
      expect(exportSecretKeyBytes(deriveActorDataKey(DEK, R, dataEpoch(e), A))).toHaveLength(32);
    }
  });

  it("rejects epoch 2^64 and sequences 0 and 2^64, without truncating", () => {
    const tooBig = (2n ** 64n) as never;
    expect(codeOf(() => dekCommitment(R, tooBig, DEK))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => deriveActorDataKey(DEK, R, tooBig, A))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => deriveSnapshotKey(DEK, R, -1n as never, A))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => dataUnitNonce(0n as never))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => dataUnitNonce(tooBig))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => dataUnitNonce((2 ** 53) as never))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => snapshotNonce(tooBig))).toBe("OUT_OF_RANGE");
  });
});

describe("15. secrets stay out of diagnostics", () => {
  const secrets = [
    ["ResourceDEK", DEK],
    ["ActorDataKey", deriveActorDataKey(DEK, R, E0, A)],
    ["SnapshotKey", deriveSnapshotKey(DEK, R, E0, A)],
  ] as const;

  it.each(secrets)(
    "%s prints [redacted] through JSON, String, templates and inspect",
    (_n, key) => {
      const bytes = exportSecretKeyBytes(key);
      const inspect = (key as unknown as Record<symbol, () => string>)[
        Symbol.for("nodejs.util.inspect.custom")
      ];
      const shown = [
        JSON.stringify(key),
        JSON.stringify({ key }),
        String(key),
        `${key}`,
        inspect?.call(key) ?? "",
        JSON.stringify(Object.values(key)),
      ].join("\n");
      expect(shown).toContain("[redacted]");
      expect(shown).not.toContain(toHex(bytes));
      expect(shown).not.toContain(toBase64url(bytes));
      expect(Object.values(key).some((v) => v instanceof Uint8Array)).toBe(false);
    },
  );

  it("errors never contain key bytes", () => {
    const errors: unknown[] = [];
    for (const attempt of [
      () => importResourceDEK(Uint8Array.from([...DEK_BYTES, 0])),
      () => importResourceDEK(DEK_BYTES.subarray(0, 31)),
      () => deriveActorDataKey(DEK, R, (2n ** 64n) as never, A),
    ]) {
      try {
        attempt();
      } catch (e) {
        errors.push(e);
      }
    }
    expect(errors).toHaveLength(3);
    for (const e of errors) {
      const text = [String(e), (e as Error).stack ?? "", JSON.stringify(e)].join("\n");
      expect(text).not.toContain(toHex(DEK_BYTES));
      expect(text).not.toContain(toHex(DEK_BYTES.subarray(0, 16)));
    }
  });
});
