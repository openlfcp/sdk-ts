import * as A from "@automerge/automerge";
import { dataEpoch, UINT64_MAX } from "@openlfcp/core";
import { describe, expect, it, vi } from "vitest";
import { checkCanonicalChange } from "../src/admission/canonical.js";
import {
  checkChange,
  decodedOf,
  frameChange,
  parsedOf,
  unframeChange,
} from "../src/admission/framing.js";
import { referenceHistoryOf } from "../src/admission/references.js";

const decoder = vi.hoisted(() => ({ error: undefined as Error | undefined }));
vi.mock("@automerge/automerge", async () => {
  const actual = await vi.importActual<typeof A>("@automerge/automerge");
  return {
    ...actual,
    decodeChange: (bytes: Uint8Array) => {
      if (decoder.error !== undefined) throw decoder.error;
      return actual.decodeChange(bytes);
    },
  };
});

describe("lossless uint64 values in SOP admission", () => {
  it.each([
    new Error("unrelated decoder error"),
    new RangeError("unrelated range error"),
    new TypeError("Error: 18446744073709551615 can't be represented as a JavaScript number"),
  ])("does not bypass an unrelated decoder failure when a bigint is present: %s (F5)", (error) => {
    const doc = A.change(A.init<Record<string, unknown>>(), { time: 0 }, (d) => {
      A.getBackend(d).put("_root", "epoch", dataEpoch(UINT64_MAX), "uint");
    });
    const bytes = A.getLastLocalChange(doc) as Uint8Array;
    decoder.error = error;
    try {
      expect(() => checkChange(bytes)).toThrow(
        expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" }),
      );
    } finally {
      decoder.error = undefined;
      A.free(doc);
    }
    expect(decodedOf(checkChange(bytes)).ops[0]).toMatchObject({ value: UINT64_MAX });
  });

  it("decodes full uint64 values without changing canonical bytes, with all references retained", () => {
    const d = A.change(A.init<Record<string, unknown>>({ actor: "aa" }), { time: 0 }, (d) => {
      d.label = new A.ImmutableString("large epoch");
      d.flag = true;
      d.list = [];
      const backend = A.getBackend(d);
      backend.put("_root", "epoch", dataEpoch(UINT64_MAX), "uint");
      backend.insert(A.getObjectId(d.list) as string, 0, dataEpoch(2n ** 53n + 1n), "uint");
    });
    const bytes = A.getAllChanges(d)[0] as Uint8Array;
    const c = checkChange(bytes);
    expect(unframeChange(frameChange(bytes)).hash).toBe(c.hash);
    expect(parsedOf(c).ops.some((op) => op.value === UINT64_MAX)).toBe(true);
    expect(decodedOf(c).ops).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: "epoch", datatype: "uint", value: UINT64_MAX }),
        expect.objectContaining({ key: "label", value: "large epoch" }),
        expect.objectContaining({
          elemId: "_head",
          insert: true,
          datatype: "uint",
          value: 2n ** 53n + 1n,
        }),
      ]),
    );
    expect(referenceHistoryOf(d).has(c.hash)).toBe(true);
    expect(A.getAllChanges(A.load(A.save(d)))[0]).toEqual(bytes);
    const corrupted = bytes.slice();
    corrupted[4] = (corrupted[4] as number) ^ 1;
    expect(() => checkChange(corrupted)).toThrow(/checksum/);
  });

  it("the canonical walk enforces the SOP sequence/time safe-integer bounds independently", () => {
    const leb = (n: bigint) => {
      const out: number[] = [];
      do {
        let b = Number(n & 127n);
        n >>= 7n;
        if (n) b |= 128;
        out.push(b);
      } while (n);
      return out;
    };
    for (const [seq, time] of [
      [2n ** 53n, 0n],
      [1n, 2n ** 53n],
    ] as const) {
      // Empty change: no deps, actor aa, seq/start/time, empty message/actors/columns.
      const body = [0, 1, 0xaa, ...leb(seq), 1, ...leb(time), 0, 0, 0];
      const bytes = Uint8Array.from([
        0x85,
        0x6f,
        0x4a,
        0x83,
        0,
        0,
        0,
        0,
        1,
        ...leb(BigInt(body.length)),
        ...body,
      ]);
      expect(() => checkCanonicalChange(bytes)).toThrow(/integer range/);
    }
  });
});
