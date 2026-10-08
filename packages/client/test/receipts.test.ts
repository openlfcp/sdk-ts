// Commit receipts (LFCP-02-025, SDK-SECTIONS-INTEGRATION-01 §3): the
// canonical intents hash and the receipt marks.

import { dataUnitId, resourceId } from "@openlfcp/core";
import { InMemoryLfcpStorage } from "@openlfcp/storage";
import { describe, expect, it } from "vitest";
import { intentsHash, type Receipt, receiptOf, releaseReceipt } from "../src/index.js";
import { receiptWrite } from "../src/receipts.js";

describe("intentsHash (§3.3)", () => {
  it("is the same for the same intents whatever the key order, and leaves absent fields out", () => {
    const a = [
      {
        intent: "text.edit",
        id: "n",
        base: "h",
        edits: [{ index: 1, deleteCount: 0, insert: "x" }],
      },
    ];
    const b = [
      {
        edits: [{ insert: "x", deleteCount: 0, index: 1 }],
        base: "h",
        id: "n",
        intent: "text.edit",
        extra: undefined,
      },
    ];
    expect(intentsHash(a)).toBe(intentsHash(b));
    expect(intentsHash(a)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("differs for different intents, order, Text and bytes", () => {
    const one = { intent: "section.set_title", title: "A" };
    const two = { intent: "section.set_title", title: "B" };
    expect(intentsHash([one])).not.toBe(intentsHash([two]));
    expect(intentsHash([one, two])).not.toBe(intentsHash([two, one]));
    expect(intentsHash([{ t: "e\u0301" }])).not.toBe(intentsHash([{ t: "é" }]));
    expect(intentsHash([{ p: new Uint8Array([1]) }])).not.toBe(
      intentsHash([{ p: new Uint8Array([2]) }]),
    );
  });

  it("refuses a value with no canonical form", () => {
    expect(() => intentsHash([{ n: 1.5 }])).toThrow("non-integer");
    expect(() => intentsHash([{ f: () => 1 }])).toThrow("canonical form");
  });
});

describe("receipts (§3.4, §3.5)", () => {
  it("stores, reads and releases a receipt per Resource and operation", async () => {
    const storage = new InMemoryLfcpStorage();
    const R = resourceId(new Uint8Array(32).fill(1));
    const other = resourceId(new Uint8Array(32).fill(2));
    const receipt: Receipt = {
      operationId: "op-1",
      unitIds: [dataUnitId(new Uint8Array(32).fill(9))],
      affectedNodeIds: ["n"],
      modelRevision: "h",
      intentsHash: intentsHash([]),
      durable: true,
    };
    await storage.commit([receiptWrite(R, receipt)]);
    expect(await receiptOf(storage, R, "op-1")).toEqual(receipt);
    expect(await receiptOf(storage, other, "op-1")).toBeUndefined();
    await releaseReceipt(storage, R, "op-1");
    expect(await receiptOf(storage, R, "op-1")).toBeUndefined();
  });
});
