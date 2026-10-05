import { dataEpoch, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { runStorageContract } from "../src/contract.js";
import { dekSecretRef, InMemoryLfcpStorage, InMemorySecretStore, secretRef } from "../src/index.js";

// The shared storage contract on the in-memory adapters (tests and
// development only); every other adapter runs the same suite.
runStorageContract({ describe, it }, "InMemoryLfcpStorage", async () => ({
  storage: new InMemoryLfcpStorage(),
  secrets: new InMemorySecretStore(),
  close: async () => {},
}));

describe("InMemorySecretStore", () => {
  it("never prints its values and refuses malformed references", async () => {
    const store = new InMemorySecretStore();
    const ref = dekSecretRef(resourceId(new Uint8Array(32).fill(1)), dataEpoch(1n));
    await store.put(ref, Uint8Array.of(0xab, 0xcd));
    expect(JSON.stringify({ store })).toBe('{"store":"[InMemorySecretStore]"}');
    expect(String(store)).toBe("[InMemorySecretStore]");
    expect(Object.keys(store)).toEqual([]);
    expect(ref).toBe(`lfcp-secret:resource-dek:${toHex(new Uint8Array(32).fill(1))}.1`);
    expect(() => secretRef("resource-dek", "has space")).toThrow();
    await expect(store.put("not-a-ref" as never, Uint8Array.of(1))).rejects.toMatchObject({
      code: "UNSUPPORTED_VALUE",
    });
  });
});
