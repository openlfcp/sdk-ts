import { dataEpoch } from "@openlfcp/core";
import { describe, expect, test } from "vitest";
import { OperationJournal, PackageLedger } from "../../src/identity/journal.js";
import { device, fill } from "./support.js";

describe("PackageLedger (§9.5)", () => {
  test("records, lists and clears per recipient", async () => {
    const { storage } = device();
    const ledger = new PackageLedger(storage);
    const R = fill(5) as never;
    await ledger.record({
      resource: R,
      epoch: dataEpoch(0n),
      recipient: fill(1) as never,
      packageId: fill(7) as never,
    });
    await ledger.record({
      resource: R,
      epoch: dataEpoch(1n),
      recipient: fill(1) as never,
      packageId: fill(8) as never,
    });
    await ledger.record({
      resource: R,
      epoch: dataEpoch(1n),
      recipient: fill(2) as never,
      packageId: fill(9) as never,
    });
    expect(await ledger.has(R, dataEpoch(1n), fill(1) as never)).toBe(true);
    expect((await ledger.list(R)).length).toBe(3);
    expect(await ledger.clear(fill(1) as never)).toBe(2);
    expect(await ledger.has(R, dataEpoch(0n), fill(1) as never)).toBe(false);
    expect(await ledger.has(R, dataEpoch(1n), fill(2) as never)).toBe(true);
  });
});

describe("OperationJournal (§9.1, §9.8)", () => {
  test("refuses a row that names a secret", async () => {
    const journal = new OperationJournal(device().storage);
    await expect(
      journal.begin({ id: "x", kind: "reconcile", createdAt: 0, intent: { pairingSecret: "…" } }),
    ).rejects.toThrow(/secrets/);
  });

  test("keeps phases, statuses and order", async () => {
    const journal = new OperationJournal(device().storage);
    await journal.begin({ id: "b", kind: "reconcile", createdAt: 2, intent: {} });
    await journal.begin({ id: "a", kind: "revoke-device", createdAt: 1, intent: { device: "00" } });
    await journal.putPhase("a", {
      id: "revoke:00",
      kind: "revoke",
      resource: "00",
      state: "pending",
    });
    await journal.putPhase("a", {
      id: "revoke:00",
      kind: "revoke",
      resource: "00",
      state: "complete",
    });
    await journal.setStatus("b", "done");
    expect((await journal.list()).map((o) => o.id)).toEqual(["a", "b"]);
    expect((await journal.list({ status: "open" })).map((o) => o.id)).toEqual(["a"]);
    expect((await journal.load("a")).phases).toEqual([
      { id: "revoke:00", kind: "revoke", resource: "00", state: "complete" },
    ]);
  });
});
