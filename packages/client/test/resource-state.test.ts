import { describe, expect, it } from "vitest";
import { resourcePhaseTransition } from "../src/index.js";

describe("§65 per-Resource sync machine", () => {
  it("follows exactly the drawn edges, and every state but CLOSED closes", () => {
    const path = [
      "OPEN",
      "OPENED",
      "CONTROL_COMPLETE",
      "DEK_AVAILABLE",
      "FRONTIER_REACHED",
    ] as const;
    let s = "CLOSED" as Parameters<typeof resourcePhaseTransition>[0];
    const seen: string[] = [];
    for (const e of path) {
      s = resourcePhaseTransition(s, e) as typeof s;
      seen.push(s);
    }
    expect(seen).toEqual(["OPENING", "CONTROL_SYNC", "KEY_SYNC", "DATA_SYNC", "LIVE"]);
    expect(resourcePhaseTransition("LIVE", "MISSING_RANGES")).toBe("DATA_SYNC");
    expect(resourcePhaseTransition("LIVE", "CONTROL_RECORD")).toBe("CONTROL_SYNC");
    expect(resourcePhaseTransition("CONTROL_SYNC", "FORK")).toBe("CONTROL_CONFLICT");
    expect(resourcePhaseTransition("KEY_SYNC", "KEY_UNAVAILABLE")).toBe("KEY_BLOCKED");
    expect(resourcePhaseTransition("KEY_BLOCKED", "PACKAGE_ARRIVED")).toBe("KEY_SYNC");
    for (const st of [
      "OPENING",
      "CONTROL_SYNC",
      "CONTROL_CONFLICT",
      "KEY_SYNC",
      "KEY_BLOCKED",
      "DATA_SYNC",
      "LIVE",
    ] as const)
      expect(resourcePhaseTransition(st, "CLOSE")).toBe("CLOSED");
    expect(resourcePhaseTransition("CLOSED", "CLOSE")).toBeUndefined();
    expect(resourcePhaseTransition("CONTROL_CONFLICT", "CONTROL_COMPLETE")).toBeUndefined();
    expect(resourcePhaseTransition("DATA_SYNC", "OPENED")).toBeUndefined();
  });
});
