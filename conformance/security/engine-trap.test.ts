// The crash-loop breaker (sdk-ts b110fdd, EngineGuard) against a REAL engine
// trap, not an injected error. Automerge JS 3.5.0 traps applying a change that
// nests about 6,500 levels, and its wasm module is then terminated for the
// whole process, so every start runs in a child process
// (engine-trap.child.mjs) over one SQLite file. The child's profile handler
// hands the change straight to Automerge (a test seam that skips the §11.2
// depth admission a real receiver applies); the breaker must:
// - classify the real trap as a trap (isEngineTrap) and leave the apply record;
// - after a restart, make the unit a suspect and replay it alone (it traps again);
// - after the next restart, quarantine it: never handed to the engine again,
//   the engine alive, and a re-delivered copy refused.

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const child = join(import.meta.dirname, "engine-trap.child.mjs");

function start(dir: string, phase: string): Record<string, unknown> {
  const r = spawnSync(process.execPath, [child, dir, phase], { encoding: "utf8", timeout: 60_000 });
  if (r.status !== 0) throw new Error(`the ${phase} start failed:\n${r.stderr.slice(-2000)}`);
  const last = r.stdout.trim().split("\n").at(-1) as string;
  return JSON.parse(last) as Record<string, unknown>;
}

describe("the crash-loop breaker against a real Automerge trap", () => {
  it("classifies the trap, makes the unit a suspect, then quarantines it", () => {
    const dir = mkdtempSync(join(tmpdir(), "lfcp-engine-trap-"));
    try {
      const first = start(dir, "first");
      expect(first).toMatchObject({
        trap: true,
        error: { name: "RuntimeError" },
        applied: 1,
        engineAlive: false,
      });
      const marks = first.marks as [string, string][];
      expect(marks.map(([k]) => k)).toEqual(["applying:units:R"]);
      const unit = `unit:${(marks[0]?.[1].match(/unit:([0-9a-f]+)/) ?? [])[1]}`;

      const second = start(dir, "restart");
      expect(second).toMatchObject({ trap: true, applied: 1, engineAlive: false });
      expect(second.marks).toEqual(
        expect.arrayContaining([
          [`suspect:R:${unit}`, "1"],
          ["applying:units:R", `["${unit}"]`],
        ]),
      );

      const third = start(dir, "restart");
      expect(third).toMatchObject({ applied: 0, engineAlive: true, replayed: [] });
      expect(third.crashed).toEqual([unit.slice("unit:".length)]);
      expect(third.marks).toEqual([[`suspect:R:${unit}`, "2"]]);

      const again = start(dir, "redeliver");
      expect(again).toMatchObject({ applied: 0, engineAlive: true });
      expect((again.outcome as { kind: string }).kind).not.toBe("applied");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 240_000);
});
