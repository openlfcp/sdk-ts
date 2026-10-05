/// <reference types="node" />
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { actorSequence, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { SqliteLfcpStorage } from "../src/index.js";
import { tempStore } from "./fixture.js";

// Crash safety (LFCP-035): a child process writes in a loop and is killed
// with SIGKILL mid-run; the reopened store must show no sequence reuse, no
// torn batch and every reported (committed) write.

const CHILD = fileURLToPath(new URL("./crash-child.mjs", import.meta.url));
const R = resourceId(new Uint8Array(32).fill(1));
const ALICE = principalId(new Uint8Array(32).fill(10));

/** Runs the child until it has reported `lines` steps, then SIGKILLs it; resolves with every reported line. */
function runAndKill(args: readonly string[], lines: number): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    const seen: string[] = [];
    let buffer = "";
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    child.stdout.on("data", (d: Buffer) => {
      buffer += d.toString();
      const parts = buffer.split("\n");
      buffer = parts.pop() ?? "";
      seen.push(...parts);
      if (seen.length >= lines) child.kill("SIGKILL");
    });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (signal === "SIGKILL") resolve(seen);
      else reject(new Error(`child exited with ${code}: ${stderr}`));
    });
  });
}

describe("SqliteLfcpStorage crash safety (SIGKILL)", () => {
  it("never hands out a sequence twice across a kill", async () => {
    const t = tempStore();
    try {
      t.storage.close();
      const all: bigint[] = [];
      for (const lines of [37, 113, 5]) {
        const reported = (await runAndKill([t.dbPath, "reserve"], lines)).map((l) =>
          BigInt(l.slice(2)),
        );
        // Reported values strictly increase and continue past every earlier run.
        expect(reported[0]).toBeGreaterThan(all.at(-1) ?? 0n);
        all.push(...reported);
      }
      expect(new Set(all).size).toBe(all.length);
      const reopened = SqliteLfcpStorage.open(t.dbPath);
      try {
        const next = await reopened.actorSequences.reserveNext(R, ALICE);
        // Reservations that committed but were not reported yet are skipped, never reused.
        expect(next).toBeGreaterThan(all.at(-1) as bigint);
      } finally {
        reopened.close();
      }
    } finally {
      t.dispose();
    }
  }, 60_000);

  it("keeps every committed batch whole and no part of an interrupted one", async () => {
    const t = tempStore();
    const perBatch = 20;
    try {
      t.storage.close();
      const reported = (await runAndKill([t.dbPath, "batch", String(perBatch)], 12)).map((l) =>
        Number(l.slice(2)),
      );
      const reopened = SqliteLfcpStorage.open(t.dbPath);
      try {
        const units = await reopened.dataUnits.withStatus(R, "merged");
        expect(units.length % perBatch).toBe(0);
        const batches = units.length / perBatch;
        // Every reported batch is there; at most the one in flight committed unreported.
        expect(batches).toBeGreaterThanOrEqual(reported.length);
        expect(batches).toBeLessThanOrEqual(reported.length + 1);
        expect(units.map((u) => u.actorSeq)).toEqual(
          units.map((_, i) => actorSequence(BigInt(i + 1))),
        );
        for (const u of units)
          expect(u.bytes.every((b) => b === (Number(u.actorSeq) - 1) % 256)).toBe(true);
        // The checkpoint belongs to the last committed batch.
        expect((await reopened.profileState.checkpoint(R))?.actorSeq).toBe(batches - 1);
      } finally {
        reopened.close();
      }
    } finally {
      t.dispose();
    }
  }, 60_000);
});
