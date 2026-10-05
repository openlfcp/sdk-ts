// LFCP-038: abrupt termination around every step of a local write, with
// genuine restarts. Each step runs in its own child process on the same
// SQLite database and secret directory (writer-proc.mjs); a run is
// SIGKILLed exactly at a crash point and the next run is a fresh process.
//
// Invariants: no actor sequence is ever used for two different units; a
// lost (reserved but unused) sequence is acceptable; a queued unit keeps
// its exact bytes and ID and is resent, never re-created; a Data Epoch
// rotation does not reset the sequence.

import { describe, expect, it } from "vitest";
import { makeTempDir, removeTempDir } from "../storage/temp-dir.mjs";
import { runWriter } from "./proc.mjs";

interface State {
  units: { seq: string; unitId: string; epoch: string; bytesSha: string }[];
  queue: { itemId: string; bytesSha: string; attempts: number }[];
  head: string;
}

const field = (lines: readonly string[], step: string): string[] =>
  (lines.find((l) => l.split(" ")[0] === step) ?? "").split(" ").slice(1);

async function state(dir: string): Promise<State> {
  const lines = await runWriter([dir, "state"]);
  return JSON.parse((lines.find((l) => l.startsWith("STATE ")) as string).slice(6)) as State;
}

describe("LFCP-038 crash points (child processes, SQLite)", () => {
  it("never reuses an actor sequence and never loses or re-creates a queued unit", async () => {
    const dir = makeTempDir("lfcp-038-crash-");
    try {
      const db = dir;
      // seq 1, complete (sent, never ACKed).
      const first = await runWriter([db, "write", "one"]);
      expect(field(first, "CREATED")[0]).toBe("1");

      // Killed before reserving: nothing used.
      await runWriter([db, "write", "lost-before", "BEFORE_RESERVE"], "BEFORE_RESERVE");
      // Killed after reserving 2: sequence 2 is lost, never reused.
      const reserved = await runWriter([db, "write", "lost-reserved", "RESERVED"], "RESERVED");
      expect(field(reserved, "RESERVED")[0]).toBe("2");
      // Killed after sealing 3 but before storing it: unit 3 is lost with its sequence.
      const created = await runWriter([db, "write", "lost-created", "CREATED"], "CREATED");
      expect(field(created, "CREATED")[0]).toBe("3");
      // Killed after queueing 4: unit 4 must survive exactly.
      const queued = await runWriter([db, "write", "queued", "QUEUED"], "QUEUED");
      const [seq4, id4] = field(queued, "CREATED");
      expect(seq4).toBe("4");
      // Killed after sending 5, before any ACK.
      const sent = await runWriter([db, "write", "sent", "SENT"], "SENT");
      const [seq5, id5] = field(sent, "CREATED");
      const [message5] = field(sent, "SENT");
      expect(seq5).toBe("5");

      // A fresh process writes again: the next sequence is 6, after every one used or lost.
      const after = await runWriter([db, "write", "after"]);
      expect(field(after, "CREATED")[0]).toBe("6");

      const s = await state(db);
      expect(s.units.map((u) => u.seq)).toEqual(["1", "4", "5", "6"]);
      expect(new Set(s.units.map((u) => u.seq)).size).toBe(s.units.length);
      expect(s.units.find((u) => u.seq === "4")?.unitId).toBe(id4);
      expect(s.units.find((u) => u.seq === "5")?.unitId).toBe(id5);
      // Every unit is still queued (no ACK ever came), with its exact bytes: ID = SHA-256 of the bytes.
      expect(s.queue.map((q) => q.itemId)).toEqual(s.units.map((u) => u.unitId));
      for (const q of s.queue) expect(q.bytesSha).toBe(q.itemId);

      // A restarted sender resends the same bytes in new messages.
      const resent = await runWriter([db, "send"]);
      const [messageId, objects] = field(resent, "SENT");
      expect(messageId).not.toBe(message5);
      expect((objects as string).split(",")).toEqual(s.units.map((u) => u.unitId));
      expect((await state(db)).queue.find((q) => q.itemId === id5)?.attempts).toBe(3);
    } finally {
      removeTempDir(dir);
    }
  }, 120_000);

  it("keeps the actor sequence across a Data Epoch rotation and a restart", async () => {
    const dir = makeTempDir("lfcp-038-epoch-");
    try {
      await runWriter([dir, "write", "one"]);
      await runWriter([dir, "write", "two"]);
      expect(await runWriter([dir, "rotate"])).toEqual(["ROTATED 1"]);
      // Killed after reserving in the new epoch, then restarted.
      const reserved = await runWriter([dir, "write", "lost", "RESERVED"], "RESERVED");
      expect(field(reserved, "RESERVED")[0]).toBe("3");
      const next = await runWriter([dir, "write", "three"]);
      const [seq, , epoch] = field(next, "CREATED");
      expect([seq, epoch]).toEqual(["4", "1"]);
      const s = await state(dir);
      expect(s.units.map((u) => [u.seq, u.epoch])).toEqual([
        ["1", "0"],
        ["2", "0"],
        ["4", "1"],
      ]);
      expect(s.head).toBe("1");
    } finally {
      removeTempDir(dir);
    }
  }, 120_000);

  it("removes its temporary directories", () => {
    const dir = makeTempDir("lfcp-038-cleanup-");
    removeTempDir(dir);
    expect(() => removeTempDir(dir)).not.toThrow();
  });
});
