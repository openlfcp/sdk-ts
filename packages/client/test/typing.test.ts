import { dataUnitId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { type Flushed, type Receipt, TypingCoalescer } from "../src/index.js";

// LFCP-02-025 acceptance 4: typing passes coalesced into one change per
// burst. Each pass is planned against the base of the last receipt, so a
// later pass on the same base replaces a waiting one.

const edit = (id: string, base: string, insert: string) => ({
  intent: "text.edit",
  id,
  base,
  edits: [{ index: 0, deleteCount: 0, insert }],
});

function harness(opts: { maxChars?: number; idleMs?: number; fail?: boolean } = {}) {
  const commits: { intents: readonly unknown[]; operationId: string }[] = [];
  const flushed: Flushed[] = [];
  const clock = { t: 0 };
  const c = new TypingCoalescer({
    commit: async (intents, { operationId }) => {
      if (opts.fail) throw new Error("NOT_WRITABLE");
      commits.push({ intents, operationId });
      return {
        operationId,
        unitIds: [dataUnitId(new Uint8Array(32).fill(commits.length))],
        affectedNodeIds: [],
        modelRevision: `r${commits.length}`,
        intentsHash: "",
        durable: true,
      } satisfies Receipt;
    },
    onFlushed: (f) => flushed.push(f),
    now: () => clock.t,
    ...(opts.maxChars === undefined ? {} : { maxChars: opts.maxChars }),
    ...(opts.idleMs === undefined ? {} : { idleMs: opts.idleMs }),
  });
  return { c, commits, flushed, clock };
}

describe("TypingCoalescer", () => {
  it("keeps only the latest typing pass on a base and commits it after the idle pause", async () => {
    const h = harness();
    expect(await h.c.submit("p", [edit("n", "r0", "h")], { operationId: "op-1" })).toEqual({
      kind: "deferred",
      operationId: "op-1",
      replaced: null,
    });
    h.clock.t = 500;
    expect(await h.c.submit("p", [edit("n", "r0", "hi")], { operationId: "op-2" })).toMatchObject({
      kind: "deferred",
      replaced: "op-1",
    });
    await h.c.tick(1_900); // 1.4 s after the last pass
    expect(h.commits).toEqual([]);
    await h.c.tick(2_000);
    expect(h.commits).toEqual([{ intents: [edit("n", "r0", "hi")], operationId: "op-2" }]);
    expect(h.flushed).toMatchObject([{ kind: "committed", key: "p", operationId: "op-2" }]);
    expect(h.c.waiting("p")).toBeUndefined();
  });

  it("commits at once a pass with a structural intent, carrying the typing before it", async () => {
    const h = harness();
    await h.c.submit("p", [edit("n", "r0", "abc")], { operationId: "op-1" });
    const split = { intent: "node.split", id: "n", base: "r0", at: 3, newId: "m" };
    const r = await h.c.submit("p", [edit("n", "r0", "abc"), split], { operationId: "op-2" });
    expect(r).toMatchObject({ kind: "committed", replaced: "op-1" });
    expect(h.commits.map((c) => c.operationId)).toEqual(["op-2"]);
  });

  it("commits once a burst reaches maxChars, or leaves its paragraph", async () => {
    const h = harness({ maxChars: 4 });
    await h.c.submit("p", [edit("n", "r0", "abc")], { operationId: "op-1" });
    expect((await h.c.submit("p", [edit("n", "r0", "abcd")], { operationId: "op-2" })).kind).toBe(
      "committed",
    );
    const g = harness();
    await g.c.submit("p", [edit("n", "r0", "abc")], { operationId: "op-1" });
    expect(
      await g.c.submit("p", [edit("n", "r0", "abc"), edit("m", "r0", "x")], {
        operationId: "op-2",
      }),
    ).toMatchObject({ kind: "committed", replaced: "op-1" });
    expect(g.commits.map((c) => c.operationId)).toEqual(["op-2"]);
  });

  it("commits a waiting pass first when the next one is on another base", async () => {
    const h = harness();
    await h.c.submit("p", [edit("n", "r0", "abc")], { operationId: "op-1" });
    // The adapter moved its base without a flush: op-1 is not contained in op-2.
    const r = await h.c.submit("p", [edit("n", "r9", "x")], { operationId: "op-2" });
    expect(r).toMatchObject({ kind: "deferred", replaced: null });
    expect(h.commits.map((c) => c.operationId)).toEqual(["op-1"]);
  });

  it("keeps projections apart, and flush commits what waits", async () => {
    const h = harness();
    await h.c.submit("p", [edit("n", "r0", "a")], { operationId: "op-1" });
    await h.c.submit("q", [edit("n", "r0", "b")], { operationId: "op-2" });
    await h.c.flush("p");
    expect(h.commits.map((c) => c.operationId)).toEqual(["op-1"]);
    expect(h.c.waiting("q")).toBe("op-2");
    await h.c.flush();
    expect(h.commits.map((c) => c.operationId)).toEqual(["op-1", "op-2"]);
  });

  it("reports a failed flush with the pass's intents, never as committed", async () => {
    const h = harness({ fail: true });
    await h.c.submit("p", [edit("n", "r0", "a")], { operationId: "op-1" });
    await h.c.flush();
    expect(h.flushed).toMatchObject([
      { kind: "failed", key: "p", operationId: "op-1", intents: [edit("n", "r0", "a")] },
    ]);
    expect(h.c.waiting("p")).toBeUndefined();
  });
});
