// SectionReplica keeps one Automerge document (#7): a batch's changes are
// made on a fork and applied to the replica's own document, instead of the
// fork becoming it. The same random sequences of stage, apply, revert,
// dropped batches, refusals and received changes run through the replica
// of 0.2.0-beta.8 (test/support/replica-091f1a9.ts) and this one: every
// step gives the same change bytes, hashes, sequences, model revision,
// heads, refusal codes and state.

import { principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { createTask } from "../src/index.js";
import { type SectionIntent, SectionReplica } from "../src/sections/index.js";
import { SectionReplica as Reference } from "./support/replica-091f1a9.js";

const resource = resourceId(new Uint8Array(32).fill(7));
const alice = principalId(new Uint8Array(32).fill(1));
const bob = principalId(new Uint8Array(32).fill(2));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);
const SEEDS = 300;
const STEPS = 40;

function random(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
}

type Replica = SectionReplica | Reference;
type Outcome = Record<string, unknown>;

const hex = (b: Uint8Array) => toHex(b);

/** What a staged or committed change says, in comparable form. */
function describeChange(c: unknown): unknown {
  if (c === null) return null;
  const x = c as {
    parts: readonly { change: Uint8Array; plaintext: Uint8Array; hash: string; seq: number }[];
    modelRevision: string;
    affectedNodeIds: readonly string[];
    intents: readonly string[];
  };
  return {
    parts: x.parts.map((p) => ({
      change: hex(p.change),
      plaintext: hex(p.plaintext),
      hash: p.hash,
      seq: p.seq,
    })),
    modelRevision: x.modelRevision,
    affectedNodeIds: [...x.affectedNodeIds],
    intents: [...x.intents],
  };
}

const refusal = (e: unknown) => ({
  refused: (e as { code?: string }).code ?? (e as Error).constructor.name,
  message: (e as Error).message,
});

/** The replica's observable state. */
const stateOf = (r: Replica) => ({
  revision: r.revision(),
  actorSeq: r.actorSeq,
  changes: r.changes().map(hex),
  json: r.toJSON(),
});

/** What the sequences exercised, by step kind and outcome. */
const seen = new Map<string, number>();

/** Runs `op` on both; their outcomes and states must agree. */
function both(a: Replica, b: Replica, op: (r: Replica) => Outcome, step: string) {
  const run = (r: Replica): Outcome => {
    try {
      return op(r);
    } catch (e) {
      return refusal(e);
    }
  };
  const oa = run(a);
  const ob = run(b);
  const kind = step.split(" ").at(-1) ?? "";
  const outcome =
    "refused" in oa ? `refused` : JSON.stringify(oa).includes('"c":null') ? "nothing" : "ok";
  seen.set(`${kind}:${outcome}`, (seen.get(`${kind}:${outcome}`) ?? 0) + 1);
  expect(ob, step).toEqual(oa);
  expect(stateOf(b), `${step}: state`).toEqual(stateOf(a));
}

describe("the replica that keeps one document gives what beta.8 gave", () => {
  it(`${SEEDS} random sequences of stage, apply, revert, refusals and received changes`, () => {
    for (let seed = 1; seed <= SEEDS; seed++) {
      const rnd = random(seed);
      const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
      const old = Reference.empty({ resource, principal: alice });
      const now = SectionReplica.empty({ resource, principal: alice });
      // A collaborator whose changes both receive (the old replica: the reference).
      const peer = Reference.empty({ resource, principal: bob });
      const create = [
        { intent: "section.create", sectionId: SECTION, title: "Plan", createdBy: alice },
      ] as SectionIntent[];
      both(old, now, (r) => ({ c: describeChange(r.commit(create)) }), `seed ${seed} create`);
      peer.receiveChanges(old.changes());
      let next = 100;
      // Placement IDs given, not generated: both replicas write the same bytes.
      let placement = 60000;
      const pid = () => id(placement++);
      const nodes: string[] = [];
      const tasks: string[] = [];
      const texts: string[] = [];
      const intent = (r: Replica): SectionIntent => {
        const any = () => (nodes.length === 0 || rnd() < 0.1 ? id(9999) : pick(nodes));
        const parent = () => (rnd() < 0.4 || nodes.length === 0 ? SECTION : pick(nodes));
        const k = rnd();
        if (k < 0.15) {
          const t = id(next++);
          return {
            intent: "task.create_in_section",
            task: createTask({ id: t as never, title: `t${t.slice(-3)}`, createdBy: alice }).task,
            parent: parent(),
            after: null,
            placementId: pid(),
          } as SectionIntent;
        }
        if (k < 0.25)
          return {
            intent: rnd() < 0.5 ? "paragraph.create" : "item.create",
            id: id(next++),
            parent: parent(),
            after: null,
            placementId: pid(),
            text: `p${next}`,
            createdBy: alice,
          } as SectionIntent;
        if (k < 0.4)
          return {
            intent: "node.move",
            id: any(),
            parent: parent(),
            after: null,
            placementId: pid(),
          } as SectionIntent;
        if (k < 0.48) return { intent: "node.delete", id: any() } as SectionIntent;
        if (k < 0.54) return { intent: "node.restore", id: any() } as SectionIntent;
        if (k < 0.68 && tasks.length > 0)
          return {
            intent: "task.set_title",
            id: pick(tasks) as never,
            title: `title ${Math.floor(rnd() * 1000)}`,
          } as SectionIntent;
        if (k < 0.76 && tasks.length > 0)
          return {
            intent: "task.set_status",
            id: pick(tasks) as never,
            status: pick(["todo", "done", "cancelled", "bogus"]),
          } as SectionIntent;
        if (k < 0.86 && texts.length > 0)
          return {
            intent: "text.edit",
            id: pick(texts),
            base: r.revision(),
            edits: [{ index: 0, deleteCount: rnd() < 0.3 ? 1 : 0, insert: "x" }],
          } as SectionIntent;
        return {
          intent: "section.set_title",
          title: `S${Math.floor(rnd() * 100)}`,
        } as SectionIntent;
      };
      const learn = (batch: readonly SectionIntent[]) => {
        for (const i of batch) {
          if (i.intent === "task.create_in_section") {
            nodes.push(i.task.id);
            tasks.push(i.task.id);
          } else if (i.intent === "paragraph.create" || i.intent === "item.create") {
            nodes.push(i.id);
            texts.push(i.id);
          }
        }
      };
      for (let step = 0; step < STEPS; step++) {
        const label = `seed ${seed} step ${step}`;
        const mode = rnd();
        if (mode < 0.1) {
          // A collaborator's change arrives.
          const before = peer.changes().length;
          try {
            peer.commit([intent(peer)]);
          } catch {
            // refused on the peer: nothing to send
          }
          const fresh = peer.changes().slice(before);
          both(
            old,
            now,
            (r) => ({ received: r.receiveChanges(fresh) as unknown }),
            `${label} receive`,
          );
          continue;
        }
        // Both replicas get the same batch (text.edit's base is the same revision).
        const n = 1 + Math.floor(rnd() * 3);
        const batch = Array.from({ length: n }, () => intent(now));
        if (mode < 0.65) {
          both(old, now, (r) => ({ c: describeChange(r.commit(batch)) }), `${label} commit`);
        } else if (mode < 0.75) {
          // Staged, never applied: nothing changes.
          both(
            old,
            now,
            (r) => ({ c: describeChange(r.stage(batch)?.change ?? null) }),
            `${label} drop`,
          );
        } else {
          // Staged, applied, then reverted (the durable store failed): as before.
          both(
            old,
            now,
            (r) => {
              const before = r.revision();
              const s = r.stage(batch);
              if (s === null) return { c: null };
              s.apply();
              const applied = r.revision();
              s.revert();
              return {
                c: describeChange(s.change),
                applied,
                back: r.revision() === before,
              };
            },
            `${label} revert`,
          );
        }
        learn(batch);
        // The peer keeps up with what the replica holds.
        peer.receiveChanges(old.changes());
      }
    }
    // Each kind of step, and refusals, actually ran.
    for (const k of [
      "commit:ok",
      "commit:refused",
      "revert:ok",
      "revert:refused",
      "drop:ok",
      "receive:ok",
    ])
      expect(seen.get(k) ?? 0, k).toBeGreaterThan(SEEDS / 2);
    expect([...seen.keys()].some((k) => k.startsWith("step"))).toBe(false);
  }, 600_000);
});
