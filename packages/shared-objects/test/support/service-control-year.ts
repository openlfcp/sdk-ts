// A bridge-style synthetic history of C (A§3.5, T§3 "synthetic year of C"), written straight
// through the engine so a year takes linear time: the root initializes C and approves the bridge;
// the bridge writes service and status, turns its bindings on (again once a month, a new
// generation, with a preview), and writes status and bindings as the bridge's ControlClient does
// (A§3.5, ServiceControlStatusSchedule): one unit per tick, with the status, the bindings, the
// events and the resolutions of that tick; the complete checks that moved (20 a day each) ride
// the next unit, transitions are merged into one write a minute; `heartbeatAt` only after 30
// minutes without a tick unit, alone if nothing else is due (any unit is a sign of life). Two
// questions a week per binding, each a unit of its own at a random time between the 30-minute
// ticks: the root answers 5 minutes later, from its view when it saw the question (concurrent with
// any question the bridge asked since), the bridge applies and resolves it in a tick of its own,
// and cleans all three up after 7 days (the cleanup runs once an hour). The plugin
// publishes a Snapshot every `snapshotEveryDays` (default daily; `snapshots` holds the length of the
// history at each). With `refusals`, units §4 refuses are mixed in: by writers outside their rows,
// and over the entry limit (refused on the post-state).

import * as A from "@automerge/automerge";
import { type PrincipalId, principalId, resourceId, toBase64url, toHex } from "@openlfcp/core";
import { checkChange } from "../../src/admission/framing.js";
import {
  deriveServiceControlActorId,
  HEARTBEAT_INTERVAL_MS,
  type ServiceControlIntent,
  type ServiceControlOptions,
  type ServiceControlSignerClass,
  ServiceControlStatusSchedule,
} from "../../src/service-control/index.js";
import { applyServiceControlIntent } from "../../src/service-control/write.js";
import { principalRef } from "../../src/values.js";

export interface YearUnit {
  readonly signer: PrincipalId;
  readonly actorSeq: number;
  readonly signerClass: ServiceControlSignerClass;
  readonly bytes: Uint8Array;
}

export interface YearOptions {
  readonly days: number;
  readonly seed?: number;
  readonly bindings?: number;
  readonly transitionsPerDay?: number;
  readonly questionsPerWeek?: number;
  readonly refusals?: boolean;
  readonly snapshotEveryDays?: number;
  /** The root's and the bridge's Principals (default: fixed IDs that sign nothing). */
  readonly root?: PrincipalId;
  readonly bridge?: PrincipalId;
}

const MINUTE = 60_000;
const DAY = 1440 * MINUTE;
const T0 = Date.parse("2026-01-05T00:00:00Z");
const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");
const bytes32 = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (n * 7 + i) & 0xff);
const uid = (n: number) => `0196f2a0-0000-7000-8000-${String(n).padStart(12, "0")}`;
const hex = (n: number) => toHex(bytes32(n));

class Writer {
  doc: A.Doc<Record<string, unknown>>;
  seq = 0;
  /** How many of the other writer's units this one has applied. */
  synced = 0;
  constructor(
    readonly signer: PrincipalId,
    readonly signerClass: ServiceControlSignerClass,
    resource: Uint8Array,
    readonly out: YearUnit[],
    readonly mine: Uint8Array[],
  ) {
    this.doc = A.init({ actor: toHex(deriveServiceControlActorId(resource as never, signer)) });
  }
  #unit(doc: A.Doc<Record<string, unknown>>, intents: readonly ServiceControlIntent[]) {
    const next = A.change(doc, { time: 0 }, (d) => {
      for (const i of intents) applyServiceControlIntent(d, i);
    });
    if (A.getHeads(next).join() === A.getHeads(doc).join()) throw new Error("no change");
    const unit = {
      signer: this.signer,
      actorSeq: this.seq + 1,
      signerClass: this.signerClass,
      bytes: A.getLastLocalChange(next) as Uint8Array,
    };
    this.out.push(unit);
    return { next, unit };
  }
  write(intents: readonly ServiceControlIntent[]): void {
    const { next, unit } = this.#unit(this.doc, intents);
    this.doc = next;
    this.seq++;
    this.mine.push(unit.bytes);
  }
  /** A unit from a copy of this writer's state, which this writer then forgets. */
  stray(intents: readonly ServiceControlIntent[]): void {
    A.free(this.#unit(A.clone(this.doc, { actor: A.getActorId(this.doc) }), intents).next);
  }
  pull(theirs: readonly Uint8Array[], upTo = theirs.length): void {
    if (upTo <= this.synced) return;
    [this.doc] = A.applyChanges(this.doc, theirs.slice(this.synced, upTo));
    this.synced = upTo;
  }
}

export function syntheticYear(o: YearOptions): {
  readonly options: ServiceControlOptions;
  readonly units: readonly YearUnit[];
  /** Units mixed in to be refused. */
  readonly strays: ReadonlySet<string>;
  /** How many units the history had at each Snapshot the plugin published. */
  readonly snapshots: readonly number[];
} {
  let s = o.seed ?? 1;
  const rnd = () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
  const C = resourceId(bytes32(150));
  const options = {
    resource: C,
    root: o.root ?? principalId(bytes32(41)),
    genesisSigner: o.root ?? principalId(bytes32(41)),
  };
  const units: YearUnit[] = [];
  const strays = new Set<string>();
  const rootLog: Uint8Array[] = [];
  const bridgeLog: Uint8Array[] = [];
  const root = new Writer(options.root, "root", C, units, rootLog);
  const bridge = new Writer(
    o.bridge ?? principalId(bytes32(42)),
    "service-device",
    C,
    units,
    bridgeLog,
  );
  const stray = (w: Writer, intents: ServiceControlIntent[]) => {
    w.stray(intents);
    strays.add(checkChange((units.at(-1) as YearUnit).bytes).hash);
  };
  const bindings = Array.from({ length: o.bindings ?? 8 }, (_, b) => toBase64url(bytes32(200 + b)));
  const generation = bindings.map(() => 0);
  const perTick = (o.transitionsPerDay ?? 20) / 48;
  const questionPerTick = (o.questionsPerWeek ?? 2) / (7 * 48);

  root.write([{ intent: "initialize", attemptId: "year", createdAt: iso(T0) }]);
  root.write([
    {
      intent: "approval.create",
      approval: {
        role: "base",
        resource: toBase64url(C),
        principal: principalRef(bridge.signer),
        certDigest: toBase64url(bytes32(1)),
        certId: toBase64url(bytes32(2)),
        generation: 0,
        origin: "year",
        at: iso(T0),
      },
    },
  ]);
  bridge.pull(rootLog);
  const schedule = new ServiceControlStatusSchedule();
  const intents: ServiceControlIntent[] = [
    {
      intent: "service.put",
      fields: {
        instance: "bridge-year",
        kind: "reminders",
        label: "MacBook Air",
        platform: "macos",
        app: "0.6.0",
        protocol: { v: 1, ops: ["check"], questionKinds: ["mass_delete"] },
        artifactSliceId: "",
        macos: "15.0",
        cert: { state: "certified", manifestSeq: 1, certTestMode: false },
        capacity: { sections: bindings.length, max: 8, devicesFree: 8 - bindings.length },
      },
    },
  ];
  schedule.status({ state: "running", since: iso(T0) });
  const turnOn = (b: number, t: number) => {
    generation[b] = (generation[b] as number) + 1;
    schedule.binding(bindings[b] as string, {
      state: "on",
      generation: generation[b],
      list: `Shared list ${b + 1}`,
      filter: "all",
      lastCompleteCheckAt: iso(t),
      pending: { toApple: 0, toLfcp: 0 },
      refused: 0,
      unconfirmed: 0,
      preview: {
        id: uid(1_000_000 + b * 1000 + (generation[b] as number)),
        planHash: hex(b + (generation[b] as number)),
        filter: "default",
        list: `Shared list ${b + 1}`,
        items: ["Buy milk", "Call the bank", "Renew passport", "Book flights", "Pay rent"],
        counts: { toApple: 12, toLfcp: 3, unchanged: 40 },
      },
    });
  };
  for (const b of bindings.keys()) turnOn(b, T0);
  /** When the bridge last wrote a tick unit: its questions and previews do not count. */
  let wroteAt = Number.NEGATIVE_INFINITY;
  /**
   * A tick of the bridge at `t`: one unit when the schedule or `intents` have something to write,
   * `heartbeatAt` in it only after HEARTBEAT_INTERVAL_MS without a tick unit.
   */
  const tick = (t: number, intents: readonly ServiceControlIntent[]) => {
    if (intents.length === 0 && !schedule.due(t)) return;
    const idle = t - wroteAt >= HEARTBEAT_INTERVAL_MS;
    const taken = schedule.take(t).flatMap((i): ServiceControlIntent[] => {
      if (i.intent !== "status.put" || idle) return [i];
      const { heartbeatAt: _, ...fields } = i.fields;
      return Object.keys(fields).length > 0 ? [{ ...i, fields }] : [];
    });
    bridge.write([...taken, ...intents]);
    wroteAt = t;
  };
  tick(T0, intents);

  let next = 0;
  const cleanup: { at: number; qid: string; aid: string }[] = [];
  const snapshots: number[] = [];
  const snapshotEvery = (o.snapshotEveryDays ?? 1) * 48;
  /** Answers the root gives, each 5 minutes after the question, in time order. */
  const waiting: {
    at: number;
    b: number;
    qid: string;
    aid: string;
    hash: string;
    upTo: number;
  }[] = [];
  const answerUntil = (until: number) => {
    while (waiting.length > 0 && (waiting[0] as { at: number }).at <= until) {
      const { at: a, b, qid, aid, hash, upTo } = waiting.shift() as (typeof waiting)[number];
      const at = iso(a);
      // The root saw the question, not what the bridge wrote after it.
      root.pull(bridgeLog, upTo);
      root.write([
        {
          intent: "answer.create",
          aid,
          answer: { qid, snapshotHash: hash, choice: "restore", at },
        },
      ]);
      if (o.refusals && rnd() < 0.5) {
        // Refused on the pre-state (writers outside the row) and,
        // over the entry limit, only on the post-state.
        stray(bridge, [
          {
            intent: "answer.create",
            aid: uid(next + 1),
            answer: { qid, snapshotHash: hash, choice: "accept", at },
          },
        ]);
        root.pull(bridgeLog);
        // A second past `at`: never a time the bridge writes, so always a change.
        stray(root, [{ intent: "status.put", fields: { heartbeatAt: iso(a + 1000) } }]);
        const binding = bindings[b] as string;
        stray(bridge, [{ intent: "binding.put", binding, fields: { list: "x".repeat(9000) } }]);
      }
      // The bridge applies the answer and resolves the question in a tick of its own.
      bridge.pull(rootLog);
      tick(a, [
        { intent: "event.put", id: aid, state: "applied", at },
        { intent: "question.resolve", qid, resolved: { answerId: aid, choice: "restore", at } },
      ]);
      cleanup.push({ at: a + 7 * DAY, qid, aid });
    }
  };
  for (let n = 1; n <= o.days * 48; n++) {
    const t = T0 + n * 30 * MINUTE;
    const day = Math.floor((t - T0) / DAY);
    if (n % 48 === 0 && day % 30 === 0) for (const b of bindings.keys()) turnOn(b, t);
    bridge.pull(rootLog);
    bindings.forEach((binding, b) => {
      if (rnd() < perTick)
        schedule.binding(binding, { lastCompleteCheckAt: iso(t - b * MINUTE) }, { defer: true });
    });
    const intents: ServiceControlIntent[] = [];
    // The cleanup, once an hour: what has been final for 7 days.
    while (n % 2 === 0 && cleanup.length > 0 && (cleanup[0] as { at: number }).at <= t) {
      const { qid, aid } = cleanup.shift() as { qid: string; aid: string };
      intents.push(
        { intent: "delete", container: "answers", key: aid },
        { intent: "delete", container: "events", key: aid },
        { intent: "delete", container: "questions", key: qid },
      );
    }
    tick(t, intents);

    // The questions until the next tick; an answer may come after it.
    const asks: { q: number; b: number }[] = [];
    for (const b of bindings.keys())
      if (rnd() < questionPerTick) asks.push({ q: t + (1 + Math.floor(rnd() * 29)) * MINUTE, b });
    asks.sort((x, y) => x.q - y.q);
    for (const { q, b } of asks) {
      answerUntil(q);
      const [qid, aid] = [uid(++next), uid(++next)];
      const hash = hex(next);
      bridge.write([
        {
          intent: "question.create",
          qid,
          question: {
            binding: bindings[b] as string,
            generation: generation[b],
            kind: "mass_delete",
            anomalyId: uid(++next),
            snapshotHash: hash,
            items: ["Buy milk", "Call the bank", "Renew passport", "Book flights", "Pay rent"],
            counts: { deleted: 14 },
            options: ["restore", "accept"],
            at: iso(q),
          },
        },
      ]);
      waiting.push({ at: q + 5 * MINUTE, b, qid, aid, hash, upTo: bridgeLog.length });
    }
    answerUntil(t + 30 * MINUTE - 1);
    if (n % snapshotEvery === 0) snapshots.push(units.length);
  }
  answerUntil(Number.POSITIVE_INFINITY);
  return { options, units, strays, snapshots };
}
