// A bridge-style synthetic history of C (A§3.5, T§3 "synthetic year of C"), written straight
// through the engine so a year takes linear time: the root initializes C and approves the bridge;
// the bridge writes service and status, turns its bindings on (again once a month, a new
// generation, with a preview), and writes status and bindings as A§3.5 has it
// (ServiceControlStatusSchedule): the complete checks that moved (20 a day each) ride the heartbeat
// unit every 30 minutes, transitions are merged into one write a minute. Two questions a week per
// binding: the root answers, at the bridge's next unit, from a view that misses it (a concurrent
// change), the bridge applies and resolves it, and cleans all three up after 7 days. The plugin
// publishes a Snapshot every `snapshotEveryDays` (default daily; `snapshots` holds the length of the
// history at each). With `refusals`, units §4 refuses are mixed in: by writers outside their rows,
// and over the entry limit (refused on the post-state).

import * as A from "@automerge/automerge";
import { type PrincipalId, principalId, resourceId, toBase64url, toHex } from "@openlfcp/core";
import { checkChange } from "../../src/admission/framing.js";
import {
  deriveServiceControlActorId,
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
  bridge.write([...intents, ...schedule.take(T0)]);

  let next = 0;
  const cleanup: { at: number; qid: string; aid: string }[] = [];
  const answered: { at: number; qid: string; aid: string }[] = [];
  /** Questions the root answers at the bridge's next unit, from its view up to `upTo`. */
  let asked: { t: number; b: number; qid: string; aid: string; hash: string; upTo: number }[] = [];
  const snapshots: number[] = [];
  const snapshotEvery = (o.snapshotEveryDays ?? 1) * 48;
  for (let tick = 1; tick <= o.days * 48; tick++) {
    const t = T0 + tick * 30 * MINUTE;
    const day = Math.floor((t - T0) / DAY);
    if (tick % 48 === 0 && day % 30 === 0) for (const b of bindings.keys()) turnOn(b, t);
    bridge.pull(rootLog);
    bindings.forEach((binding, b) => {
      if (rnd() < perTick)
        schedule.binding(binding, { lastCompleteCheckAt: iso(t - b * MINUTE) }, { defer: true });
    });
    const intents: ServiceControlIntent[] = [];
    // The bridge applies an answer at one of its next units (the Mac may sleep in between).
    for (const a of answered.filter((x) => x.at <= t)) {
      const at = iso(t);
      const { qid, aid } = a;
      intents.push(
        { intent: "event.put", id: aid, state: "applied", at },
        { intent: "question.resolve", qid, resolved: { answerId: aid, choice: "restore", at } },
      );
      answered.splice(answered.indexOf(a), 1);
      cleanup.push({ at: t + 7 * DAY, qid, aid });
    }
    while (cleanup.length > 0 && (cleanup[0] as { at: number }).at <= t) {
      const { qid, aid } = cleanup.shift() as { qid: string; aid: string };
      intents.push(
        { intent: "delete", container: "answers", key: aid },
        { intent: "delete", container: "events", key: aid },
        { intent: "delete", container: "questions", key: qid },
      );
    }
    if (intents.length > 0 || schedule.due(t)) bridge.write([...schedule.take(t), ...intents]);

    for (const { t: q, b, qid, aid, hash, upTo } of asked) {
      // The bridge's unit above is not in the root's view when it answers.
      root.pull(bridgeLog, upTo);
      root.write([
        {
          intent: "answer.create",
          aid,
          answer: { qid, snapshotHash: hash, choice: "restore", at: iso(q + 5 * MINUTE) },
        },
      ]);
      answered.push({ at: t + Math.ceil(rnd() * 4) * 30 * MINUTE, qid, aid });
      const at = iso(q + 5 * MINUTE);
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
        stray(root, [{ intent: "status.put", fields: { heartbeatAt: at } }]);
        const binding = bindings[b] as string;
        stray(bridge, [{ intent: "binding.put", binding, fields: { list: "x".repeat(9000) } }]);
      }
    }
    asked = [];

    for (const [b, binding] of bindings.entries()) {
      if (rnd() >= questionPerTick) continue;
      const [qid, aid] = [uid(++next), uid(++next)];
      const hash = hex(next);
      bridge.write([
        {
          intent: "question.create",
          qid,
          question: {
            binding,
            generation: generation[b],
            kind: "mass_delete",
            anomalyId: uid(++next),
            snapshotHash: hash,
            items: ["Buy milk", "Call the bank", "Renew passport", "Book flights", "Pay rent"],
            counts: { deleted: 14 },
            options: ["restore", "accept"],
            at: iso(t),
          },
        },
      ]);
      asked.push({ t, b, qid, aid, hash, upTo: bridgeLog.length });
    }
    if (tick % snapshotEvery === 0) snapshots.push(units.length);
  }
  return { options, units, strays, snapshots };
}
