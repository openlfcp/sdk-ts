// A§3.5 (E-030): a cold personal client connecting to C, alone in a process so that its peak RSS
// is its own (typed in cold-client.d.mts: sdk-ts has no Node type definitions). measureColdClient
// writes C's Snapshot and every unit to a file, as a client fetches them, and runs this file on it:
// the child builds the replica from the Snapshot and the units it carries, admits the tail (the
// units after the Snapshot), makes a client's reads of C (validate, creatorsOf, requestHistory)
// and prints one JSON line of its figures.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SELF = fileURLToPath(import.meta.url);
const MIB = 2 ** 20;
// Keeps the replica reachable across the final GC, so the live set includes it.
let held;
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");

/** [header length][header JSON][snapshot length][snapshot]{[signer 32][actorSeq u32][class u8][length u32][bytes]}* */
function write(file, snapshot, units, tail, options) {
  const classes = [...new Set(units.map((u) => u.signerClass))];
  const head = Buffer.from(
    JSON.stringify({
      classes,
      tail,
      resource: b64(options.resource),
      root: b64(options.root),
      genesisSigner: b64(options.genesisSigner),
    }),
  );
  let size = 8 + head.length + snapshot.length;
  for (const u of units) size += 41 + u.bytes.length;
  const out = Buffer.alloc(size);
  let at = out.writeUInt32LE(head.length, 0);
  at += head.copy(out, at);
  at = out.writeUInt32LE(snapshot.length, at);
  at += Buffer.from(snapshot).copy(out, at);
  for (const u of units) {
    at += Buffer.from(u.signer).copy(out, at);
    at = out.writeUInt32LE(u.actorSeq, at);
    at = out.writeUInt8(classes.indexOf(u.signerClass), at);
    at = out.writeUInt32LE(u.bytes.length, at);
    at += Buffer.from(u.bytes).copy(out, at);
  }
  writeFileSync(file, out);
}

function read(file) {
  const b = readFileSync(file);
  let at = 0;
  const u32 = () => {
    const v = b.readUInt32LE(at);
    at += 4;
    return v;
  };
  // Each its own copy, as a client holds each unit it decrypted, not views of one buffer.
  const take = (n) => {
    const v = new Uint8Array(b.subarray(at, at + n));
    at += n;
    return v;
  };
  const head = JSON.parse(new TextDecoder().decode(take(u32())));
  const raw = (s) => new Uint8Array(Buffer.from(s, "base64url"));
  const options = {
    resource: raw(head.resource),
    root: raw(head.root),
    genesisSigner: raw(head.genesisSigner),
  };
  const snapshot = take(u32());
  const units = [];
  while (at < b.length) {
    const signer = take(32);
    const actorSeq = u32();
    const signerClass = head.classes[b.readUInt8(at++)];
    units.push({ signer, actorSeq, signerClass, bytes: take(u32()) });
  }
  return { options, snapshot, units, tail: head.tail };
}

async function child(file) {
  const { ServiceControlReplica } = await import("@openlfcp/shared-objects/service-control");
  const { options, snapshot, units, tail } = read(file);
  const base = process.memoryUsage().rss;
  const timed = (f) => {
    const t = performance.now();
    const r = f();
    return [r, Math.round(performance.now() - t)];
  };
  const [cold, fromSnapshot] = timed(() =>
    ServiceControlReplica.fromSnapshot(snapshot, options, units.slice(0, units.length - tail)),
  );
  const [received, tailMs] = timed(() => cold.receiveChanges(units.slice(units.length - tail)));
  if (received.refused.length > 0) throw new Error("the tail was refused");
  const [state, validate] = timed(() => cold.validate());
  const [, creatorsOf] = timed(() => {
    cold.creatorsOf("bindings", Object.keys(state.bindings)[0] ?? "");
    cold.creatorsOf("approvals", Object.keys(state.approvals)[0] ?? "");
  });
  const [, requestHistory] = timed(() => cold.requestHistory());
  const figures = {
    coldConnectMs: fromSnapshot + tailMs + validate + creatorsOf + requestHistory,
    cold: { fromSnapshot, tail: tailMs, validate, creatorsOf, requestHistory },
    tailUnits: tail,
    // The process with the Snapshot and the units in hand, before the replica is built.
    baseRssMiB: Math.round(base / MIB),
    // maxRSS is in KiB.
    peakRssMiB: Math.round((process.resourceUsage().maxRSS * 1024) / MIB),
    heapMiB: Math.round(process.memoryUsage().heapUsed / MIB),
  };
  // The live set: what a full GC keeps with the replica still held (the child runs with --expose-gc).
  held = cold;
  globalThis.gc();
  const after = process.memoryUsage();
  figures.liveHeapMiB = Math.round(after.heapUsed / MIB);
  // Off-heap buffers, Automerge's wasm memory among them.
  figures.arrayBuffersMiB = Math.round(after.arrayBuffers / MIB);
  process.stdout.write(`${JSON.stringify(figures)}\n`);
}

/**
 * From --trace-gc lines ("Scavenge|Mark-Compact <used> (<committed>) -> <used> (<committed>) MB"):
 * the largest heap a GC found (live set plus the garbage V8 let accumulate before collecting) and
 * the largest committed heap. Garbage at the peak is that heap less the live set.
 */
function heapPeak(lines, liveHeapMiB) {
  let peakHeapMiB = 0;
  let peakCommittedMiB = 0;
  for (const l of lines) {
    const m = / ms: \S+ ([\d.]+) \(([\d.]+)\) -> ([\d.]+) \(([\d.]+)\) MB/.exec(l);
    if (m === null) continue;
    peakHeapMiB = Math.max(peakHeapMiB, Number(m[1]));
    peakCommittedMiB = Math.max(peakCommittedMiB, Number(m[2]), Number(m[4]));
  }
  return {
    peakHeapMiB: Math.round(peakHeapMiB),
    peakCommittedHeapMiB: Math.round(peakCommittedMiB),
    garbageAtPeakMiB: Math.round(peakHeapMiB - liveHeapMiB),
  };
}

/** `units`: the history, its last `tail` units after the Snapshot. */
export function measureColdClient(snapshot, units, tail, options) {
  const dir = mkdtempSync(join(tmpdir(), "lfcp-cold-c-"));
  try {
    const file = join(dir, "c.bin");
    write(file, snapshot, units, tail, options);
    const run = spawnSync(process.execPath, ["--expose-gc", "--trace-gc", SELF, file], {
      encoding: "utf8",
      maxBuffer: 256 * MIB,
    });
    if (run.status !== 0) throw new Error(`cold client exited ${run.status}: ${run.stderr}`);
    const lines = run.stdout.trim().split("\n");
    const figures = JSON.parse(lines.findLast((l) => l.startsWith("{")));
    return { ...figures, ...heapPeak(lines, figures.liveHeapMiB) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] === SELF) await child(process.argv[2]);
