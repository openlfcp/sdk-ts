// One "process start" of a client that receives content trapping the
// Automerge engine for real (LFCP engine-trap test; see engine-trap.test.ts).
// Run as: node engine-trap.child.mjs <state-dir> <phase>
//   phase "first":   create the Resource and the poisoned unit, receive it;
//   phase "restart": replay stored units after a restart;
//   phase "redeliver": after the restarts, the same unit arrives again.
// Prints one JSON line with what happened. Exits 0 unless the test itself fails.
//
// The poisoned unit is one self-contained change (no dependencies) nesting
// 16,000 maps: within the change expansion limits (16,384 operations) and far
// past the depth at which Automerge JS 3.5.0 traps (about 6,500). Deeper traps
// sooner: about 30 s at 16,000 levels, 90 s at 6,600. The profile
// handler below is a TEST SEAM: it hands the change straight to the Automerge
// engine, without the §11.2 depth admission a real receiver applies, so the
// real trap happens and the crash-loop breaker (EngineGuard) is exercised end
// to end. Nothing in production code is bypassed.

import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createDataUnit, DataUnitApplier, isEngineTrap, saveControlChain } from "@openlfcp/client";
import { dataEpoch, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import {
  deriveActorId,
  frameProfilePayload,
  PROFILE_ID,
  unframeChange,
} from "@openlfcp/shared-objects";
import { SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  principalDescriptorFromKeys,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";

const here = dirname(fileURLToPath(import.meta.url));
// The same Automerge module instance @openlfcp/shared-objects uses (ESM, by file URL).
const cjs = createRequire(join(here, "../../packages/shared-objects/package.json")).resolve(
  "@automerge/automerge",
);
const A = await import(
  pathToFileURL(join(dirname(cjs), "../mjs/entrypoints/fullfat_node.js")).href
);

const [dir, phase] = process.argv.slice(2);
const bytes32 = (from) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = importSigningKey(bytes32(1));
const OWNER = {
  key,
  descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(101))),
};
const R = resourceId(bytes32(200));
const DEK = importResourceDEK(bytes32(90));
const genesis = signControlRecord(
  { resourceId: R, controlSeq: 0n, prevControlId: null },
  {
    type: "GENESIS",
    dataProfile: PROFILE_ID,
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK),
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  },
  OWNER,
);
const view = validateControlChain([genesis.bytes]);
const storage = SqliteLfcpStorage.open(join(dir, "lfcp.sqlite"));

// The test seam: the raw engine, no admission.
let doc = A.init();
const merged = new Set();
let applied = 0;
const handler = {
  dataProfile: PROFILE_ID,
  codecFor: () => ({
    dataProfile: PROFILE_ID,
    encode: () => {
      throw new Error("decode only");
    },
    decode: (plaintext) => unframeChange(plaintext),
  }),
  apply: (unit, value) => {
    applied += 1;
    doc = A.applyChanges(doc, [value.bytes])[0];
    merged.add(toHex(unit.unitId));
    return { merged: [unit.unitId], objects: [], diagnostics: [] };
  },
  exclude: () => ({ objects: [], pending: [] }),
  has: (id) => merged.has(toHex(id)),
};
const applier = new DataUnitApplier({ storage, dek: () => DEK, handlers: [handler] });
const engineAlive = () => {
  try {
    A.save(
      A.change(A.init(), (d) => {
        d.ok = 1;
      }),
    );
    return true;
  } catch {
    return false;
  }
};
const marks = async () =>
  (await storage.localMarks.list("")).map((m) => [m.key.replace(toHex(R), "R"), m.value]);
const describe = (e) => ({ name: e?.constructor?.name, message: String(e?.message).slice(0, 120) });
const out = { phase };

if (phase === "first") {
  const saved = await saveControlChain(storage, view, null);
  if (!saved.ok) throw new Error(saved.reason);
  const actor = toHex(deriveActorId(R, OWNER.descriptor.principalId));
  let parent = "_root";
  const ops = Array.from({ length: 16_000 }, (_, i) => {
    const op = { action: "makeMap", obj: parent, key: "d", pred: [] };
    parent = `${i + 1}@${actor}`;
    return op;
  });
  const change = A.encodeChange({
    actor,
    seq: 1,
    startOp: 1,
    time: 0,
    message: null,
    deps: [],
    ops,
  });
  const unit = await createDataUnit({
    view,
    controlHead: view.state.head,
    actor: OWNER,
    dek: DEK,
    sequences: storage.actorSequences,
    previousUnitId: null,
    profile: {
      dataProfile: PROFILE_ID,
      encode: () => frameProfilePayload(change),
      decode: () => undefined,
    },
    value: undefined,
  });
  writeFileSync(join(dir, "unit.hex"), toHex(unit.unitId));
  const t0 = Date.now();
  try {
    await applier.receive(view, unit.bytes);
    out.received = "no trap";
  } catch (e) {
    out.trap = isEngineTrap(e);
    out.error = describe(e);
  }
  out.applyMs = Date.now() - t0;
} else if (phase === "redeliver") {
  const unitHex = readFileSync(join(dir, "unit.hex"), "utf8");
  const stored = await storage.dataUnits.get(Uint8Array.from(Buffer.from(unitHex, "hex")));
  await applier.replayStored(view);
  const outcome = await applier.receive(view, stored.bytes);
  out.outcome = { kind: outcome.kind, code: outcome.code };
} else {
  const unitHex = readFileSync(join(dir, "unit.hex"), "utf8");
  const t0 = Date.now();
  try {
    const r = await applier.replayStored(view);
    out.crashed = r.crashed.map(toHex);
    out.replayed = r.replayed.map(toHex);
    out.skipped = r.skipped.map((s) => [toHex(s.unitId), s.reason]);
  } catch (e) {
    out.trap = isEngineTrap(e);
    out.error = describe(e);
  }
  out.unit = unitHex;
  out.applyMs = Date.now() - t0;
}
out.applied = applied;
out.engineAlive = engineAlive();
out.marks = await marks();
console.log(JSON.stringify(out));
