// A writing LFCP client in its own process, for the LFCP-038 restart and
// crash tests. Every run opens the same SQLite database and secret
// directory; nothing survives between runs except what was persisted.
//
//   node writer-proc.mjs <dir> write <value> [<stop-at>]
//   node writer-proc.mjs <dir> rotate
//   node writer-proc.mjs <dir> send
//   node writer-proc.mjs <dir> state
//
// `write` prints each step after it completed; at <stop-at> it waits
// forever, so the parent can SIGKILL it exactly there. Steps:
// BEFORE_RESERVE, RESERVED <seq>, CREATED <seq> <unit id>, QUEUED,
// SENT <message id>, DONE. Secrets are never printed.

import { join } from "node:path";
import {
  createDataUnit,
  dataUnitRow,
  dekResolver,
  loadControlChain,
  OutboundQueue,
  outboundItem,
  saveControlChain,
} from "@openlfcp/client";
import { dataEpoch, hash32, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  sha256,
} from "@openlfcp/crypto";
import { dekSecretRef } from "@openlfcp/storage";
import { FileSecretStore, SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  decodeMessage,
  principalDescriptorFromKeys,
  rotateEpoch,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";

const [dir, cmd, ...args] = process.argv.slice(2);
const bytes32 = (from) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = importSigningKey(bytes32(1));
const OWNER = {
  key,
  descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(101))),
};
const ME = OWNER.descriptor.principalId;
const R = resourceId(bytes32(240));
const DEKS = [importResourceDEK(bytes32(90)), importResourceDEK(bytes32(91))];
const PROFILE = "org.example.text.v1";
const TEXT = {
  dataProfile: PROFILE,
  encode: (s) => new TextEncoder().encode(s),
  decode: (b) => new TextDecoder().decode(b),
};
const out = (line) => process.stdout.write(`${line}\n`);
const forever = () => new Promise(() => {});
const iso = () => new Date().toISOString();

const storage = SqliteLfcpStorage.open(join(dir, "lfcp.sqlite"));
const secrets = new FileSecretStore(join(dir, "secrets"));

async function storeDek(epoch) {
  const ref = dekSecretRef(R, dataEpoch(epoch));
  await secrets.put(ref, exportSecretKeyBytes(DEKS[Number(epoch)]));
  const row = (await storage.control.epochs(R)).find((e) => e.epoch === epoch);
  await storage.commit([{ op: "put-epoch", resourceId: R, epoch: { ...row, dekRef: ref } }]);
}

async function init() {
  if ((await storage.control.head(R)) !== undefined) return;
  const genesis = signControlRecord(
    { resourceId: R, controlSeq: 0n, prevControlId: null },
    {
      type: "GENESIS",
      dataProfile: PROFILE,
      owner: OWNER.descriptor,
      dekCommitment: dekCommitment(R, dataEpoch(0n), DEKS[0]),
      endpoints: [{ url: "ws://127.0.0.1:1/v1/ws", priority: 0n }],
      coordinatorUrl: "ws://127.0.0.1:1/v1/ws",
    },
    OWNER,
  );
  await saveControlChain(storage, validateControlChain([genesis.bytes]), null);
  await storeDek(0n);
}

async function mine() {
  return (await storage.dataUnits.range(R, ME, 1n, 2n ** 64n - 1n)).filter((u) => u.accepted);
}

async function write(value, stopAt) {
  const mark = async (step, extra = "") => {
    out(`${step}${extra === "" ? "" : ` ${extra}`}`);
    if (step === stopAt) await forever();
  };
  await init();
  const chain = await loadControlChain(storage, R);
  const dek = await dekResolver(storage, secrets, R)(chain.state.epoch.epoch);
  const previous = (await mine()).at(-1)?.unitId ?? null;
  await mark("BEFORE_RESERVE");
  const seq = await storage.actorSequences.reserveNext(R, ME);
  await mark("RESERVED", String(seq));
  const created = await createDataUnit({
    view: chain,
    controlHead: chain.state.head,
    actor: OWNER,
    dek,
    sequences: { reserveNext: async () => seq },
    previousUnitId: previous,
    profile: TEXT,
    value,
  });
  await mark("CREATED", `${seq} ${toHex(created.unitId)} ${created.epoch}`);
  const row = dataUnitRow(created.bytes);
  await storage.commit([
    { op: "put-data-unit", unit: row, status: "merged", detail: "local", accepted: true },
    { op: "enqueue", item: outboundItem("data-unit", hash32(created.unitId), R, created.bytes) },
  ]);
  await mark("QUEUED");
  const [m] = await new OutboundQueue({ storage }).next(R, iso());
  await mark("SENT", toHex(m.message.messageId));
  await mark("DONE");
}

switch (cmd) {
  case "write":
    await write(args[0], args[1]);
    break;
  case "rotate": {
    const chain = await loadControlChain(storage, R);
    const last = (await mine()).at(-1)?.actorSeq ?? 0n;
    const rotation = rotateEpoch(chain.state, OWNER, {
      reason: 0n,
      finalFrontier: last === 0n ? [] : [{ principalId: ME, contiguous: last, extras: [] }],
      dek: DEKS[1],
    });
    const next = validateControlChain([
      ...chain.records.map((r) => r.signed.bytes),
      rotation.bytes,
    ]);
    await saveControlChain(storage, next, chain.state.head);
    await storeDek(1n);
    out(`ROTATED ${next.state.epoch.epoch}`);
    break;
  }
  case "send": {
    for (const m of await new OutboundQueue({ storage }).next(R, iso())) {
      const d = decodeMessage(m.bytes);
      out(
        `SENT ${toHex(m.message.messageId)} ${d.body.objects.map((o) => toHex(sha256(o))).join(",")}`,
      );
    }
    break;
  }
  case "state": {
    const units = (await storage.dataUnits.range(R, ME, 1n, 2n ** 64n - 1n)).map((u) => ({
      seq: String(u.actorSeq),
      unitId: toHex(u.unitId),
      epoch: String(u.dataEpoch),
      bytesSha: toHex(sha256(u.bytes)),
    }));
    const queue = (await storage.outbound.list(R)).map((o) => ({
      itemId: toHex(o.itemId),
      bytesSha: toHex(sha256(o.bytes)),
      attempts: o.attempts,
    }));
    const head = await storage.control.head(R);
    out(`STATE ${JSON.stringify({ units, queue, head: String(head?.controlSeq) })}`);
    break;
  }
}
storage.close();
