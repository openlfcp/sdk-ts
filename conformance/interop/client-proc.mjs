// A complete LFCP client in its own process for the LFCP-038 live restart
// test: SyncClient over SqliteLfcpStorage and FileSecretStore, the Shared
// Objects profile restored from its checkpoint when there is one.
//
//   node client-proc.mjs <dir> <url> <resource hex> <principal seed>
//
// It prints one JSON object per line (resource states, unit outcomes,
// replays, writes, roots) and reads commands from stdin:
//   write <title>   set the Task's title (a new local unit)
//   root            print the replica's logical root
// Plaintext is printed only through `root`, on request.

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import {
  createQueuedDataUnit,
  DataUnitApplier,
  dekResolver,
  loadControlChain,
  OutboundQueue,
  ProfileCheckpointer,
  SyncClient,
  startSyncDriver,
} from "@openlfcp/client";
import { fromHex, resourceId, toHex } from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import {
  checkChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setTitle,
} from "@openlfcp/shared-objects";
import { FileSecretStore, SqliteLfcpStorage } from "@openlfcp/storage-node";
import { principalDescriptorFromKeys } from "@openlfcp/wire";

const [dir, url, resourceHex, seedText] = process.argv.slice(2);
const seed = Number(seedText);
const bytes32 = (from) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = importSigningKey(bytes32(seed));
const agreement = importAgreementKey(bytes32(seed + 100));
const me = { key, descriptor: principalDescriptorFromKeys(key, agreement) };
const R = resourceId(fromHex(resourceHex));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
const out = (o) =>
  process.stdout.write(
    `${JSON.stringify(o, (_k, v) => (typeof v === "bigint" ? String(v) : v instanceof Uint8Array ? toHex(v) : v))}\n`,
  );

mkdirSync(dir, { recursive: true });
const storage = SqliteLfcpStorage.open(join(dir, "lfcp.sqlite"));
const secrets = new FileSecretStore(join(dir, "secrets"));
const cp = await storage.profileState.checkpoint(R);
const opts = { resource: R, principal: me.descriptor.principalId };
const profile =
  cp === undefined
    ? new SharedObjectsDataProfile(SharedObjectsReplica.empty(opts))
    : SharedObjectsDataProfile.restore(cp, opts);
const checkpointer = new ProfileCheckpointer(storage, profile, { minIntervalMs: 0 });
const applier = new DataUnitApplier({
  storage,
  dek: dekResolver(storage, secrets, R),
  handlers: [
    {
      dataProfile: profile.dataProfile,
      codecFor: (u) => profile.codecFor(u),
      apply: (u, v) => profile.apply(u, v),
      exclude: (ids) => profile.exclude(ids),
      has: (id) => profile.has(id),
      reset: () => profile.reset(),
    },
  ],
});
const client = new SyncClient({
  url,
  signer: me,
  agreement,
  storage,
  secrets,
  outbound: new OutboundQueue({ storage }),
  now: () => Date.now(),
  reconnect: () => 200,
  antiEntropyMs: 500,
});
client.on((e) => {
  if (e.type === "resource-state") out({ t: "state", state: e.state });
  else if (e.type === "unit")
    out({
      t: "unit",
      kind: e.outcome.kind,
      unitId: "unitId" in e.outcome ? e.outcome.unitId : null,
    });
  else if (e.type === "replayed")
    out({ t: "replayed", n: e.replayed.length, skipped: e.skipped.length });
  else if (e.type === "error") out({ t: "error", code: e.code, message: e.message });
  else if (e.type === "ack") out({ t: "ack", n: e.outcome.acked.length });
});
client.open({
  resourceId: R,
  applier,
  checkpointer,
  snapshot: {
    codec: profile.snapshotCodec(),
    load: (s) => profile.loadSnapshot(s),
    current: () => profile.snapshotState(),
  },
});
client.start();
startSyncDriver(client, { setInterval, clearInterval, now: () => Date.now() }, 50);
out({ t: "started", restored: cp !== undefined });

for await (const line of createInterface({ input: process.stdin })) {
  const [cmd, ...rest] = line.split(" ");
  if (cmd === "root")
    out({ t: "root", root: profile.replica.root(), actorSeq: profile.replica.actorSeq });
  if (cmd === "write") {
    const chain = await loadControlChain(storage, R);
    const dek = await dekResolver(storage, secrets, R)(chain.state.epoch.epoch);
    const mine = (
      await storage.dataUnits.range(R, me.descriptor.principalId, 1n, 2n ** 64n - 1n)
    ).filter((u) => u.accepted);
    const local = profile.replica.apply(
      setTitle(profile.replica.task(TASK).task, rest.join(" ")).intent,
    );
    const u = await createQueuedDataUnit(
      storage,
      {
        view: chain,
        controlHead: chain.state.head,
        actor: me,
        dek,
        profile: profile.codecFor({ resourceId: R, actor: me.descriptor.principalId }),
        previousUnitId: mine.at(-1)?.unitId ?? null,
        value: checkChange(local.change),
        onCreated: (created, value) => profile.recordLocal(created.unitId, value),
      },
      () => [checkpointer.write()],
    );
    client.flush();
    out({ t: "wrote", seq: u.seq, unitId: u.unitId });
  }
}
