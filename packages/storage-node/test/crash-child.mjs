// Child process for the crash tests (LFCP-035): writes to the store in a
// loop and reports each step only after its promise resolved (that is,
// after the transaction committed). The parent kills it with SIGKILL at an
// arbitrary point and checks the reopened store.
//
//   node crash-child.mjs <db path> reserve
//   node crash-child.mjs <db path> batch <units per batch>

import { SqliteLfcpStorage } from "@openlfcp/storage-node";

const [dbPath, mode, perBatch = "20"] = process.argv.slice(2);
const storage = SqliteLfcpStorage.open(dbPath);
const R = new Uint8Array(32).fill(1);
const ALICE = new Uint8Array(32).fill(10);
const id = (n) => {
  const b = new Uint8Array(32);
  new DataView(b.buffer).setUint32(28, n);
  b[0] = 0xdd;
  return b;
};

if (mode === "reserve") {
  for (;;) {
    const seq = await storage.actorSequences.reserveNext(R, ALICE);
    process.stdout.write(`R ${seq}\n`);
  }
} else if (mode === "batch") {
  const k = Number(perBatch);
  for (let batch = 0; ; batch++) {
    const writes = [];
    for (let i = 0; i < k; i++) {
      const n = batch * k + i;
      writes.push({
        op: "put-data-unit",
        unit: {
          unitId: id(n),
          resourceId: R,
          dataEpoch: 0n,
          actor: ALICE,
          actorSeq: BigInt(n + 1),
          prevDataUnitId: null,
          controlHead: id(0),
          bytes: new Uint8Array(4096).fill(n & 0xff),
        },
        status: "merged",
        accepted: true,
      });
    }
    writes.push({
      op: "put-profile-checkpoint",
      checkpoint: {
        resourceId: R,
        dataProfile: "x",
        state: new Uint8Array(64 * 1024).fill(batch & 0xff),
        actorSeq: batch,
        units: [],
      },
    });
    await storage.commit(writes);
    process.stdout.write(`B ${batch}\n`);
  }
}
