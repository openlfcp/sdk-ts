// REVIEW-20261015-02 on the durable adapters: createInvitation stores the
// grant and its Key Package in one commit. A commit that fails (thrown, as a
// full disk does, or refused) leaves nothing of the invitation after the
// store is closed and reopened; the retry after the restart queues both, the
// grant first, on the committed head, and they are still there, in that
// order, after another restart.
//
// Cross-package (client + storage-node + storage-idb), so it lives under
// conformance/.

/// <reference lib="dom" />
import "fake-indexeddb/auto";
import { createInvitation, localControlChain, saveControlChain } from "@openlfcp/client";
import { dataEpoch, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import type { LfcpStorage, StorageWrite } from "@openlfcp/storage";
import { IdbLfcpStorage } from "@openlfcp/storage-idb";
import { SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  parseControlRecord,
  parseKeyPackage,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { inDir, makeTempDir, removeTempDir } from "./temp-dir.mjs";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const KEY = importSigningKey(bytes32(1));
const OWNER: Signer = {
  key: KEY,
  descriptor: principalDescriptorFromKeys(KEY, importAgreementKey(bytes32(101))),
};
const R = resourceId(bytes32(200));
const DEK = importResourceDEK(bytes32(90));
const URL = "wss://sync.example.test/v1/ws";
const genesis = signControlRecord(
  { resourceId: R, controlSeq: 0n, prevControlId: null },
  {
    type: "GENESIS",
    dataProfile: "org.example.custom.v1",
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK),
    endpoints: [{ url: URL, priority: 0n }],
    coordinatorUrl: URL,
  },
  OWNER,
);
const chain = validateControlChain([genesis.bytes]);
if (chain.kind !== "linear") throw new Error(chain.kind);

type Durable = LfcpStorage & { close(): void };
interface Backend {
  readonly name: string;
  setup(): { open(): Promise<Durable>; cleanup(): void };
}
let idbCount = 0;
const BACKENDS: Backend[] = [
  {
    name: "SQLite",
    setup() {
      const dir = makeTempDir("lfcp-invite-restart-");
      const path = inDir(dir, "lfcp.sqlite");
      return {
        open: async () => SqliteLfcpStorage.open(path),
        cleanup: () => removeTempDir(dir),
      };
    },
  },
  {
    name: "IndexedDB",
    setup() {
      const name = `lfcp-invite-restart-${++idbCount}`;
      return {
        open: () => IdbLfcpStorage.open(name),
        cleanup: () => indexedDB.deleteDatabase(name),
      };
    },
  },
];

/**
 * The parts createInvitation uses, with a commit that fails as `fault` says
 * once it stores a Key Package: a commit of the grant alone still lands, as
 * it did before the fix (two commits, the second failing).
 */
function faulty(storage: Durable, fault: "throw" | "refuse") {
  return {
    control: storage.control,
    outbound: storage.outbound,
    commit: async (writes: readonly StorageWrite[]) => {
      if (!writes.some((w) => w.op === "put-key-package")) return storage.commit(writes);
      if (fault === "throw") throw new Error("SQLITE_FULL: database or disk is full");
      return { ok: false, reason: "CONTROL_HEAD_MISMATCH", resourceId: R, current: null } as const;
    },
  };
}

describe("createInvitation across a restart (REVIEW-20261015-02)", () => {
  for (const backend of BACKENDS)
    for (const fault of ["throw", "refuse"] as const)
      it(`${backend.name}: a ${fault === "throw" ? "failed" : "refused"} commit leaves nothing; the retry queues both, grant first`, async () => {
        const { open, cleanup } = backend.setup();
        try {
          let storage = await open();
          expect((await saveControlChain(storage, chain, null)).ok).toBe(true);
          const base = { resourceId: R, inviter: OWNER, dek: DEK, endpoints: [URL] };
          await expect(
            createInvitation({ ...base, storage: faulty(storage, fault) }),
          ).rejects.toThrow();
          storage.close();

          storage = await open();
          expect(await storage.outbound.list(R)).toEqual([]);
          expect(await storage.keyPackages.list(R)).toEqual([]);
          const local = await localControlChain(storage, R);
          expect(local?.kind === "linear" && toHex(local.state.head)).toBe(toHex(genesis.recordId));
          const created = await createInvitation({ ...base, storage });
          storage.close();

          storage = await open();
          const queued = await storage.outbound.list(R);
          expect(queued.map((q) => q.kind)).toEqual(["control-record", "key-package"]);
          const grant = parseControlRecord(queued[0]?.bytes as Uint8Array);
          expect(grant.payload.controlSeq).toBe(1n);
          expect(toHex(grant.signed.id)).toBe(toHex(created.grantId));
          const kp = parseKeyPackage(queued[1]?.bytes as Uint8Array);
          expect(toHex(kp.payload.controlHead)).toBe(toHex(created.grantId));
          expect((await storage.keyPackages.list(R)).map((p) => toHex(p.packageId))).toEqual([
            toHex(created.keyPackageId),
          ]);
          storage.close();
        } finally {
          cleanup();
        }
      });
});
