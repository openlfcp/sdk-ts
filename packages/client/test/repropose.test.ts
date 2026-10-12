import { dataEpoch, type Hash32, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  InvitationSecret,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import {
  dekSecretRef,
  InMemoryLfcpStorage,
  InMemorySecretStore,
  type StorageWrite,
} from "@openlfcp/storage";
import {
  ABILITY,
  decodeControlRecord,
  parseControlRecord,
  parseKeyPackage,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
  verifyKeyPackage,
} from "@openlfcp/wire";
import { beforeEach, describe, expect, it } from "vitest";
import {
  createInvitation,
  OutboundQueue,
  reproposeControlRecords,
  saveControlChain,
} from "../src/index.js";

// Synthetic keys; the end-to-end flow runs live in conformance/interop.
const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const OTHER = signer(70);
const R = resourceId(bytes32(200));
const DEK = importResourceDEK(bytes32(90));
const URL = "wss://sync.example.test/v1/ws";

async function owned() {
  const storage = new InMemoryLfcpStorage();
  const secrets = new InMemorySecretStore();
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
  await saveControlChain(storage, chain, null);
  // The inviter holds the current epoch's DEK (for re-sealing on re-propose).
  await secrets.put(dekSecretRef(R, dataEpoch(0n)), exportSecretKeyBytes(DEK));
  return { storage, secrets, chain };
}

/** Commits a record by OWNER onto the stored head, moving it (another writer winning the race). */
async function moveHead(storage: InMemoryLfcpStorage, subjectSeed: number): Promise<void> {
  const head = await storage.control.head(R);
  const records = await storage.control.records(R);
  const chain = validateControlChain(records.map((r) => r.bytes));
  if (chain.kind !== "linear") throw new Error(chain.kind);
  const record = signControlRecord(
    { resourceId: R, controlSeq: chain.state.seq + 1n, prevControlId: chain.state.head },
    {
      type: "CAPABILITY_GRANT",
      subject: signer(subjectSeed).descriptor,
      abilities: [ABILITY.DATA_READ],
      delegable: [],
    },
    OWNER,
  );
  const next = validateControlChain([...records.map((r) => r.bytes), record.bytes]);
  if (next.kind !== "linear") throw new Error(next.kind);
  await saveControlChain(storage, next, head?.head ?? null);
}

/** Marks a queued control record blocked "repropose", as the OutboundQueue does on CONTROL_HEAD_MISMATCH. */
async function blockRepropose(storage: InMemoryLfcpStorage, itemId: Hash32): Promise<void> {
  const w: StorageWrite = {
    op: "update-outbound",
    itemId,
    blocked: { reason: "repropose", detail: null },
  };
  const r = await storage.commit([w]);
  if (!r.ok) throw new Error(r.reason);
}

const queueFor = (storage: InMemoryLfcpStorage) => new OutboundQueue({ storage });

describe("reproposeControlRecords (§47, §21)", () => {
  let storage: InMemoryLfcpStorage;
  let secrets: InMemorySecretStore;

  beforeEach(async () => {
    ({ storage, secrets } = await owned());
  });

  async function queuedInvite() {
    const created = await createInvitation({
      storage,
      resourceId: R,
      inviter: OWNER,
      dek: DEK,
      endpoints: [URL],
      secret: InvitationSecret.fromKeys(
        importSigningKey(bytes32(5)),
        importAgreementKey(bytes32(6)),
      ),
    });
    const items = await storage.outbound.list(R);
    const control = items.find((i) => i.kind === "control-record");
    if (control === undefined) throw new Error("no queued grant");
    return { created, controlItemId: control.itemId };
  }

  it("re-authors a blocked grant on the moved head and re-seals its Key Package", async () => {
    const { created, controlItemId } = await queuedInvite();
    await moveHead(storage, 71); // another writer commits first
    await blockRepropose(storage, controlItemId);

    const attempts = new Map<string, number>();
    const { outcomes } = await reproposeControlRecords({
      storage,
      secrets,
      signer: OWNER,
      resource: R,
      queue: queueFor(storage),
      attempts,
    });

    expect(outcomes).toHaveLength(1);
    const outcome = outcomes[0];
    if (outcome?.kind !== "reproposed")
      throw new Error(`expected reproposed, got ${outcome?.kind}`);
    expect(toHex(outcome.oldId)).toBe(toHex(created.grantId));
    expect(toHex(outcome.newId)).not.toBe(toHex(created.grantId));
    expect(outcome.keyPackages).toHaveLength(1);

    // The old blocked grant and its old Key Package are gone; a new linear pair is queued.
    const items = await storage.outbound.list(R);
    expect(items.every((i) => i.blocked === null)).toBe(true);
    const newGrant = parseControlRecord(
      items.find((i) => i.kind === "control-record")?.bytes as Uint8Array,
    );
    const stored = validateControlChain((await storage.control.records(R)).map((r) => r.bytes));
    if (stored.kind !== "linear") throw new Error(stored.kind);
    // It chains on the moved head.
    expect(toHex(newGrant.payload.prevControlId as Uint8Array)).toBe(toHex(stored.state.head));
    expect(newGrant.payload.controlSeq).toBe(stored.state.seq + 1n);
    expect(toHex(newGrant.signed.id)).toBe(toHex(outcome.newId));

    // The re-sealed Key Package names the new head and verifies on it.
    const extended = validateControlChain([
      ...stored.records.map((r) => r.signed.bytes),
      newGrant.signed.bytes,
    ]);
    if (extended.kind !== "linear") throw new Error(extended.kind);
    const kp = parseKeyPackage(items.find((i) => i.kind === "key-package")?.bytes as Uint8Array);
    expect(toHex(kp.payload.controlHead)).toBe(toHex(outcome.newId));
    expect(toHex(kp.payload.recipient)).toBe(toHex(created.invitationPrincipal.principalId));
    expect(verifyKeyPackage(extended, kp).kind).toBe("authorized");
  });

  it("is idempotent: a second run finds nothing once the record is live again", async () => {
    const { controlItemId } = await queuedInvite();
    await moveHead(storage, 71);
    await blockRepropose(storage, controlItemId);
    const attempts = new Map<string, number>();
    const first = await reproposeControlRecords({
      storage,
      secrets,
      signer: OWNER,
      resource: R,
      queue: queueFor(storage),
      attempts,
    });
    expect(first.outcomes[0]?.kind).toBe("reproposed");
    const second = await reproposeControlRecords({
      storage,
      secrets,
      signer: OWNER,
      resource: R,
      queue: queueFor(storage),
      attempts,
    });
    expect(second.outcomes).toEqual([]);
  });

  it("drops a blocked grant whose equivalent is already on the chain (superseded)", async () => {
    const { controlItemId } = await queuedInvite();
    await blockRepropose(storage, controlItemId);
    // Commit an equivalent grant (same subject and abilities) onto the chain,
    // as if this grant had been re-proposed and acknowledged before a crash.
    const blocked = decodeControlRecord(
      (await storage.outbound.list(R)).find((i) => i.kind === "control-record")
        ?.bytes as Uint8Array,
    );
    if (blocked.body.type !== "CAPABILITY_GRANT") throw new Error("not a grant");
    const records = await storage.control.records(R);
    const head = await storage.control.head(R);
    const chain = validateControlChain(records.map((r) => r.bytes));
    if (chain.kind !== "linear") throw new Error(chain.kind);
    const dup = signControlRecord(
      { resourceId: R, controlSeq: chain.state.seq + 1n, prevControlId: chain.state.head },
      {
        type: "CAPABILITY_GRANT",
        subject: blocked.body.subject,
        abilities: blocked.body.abilities,
        delegable: blocked.body.delegable,
        ...(blocked.body.claimLimit === undefined ? {} : { claimLimit: blocked.body.claimLimit }),
      },
      OWNER,
    );
    const next = validateControlChain([...records.map((r) => r.bytes), dup.bytes]);
    if (next.kind !== "linear") throw new Error(next.kind);
    await saveControlChain(storage, next, head?.head ?? null);

    const { outcomes } = await reproposeControlRecords({
      storage,
      secrets,
      signer: OWNER,
      resource: R,
      queue: queueFor(storage),
      attempts: new Map(),
    });
    expect(outcomes[0]).toMatchObject({ kind: "dropped", reason: "superseded" });
    // The blocked item and its Key Package are gone.
    expect((await storage.outbound.list(R)).filter((i) => i.blocked !== null)).toEqual([]);
  });

  it("drops a blocked record this client did not author (not-author)", async () => {
    const { controlItemId } = await queuedInvite();
    await moveHead(storage, 71);
    await blockRepropose(storage, controlItemId);
    const { outcomes } = await reproposeControlRecords({
      storage,
      secrets,
      signer: OTHER, // a different client cannot re-sign OWNER's record
      resource: R,
      queue: queueFor(storage),
      attempts: new Map(),
    });
    expect(outcomes[0]).toMatchObject({ kind: "dropped", reason: "not-author" });
  });

  it("is bounded: an item re-proposed too many times is dropped (attempts-exhausted)", async () => {
    const { controlItemId } = await queuedInvite();
    await moveHead(storage, 71);
    await blockRepropose(storage, controlItemId);
    const attempts = new Map<string, number>([[toHex(controlItemId), 8]]);
    const { outcomes } = await reproposeControlRecords({
      storage,
      secrets,
      signer: OWNER,
      resource: R,
      queue: queueFor(storage),
      attempts,
      maxAttempts: 8,
    });
    expect(outcomes[0]).toMatchObject({ kind: "dropped", reason: "attempts-exhausted" });
  });
});
