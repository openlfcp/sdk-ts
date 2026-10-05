import { dataEpoch, LfcpError, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  InvitationSecret,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { InMemoryLfcpStorage, InMemorySecretStore } from "@openlfcp/storage";
import {
  ABILITY,
  assembleInviteUri,
  parseControlRecord,
  parseInviteUri,
  parseKeyPackage,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
  verifyKeyPackage,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import {
  acceptInvitation,
  createInvitation,
  DEFAULT_INVITATION_ABILITIES,
  InvitationLink,
  saveControlChain,
} from "../src/index.js";

// Synthetic keys; the end-to-end flow runs live in conformance/interop (LFCP-053).

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const READER = signer(33);
const R = resourceId(bytes32(200));
const DEK = importResourceDEK(bytes32(90));
const URL = "wss://sync.example.test/v1/ws";

async function owned() {
  const storage = new InMemoryLfcpStorage();
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
  const reader = signControlRecord(
    { resourceId: R, controlSeq: 1n, prevControlId: genesis.recordId },
    { type: "CAPABILITY_GRANT", subject: READER.descriptor, abilities: [1n], delegable: [] },
    OWNER,
  );
  const chain = validateControlChain([genesis.bytes, reader.bytes]);
  if (chain.kind !== "linear") throw new Error(chain.kind);
  await saveControlChain(storage, chain, null);
  return { storage, chain };
}
const codeOf = async (p: Promise<unknown>): Promise<string> =>
  p.then(
    () => "no error",
    (e) => (e instanceof LfcpError ? e.code : String(e)),
  );

describe("createInvitation (§18, §73)", () => {
  it("queues a claimable grant to a fresh Invitation Principal, then its Key Package", async () => {
    const { storage, chain } = await owned();
    const secret = InvitationSecret.fromKeys(
      importSigningKey(bytes32(5)),
      importAgreementKey(bytes32(6)),
    );
    const created = await createInvitation({
      storage,
      resourceId: R,
      inviter: OWNER,
      dek: DEK,
      endpoints: [URL],
      secret,
    });
    const queued = await storage.outbound.list(R);
    expect(queued.map((q) => q.kind)).toEqual(["control-record", "key-package"]);
    const grant = parseControlRecord(queued[0]?.bytes as Uint8Array);
    expect(toHex(grant.signed.id)).toBe(toHex(created.grantId));
    expect(grant.payload.controlSeq).toBe(2n);
    const extended = validateControlChain([
      ...chain.records.map((r) => r.signed.bytes),
      grant.signed.bytes,
    ]);
    if (extended.kind !== "linear") throw new Error(extended.kind);
    expect(extended.state.grants.get(toHex(created.grantId))).toMatchObject({
      abilities: DEFAULT_INVITATION_ABILITIES,
      claimLimit: 1n,
    });
    expect(toHex(extended.state.grants.get(toHex(created.grantId))?.subject as Uint8Array)).toBe(
      toHex(created.invitationPrincipal.principalId),
    );
    const kp = parseKeyPackage(queued[1]?.bytes as Uint8Array);
    expect(toHex(kp.payload.recipient)).toBe(toHex(created.invitationPrincipal.principalId));
    expect(toHex(kp.payload.controlHead)).toBe(toHex(created.grantId));
    expect(verifyKeyPackage(extended, kp).kind).toBe("authorized");

    const uri = created.link.reveal();
    const parsed = parseInviteUri(uri);
    expect([toHex(parsed.grantId), parsed.endpoints]).toEqual([toHex(created.grantId), [URL]]);
    expect(uri).toBe(
      assembleInviteUri({ resourceId: R, endpoints: [URL], grantId: created.grantId, secret }),
    );
  });

  it("keeps the link redacted", async () => {
    const { storage } = await owned();
    const { link } = await createInvitation({
      storage,
      resourceId: R,
      inviter: OWNER,
      dek: DEK,
      endpoints: [URL],
    });
    const uri = link.reveal();
    const secret = uri.slice(uri.indexOf("#secret=") + 8);
    for (const text of [JSON.stringify({ link }), String(link), `${link}`])
      expect(text).not.toContain(secret);
    const inspect = (link as unknown as Record<symbol, () => string>)[
      Symbol.for("nodejs.util.inspect.custom")
    ];
    expect(inspect?.call(link)).toBe("[redacted]");
    expect(Object.getOwnPropertyNames(link)).toEqual([]);
  });

  it("refuses before queueing: no invite/claim, no claim_limit, a wrong DEK, an inviter without authority", async () => {
    const { storage } = await owned();
    const base = { storage, resourceId: R, inviter: OWNER, dek: DEK, endpoints: [URL] };
    expect(await codeOf(createInvitation({ ...base, abilities: [ABILITY.DATA_READ] }))).toBe(
      "UNSUPPORTED_VALUE",
    );
    expect(await codeOf(createInvitation({ ...base, claimLimit: 0n }))).toBe("UNSUPPORTED_VALUE");
    expect(await codeOf(createInvitation({ ...base, dek: importResourceDEK(bytes32(91)) }))).toBe(
      "DEK_COMMITMENT_MISMATCH",
    );
    expect(await codeOf(createInvitation({ ...base, inviter: READER }))).toBe(
      "AUTHORIZATION_FAILED",
    );
    expect(await codeOf(createInvitation({ ...base, resourceId: resourceId(bytes32(7)) }))).toBe(
      "MISSING_DEPENDENCY",
    );
    expect(await storage.outbound.list(R)).toEqual([]);
  });
});

describe("acceptInvitation (§18.2)", () => {
  it("refuses a targeted link (no secret) and a malformed one before connecting", async () => {
    const base = {
      claimant: { signer: READER, agreement: importAgreementKey(bytes32(133)) },
      storage: new InMemoryLfcpStorage(),
      secrets: new InMemorySecretStore(),
      now: () => 0,
      webSocket: () => {
        throw new Error("must not connect");
      },
    };
    const targeted = assembleInviteUri({
      resourceId: R,
      endpoints: [URL],
      grantId: bytes32(9) as never,
    });
    expect(await codeOf(acceptInvitation({ ...base, link: targeted }))).toBe("INVALID_INVITATION");
    expect(
      await codeOf(acceptInvitation({ ...base, link: new InvitationLink("lfcp://join/x") })),
    ).toBe("INVALID_INVITATION");
  });
});
