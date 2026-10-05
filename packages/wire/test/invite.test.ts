import {
  type ControlRecordId,
  controlRecordId,
  dataEpoch,
  LfcpError,
  resourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  InvitationSecret,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, encode } from "../src/cbor/index.js";
import {
  assembleInviteUri,
  type ChainResult,
  type ControlBody,
  decodeInviteSecret,
  encodeInviteSecret,
  INVITE_SECRET_VERSION,
  invitationPrincipal,
  parseInviteUri,
  signControlRecord,
  validateControlChain,
  verifyInvitationSecret,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic values; the published invite_uri vector runs in the conformance runner.

const SECRET = InvitationSecret.fromKeys(
  importSigningKey(seq32(10)),
  importAgreementKey(seq32(50)),
);
const SECRET_BYTES = encodeInviteSecret(SECRET);
const R = resourceId(seq32(200));
const GRANT = controlRecordId(seq32(120));
const ENDPOINT = "wss://sync.example.test/v1/ws";

/** Every rendering of the secret that must never appear in output: hex and base64url of the CBOR and of each key. */
const SECRET_FORMS = [
  toHex(SECRET_BYTES),
  toBase64url(SECRET_BYTES),
  toHex(seq32(10)),
  toHex(seq32(50)),
  toBase64url(seq32(10)),
  toBase64url(seq32(50)),
];
const expectNoSecret = (text: string) => {
  for (const form of SECRET_FORMS) expect(text.toLowerCase()).not.toContain(form.toLowerCase());
};
const codeOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not an LfcpError: ${String(e)}`;
  }
  return "no error";
};
/** The error a call throws; its message must not carry the secret. */
const errorOf = (fn: () => unknown): LfcpError => {
  try {
    fn();
  } catch (e) {
    expectNoSecret(String((e as Error).message));
    return e as LfcpError;
  }
  throw new Error("expected an error");
};

describe("invite-secret (§18.2)", () => {
  it("is deterministic CBOR {0: 1, 1: Ed25519 seed, 2: X25519 key} and decodes back", () => {
    expect(INVITE_SECRET_VERSION).toBe(1n);
    expect(toHex(SECRET_BYTES)).toBe(
      toHex(
        encode(
          cborMap([
            [0, 1],
            [1, seq32(10)],
            [2, seq32(50)],
          ]),
        ),
      ),
    );
    const back = decodeInviteSecret(SECRET_BYTES);
    expect(toHex(encodeInviteSecret(back))).toBe(toHex(SECRET_BYTES));
    expect(toHex(invitationPrincipal(back).principalId)).toBe(
      toHex(invitationPrincipal(SECRET).principalId),
    );
  });

  it("derives the Invitation Principal from both keys (§7)", () => {
    const d = invitationPrincipal(SECRET);
    expect(toHex(d.ed25519PublicKey)).toBe(toHex(importSigningKey(seq32(10)).publicKey));
    expect(toHex(d.x25519PublicKey)).toBe(toHex(importAgreementKey(seq32(50)).publicKey));
  });

  it.each([
    [
      "version 2",
      encode(
        cborMap([
          [0, 2],
          [1, seq32(10)],
          [2, seq32(50)],
        ]),
      ),
    ],
    [
      "a missing field",
      encode(
        cborMap([
          [0, 1],
          [1, seq32(10)],
        ]),
      ),
    ],
    [
      "an extra field",
      encode(
        cborMap([
          [0, 1],
          [1, seq32(10)],
          [2, seq32(50)],
          [3, 0],
        ]),
      ),
    ],
    [
      "a 31-byte seed",
      encode(
        cborMap([
          [0, 1],
          [1, seq32(10).subarray(1)],
          [2, seq32(50)],
        ]),
      ),
    ],
    [
      "a text key",
      encode(
        cborMap([
          [0, 1],
          [1, "seed"],
          [2, seq32(50)],
        ]),
      ),
    ],
    ["an array", encode([1, seq32(10), seq32(50)])],
    ["trailing bytes", Uint8Array.of(...SECRET_BYTES, 0)],
    ["a non-shortest head", Uint8Array.of(0xb8, 3, ...SECRET_BYTES.subarray(1))],
  ])("rejects %s with INVALID_INVITATION and no key bytes in the error", (_n, bytes) => {
    expect(errorOf(() => decodeInviteSecret(bytes)).code).toBe("INVALID_INVITATION");
  });

  it("is redacted when printed or serialized", () => {
    const secret = decodeInviteSecret(SECRET_BYTES);
    expect(JSON.stringify(secret)).toBe('"[redacted]"');
    expect(String(secret)).toBe("[redacted]");
    const inspect = (secret as unknown as Record<symbol, () => string>)[
      Symbol.for("nodejs.util.inspect.custom")
    ];
    expect(inspect?.call(secret)).toBe("[redacted]");
    expectNoSecret(JSON.stringify({ secret, keys: [secret.signingKey, secret.agreementKey] }));
    const own = Object.getOwnPropertyNames(secret).map(
      (n) => (secret as unknown as Record<string, unknown>)[n],
    );
    expect(own).toEqual([]);
  });

  it("generates independent fresh keys", () => {
    const a = invitationPrincipal(InvitationSecret.generate());
    const b = invitationPrincipal(InvitationSecret.generate());
    expect(toHex(a.principalId)).not.toBe(toHex(b.principalId));
    expect(toHex(a.ed25519PublicKey)).not.toBe(toHex(a.x25519PublicKey));
  });
});

describe("invitation URI (§18.2)", () => {
  const targeted = { resourceId: R, endpoints: [ENDPOINT], grantId: GRANT };

  it("assembles the targeted form with unpadded base64url IDs and a percent-encoded endpoint", () => {
    expect(assembleInviteUri(targeted)).toBe(
      `lfcp://join/${toBase64url(R)}?endpoint=wss%3A%2F%2Fsync.example.test%2Fv1%2Fws&grant=${toBase64url(GRANT)}`,
    );
  });

  it("assembles the bearer form with #secret=", () => {
    const uri = assembleInviteUri({ ...targeted, secret: SECRET });
    expect(uri.endsWith(`#secret=${toBase64url(SECRET_BYTES)}`)).toBe(true);
    expect(uri).not.toContain("=#");
  });

  it("percent-encodes every UTF-8 byte outside the unreserved set with upper-case hex (G-RS4)", () => {
    const url = "wss://sync.example.test/a/ü~x-y_z.q?k=v&w";
    expect(assembleInviteUri({ ...targeted, endpoints: [url] })).toContain(
      "endpoint=wss%3A%2F%2Fsync.example.test%2Fa%2F%C3%BC~x-y_z.q%3Fk%3Dv%26w&",
    );
    expect(parseInviteUri(assembleInviteUri({ ...targeted, endpoints: [url] })).endpoints).toEqual([
      url,
    ]);
  });

  it("keeps several endpoints in order", () => {
    const endpoints = [ENDPOINT, "wss://b.example.test/ws", "ws://127.0.0.1:9000/ws"];
    const uri = assembleInviteUri({ ...targeted, endpoints });
    expect(uri.match(/endpoint=/g)).toHaveLength(3);
    expect(parseInviteUri(uri).endpoints).toEqual(endpoints);
  });

  it("refuses to assemble without an endpoint or with one a writer may not use (§16)", () => {
    expect(codeOf(() => assembleInviteUri({ ...targeted, endpoints: [] }))).toBe(
      "INVALID_INVITATION",
    );
    expect(
      codeOf(() => assembleInviteUri({ ...targeted, endpoints: ["ws://remote.example.test/ws"] })),
    ).toBe("INVALID_INVITATION");
  });

  it("parses both forms back to their parts", () => {
    const t = parseInviteUri(assembleInviteUri(targeted));
    expect([toHex(t.resourceId), t.endpoints, toHex(t.grantId), t.secret]).toEqual([
      toHex(R),
      [ENDPOINT],
      toHex(GRANT),
      undefined,
    ]);
    const b = parseInviteUri(assembleInviteUri({ ...targeted, secret: SECRET }));
    expect(toHex(encodeInviteSecret(b.secret as InvitationSecret))).toBe(toHex(SECRET_BYTES));
    expectNoSecret(JSON.stringify(b));
  });

  it("compares the scheme and host case-insensitively and accepts any valid percent-encoding", () => {
    const uri = assembleInviteUri(targeted)
      .replace("lfcp://join/", "LFCP://Join/")
      .replace("%2F%2F", "%2f%2f");
    expect(parseInviteUri(uri).endpoints).toEqual([ENDPOINT]);
  });

  const base = assembleInviteUri(targeted);
  const bearer = assembleInviteUri({ ...targeted, secret: SECRET });
  const padded = `${toBase64url(GRANT)}=`;
  it.each([
    ["another scheme", base.replace("lfcp:", "https:")],
    ["another host", base.replace("//join/", "//open/")],
    ["no query", base.slice(0, base.indexOf("?"))],
    ["a short Resource ID", base.replace(toBase64url(R), toBase64url(R).slice(4))],
    ["a padded grant ID", base.replace(toBase64url(GRANT), padded)],
    ["no grant", base.slice(0, base.indexOf("&grant="))],
    ["two grants", `${base}&grant=${toBase64url(GRANT)}`],
    ["no endpoint", base.replace(/endpoint=[^&]*&/, "")],
    ["an empty endpoint", base.replace(/endpoint=[^&]*/, "endpoint=")],
    ["an https endpoint", base.replace(/endpoint=[^&]*/, "endpoint=https%3A%2F%2Fx.example.test")],
    ["a broken percent-encoding", base.replace("%3A", "%3")],
    ["a raw space", base.replace("%2F", " ")],
    ["an unknown parameter", `${base}&mode=x`],
    ["a fragment that is not secret=", `${base}#token=abc`],
    ["an empty fragment", `${base}#`],
    ["a padded secret", `${bearer}=`],
    ["a secret that is not an invite-secret", `${base}#secret=${toBase64url(seq32(1))}`],
  ])("rejects %s with INVALID_INVITATION, never echoing the URI or secret", (_n, uri) => {
    expect(errorOf(() => parseInviteUri(uri)).code).toBe("INVALID_INVITATION");
  });
});

describe("verifyInvitationSecret (§18.2)", () => {
  const INVITE = invitationPrincipal(SECRET);
  const DEK = importResourceDEK(seq32(90));
  const records: Uint8Array[] = [];
  let head: ControlRecordId | undefined;
  const add = (body: ControlBody): ControlRecordId => {
    const s = signControlRecord(
      { resourceId: R, controlSeq: BigInt(records.length), prevControlId: head ?? null },
      body,
      ALICE,
    );
    records.push(s.bytes);
    head = s.recordId;
    return s.recordId;
  };
  add({
    type: "GENESIS",
    dataProfile: "org.example.custom.v1",
    owner: ALICE.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK),
    endpoints: [{ url: ENDPOINT, priority: 0n }],
    coordinatorUrl: ENDPOINT,
  });
  const invitation = add({
    type: "CAPABILITY_GRANT",
    subject: INVITE,
    abilities: [1n, 2n, 11n],
    delegable: [],
    claimLimit: 1n,
  });
  const plain = add({
    type: "CAPABILITY_GRANT",
    subject: BRUNO.descriptor,
    abilities: [1n],
    delegable: [],
  });
  const state = (validateControlChain(records) as Extract<ChainResult, { kind: "linear" }>).state;

  it("returns the Invitation Principal as a signer when it is the grant's subject", () => {
    const signer = verifyInvitationSecret(state, invitation, decodeInviteSecret(SECRET_BYTES));
    expect(toHex(signer.descriptor.principalId)).toBe(toHex(INVITE.principalId));
    expect(toHex(signer.key.publicKey)).toBe(toHex(INVITE.ed25519PublicKey));
  });

  it("refuses a secret of another Principal, a grant without invite/claim and an unknown grant", () => {
    const other = InvitationSecret.fromKeys(
      importSigningKey(seq32(11)),
      importAgreementKey(seq32(50)),
    );
    expect(errorOf(() => verifyInvitationSecret(state, invitation, other)).code).toBe(
      "INVALID_INVITATION",
    );
    expect(errorOf(() => verifyInvitationSecret(state, plain, SECRET)).code).toBe(
      "INVALID_INVITATION",
    );
    expect(errorOf(() => verifyInvitationSecret(state, GRANT, SECRET)).code).toBe(
      "MISSING_DEPENDENCY",
    );
  });
});
