import {
  type ControlRecordId,
  compareCanonicalFrontierOrder,
  controlRecordId,
  dataEpoch,
  generateResourceId,
  LfcpError,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { dekCommitment, importResourceDEK, sha256 } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { type CborMap, type CborValue, cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  type ControlBody,
  checkReceivedUrl,
  checkWriterUrl,
  controlBodyFromCbor,
  controlRecordSigner,
  decodeControlRecord,
  encodeControlRecordPayload,
  encodePrincipalDescriptor,
  endpointFromCbor,
  endpointToCbor,
  signControlRecord,
  signObject,
  verifyGenesis,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic records. The published C0-C6 (exact payloads, COSE bytes and
// record IDs, decoded and re-signed) run in the conformance runner.

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};

/** Field `key` of a decoded CBOR map. */
const field = (value: CborValue, key: number): CborValue =>
  (value as CborMap).entries.find(([k]) => k === key)?.[1] as CborValue;

const R = resourceId(seq32(200));
const COMMITMENT = dekCommitment(R, dataEpoch(0n), importResourceDEK(seq32(90)));
const ENDPOINT = { url: "wss://sync.example.test/v1/ws", priority: 0n, flags: 3n };
const genesisBody = (
  over: Partial<Extract<ControlBody, { type: "GENESIS" }>> = {},
): ControlBody => ({
  type: "GENESIS",
  dataProfile: "org.example.custom.v1",
  owner: ALICE.descriptor,
  dekCommitment: COMMITMENT,
  endpoints: [ENDPOINT],
  coordinatorUrl: "wss://sync.example.test/v1/ws",
  ...over,
});
const GENESIS_HEADER = { resourceId: R, controlSeq: 0n, prevControlId: null };
const GENESIS = signControlRecord(GENESIS_HEADER, genesisBody(), ALICE);
const next = (seq: bigint, prev: ControlRecordId = GENESIS.recordId) => ({
  resourceId: R,
  controlSeq: seq,
  prevControlId: prev,
});

describe("Genesis (§13.1, §15)", () => {
  const record = decodeControlRecord(GENESIS.bytes);

  it("1, 11, 12. signs to a canonical record whose ID is SHA-256 of the exact bytes", () => {
    expect(GENESIS.bytes[0]).toBe(0x84);
    expect(toHex(GENESIS.recordId)).toBe(toHex(sha256(GENESIS.bytes)));
    expect(toHex(record.signed.id)).toBe(toHex(GENESIS.recordId));
  });

  it("2, 3. has control_seq exactly 0 and a null previous record", () => {
    expect(record.payload.controlSeq).toBe(0n);
    expect(record.payload.prevControlId).toBeNull();
    expect(
      codeOf(() => signControlRecord({ ...GENESIS_HEADER, controlSeq: 1n }, genesisBody(), ALICE)),
    ).toBe("INVALID_STRUCTURE");
    expect(
      codeOf(() =>
        signControlRecord(
          { ...GENESIS_HEADER, prevControlId: controlRecordId(seq32(1)) },
          genesisBody(),
          ALICE,
        ),
      ),
    ).toBe("INVALID_STRUCTURE");
  });

  it("4. encodes the owner as the exact Principal Descriptor (body field 1)", () => {
    const owner = field(field(decodeStrict(record.signed.payloadBytes), 5), 1);
    expect(toHex(encode(owner))).toBe(toHex(encodePrincipalDescriptor(ALICE.descriptor)));
    expect(record.body.type === "GENESIS" && toHex(record.body.owner.principalId)).toBe(
      toHex(ALICE.descriptor.principalId),
    );
  });

  it("5. is signed by the owner in its body", () => {
    expect(verifyGenesis(record)).toEqual({ valid: true });
    expect(toHex(controlRecordSigner(record))).toBe(toHex(ALICE.descriptor.principalId));
  });

  it("6. rejects a wrong signer, on both the writing and the receiving side", () => {
    // Writing: the owner in the body must be the signer.
    expect(codeOf(() => signControlRecord(GENESIS_HEADER, genesisBody(), BRUNO))).toBe(
      "INVALID_STRUCTURE",
    );
    // Receiving: issuer = owner, but signed by another key (kid is BRUNO).
    const payload = encodeControlRecordPayload(
      GENESIS_HEADER,
      ALICE.descriptor.principalId,
      genesisBody(),
    );
    const forged = decodeControlRecord(signObject(payload, BRUNO).bytes);
    expect(verifyGenesis(forged)).toEqual({ valid: false, reason: "KID_MISMATCH" });
    // Receiving: issuer and kid are BRUNO, but the body names ALICE as owner.
    const raw = encode(
      cborMap([
        [0, R],
        [1, 0],
        [2, null],
        [3, 0],
        [4, BRUNO.descriptor.principalId],
        [5, field(decodeStrict(payload), 5)],
      ]),
    );
    expect(verifyGenesis(decodeControlRecord(signObject(raw, BRUNO).bytes))).toEqual({
      valid: false,
      reason: "ISSUER_NOT_OWNER",
    });
  });

  it("7, 8, 10. keeps the Data Profile, the epoch-0 commitment and the coordinator URL", () => {
    expect(record.body).toMatchObject({
      type: "GENESIS",
      dataProfile: "org.example.custom.v1",
      coordinatorUrl: "wss://sync.example.test/v1/ws",
    });
    expect(record.body.type === "GENESIS" && toHex(record.body.dekCommitment)).toBe(
      toHex(COMMITMENT),
    );
  });

  it("9. encodes an endpoint exactly", () => {
    // {0: "wss://a.test/x", 1: 0, 2: 3}
    const url = "wss://a.test/x";
    const expected = `a3006e${toHex(Uint8Array.from(url, (c) => c.charCodeAt(0)))}01000203`;
    expect(toHex(encode(endpointToCbor({ url, priority: 0n, flags: 3n })))).toBe(expected);
    expect(toHex(encode(endpointToCbor({ url, priority: 0n })))).toBe(
      expected.slice(0, -4).replace(/^a3/, "a2"),
    );
  });

  it("13. decoding keeps the exact received bytes", () => {
    const input = Uint8Array.from(GENESIS.bytes);
    const decoded = decodeControlRecord(input);
    input.fill(0);
    expect(toHex(decoded.signed.bytes)).toBe(toHex(GENESIS.bytes));
  });

  it("14. the Resource ID is the caller's, never derived from owner, route or profile", () => {
    const a = generateResourceId();
    const b = generateResourceId();
    const ra = decodeControlRecord(
      signControlRecord({ ...GENESIS_HEADER, resourceId: a }, genesisBody(), ALICE).bytes,
    );
    const rb = decodeControlRecord(
      signControlRecord({ ...GENESIS_HEADER, resourceId: b }, genesisBody(), ALICE).bytes,
    );
    expect(toHex(ra.payload.resourceId)).toBe(toHex(a));
    expect(toHex(rb.payload.resourceId)).toBe(toHex(b));
    expect(toHex(a)).not.toBe(toHex(b));
    // Same Resource, different owner, route and profile: the ID does not move.
    const other = signControlRecord(
      GENESIS_HEADER,
      genesisBody({
        owner: BRUNO.descriptor,
        dataProfile: "lfcp.yjs.v1",
        coordinatorUrl: "wss://other.test",
      }),
      BRUNO,
    );
    expect(toHex(decodeControlRecord(other.bytes).payload.resourceId)).toBe(toHex(R));
  });
});

describe("typed bodies", () => {
  const grant: ControlBody = {
    type: "CAPABILITY_GRANT",
    subject: BRUNO.descriptor,
    abilities: [1n, 2n, 11n],
    delegable: [],
    claimLimit: 1n,
  };
  const bodies: [string, ControlBody, boolean][] = [
    ["CAPABILITY_GRANT", grant, true],
    [
      "CAPABILITY_GRANT with parent",
      { ...grant, parentGrantId: controlRecordId(seq32(5)), delegable: [1n] },
      true,
    ],
    ["CAPABILITY_REVOKE", { type: "CAPABILITY_REVOKE", grantId: controlRecordId(seq32(6)) }, true],
    [
      "CAPABILITY_CLAIM",
      {
        type: "CAPABILITY_CLAIM",
        invitationGrantId: controlRecordId(seq32(7)),
        claimant: BRUNO.descriptor,
        abilities: [1n, 2n],
      },
      true,
    ],
    [
      "KEY_EPOCH",
      {
        type: "KEY_EPOCH",
        epoch: dataEpoch(1n),
        dekCommitment: COMMITMENT,
        // A canonical frontier: sorted by raw Principal ID (§28.2, G-CP1).
        finalFrontier: [
          { principalId: ALICE.descriptor.principalId, contiguous: 2n, extras: [] },
          { principalId: BRUNO.descriptor.principalId, contiguous: 7n, extras: [[9n, 9n]] },
        ].sort((a, b) => compareCanonicalFrontierOrder(a.principalId, b.principalId)) as never,
        reason: 1n,
      },
      true,
    ],
    [
      "ROUTE_UPDATE",
      {
        type: "ROUTE_UPDATE",
        routeVersion: 2n,
        endpoints: [ENDPOINT, { url: "wss://b.test", priority: 1n }],
        coordinatorUrl: "wss://b.test",
      },
      true,
    ],
    [
      "OWNER_TRANSFER_COMMIT",
      { type: "OWNER_TRANSFER_COMMIT", offer: seq32(1), accept: seq32(2) },
      true,
    ],
    [
      "COORDINATOR_RECOVERY",
      {
        type: "COORDINATOR_RECOVERY",
        routeVersion: 3n,
        endpoints: [ENDPOINT],
        coordinatorUrl: "wss://c.test",
        reason: "coordinator lost",
      },
      false,
    ],
    ["RESOURCE_TOMBSTONE", { type: "RESOURCE_TOMBSTONE", reason: 0n, note: "done" }, false],
    ["RESOURCE_TOMBSTONE without note", { type: "RESOURCE_TOMBSTONE", reason: 0n }, false],
    ["EXTENSION", { type: "EXTENSION", code: 40n, body: cborMap([[0, "x"]]) }, false],
  ];

  it.each(bodies)(
    "15. %s signs, decodes back to the same body and re-signs byte for byte",
    (_n, body, mvp) => {
      const signed = signControlRecord(next(1n), body, ALICE);
      const record = decodeControlRecord(signed.bytes);
      expect(record.body).toEqual(body);
      expect(record.mvpSupported).toBe(mvp);
      const header = {
        resourceId: record.payload.resourceId,
        controlSeq: record.payload.controlSeq,
        prevControlId: record.payload.prevControlId,
      };
      expect(toHex(signControlRecord(header, record.body, ALICE).bytes)).toBe(toHex(signed.bytes));
    },
  );

  it("decodes MVP-deferred core types without applying them (mvpSupported false)", () => {
    for (const type of ["COORDINATOR_RECOVERY", "RESOURCE_TOMBSTONE"]) {
      const body = bodies.find(([n]) => n === type)?.[1] as ControlBody;
      expect(decodeControlRecord(signControlRecord(next(1n), body, ALICE).bytes).mvpSupported).toBe(
        false,
      );
    }
  });

  it("rejects reserved core types 9-31 with UNSUPPORTED_VALUE (§14: INVALID_CONTROL_CHAIN on the wire)", () => {
    expect(codeOf(() => controlBodyFromCbor(9n, cborMap([])))).toBe("UNSUPPORTED_VALUE");
    expect(codeOf(() => controlBodyFromCbor(31n, cborMap([])))).toBe("UNSUPPORTED_VALUE");
  });

  it.each([
    [
      "an extra field",
      1n,
      cborMap([
        [0, encodePrincipalDescriptor(BRUNO.descriptor)],
        [1, [1]],
        [2, []],
        [9, 0],
      ]),
    ],
    ["a missing field", 2n, cborMap([])],
    [
      "an empty ability list",
      3n,
      cborMap([
        [0, seq32(1)],
        [1, decodeStrict(encodePrincipalDescriptor(BRUNO.descriptor))],
        [2, []],
      ]),
    ],
    ["a 31-byte grant ID", 2n, cborMap([[0, seq32(1).subarray(1)]])],
    [
      "an empty endpoint list",
      5n,
      cborMap([
        [0, 1],
        [1, []],
        [2, "wss://x"],
      ]),
    ],
    [
      "a duplicate frontier Principal",
      4n,
      cborMap([
        [0, 1],
        [1, seq32(1)],
        [
          2,
          [
            cborMap([
              [0, seq32(3)],
              [1, 1],
            ]),
            cborMap([
              [0, seq32(3)],
              [1, 2],
            ]),
          ],
        ],
        [3, 0],
      ]),
    ],
    [
      "a non-canonical frontier entry",
      4n,
      cborMap([
        [0, 1],
        [1, seq32(1)],
        [
          2,
          [
            cborMap([
              [0, seq32(3)],
              [1, 1],
              [2, []],
            ]),
          ],
        ],
        [3, 0],
      ]),
    ],
    // §17.1: an ability list MUST NOT repeat a code (MALFORMED_MESSAGE).
    [
      "a duplicate ability",
      1n,
      cborMap([
        [0, decodeStrict(encodePrincipalDescriptor(BRUNO.descriptor))],
        [1, [1, 2, 1]],
        [2, []],
      ]),
    ],
    ["a negative reason", 8n, cborMap([[0, -1]])],
  ] as const)("rejects %s with INVALID_STRUCTURE", (_n, type, value) => {
    expect(codeOf(() => controlBodyFromCbor(type, value))).toBe("INVALID_STRUCTURE");
  });

  it("writers refuse what the prose forbids creating", () => {
    const long = "x".repeat(257);
    for (const body of [
      { ...grant, abilities: [] },
      { ...grant, abilities: [1n, 1n] },
      { type: "RESOURCE_TOMBSTONE", reason: 0n, note: long },
      {
        type: "COORDINATOR_RECOVERY",
        routeVersion: 1n,
        endpoints: [ENDPOINT],
        coordinatorUrl: "wss://c.test",
        reason: long,
      },
      { type: "ROUTE_UPDATE", routeVersion: 1n, endpoints: [], coordinatorUrl: "wss://c.test" },
      { type: "EXTENSION", code: 20n, body: null },
    ] as ControlBody[]) {
      expect(codeOf(() => signControlRecord(next(1n), body, ALICE))).toBe("INVALID_STRUCTURE");
    }
    // 256 UTF-8 bytes is the limit, counted in bytes: 128 two-byte characters fit.
    expect(() =>
      signControlRecord(
        next(1n),
        { type: "RESOURCE_TOMBSTONE", reason: 0n, note: "é".repeat(128) },
        ALICE,
      ),
    ).not.toThrow();
    expect(
      codeOf(() =>
        signControlRecord(
          next(1n),
          { type: "RESOURCE_TOMBSTONE", reason: 0n, note: "é".repeat(129) },
          ALICE,
        ),
      ),
    ).toBe("INVALID_STRUCTURE");
    // A non-Genesis record needs control_seq >= 1 and a link (§13.1).
    expect(
      codeOf(() =>
        signControlRecord({ resourceId: R, controlSeq: 0n, prevControlId: null }, grant, ALICE),
      ),
    ).toBe("INVALID_STRUCTURE");
  });
});

describe("endpoint URL rules (§16)", () => {
  it.each([
    "wss://sync.example.test/v1/ws",
    "WSS://sync.example.test",
    "wss://sync.example.test:8443/ws?x=1",
    "ws://localhost:8080/ws",
    "ws://127.0.0.1/ws",
    "ws://[::1]:9000",
  ])("a writer accepts %s", (url) => {
    expect(() => checkWriterUrl(url)).not.toThrow();
  });

  it.each([
    ["ws to a remote host", "ws://sync.example.test/ws"],
    ["http", "https://sync.example.test"],
    ["a relative URL", "/v1/ws"],
    ["no authority", "wss:/sync"],
    ["a fragment", "wss://sync.example.test/ws#x"],
    ["user information", "wss://user@sync.example.test"],
    ["whitespace", "wss://sync.example.test/ w"],
  ])("a writer refuses %s", (_n, url) => {
    expect(codeOf(() => checkWriterUrl(url))).toBe("INVALID_STRUCTURE");
  });

  it.each(["wss://sync.example.test", "WS://remote.example.test", "ws://remote.example.test"])(
    "a receiver accepts the ws or wss URL %s in a Control Record (§16)",
    (url) => {
      expect(() => checkReceivedUrl(url)).not.toThrow();
      const route = controlBodyFromCbor(
        5n,
        cborMap([
          [0, 1],
          [
            1,
            [
              cborMap([
                [0, url],
                [1, 0],
              ]),
            ],
          ],
          [2, url],
        ]),
      );
      expect(route).toMatchObject({ coordinatorUrl: url });
    },
  );

  it.each([
    ["http in an endpoint", "https://sync.example.test", "wss://sync.example.test"],
    ["http as the coordinator", "wss://sync.example.test", "http://sync.example.test"],
    ["no scheme", "sync.example.test", "wss://sync.example.test"],
  ])(
    "a receiver rejects %s with INVALID_STRUCTURE (MALFORMED_MESSAGE, §16)",
    (_n, endpoint, coordinator) => {
      expect(
        codeOf(() =>
          controlBodyFromCbor(
            5n,
            cborMap([
              [0, 1],
              [
                1,
                [
                  cborMap([
                    [0, endpoint],
                    [1, 0],
                  ]),
                ],
              ],
              [2, coordinator],
            ]),
          ),
        ),
      ).toBe("INVALID_STRUCTURE");
    },
  );

  it("a writer refuses reserved flag bits; a reader keeps them", () => {
    expect(
      codeOf(() => endpointToCbor({ url: "wss://a.test", priority: 0n, flags: 1n << 6n })),
    ).toBe("INVALID_STRUCTURE");
    expect(
      endpointFromCbor(
        cborMap([
          [0, "ws://remote.test"],
          [1, 0],
          [2, 1 << 6],
        ]),
      ),
    ).toEqual({
      url: "ws://remote.test",
      priority: 0n,
      flags: 64n,
    });
  });
});
