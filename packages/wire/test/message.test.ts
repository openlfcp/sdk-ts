import { controlRecordId, hash32, LfcpError, principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { type CborValue, cborMap, encode } from "../src/cbor/index.js";
import {
  type AnyMessage,
  createMessage,
  DEFAULT_MAX_MESSAGE_BYTES,
  decodeEnvelope,
  decodeFrame,
  decodeMessage,
  ERROR_CODE,
  encodeMessage,
  type LfcpMessage,
  type LiveActorHave,
  MESSAGE_TYPE,
  type MessageBodies,
  newMessageId,
  principalDescriptorToCbor,
  replyTo,
  signObject,
} from "../src/index.js";
import { ALICE, DATA_UNIT, seq32 } from "./synthetic.js";

// Synthetic messages; the published message vectors are decoded and
// re-encoded byte for byte by the conformance runner.

const ID = seq32(1).subarray(0, 16);
const R = resourceId(seq32(200));
const P = principalId(seq32(100));
const H = controlRecordId(seq32(64));

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};

/** The envelope CBOR, written by hand. */
const raw = (fields: [number, CborValue][]) => encode(cborMap(fields));

const msg = <T extends keyof MessageBodies>(
  type: T,
  body: MessageBodies[T],
  extra: { correlationId?: Uint8Array } = {},
) => ({ type, messageId: ID, ...extra, body }) as LfcpMessage<T>;

const roundTrip = (m: AnyMessage) => {
  const bytes = encodeMessage(m);
  const back = decodeMessage(bytes);
  expect(toHex(encodeMessage(back))).toBe(toHex(bytes));
  return { bytes, back };
};

describe("exact encodings of the session messages (§34-§38)", () => {
  it("1. HELLO", () => {
    const m = msg("HELLO", {
      wireProfiles: ["LFCP-WIRE-01"],
      principal: ALICE.descriptor,
      clientNonce: seq32(5).subarray(0, 16),
      dataProfiles: ["org.example.custom.v1"],
    });
    const { bytes, back } = roundTrip(m);
    expect(toHex(bytes)).toBe(
      toHex(
        raw([
          [0, 0],
          [1, ID],
          [
            4,
            cborMap([
              [0, ["LFCP-WIRE-01"]],
              [1, principalDescriptorToCbor(ALICE.descriptor)],
              [2, seq32(5).subarray(0, 16)],
              [3, ["org.example.custom.v1"]],
            ]),
          ],
        ]),
      ),
    );
    expect(back).toMatchObject({ type: "HELLO", body: { wireProfiles: ["LFCP-WIRE-01"] } });
  });

  it("2, 3, 4. CHALLENGE, AUTH and READY", () => {
    const challenge = msg("CHALLENGE", {
      wireProfile: "LFCP-WIRE-01",
      serverNonce: seq32(6).subarray(0, 16),
      sessionId: seq32(7).subarray(0, 16),
      serverId: seq32(8),
    });
    expect(toHex(roundTrip(challenge).bytes)).toBe(
      toHex(
        raw([
          [0, 1],
          [1, ID],
          [
            4,
            cborMap([
              [0, "LFCP-WIRE-01"],
              [1, seq32(6).subarray(0, 16)],
              [2, seq32(7).subarray(0, 16)],
              [3, seq32(8)],
            ]),
          ],
        ]),
      ),
    );
    const proof = signObject(Uint8Array.of(0x80), ALICE).bytes;
    const auth = roundTrip(msg("AUTH", { proof, credential: Uint8Array.of(1, 2) }));
    expect(auth.back).toMatchObject({ body: { proof, credential: Uint8Array.of(1, 2) } });
    const ready = msg("READY", {
      wireProfile: "LFCP-WIRE-01",
      serverId: seq32(8),
      maxMessageBytes: 8_388_608n,
      durability: 2n,
      heartbeatMs: 30_000n,
      extensions: [],
    });
    expect(toHex(roundTrip(ready).bytes)).toBe(
      toHex(
        raw([
          [0, 3],
          [1, ID],
          [
            4,
            cborMap([
              [0, "LFCP-WIRE-01"],
              [1, seq32(8)],
              [2, 8_388_608],
              [3, 2],
              [4, 30_000],
              [5, []],
            ]),
          ],
        ]),
      ),
    );
  });

  it("13. PING and PONG carry 8 bytes; PONG echoes", () => {
    const ping = msg("PING", { payload: seq32(9).subarray(0, 8) });
    const pong = replyTo(ping, "PONG", ping.body);
    roundTrip(ping);
    expect(toHex(roundTrip(pong).back.correlationId as Uint8Array)).toBe(toHex(ID));
    expect(codeOf(() => encodeMessage(msg("PING", { payload: seq32(9).subarray(0, 7) })))).toBe(
      "INVALID_STRUCTURE",
    );
  });
});

const have = (ranges?: [bigint, bigint][]): LiveActorHave => ({
  principalId: P,
  contiguous: 3n,
  ...(ranges ? { ranges } : {}),
});

describe("every other body round-trips (§39-§61)", () => {
  const cases: AnyMessage[] = [
    // 5. Resource lifecycle
    msg("RESOURCE_HOST", { genesis: DATA_UNIT.bytes }),
    msg("RESOURCE_HOSTED", { resourceId: R, durability: 1n }),
    msg("RESOURCE_OPEN", {
      resourceId: R,
      heads: [{ seq: 4n, recordId: H }],
      haves: [have(), have([[6n, 7n]])],
      grantIds: [hash32(seq32(3))],
      flags: 3n,
    }),
    msg("RESOURCE_OPENED", {
      resourceId: R,
      heads: [],
      haves: [],
      snapshot: { snapshotId: hash32(seq32(4)), dataEpoch: 1n, frontier: [have()] },
      routeVersion: 2n,
      coordinatorUrl: "wss://c.example.test",
    }),
    msg("RESOURCE_CLOSE", { resourceId: R }),
    // 6. Control
    msg("CONTROL_HAVE", { resourceId: R, heads: [{ seq: 0n, recordId: H }] }),
    msg("CONTROL_GET", { resourceId: R, start: 0n, end: 9n }),
    msg("CONTROL_BATCH", { resourceId: R, objects: [DATA_UNIT.bytes] }),
    msg("CONTROL_PUT", { resourceId: R, expectedHead: H, record: DATA_UNIT.bytes }),
    // 7. Data
    msg("DATA_HAVE", { resourceId: R, haves: [have([[5n, 9n]])] }),
    msg("DATA_GET", { resourceId: R, ranges: [{ actor: P, start: 1n, end: 2n }] }),
    msg("DATA_BATCH", { resourceId: R, objects: [] }),
    msg("DATA_PUT", { resourceId: R, objects: [DATA_UNIT.bytes, DATA_UNIT.bytes] }),
    // 8. Key Packages
    msg("KEY_PACKAGE_GET", { resourceId: R, recipient: P, epochs: [0n, 1n] }),
    msg("KEY_PACKAGE_BATCH", { resourceId: R, objects: [DATA_UNIT.bytes] }),
    msg("KEY_PACKAGE_PUT", { resourceId: R, objects: [DATA_UNIT.bytes] }),
    // 9. Snapshots
    msg("SNAPSHOT_GET", { resourceId: R }),
    msg("SNAPSHOT_GET", { resourceId: R, snapshotId: hash32(seq32(4)) }),
    msg("SNAPSHOT", { resourceId: R, snapshot: DATA_UNIT.bytes }),
    msg("SNAPSHOT_PUT", { resourceId: R, snapshot: DATA_UNIT.bytes }),
    // 10, 11, 12. ACK, NACK, ERROR
    msg("ACK", {
      requestType: MESSAGE_TYPE.DATA_PUT,
      objectIds: [hash32(seq32(2))],
      durable: true,
    }),
    msg("NACK", { code: ERROR_CODE.STALE_DATA_EPOCH, diagnostic: "stale" }),
    msg("NACK", { code: ERROR_CODE.CONTROL_HEAD_MISMATCH, details: H }),
    msg("ERROR", { code: ERROR_CODE.AUTH_FAILED, details: cborMap([[0, "x"]]) }),
    // Presence (structure only)
    msg("PRESENCE", { resourceId: R, principalId: P, ttlMs: 5000n, payload: Uint8Array.of(1) }),
    msg("PRESENCE_LEAVE", { resourceId: R, principalId: P }),
  ];
  it.each(cases.map((m, i) => [`${i} ${m.type}`, m] as const))("%s", (_n, m) => {
    const { bytes, back } = roundTrip(m);
    expect(decodeEnvelope(bytes).code).toBe(m.type === "EXTENSION" ? m.code : MESSAGE_TYPE[m.type]);
    expect(back.type).toBe(m.type);
  });

  it("23. embedded persistent objects keep their exact bytes, unparsed and never re-encoded", () => {
    // Bytes that are not even CBOR travel unchanged: the codec never re-encodes objects.
    const opaque = Uint8Array.of(0xff, 0x00, 0x18, 0x01);
    for (const m of [
      msg("DATA_PUT", { resourceId: R, objects: [DATA_UNIT.bytes, opaque] }),
      msg("SNAPSHOT", { resourceId: R, snapshot: opaque }),
      msg("RESOURCE_HOST", { genesis: opaque }),
    ]) {
      const back = decodeMessage(encodeMessage(m)) as AnyMessage;
      expect(
        JSON.stringify(back.body, (_k, v) =>
          v instanceof Uint8Array ? toHex(v) : typeof v === "bigint" ? String(v) : v,
        ),
      ).toBe(
        JSON.stringify(m.body, (_k, v) =>
          v instanceof Uint8Array ? toHex(v) : typeof v === "bigint" ? String(v) : v,
        ),
      );
    }
  });

  it("refuses bodies that break their section: null expected head, short NACK head, non-bool durable", () => {
    const putWith = (head: CborValue) =>
      raw([
        [0, 23],
        [1, ID],
        [
          4,
          cborMap([
            [0, R],
            [1, head],
            [2, DATA_UNIT.bytes],
          ]),
        ],
      ]);
    expect(codeOf(() => decodeMessage(putWith(null)))).toBe("INVALID_STRUCTURE");
    expect(codeOf(() => decodeMessage(putWith(H)))).toBeUndefined();
    expect(
      codeOf(() =>
        encodeMessage(
          msg("NACK", {
            code: ERROR_CODE.CONTROL_HEAD_MISMATCH,
            details: seq32(1).subarray(0, 31),
          }),
        ),
      ),
    ).toBe("INVALID_STRUCTURE");
    expect(
      codeOf(() =>
        decodeMessage(
          raw([
            [0, 90],
            [1, ID],
            [
              4,
              cborMap([
                [0, 33],
                [2, 1],
              ]),
            ],
          ]),
        ),
      ),
    ).toBe("INVALID_STRUCTURE");
    expect(codeOf(() => encodeMessage(msg("DATA_PUT", { resourceId: R, objects: [] })))).toBe(
      "INVALID_STRUCTURE",
    );
  });

  it("decodes live haves as received, refuses reversed ranges and sequence 0 (G-HV1), and calls the hook", () => {
    const unsorted = msg("DATA_HAVE", {
      resourceId: R,
      haves: [
        have([
          [9n, 12n],
          [5n, 10n],
          [4n, 4n],
        ]),
        have(),
      ],
    });
    const bytes = encodeMessage(unsorted);
    const seen: LiveActorHave[] = [];
    const back = decodeMessage(bytes, { liveHave: (h) => seen.push(h) });
    expect(back).toMatchObject({
      body: {
        haves: [
          {
            ranges: [
              [9n, 12n],
              [5n, 10n],
              [4n, 4n],
            ],
          },
          {},
        ],
      },
    });
    expect(seen).toHaveLength(2);
    expect(toHex(encodeMessage(back))).toBe(toHex(bytes)); // kept as received
    for (const range of [
      [9n, 5n],
      [0n, 3n],
    ] as [bigint, bigint][]) {
      const raw = encode(
        cborMap([
          [0, 30],
          [1, ID],
          [
            4,
            cborMap([
              [0, R],
              [
                1,
                [
                  cborMap([
                    [0, P],
                    [1, 3],
                    [2, [range]],
                  ]),
                ],
              ],
            ]),
          ],
        ]),
      );
      expect(
        codeOf(() => decodeMessage(raw)),
        String(range),
      ).toBe("INVALID_STRUCTURE");
    }
    expect(
      codeOf(() =>
        decodeMessage(bytes, {
          liveHave: () => {
            throw new LfcpError("INVALID_STRUCTURE", "refused by the hook");
          },
        }),
      ),
    ).toBe("INVALID_STRUCTURE");
  });
});

describe("the §32 envelope", () => {
  it("14. Message IDs are 16 random bytes", () => {
    const a = newMessageId();
    expect(a).toHaveLength(16);
    expect(toHex(a)).not.toBe(toHex(newMessageId()));
    expect(createMessage("PING", { payload: new Uint8Array(8) }).messageId).toHaveLength(16);
  });

  it("15. a reply copies the request's Message ID into the correlation ID", () => {
    const request = createMessage("CONTROL_GET", { resourceId: R, start: 0n, end: 1n });
    const reply = replyTo(request, "ACK", { requestType: MESSAGE_TYPE.CONTROL_GET });
    const back = decodeMessage(encodeMessage(reply));
    expect(toHex(back.correlationId as Uint8Array)).toBe(toHex(request.messageId));
    expect(toHex(back.messageId)).not.toBe(toHex(request.messageId));
  });

  it("16, 17. Message and correlation IDs must be 16 bytes", () => {
    const ping = cborMap([[0, new Uint8Array(8)]]);
    for (const fields of [
      [
        [0, 5],
        [1, seq32(1).subarray(0, 15)],
        [4, ping],
      ],
      [
        [0, 5],
        [1, ID],
        [2, seq32(1).subarray(0, 17)],
        [4, ping],
      ],
    ] as [number, CborValue][][])
      expect(codeOf(() => decodeMessage(raw(fields)))).toBe("INVALID_STRUCTURE");
    expect(
      codeOf(() =>
        encodeMessage({
          ...msg("PING", { payload: new Uint8Array(8) }),
          messageId: ID.subarray(1),
        }),
      ),
    ).toBe("INVALID_STRUCTURE");
  });

  it("18. an undefined envelope key 5-15 is MALFORMED_MESSAGE", () => {
    for (const key of [5, 15])
      expect(
        codeOf(() =>
          decodeMessage(
            raw([
              [0, 5],
              [1, ID],
              [4, cborMap([[0, new Uint8Array(8)]])],
              [key, 0],
            ]),
          ),
        ),
      ).toBe("INVALID_STRUCTURE");
  });

  it("19. keys above 15 are ignored and dropped on re-encoding (G-MSG2)", () => {
    const bytes = raw([
      [0, 5],
      [1, ID],
      [4, cborMap([[0, new Uint8Array(8)]])],
      [16, "future"],
      [300, [1, 2]],
    ]);
    const m = decodeMessage(bytes);
    expect(m.type).toBe("PING");
    expect(toHex(encodeMessage(m))).toBe(
      toHex(
        raw([
          [0, 5],
          [1, ID],
          [4, cborMap([[0, new Uint8Array(8)]])],
        ]),
      ),
    );
  });

  it("flags are read and ignored on receipt; a sender writes 0 or nothing (G-MSG3)", () => {
    const bytes = raw([
      [0, 5],
      [1, ID],
      [3, 7],
      [4, cborMap([[0, new Uint8Array(8)]])],
    ]);
    const m = decodeMessage(bytes);
    expect(m).toMatchObject({ type: "PING", flags: 7n });
    expect(codeOf(() => encodeMessage(m))).toBe("INVALID_STRUCTURE");
    expect(codeOf(() => encodeMessage({ ...m, flags: 0n }))).toBeUndefined();
  });

  it("20, 21. unassigned and non-negotiated extension types are PROTOCOL_UNSUPPORTED", () => {
    const typed = (code: number) =>
      raw([
        [0, code],
        [1, ID],
        [4, cborMap([])],
      ]);
    for (const code of [7, 15, 92, 127, 128, 200])
      expect(
        codeOf(() => decodeMessage(typed(code))),
        String(code),
      ).toBe("PROTOCOL_UNSUPPORTED");
    const ext = decodeMessage(typed(200), { extensions: new Set([200n]) });
    expect(ext).toMatchObject({ type: "EXTENSION", code: 200n });
    expect(toHex(encodeMessage(ext))).toBe(toHex(typed(200)));
    // A negotiated set never makes an unassigned core code valid.
    expect(codeOf(() => decodeMessage(typed(92), { extensions: new Set([92n]) }))).toBe(
      "PROTOCOL_UNSUPPORTED",
    );
  });

  it("22. a message above the limit is MESSAGE_TOO_LARGE, before any decoding", () => {
    const big = encodeMessage(msg("SNAPSHOT", { resourceId: R, snapshot: new Uint8Array(2000) }));
    expect(codeOf(() => decodeMessage(big, { maxMessageBytes: 1000 }))).toBe("MESSAGE_TOO_LARGE");
    expect(codeOf(() => decodeMessage(big, { maxMessageBytes: big.length }))).toBeUndefined();
    // Not CBOR at all: the size is refused first.
    expect(
      codeOf(() => decodeMessage(new Uint8Array(1001).fill(0xff), { maxMessageBytes: 1000 })),
    ).toBe("MESSAGE_TOO_LARGE");
    expect(DEFAULT_MAX_MESSAGE_BYTES).toBe(8 * 1024 * 1024);
  });

  it("rejects malformed and non-deterministic CBOR, a wrong body and a missing body", () => {
    expect(codeOf(() => decodeMessage(Uint8Array.of(0xa1)))).toMatch(/^CBOR_/);
    const reordered = Uint8Array.of(
      0xa3,
      0x01,
      0x50,
      ...ID,
      0x00,
      0x05,
      0x04,
      0xa1,
      0x00,
      0x48,
      ...new Uint8Array(8),
    );
    expect(codeOf(() => decodeMessage(reordered))).toBe("CBOR_NON_CANONICAL");
    // HELLO carrying a CHALLENGE body (the CDDL must-fail fixture shape).
    const helloWithChallenge = raw([
      [0, 0],
      [1, ID],
      [
        4,
        cborMap([
          [0, "LFCP-WIRE-01"],
          [1, ID],
          [2, ID],
          [3, seq32(8)],
        ]),
      ],
    ]);
    expect(codeOf(() => decodeMessage(helloWithChallenge))).toBe("INVALID_STRUCTURE");
    expect(
      codeOf(() =>
        decodeMessage(
          raw([
            [0, 5],
            [1, ID],
          ]),
        ),
      ),
    ).toBe("INVALID_STRUCTURE");
  });
});

describe("decodeFrame (§31, G-MSG7)", () => {
  const ping = encodeMessage(msg("PING", { payload: new Uint8Array(8) }));

  it("decodes a binary frame", () => {
    expect(decodeFrame({ kind: "binary", data: ping })).toMatchObject({
      kind: "message",
      message: { type: "PING" },
    });
  });

  it("a text frame is MALFORMED_MESSAGE and closes the connection", () => {
    expect(decodeFrame({ kind: "text", data: "hello" })).toMatchObject({
      kind: "error",
      wireCode: "MALFORMED_MESSAGE",
      errorCode: ERROR_CODE.MALFORMED_MESSAGE,
      closesConnection: true,
    });
  });

  it("maps failures to §62 codes without closing", () => {
    const unknown = raw([
      [0, 7],
      [1, ID],
      [4, cborMap([])],
    ]);
    expect(decodeFrame({ kind: "binary", data: unknown })).toMatchObject({
      wireCode: "PROTOCOL_UNSUPPORTED",
      errorCode: 1n,
      closesConnection: false,
    });
    expect(decodeFrame({ kind: "binary", data: ping }, { maxMessageBytes: 4 })).toMatchObject({
      wireCode: "MESSAGE_TOO_LARGE",
      errorCode: 19n,
    });
    expect(decodeFrame({ kind: "binary", data: Uint8Array.of(0xa1) })).toMatchObject({
      wireCode: "MALFORMED_MESSAGE",
    });
  });

  it("an invalid Principal Descriptor in HELLO is AUTH_FAILED (§7, P3)", () => {
    const bad = cborMap([
      [0, seq32(1)],
      [1, seq32(2)],
      [2, seq32(3)],
    ]);
    const hello = (descriptor: CborValue) =>
      raw([
        [0, 0],
        [1, ID],
        [
          4,
          cborMap([
            [0, ["LFCP-WIRE-01"]],
            [1, descriptor],
            [2, ID],
          ]),
        ],
      ]);
    expect(decodeFrame({ kind: "binary", data: hello(bad) })).toMatchObject({
      wireCode: "AUTH_FAILED",
      errorCode: 3n,
    });
  });
});
