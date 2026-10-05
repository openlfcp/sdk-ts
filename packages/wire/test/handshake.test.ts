import { LfcpError, principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { encode } from "../src/cbor/index.js";
import {
  ABILITY,
  type AnyMessage,
  type AuthTranscriptFields,
  authTranscript,
  type ClientHandshakeConfig,
  type ClientSession,
  clientConnectionTransition,
  clientReceive,
  decodeAuthTranscript,
  decodeMessage,
  ERROR_CODE,
  encodeMessage,
  hasAbility,
  type LfcpMessage,
  type ServerHandshakeConfig,
  type ServerSession,
  selectWireProfile,
  serverReceive,
  serverSessionTransition,
  signAuthProof,
  signControlRecord,
  signObject,
  startClientHandshake,
  startServerSession,
  validateControlChain,
  verifyAuthProof,
  WIRE_PROFILE,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic handshakes; the published HELLO, CHALLENGE, AUTH and READY
// vectors are replayed end to end by the conformance runner.

/** TESTS ONLY: deterministic bytes, so a handshake is reproducible. */
function counter(start: number) {
  let n = start;
  return (length: number) => Uint8Array.from({ length }, () => n++ & 0xff);
}
const SERVER_ID = seq32(150);
const serverConfig = (over: Partial<ServerHandshakeConfig> = {}): ServerHandshakeConfig => ({
  serverId: SERVER_ID,
  wireProfiles: [WIRE_PROFILE],
  maxMessageBytes: 8_388_608n,
  durability: 2n,
  heartbeatMs: 30_000n,
  extensions: [],
  random: counter(10),
  ...over,
});
const clientConfig = (over: Partial<ClientHandshakeConfig> = {}): ClientHandshakeConfig => ({
  signer: ALICE,
  dataProfiles: ["org.example.custom.v1"],
  random: counter(200),
  ...over,
});
/** Through the codec, as a transport would deliver it. */
const wire = (m: AnyMessage): AnyMessage => decodeMessage(encodeMessage(m));
const errorCode = (m: AnyMessage | undefined) =>
  m?.type === "ERROR" || m?.type === "NACK" ? m.body.code : undefined;

/** Runs a full handshake; returns every step. */
function handshake(client = clientConfig(), server = serverConfig()) {
  const start = startClientHandshake(client);
  const hello = start.send[0] as AnyMessage;
  const s1 = serverReceive(startServerSession(), wire(hello), server);
  const challenge = s1.send[0] as AnyMessage;
  const c1 = clientReceive(start.session, wire(challenge), client);
  const auth = c1.send[0] as AnyMessage;
  const s2 = serverReceive(s1.session, wire(auth), server);
  const ready = s2.send[0] as AnyMessage;
  const c2 = clientReceive(c1.session, wire(ready), client);
  return { hello, challenge, auth, ready, s1, s2, c1, c2 };
}

describe("a complete handshake (§34-§37)", () => {
  it("1, 4, 5, 8, 16. HELLO → CHALLENGE → AUTH → READY authenticates the Principal", () => {
    const h = handshake();
    expect(h.challenge).toMatchObject({ type: "CHALLENGE", body: { wireProfile: WIRE_PROFILE } });
    expect(toHex(h.challenge.correlationId as Uint8Array)).toBe(toHex(h.hello.messageId));
    expect(h.s2.session).toMatchObject({ phase: "READY" });
    if (h.s2.session.phase !== "READY") throw new Error();
    expect(toHex(h.s2.session.session.principal.principalId)).toBe(
      toHex(ALICE.descriptor.principalId),
    );
    expect(h.c2.session).toMatchObject({
      phase: "READY",
      ready: { wireProfile: WIRE_PROFILE, maxMessageBytes: 8_388_608n, durability: 2n },
    });
    expect([h.s1.close, h.s2.close, h.c1.close, h.c2.close]).toEqual([false, false, false, false]);
  });

  it("3. HELLO carries a fresh 16-byte client nonce from the CSPRNG by default", () => {
    const a = startClientHandshake({ signer: ALICE }).send[0] as LfcpMessage<"HELLO">;
    const b = startClientHandshake({ signer: ALICE }).send[0] as LfcpMessage<"HELLO">;
    expect(a.body.clientNonce).toHaveLength(16);
    expect(toHex(a.body.clientNonce)).not.toBe(toHex(b.body.clientNonce));
    expect(a.body.wireProfiles).toEqual([WIRE_PROFILE]);
  });

  it("server nonces and session IDs are fresh per session by default", () => {
    const s = (cfg: ServerHandshakeConfig) =>
      serverReceive(startServerSession(), handshake().hello, cfg)
        .send[0] as LfcpMessage<"CHALLENGE">;
    const { random: _r, ...noRandom } = serverConfig();
    const a = s(noRandom);
    const b = s(noRandom);
    expect(toHex(a.body.serverNonce)).not.toBe(toHex(b.body.serverNonce));
    expect(toHex(a.body.sessionId)).not.toBe(toHex(b.body.sessionId));
    expect(toHex(a.body.serverId)).toBe(toHex(SERVER_ID)); // the configured stable ID
  });
});

describe("HELLO validation and profile negotiation", () => {
  it("2. an invalid Principal Descriptor is AUTH_FAILED and closes (§7, P3)", () => {
    const hello = startClientHandshake(clientConfig()).send[0] as LfcpMessage<"HELLO">;
    const forged = {
      ...hello,
      body: {
        ...hello.body,
        principal: { ...hello.body.principal, principalId: principalId(seq32(9)) },
      },
    };
    const step = serverReceive(startServerSession(), forged, serverConfig());
    expect([errorCode(step.send[0]), step.close, step.session.phase]).toEqual([
      ERROR_CODE.AUTH_FAILED,
      true,
      "CLOSED",
    ]);
  });

  it("5, 6. the first offered supported profile is selected; none is PROTOCOL_UNSUPPORTED and closes", () => {
    expect(selectWireProfile(["LFCP-WIRE-02", WIRE_PROFILE, "X"], [WIRE_PROFILE, "X"])).toBe(
      WIRE_PROFILE,
    );
    const none = startClientHandshake(clientConfig({ wireProfiles: ["LFCP-WIRE-99"] }));
    const step = serverReceive(startServerSession(), none.send[0] as AnyMessage, serverConfig());
    expect([errorCode(step.send[0]), step.close]).toEqual([ERROR_CODE.PROTOCOL_UNSUPPORTED, true]);
  });

  it("the client refuses a CHALLENGE selecting a profile it did not offer", () => {
    const h = handshake();
    const other = {
      ...h.challenge,
      body: { ...(h.challenge as LfcpMessage<"CHALLENGE">).body, wireProfile: "X" },
    };
    const start = startClientHandshake(clientConfig());
    const step = clientReceive(start.session, other as AnyMessage, clientConfig());
    expect([errorCode(step.send[0]), step.close]).toEqual([ERROR_CODE.PROTOCOL_UNSUPPORTED, true]);
  });
});

describe("the AUTH transcript and proof (§36)", () => {
  const fields: AuthTranscriptFields = {
    sessionId: seq32(1).subarray(0, 16),
    clientNonce: seq32(2).subarray(0, 16),
    serverNonce: seq32(3).subarray(0, 16),
    serverId: seq32(4),
    principalId: ALICE.descriptor.principalId,
  };

  it("7. the transcript is exactly the six-element §36 array", () => {
    const t = authTranscript(fields);
    expect(toHex(t)).toBe(
      toHex(
        encode([
          "LFCP-AUTH-v1",
          fields.sessionId,
          fields.clientNonce,
          fields.serverNonce,
          fields.serverId,
          fields.principalId,
        ]),
      ),
    );
    expect(decodeAuthTranscript(t)).toMatchObject({ serverId: fields.serverId });
  });

  it("8. a proof by the Principal over the transcript verifies", () => {
    expect(verifyAuthProof(signAuthProof(fields, ALICE), fields, ALICE.descriptor)).toEqual({
      valid: true,
    });
  });

  it("9-12. a proof for one handshake does not verify for another (replay binding)", () => {
    const proof = signAuthProof(fields, ALICE);
    for (const change of [
      { clientNonce: seq32(20).subarray(0, 16) },
      { serverNonce: seq32(21).subarray(0, 16) },
      { sessionId: seq32(22).subarray(0, 16) },
      { serverId: seq32(23) },
    ])
      expect(verifyAuthProof(proof, { ...fields, ...change }, ALICE.descriptor)).toEqual({
        valid: false,
        reason: "TRANSCRIPT_MISMATCH",
      });
  });

  it("13. a proof with another Principal's key or kid fails", () => {
    // BRUNO signs ALICE's transcript.
    const byBruno = signObject(authTranscript(fields), BRUNO).bytes;
    expect(verifyAuthProof(byBruno, fields, ALICE.descriptor)).toMatchObject({
      reason: "KID_MISMATCH",
    });
    const bad = Uint8Array.from(signAuthProof(fields, ALICE));
    bad[bad.length - 1] = (bad[bad.length - 1] as number) ^ 1;
    expect(verifyAuthProof(bad, fields, ALICE.descriptor)).toMatchObject({
      reason: "BAD_SIGNATURE",
    });
    expect(verifyAuthProof(Uint8Array.of(0x80), fields, ALICE.descriptor)).toMatchObject({
      reason: "MALFORMED",
    });
    expect(() => signAuthProof(fields, BRUNO)).toThrow(LfcpError);
  });

  it("every AUTH proof failure is AUTH_FAILED and closes (G-MSG4); diagnostics carry no key bytes", () => {
    const h = handshake();
    const auth = h.auth as LfcpMessage<"AUTH">;
    for (const proof of [Uint8Array.of(0x80), signObject(Uint8Array.of(0x01), ALICE).bytes]) {
      const step = serverReceive(h.s1.session, { ...auth, body: { proof } }, serverConfig());
      expect([errorCode(step.send[0]), step.close, step.session.phase]).toEqual([
        ERROR_CODE.AUTH_FAILED,
        true,
        "CLOSED",
      ]);
      const text = JSON.stringify(step.send[0], (_k, v) =>
        v instanceof Uint8Array ? toHex(v) : typeof v === "bigint" ? String(v) : v,
      );
      expect(text).not.toContain(toHex(ALICE.descriptor.ed25519PublicKey));
    }
  });
});

describe("the hosting credential (§36)", () => {
  it("14. is carried opaquely to the authenticated session", () => {
    const credential = Uint8Array.of(0xde, 0xad, 0x00, 0x01);
    const h = handshake(clientConfig({ credential }));
    expect(toHex((h.auth as LfcpMessage<"AUTH">).body.credential as Uint8Array)).toBe(
      toHex(credential),
    );
    if (h.s2.session.phase !== "READY") throw new Error();
    expect(toHex(h.s2.session.session.credential as Uint8Array)).toBe(toHex(credential));
  });

  it("15. creates no Resource ability: authority comes only from the Control Chain", () => {
    const h = handshake(clientConfig({ signer: BRUNO, credential: Uint8Array.of(1) }));
    if (h.s2.session.phase !== "READY") throw new Error();
    expect(Object.keys(h.s2.session.session)).not.toContain("abilities");
    const genesis = signControlRecord(
      { resourceId: resourceId(seq32(200)), controlSeq: 0n, prevControlId: null },
      {
        type: "GENESIS",
        dataProfile: "org.example.custom.v1",
        owner: ALICE.descriptor,
        dekCommitment: seq32(10) as never,
        endpoints: [{ url: "wss://a.example.test", priority: 0n }],
        coordinatorUrl: "wss://a.example.test",
      },
      ALICE,
    );
    const chain = validateControlChain([genesis.bytes]);
    if (chain.kind !== "linear") throw new Error();
    for (const a of [ABILITY.DATA_READ, ABILITY.DATA_WRITE])
      expect(hasAbility(chain.state, h.s2.session.session.principal.principalId, a)).toBe(false);
  });
});

describe("READY validation (§37)", () => {
  it("17, 18. READY with another profile or another server ID is refused", () => {
    const h = handshake();
    const ready = h.ready as LfcpMessage<"READY">;
    for (const body of [
      { ...ready.body, wireProfile: "LFCP-WIRE-99" },
      { ...ready.body, serverId: seq32(99) },
    ]) {
      const step = clientReceive(h.c1.session, { ...ready, body }, clientConfig());
      expect([errorCode(step.send[0]), step.close, step.session.phase]).toEqual([
        ERROR_CODE.MALFORMED_MESSAGE,
        true,
        "DISCONNECTED",
      ]);
    }
  });

  it("18. a malformed server ID does not decode", () => {
    const h = handshake();
    const ready = h.ready as LfcpMessage<"READY">;
    expect(() =>
      encodeMessage({ ...ready, body: { ...ready.body, serverId: seq32(1).subarray(0, 31) } }),
    ).toThrow(LfcpError);
  });

  it("a client that knows the server ID refuses a CHALLENGE from another server", () => {
    const client = clientConfig({ expectedServerId: seq32(77) });
    const start = startClientHandshake(client);
    const challenge = serverReceive(
      startServerSession(),
      start.send[0] as AnyMessage,
      serverConfig(),
    ).send[0] as AnyMessage;
    const step = clientReceive(start.session, challenge, client);
    expect([errorCode(step.send[0]), step.close]).toEqual([ERROR_CODE.AUTH_FAILED, true]);
  });
});

describe("ordering (§64, G-MSG7, G-SM4)", () => {
  it("19. AUTH before CHALLENGE, READY before AUTH and a second HELLO are protocol violations", () => {
    const h = handshake();
    const before = serverReceive(startServerSession(), h.auth, serverConfig());
    expect([errorCode(before.send[0]), before.close]).toEqual([ERROR_CODE.MALFORMED_MESSAGE, true]);
    const early = clientReceive(
      startClientHandshake(clientConfig()).session,
      h.ready,
      clientConfig(),
    );
    expect([errorCode(early.send[0]), early.close]).toEqual([ERROR_CODE.MALFORMED_MESSAGE, true]);
    const again = serverReceive(h.s2.session, h.hello, serverConfig());
    expect([errorCode(again.send[0]), again.close]).toEqual([ERROR_CODE.MALFORMED_MESSAGE, true]);
    const helloTwice = serverReceive(h.s1.session, h.hello, serverConfig());
    expect(helloTwice.close).toBe(true);
  });

  it("Resource-family messages before READY get NACK(AUTHORIZATION_FAILED) without closing", () => {
    const open: AnyMessage = {
      type: "RESOURCE_OPEN",
      messageId: seq32(5).subarray(0, 16),
      body: { resourceId: resourceId(seq32(200)), heads: [], haves: [] },
    };
    for (const session of [startServerSession(), handshake().s1.session] as ServerSession[]) {
      const step = serverReceive(session, open, serverConfig());
      expect([step.send[0]?.type, errorCode(step.send[0]), step.close, step.session.phase]).toEqual(
        ["NACK", ERROR_CODE.AUTHORIZATION_FAILED, false, session.phase],
      );
    }
    // After READY the message is delivered to the Resource logic.
    expect(serverReceive(handshake().s2.session, open, serverConfig()).deliver).toBe(open);
  });

  it("PING is answered and PONG and ERROR are accepted in every state (G-SM4)", () => {
    const ping: AnyMessage = {
      type: "PING",
      messageId: seq32(6).subarray(0, 16),
      body: { payload: seq32(1).subarray(0, 8) },
    };
    const h = handshake();
    for (const session of [startServerSession(), h.s1.session, h.s2.session] as ServerSession[]) {
      const step = serverReceive(session, ping, serverConfig());
      expect(step.send[0]).toMatchObject({
        type: "PONG",
        body: { payload: seq32(1).subarray(0, 8) },
      });
      expect(step.session).toBe(session);
    }
    for (const session of [h.c1.session, h.c2.session] as ClientSession[])
      expect(clientReceive(session, ping, clientConfig()).send[0]?.type).toBe("PONG");
    const pong: AnyMessage = { ...ping, type: "PONG" } as AnyMessage;
    expect(serverReceive(startServerSession(), pong, serverConfig()).send).toEqual([]);
  });
});

describe("state machines (§63, §64, G-SM1, G-SM3)", () => {
  it("the client follows only the drawn edges, with a failure edge from CONNECTING", () => {
    let s = clientConnectionTransition("DISCONNECTED", "OPEN");
    expect(s).toBe("CONNECTING");
    expect(clientConnectionTransition("CONNECTING", "CONNECT_FAILED")).toBe("DISCONNECTED");
    s = clientConnectionTransition("CONNECTING", "CONNECTED");
    s = clientConnectionTransition(s as never, "CHALLENGED");
    s = clientConnectionTransition(s as never, "READY_RECEIVED");
    expect(s).toBe("READY");
    expect(clientConnectionTransition("READY", "RESOURCE")).toBe("READY");
    expect(clientConnectionTransition("NEGOTIATING", "FATAL_ERROR")).toBe("DISCONNECTED");
    expect(clientConnectionTransition("AUTHENTICATING", "AUTH_FAILURE")).toBe("DISCONNECTED");
    for (const from of ["CONNECTING", "NEGOTIATING", "AUTHENTICATING", "READY"] as const)
      expect(clientConnectionTransition(from, "CONNECTION_LOST")).toBe("DISCONNECTED");
    // Undrawn edges.
    expect(clientConnectionTransition("NEGOTIATING", "READY_RECEIVED")).toBeUndefined();
    expect(clientConnectionTransition("DISCONNECTED", "CHALLENGED")).toBeUndefined();
    expect(clientConnectionTransition("READY", "CHALLENGED")).toBeUndefined();
  });

  it("the server follows only the drawn edges; every live state closes on socket close", () => {
    expect(serverSessionTransition("ACCEPTED", "START")).toBe("WAIT_HELLO");
    expect(serverSessionTransition("WAIT_HELLO", "VALID_HELLO")).toBe("WAIT_AUTH");
    expect(serverSessionTransition("WAIT_AUTH", "VALID_AUTH")).toBe("READY");
    expect(serverSessionTransition("READY", "MESSAGE")).toBe("READY");
    expect(serverSessionTransition("WAIT_HELLO", "PROTOCOL_VIOLATION")).toBe("CLOSED");
    expect(serverSessionTransition("WAIT_AUTH", "AUTH_FAILURE")).toBe("CLOSED");
    expect(serverSessionTransition("READY", "FATAL_ERROR")).toBe("CLOSED");
    for (const from of ["ACCEPTED", "WAIT_HELLO", "WAIT_AUTH", "READY"] as const)
      expect(serverSessionTransition(from, "SOCKET_CLOSED")).toBe("CLOSED");
    expect(serverSessionTransition("WAIT_HELLO", "VALID_AUTH")).toBeUndefined();
    expect(serverSessionTransition("CLOSED", "START")).toBeUndefined();
  });
});
