import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import {
  type AnyMessage,
  type ClientConnectionState,
  createMessage,
  decodeMessage,
  encodeMessage,
  principalDescriptorFromKeys,
  type ReadySession,
  type Signer,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { LfcpConnection, platformWebSocket } from "../src/index.js";
import { FakeServer, settle } from "./fake-server.js";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = importSigningKey(bytes32(1));
const SIGNER: Signer = {
  key,
  descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(101))),
};

function connect(server: FakeServer, clock = { t: 0 }, maxMessageBytes?: number) {
  const log = {
    states: [] as ClientConnectionState[],
    ready: null as ReadySession | null,
    messages: [] as AnyMessage[],
    closed: [] as string[],
  };
  const c = new LfcpConnection(
    {
      url: "ws://127.0.0.1:1/v1/ws",
      signer: SIGNER,
      webSocket: server.factory,
      now: () => clock.t,
      ...(maxMessageBytes === undefined ? {} : { maxMessageBytes }),
    },
    {
      state: (s) => log.states.push(s),
      ready: (r) => {
        log.ready = r;
      },
      message: (m) => log.messages.push(m),
      closed: (r) => log.closed.push(r),
    },
  );
  c.connect();
  return { c, log, clock };
}

describe("LfcpConnection (§30, §31, §34-§38, §63)", () => {
  it("requests lfcp-1, uses binary frames and reaches READY through the handshake", async () => {
    const server = new FakeServer();
    const { c, log } = connect(server);
    await settle();
    expect(server.current.protocols).toEqual(["lfcp-1"]);
    expect(server.current.binaryType).toBe("arraybuffer");
    expect(log.states).toEqual(["CONNECTING", "NEGOTIATING", "AUTHENTICATING", "READY"]);
    expect(log.ready?.durability).toBe(2n);
    expect(c.state).toBe("READY");
    const types = server.current.sent.map((b) => decodeMessage(b).type);
    expect(types).toEqual(["HELLO", "AUTH"]);
    // After READY, messages reach the application; PING is answered by the handshake layer.
    server.push(createMessage("PING", { payload: new Uint8Array(8) }));
    server.push(createMessage("DATA_HAVE", { resourceId: bytes32(5) as never, haves: [] }));
    await settle();
    expect(log.messages.map((m) => m.type)).toEqual(["DATA_HAVE"]);
    expect(decodeMessage(server.current.sent.at(-1) as Uint8Array).type).toBe("PONG");
  });

  it("drops a connection whose server did not accept lfcp-1", async () => {
    const server = new FakeServer();
    server.protocol = "other";
    const { c, log } = connect(server);
    await settle();
    expect(c.state).toBe("DISCONNECTED");
    expect(log.states).toEqual(["CONNECTING", "DISCONNECTED"]);
    expect(log.closed[0]).toMatch(/lfcp-1/);
  });

  it("answers a text frame with ERROR(MALFORMED_MESSAGE) and closes (§31)", async () => {
    const server = new FakeServer();
    const { c, log } = connect(server);
    await settle();
    server.current.deliver("hello");
    await settle();
    expect(c.state).toBe("DISCONNECTED");
    const last = decodeMessage(server.current.sent.at(-1) as Uint8Array);
    expect(last.type === "ERROR" && last.body.code).toBe(2n);
    expect(log.closed).toHaveLength(1);
  });

  it("enforces READY's size limit both ways (MESSAGE_TOO_LARGE closes)", async () => {
    const server = new FakeServer();
    server.maxMessageBytes = 200n;
    const { c } = connect(server);
    await settle();
    expect(() => c.send(createMessage("PING", { payload: new Uint8Array(8) }))).not.toThrow();
    expect(() => c.sendEncoded(new Uint8Array(201))).toThrow(
      expect.objectContaining({ code: "MESSAGE_TOO_LARGE" }),
    );
    server.push(
      createMessage("DATA_BATCH", {
        resourceId: bytes32(5) as never,
        objects: [new Uint8Array(300)],
      }),
    );
    await settle();
    expect(c.state).toBe("DISCONNECTED");
    const last = decodeMessage(server.current.sent.at(-1) as Uint8Array);
    expect(last.type === "ERROR" && last.body.code).toBe(19n);
  });

  it("never lets READY raise the receive limit above the client's own maximum (§31)", async () => {
    const MiB = 1024 * 1024;
    const big = createMessage("DATA_BATCH", {
      resourceId: bytes32(5) as never,
      objects: [new Uint8Array(9 * MiB)],
    });
    // The server advertises 64 MiB; the client keeps its 8 MiB default.
    const server = new FakeServer();
    server.maxMessageBytes = BigInt(64 * MiB);
    const { c } = connect(server);
    await settle();
    server.push(big);
    await settle();
    expect(c.state).toBe("DISCONNECTED");
    const last = decodeMessage(server.current.sent.at(-1) as Uint8Array);
    expect(last.type === "ERROR" && last.body.code).toBe(19n);
    // A client configured for 16 MiB accepts it.
    const roomy = new FakeServer();
    roomy.maxMessageBytes = BigInt(64 * MiB);
    const { c: c2, log } = connect(roomy, { t: 0 }, 16 * MiB);
    await settle();
    roomy.push(big);
    await settle();
    expect(c2.state).not.toBe("DISCONNECTED");
    expect(log.messages.some((m) => m.type === "DATA_BATCH")).toBe(true);
  });

  it("sends PING every heartbeat and declares the connection dead after three silent ones (§38)", async () => {
    const server = new FakeServer();
    server.heartbeatMs = 1000n;
    const { c, log, clock } = connect(server);
    await settle();
    const pings = () => server.current.sent.filter((b) => decodeMessage(b).type === "PING").length;
    clock.t = 500;
    expect(c.tick(500)).toBe(true);
    expect(pings()).toBe(0);
    clock.t = 1000;
    c.tick(1000);
    expect(pings()).toBe(1);
    clock.t = 2999;
    expect(c.tick(2999)).toBe(true);
    clock.t = 3001;
    expect(c.tick(3001)).toBe(false);
    expect(c.state).toBe("DISCONNECTED");
    expect(log.closed[0]).toMatch(/three heartbeat/);
  });

  it("reports a server-side drop once and can connect again", async () => {
    const server = new FakeServer();
    const { c, log } = connect(server);
    await settle();
    server.current.drop();
    await settle();
    expect(c.state).toBe("DISCONNECTED");
    expect(log.closed).toHaveLength(1);
    c.connect();
    await settle();
    expect(c.state).toBe("READY");
    expect(server.sockets).toHaveLength(2);
  });

  it("finds the platform WebSocket (Node 24 has one)", () => {
    expect(typeof platformWebSocket()).toBe("function");
    void encodeMessage;
  });
});
