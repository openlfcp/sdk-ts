import { type PrincipalId, toHex } from "@openlfcp/core";
import { parseDataUnit } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { createResourceAsDevice } from "../../src/identity/accept.js";
import { OperationJournal } from "../../src/identity/journal.js";
import { party, URL } from "./support.js";
import { type Node, pair, world } from "./world.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const rosterPut =
  (w: Awaited<ReturnType<typeof world>>, A: Node) =>
  (e: { op: string; resource: Uint8Array; bytes: Uint8Array; signer: unknown }) =>
    e.op === "data-unit" &&
    toHex(e.resource) === toHex(w.I) &&
    e.signer === A.installation.signer &&
    toHex(parseDataUnit(e.bytes).payload.actor) === toHex(id(2));

describe("Resources from a device and the revoked device (review follow-up)", {
  timeout: 120_000,
}, () => {
  test("13.1: a roster unit refused as stale is written again in the new epoch", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    const isRoster = rosterPut(w, A);
    let once = false;
    w.server.fault = (e) => {
      if (once || !isRoster(e)) return undefined;
      once = true;
      return { nack: "STALE_DATA_EPOCH" };
    };
    const r = await createResourceAsDevice({ ...A, dataProfile: "org.example.v1", url: URL });
    expect(r.kind === "created" && r.roster).toBe(true);
  });

  test("13.1: without its roster entry the operation stays open, and its resume writes it", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    const isRoster = rosterPut(w, A);
    w.server.fault = (e) => (isRoster(e) ? { nack: "STALE_DATA_EPOCH" } : undefined);
    const r = await createResourceAsDevice({ ...A, dataProfile: "org.example.v1", url: URL });
    if (r.kind !== "incomplete") throw new Error(r.kind);
    expect((await new OperationJournal(A.storage).load(r.operation)).status).toBe("open");
    w.server.fault = () => undefined;
    const again = await createResourceAsDevice({
      ...A,
      dataProfile: "org.example.v1",
      url: URL,
      operation: r.operation,
    });
    expect(again.kind === "created" && again.roster).toBe(true);
    expect(toHex((again as { resource: Uint8Array }).resource)).toBe(toHex(r.resource));
  });
});
