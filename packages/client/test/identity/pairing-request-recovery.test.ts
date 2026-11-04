import { toHex } from "@openlfcp/core";
import { parseDataUnit } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { createPairingSession, pairingRequests } from "../../src/identity/pairing.js";
import { completePairing, requestPairing } from "../../src/identity/pairing-request.js";
import { party } from "./support.js";
import { node, world } from "./world.js";

describe("a pairing request after a restart (IDENTITY-PROFILE-01 §5.3 step 3, §9.1)", {
  timeout: 60_000,
}, () => {
  test("a request lost on the way is sent from the journal by completePairing (11.1)", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    const B = node(w.server, party(3));
    w.server.fault = (e) => (e.op === "data-unit" ? "drop-request" : undefined);
    const req = await requestPairing({ ...B, link: s.link, label: "phone", kind: 0 });
    expect(req.kind).toBe("unavailable");
    w.server.fault = () => undefined;
    const operation = (req as { operation?: string }).operation;
    if (operation === undefined) throw new Error("no operation");
    expect(await completePairing({ ...B, operation })).toEqual({ kind: "waiting" });
    const reviews = await pairingRequests({ ...w.P, session: s.session });
    expect(reviews.map((r) => r.label)).toEqual(["phone"]);
    // The resent unit is the journaled one: one byte string for J's sequence 1.
    const sent = w.server.uploads.filter(
      (u) =>
        u.op === "data-unit" &&
        toHex(parseDataUnit(u.bytes).payload.actor) === toHex(s.pairingDevice),
    );
    expect(new Set(sent.map((u) => toHex(u.bytes))).size).toBe(1);
    // Asking again resumes the same operation instead of writing a second request.
    const again = await requestPairing({ ...B, link: s.link, label: "phone", kind: 0 });
    expect(again.kind === "requested" && again.operation).toBe(operation);
  });
});
