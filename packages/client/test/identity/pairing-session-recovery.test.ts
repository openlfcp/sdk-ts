import { toHex } from "@openlfcp/core";
import { parseDataUnit } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { OperationJournal } from "../../src/identity/journal.js";
import { createPairingSession, resumePairingSession } from "../../src/identity/pairing.js";
import { world } from "./world.js";

describe("a pairing session after a restart (IDENTITY-PROFILE-01 §5.3 step 1)", {
  timeout: 60_000,
}, () => {
  test("a resumed session shows no link once the root's unit 1 is gone (11.2)", async () => {
    const w = await world(0);
    w.server.fault = (e) => (e.op === "control" ? "drop-answer" : undefined);
    expect((await createPairingSession(w.P)).kind).toBe("unavailable");
    w.server.fault = () => undefined;
    const hosted = w.server.hosted.get(toHex(w.I));
    for (const [k, b] of hosted?.units ?? [])
      if (parseDataUnit(b).payload.actorSeq === 1n) hosted?.units.delete(k);
    const [op] = await new OperationJournal(w.P.storage).list({ kind: "pairing-session" });
    const r = await resumePairingSession(w.P, (op as { id: string }).id);
    expect(r.kind).toBe("missing-material");
  });
});
