// LFCP-IDENTITY-TEST-VECTORS-01 against @openlfcp/wire (LFCP-04-409b): every
// Control Record case on its context chain, with its verdict and wire code
// (the six KEY_EPOCH cases of decision I9 among them: the epoch number is a
// chain placement check, §62 class 2) and, when accepted, the owner, sequence,
// epoch and rootOf table of its post-state; and the READY message that
// announces identity-01, byte for byte (corrected in mvp-0.4-baseline.2).
import { bytesEqual, fromHex, type PrincipalId, toHex } from "@openlfcp/core";
import {
  activeDevice,
  actsFor,
  decodeMessage,
  encodeMessage,
  isBound,
  rootOf,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { contextOf, idOf, recordOf, type WireCase, wire, wireCase } from "./corpus.js";

const records = wire.cases.filter((c) => c.kind === "control_record");

/** A Principal's fixture label, as the corpus writes post-states. */
function labelOf(table: Readonly<Record<string, unknown>>, id: PrincipalId): string {
  return Object.keys(table).find((l) => bytesEqual(idOf(l), id)) ?? toHex(id);
}

function outcome(c: WireCase) {
  const r = validateControlChain([...contextOf(c.id), recordOf(c.id)]);
  if (r.kind !== "linear") return { valid: false, code: r.wireCode };
  const queries = c.expected.post_state.queries as Record<string, unknown> | undefined;
  return {
    valid: true,
    owner: labelOf(queries ?? { [c.expected.post_state.owner]: 0 }, r.state.owner.principalId),
    control_seq: Number(r.state.seq),
    epoch: Number(r.state.epoch.epoch),
    ...(queries === undefined
      ? {}
      : {
          queries: Object.fromEntries(
            Object.keys(queries).map((label) => {
              const p = idOf(label);
              return [
                label,
                {
                  rootOf: labelOf(queries, rootOf(r.state, p)),
                  actsFor: labelOf(queries, actsFor(r.state, p)),
                  bound: isBound(r.state, p),
                  active: activeDevice(r.state, p) !== undefined,
                },
              ];
            }),
          ),
        }),
  };
}

describe("LFCP-IDENTITY-TEST-VECTORS-01: Control Records (W §7.3, §14 to §23, §62)", () => {
  test("covers the corpus, the I9 cases included", () => {
    expect(records.length).toBeGreaterThanOrEqual(196);
    expect(records.filter((c) => c.id.startsWith("key_epoch_")).map((c) => c.id)).toEqual(
      expect.arrayContaining([
        "key_epoch_repeats_current_number",
        "key_epoch_wrong_number",
        "key_epoch_wrong_number_and_bad_sig",
        "key_epoch_wrong_number_unknown_issuer",
        "key_epoch_wrong_number_without_key_rotate",
        "key_epoch_wrong_number_noncanonical_frontier",
      ]),
    );
  });
  test.each(records.map((c) => [c.id, c] as const))("%s", (_, c) => {
    const e = c.expected;
    const ps = e.post_state;
    const got = outcome(c) as Record<string, unknown>;
    if (e.valid !== true) {
      expect(got).toEqual({ valid: false, code: e.error.code });
      return;
    }
    expect(got.valid).toBe(true);
    for (const k of ["owner", "control_seq", "epoch", "queries"])
      if (ps[k] !== undefined) expect([k, got[k]]).toEqual([k, ps[k]]);
    if (ps.already_in_chain === true) {
      // The exact bytes of an accepted record again: the chain and its state are unchanged.
      const before = validateControlChain(contextOf(c.id));
      if (before.kind !== "linear") throw new Error(before.kind);
      expect(got.control_seq).toBe(Number(before.state.seq));
      expect(toHex(recordOf(c.id))).toBe(wireCase(ps.ack_record).inputs.cose_sign1.hex);
    }
  });
});

describe("LFCP-IDENTITY-TEST-VECTORS-01: READY_identity_01 (W §33, §37)", () => {
  const c = wireCase("READY_identity_01");
  const i = c.inputs;
  const bytes = fromHex(c.expected.message_cbor.hex);
  test("encodes byte for byte as a READY message", () => {
    expect(i.message_type).toBe("READY");
    const encoded = encodeMessage({
      type: "READY",
      messageId: fromHex(i.message_id.hex),
      correlationId: fromHex(i.correlation.hex),
      body: {
        wireProfile: i.wire_profile,
        serverId: fromHex(i.server_id.hex),
        maxMessageBytes: BigInt(i.max_message_bytes),
        durability: BigInt(i.durability),
        heartbeatMs: BigInt(i.heartbeat_ms),
        extensions: [i.extension],
      },
    });
    expect(toHex(encoded)).toBe(toHex(bytes));
  });
  test("decodes as READY with the LFCP-WIRE-01 profile and identity-01", () => {
    const m = decodeMessage(bytes);
    if (m.type !== "READY") throw new Error(`a ${m.type}, not a READY`);
    expect(m.body.wireProfile).toBe("LFCP-WIRE-01");
    expect(m.body.extensions).toEqual(["identity-01"]);
  });
});
