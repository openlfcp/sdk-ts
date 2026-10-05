import {
  type ControlRecordId,
  controlRecordId,
  dataEpoch,
  type PrincipalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, encode } from "../src/cbor/index.js";
import {
  type ChainResult,
  type ControlBody,
  type ControlRecordHeader,
  decodeControlRecord,
  encodeControlRecordPayload,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  signObject,
  validateControlChain,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic chains from synthetic keys. The published C0-C6 chain and the
// control_fork_C6 conflict run in the conformance runner.

const CARLA: Signer = (() => {
  const key = importSigningKey(seq32(65));
  return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(165))) };
})();
const R = resourceId(seq32(200));
const R2 = resourceId(seq32(201));

const genesisBody = (owner: Signer = ALICE): ControlBody => ({
  type: "GENESIS",
  dataProfile: "org.example.custom.v1",
  owner: owner.descriptor,
  dekCommitment: seq32(10) as never,
  endpoints: [{ url: "wss://sync.example.test", priority: 0n }],
  coordinatorUrl: "wss://sync.example.test",
});
// data/read, data/write and route/update: enough authority (LFCP-021) for
// the grantee's route updates below.
const grant = (who: Signer): ControlBody => ({
  type: "CAPABILITY_GRANT",
  subject: who.descriptor,
  abilities: [1n, 2n, 8n],
  delegable: [],
});
const route = (v: bigint): ControlBody => ({
  type: "ROUTE_UPDATE",
  routeVersion: v,
  endpoints: [{ url: "wss://b.example.test", priority: 0n }],
  coordinatorUrl: "wss://b.example.test",
});

interface Built {
  readonly bytes: Uint8Array;
  readonly id: ControlRecordId;
}
const after = (prev: Built | null, seq: bigint, resource = R): ControlRecordHeader => ({
  resourceId: resource,
  controlSeq: seq,
  prevControlId: prev === null ? null : prev.id,
});
const sign = (header: ControlRecordHeader, body: ControlBody, signer: Signer): Built => {
  const s = signControlRecord(header, body, signer);
  return { bytes: s.bytes, id: s.recordId };
};
/** A record signed whatever the writer rules say (to build invalid chains). */
const raw = (fields: [number, unknown][], signer: Signer): Built => {
  const s = signObject(encode(cborMap(fields as never)), signer);
  return { bytes: s.bytes, id: controlRecordId(s.id) };
};

// G <- C1 (grant BRUNO, by ALICE) <- C2 (route, by BRUNO) <- C3 (grant CARLA, by ALICE)
//   <- C4 (tombstone, deferred) <- C5 (route, by CARLA)
const G = sign(after(null, 0n), genesisBody(), ALICE);
const C1 = sign(after(G, 1n), grant(BRUNO), ALICE);
const C2 = sign(after(C1, 2n), route(2n), BRUNO);
const C3 = sign(after(C2, 3n), grant(CARLA), ALICE);
const C4 = sign(after(C3, 4n), { type: "RESOURCE_TOMBSTONE", reason: 0n }, ALICE);
const C5 = sign(after(C4, 5n), route(3n), CARLA);
const CHAIN = [G, C1, C2, C3, C4, C5];
const bytesOf = (list: readonly Built[]) => list.map((b) => b.bytes);

const expectLinear = (r: ChainResult) => {
  if (r.kind !== "linear") throw new Error(`expected linear, got ${JSON.stringify(summary(r))}`);
  return r;
};
const expectInvalid = (r: ChainResult) => {
  if (r.kind !== "invalid") throw new Error(`expected invalid, got ${r.kind}`);
  return r;
};

/** A permutation-independent summary of a result (the input index is a position, so it is left out). */
function summary(r: ChainResult): unknown {
  switch (r.kind) {
    case "linear":
      return {
        kind: r.kind,
        head: toHex(r.state.head),
        seq: String(r.state.seq),
        records: r.records.map((x) => toHex(x.signed.id)),
        unapplied: r.unappliedRecords.map(toHex),
        principals: [...r.state.principals.keys()].sort(),
      };
    case "conflict":
      return {
        kind: r.kind,
        head: r.commonHead && toHex(r.commonHead),
        seq: String(r.seq),
        competing: r.competing.map(toHex),
        prefix: r.prefixState && toHex(r.prefixState.head),
      };
    case "invalid":
      return {
        kind: r.kind,
        problem: r.problem,
        wire: r.wireCode,
        record: r.recordId && toHex(r.recordId),
      };
  }
}

describe("validateControlChain", () => {
  it("1. validates a Genesis alone", () => {
    const r = expectLinear(validateControlChain([G.bytes]));
    expect(toHex(r.state.genesisId)).toBe(toHex(G.id));
    expect(toHex(r.state.head)).toBe(toHex(G.id));
    expect(r.state.seq).toBe(0n);
    expect(r.state).toMatchObject({ dataProfile: "org.example.custom.v1", resourceId: R });
    expect(r.state.epoch.epoch).toBe(dataEpoch(0n));
  });

  it("2, 12. validates a linear chain and derives the Control Head", () => {
    const r = expectLinear(validateControlChain(bytesOf(CHAIN)));
    expect(toHex(r.state.head)).toBe(toHex(C5.id));
    expect(r.state.seq).toBe(5n);
    expect(r.records.map((x) => toHex(x.signed.id))).toEqual(CHAIN.map((b) => toHex(b.id)));
  });

  it("3. rejects a sequence skip", () => {
    const skip = sign(after(C1, 3n), route(2n), BRUNO);
    const r = expectInvalid(validateControlChain(bytesOf([G, C1, skip])));
    expect([r.problem, r.wireCode, toHex(r.recordId as ControlRecordId)]).toEqual([
      "SEQUENCE",
      "INVALID_CONTROL_CHAIN",
      toHex(skip.id),
    ]);
  });

  it("4. rejects a duplicate sequence with an incompatible predecessor", () => {
    const sameSeqOtherPrev = sign(after(G, 2n), route(2n), BRUNO);
    expect(
      expectInvalid(validateControlChain(bytesOf([G, C1, C2, sameSeqOtherPrev]))).problem,
    ).toBe("SEQUENCE");
    const dangling = sign(
      { resourceId: R, controlSeq: 2n, prevControlId: controlRecordId(seq32(9)) },
      route(2n),
      BRUNO,
    );
    expect(expectInvalid(validateControlChain(bytesOf([G, C1, C2, dangling]))).problem).toBe(
      "PREVIOUS",
    );
  });

  it("5. rejects a wrong previous record ID", () => {
    const wrong = sign(
      { resourceId: R, controlSeq: 2n, prevControlId: controlRecordId(seq32(9)) },
      route(2n),
      BRUNO,
    );
    const r = expectInvalid(validateControlChain(bytesOf([G, C1, wrong])));
    expect([r.problem, r.wireCode]).toEqual(["PREVIOUS", "INVALID_CONTROL_CHAIN"]);
  });

  it("6. rejects a successor of another Resource", () => {
    const other = sign(after(C1, 2n, R2), route(2n), BRUNO);
    expect(expectInvalid(validateControlChain(bytesOf([G, C1, other]))).problem).toBe("RESOURCE");
  });

  it("7. rejects an invalid signature as INVALID_SIGNATURE", () => {
    const bad = Uint8Array.from(C2.bytes);
    bad[bad.length - 1] = (bad[bad.length - 1] as number) ^ 1;
    const r = expectInvalid(validateControlChain([G.bytes, C1.bytes, bad]));
    expect([r.problem, r.wireCode, r.error.code]).toEqual([
      "SIGNATURE",
      "INVALID_SIGNATURE",
      "INVALID_SIGNATURE",
    ]);
    // A record signed by someone other than its issuer.
    const payload = encodeControlRecordPayload(
      after(C1, 2n),
      BRUNO.descriptor.principalId,
      route(2n),
    );
    const forged = signObject(payload, CARLA);
    expect(expectInvalid(validateControlChain([G.bytes, C1.bytes, forged.bytes])).problem).toBe(
      "SIGNATURE",
    );
  });

  it("8. uses the exact bytes: changed bytes change the record ID, decoded objects are not trusted", () => {
    const changed = Uint8Array.from(C1.bytes);
    changed[changed.length - 2] = (changed[changed.length - 2] as number) ^ 1;
    expect(toHex(decodeControlRecord(changed).signed.id)).not.toBe(toHex(C1.id));
    expect(expectInvalid(validateControlChain([G.bytes, changed, C2.bytes])).problem).toBe(
      "SIGNATURE",
    );
    // A decoded object with a doctored payload is re-decoded from its exact bytes.
    const decoded = decodeControlRecord(C1.bytes);
    const doctored = { ...decoded, payload: { ...decoded.payload, controlSeq: 99n } };
    const r = expectLinear(validateControlChain([G.bytes, doctored, C2.bytes]));
    expect(r.state.seq).toBe(2n);
  });

  it("9, 10, 11. reports a fork as CONTROL_CONFLICT without choosing a branch", () => {
    const a = sign(after(C1, 2n), route(2n), BRUNO);
    const b = sign(after(C1, 2n), route(7n), BRUNO);
    const later = sign(after(a, 3n), grant(CARLA), ALICE);
    const r = validateControlChain(bytesOf([G, C1, a, b, later]));
    if (r.kind !== "conflict") throw new Error(r.kind);
    expect(r.wireCode).toBe("CONTROL_CONFLICT");
    expect(toHex(r.commonHead as ControlRecordId)).toBe(toHex(C1.id));
    expect(r.seq).toBe(2n);
    expect(r.competing.map(toHex).sort()).toEqual([toHex(a.id), toHex(b.id)].sort());
    // Only the common prefix is state: neither branch (nor what follows it) is applied.
    expect(toHex((r.prefixState as { head: ControlRecordId }).head)).toBe(toHex(C1.id));
    expect(r).not.toHaveProperty("state");
  });

  it("13. gives the same result for every arrival order (seeded permutations)", () => {
    let seed = 0x5eed_2020;
    const random = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const shuffle = <T>(list: readonly T[]): T[] => {
      const out = [...list];
      for (let i = out.length - 1; i > 0; i--) {
        const j = Math.floor(random() * (i + 1));
        [out[i], out[j]] = [out[j] as T, out[i] as T];
      }
      return out;
    };
    const forkA = sign(after(C2, 3n), grant(CARLA), ALICE);
    const forkB = sign(after(C2, 3n), route(9n), BRUNO);
    const skip = sign(after(C2, 4n), route(9n), BRUNO);
    const sets: Built[][] = [
      CHAIN,
      [...CHAIN.slice(0, 3), forkA, forkB],
      [...CHAIN.slice(0, 3), skip, C3],
    ];
    const kinds = new Set<string>();
    for (const set of sets) {
      const reference = JSON.stringify(summary(validateControlChain(bytesOf(set))));
      kinds.add(JSON.parse(reference).kind);
      for (let n = 0; n < 60; n++) {
        expect(JSON.stringify(summary(validateControlChain(bytesOf(shuffle(set)))))).toBe(
          reference,
        );
      }
    }
    expect([...kinds].sort()).toEqual(["conflict", "invalid", "linear"]);
  }, 30_000);

  it("rejects an unknown core type mid-chain as UNSUPPORTED_VALUE", () => {
    const unknown = raw(
      [
        [0, R],
        [1, 2],
        [2, C1.id],
        [3, 9],
        [4, BRUNO.descriptor.principalId],
        [5, cborMap([])],
      ],
      BRUNO,
    );
    const r = expectInvalid(validateControlChain(bytesOf([G, C1, unknown])));
    expect([r.problem, r.error.code, r.wireCode]).toEqual([
      "UNSUPPORTED_TYPE",
      "UNSUPPORTED_VALUE",
      "MALFORMED_MESSAGE",
    ]);
  });

  it("keeps deferred types and extensions in the chain, unapplied", () => {
    const ext = sign(
      after(C5, 6n),
      { type: "EXTENSION", code: 40n, body: cborMap([[0, "x"]]) },
      CARLA,
    );
    const r = expectLinear(validateControlChain(bytesOf([...CHAIN, ext])));
    expect(r.unappliedRecords.map(toHex)).toEqual([toHex(C4.id), toHex(ext.id)]);
    expect(toHex(r.state.head)).toBe(toHex(ext.id));
    // Unapplied records move the head and change nothing else.
    const before = r.stateAt(C5.id);
    if (before === undefined) throw new Error("no state at C5");
    expect({ ...r.state, head: before.head, seq: before.seq }).toEqual(before);
    const beforeTombstone = r.stateAt(C3.id);
    const afterTombstone = r.stateAt(C4.id);
    expect(afterTombstone?.grants).toBe(beforeTombstone?.grants);
    expect(afterTombstone?.route).toBe(beforeTombstone?.route);
  });

  it("reports an issuer no record describes, unless a resolver knows it", () => {
    const byStranger = sign(after(C1, 2n), route(2n), CARLA);
    const r = expectInvalid(validateControlChain(bytesOf([G, C1, byStranger])));
    expect([r.problem, r.wireCode]).toEqual(["UNRESOLVED_ISSUER", "INVALID_CONTROL_CHAIN"]);
    const resolve = (id: PrincipalId) =>
      toHex(id) === toHex(CARLA.descriptor.principalId) ? CARLA.descriptor : undefined;
    // With the descriptor resolved the signature verifies; CARLA holds no
    // grant, so the default capability engine then refuses the record.
    const resolved = expectInvalid(
      validateControlChain(bytesOf([G, C1, byStranger]), { resolvePrincipal: resolve }),
    );
    expect(resolved.problem).toBe("UNAUTHORIZED");
    expect(
      validateControlChain(bytesOf([G, C1, byStranger]), {
        resolvePrincipal: resolve,
        authorize: () => true,
      }).kind,
    ).toBe("linear");
    // A resolver that lies about the descriptor does not help.
    const liar = () => BRUNO.descriptor;
    expect(
      expectInvalid(
        validateControlChain(bytesOf([G, C1, byStranger]), {
          resolvePrincipal: liar,
          authorize: () => true,
        }),
      ).problem,
    ).toBe("SIGNATURE");
  });

  it("calls the authorization hook (allow by default)", () => {
    const seen: string[] = [];
    const r = validateControlChain(bytesOf(CHAIN), {
      authorize: (record) => {
        seen.push(record.body.type);
        return record.body.type !== "RESOURCE_TOMBSTONE";
      },
    });
    expect(seen).toEqual([
      "CAPABILITY_GRANT",
      "ROUTE_UPDATE",
      "CAPABILITY_GRANT",
      "RESOURCE_TOMBSTONE",
    ]);
    expect([expectInvalid(r).problem, expectInvalid(r).wireCode]).toEqual([
      "UNAUTHORIZED",
      "AUTHORIZATION_FAILED",
    ]);
  });

  it("continues after a validated head", () => {
    const first = expectLinear(validateControlChain(bytesOf(CHAIN.slice(0, 3))));
    const rest = expectLinear(
      validateControlChain(bytesOf([C2, ...CHAIN.slice(3)]), { start: first.state }),
    );
    const whole = expectLinear(validateControlChain(bytesOf(CHAIN)));
    expect(toHex(rest.state.head)).toBe(toHex(whole.state.head));
    expect(rest.state.seq).toBe(5n);
    expect(rest.records.map((x) => toHex(x.signed.id))).toEqual(
      CHAIN.slice(3).map((b) => toHex(b.id)),
    );
  });

  it("handles Genesis problems", () => {
    expect(expectInvalid(validateControlChain(bytesOf([C1, C2]))).problem).toBe("NO_GENESIS");
    // Two Genesis records for one Resource: a root conflict (open gap).
    const G2 = sign(after(null, 0n), genesisBody(BRUNO), BRUNO);
    const r = validateControlChain(bytesOf([G, G2, C1]));
    expect(r.kind === "conflict" && r.commonHead === null && r.seq === 0n).toBe(true);
    // Genesis records of two Resources.
    const other = sign(after(null, 0n, R2), genesisBody(), ALICE);
    expect(expectInvalid(validateControlChain(bytesOf([G, other]))).problem).toBe("RESOURCE");
    // A Genesis signed by someone other than its owner.
    const payload = encodeControlRecordPayload(
      after(null, 0n),
      ALICE.descriptor.principalId,
      genesisBody(),
    );
    const forged = signObject(payload, BRUNO);
    expect(expectInvalid(validateControlChain([forged.bytes])).problem).toBe("SIGNATURE");
  });

  it("treats the same record delivered twice as one", () => {
    const r = expectLinear(validateControlChain(bytesOf([G, C1, C1, G, C2])));
    expect(r.state.seq).toBe(2n);
  });

  it("reports malformed input as MALFORMED_MESSAGE", () => {
    const r = expectInvalid(validateControlChain([G.bytes, Uint8Array.of(0x80)]));
    expect([r.problem, r.wireCode, r.index]).toEqual(["MALFORMED", "MALFORMED_MESSAGE", 1]);
  });
});
