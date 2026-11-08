import { bytesEqual, type ResourceId, toHex } from "@openlfcp/core";
import {
  ABILITY,
  checkDataUnit,
  hasAbility,
  InMemorySeenUnits,
  parseControlRecord,
  parseDataUnit,
  parseKeyPackage,
  revokedReaderPrefix,
  type Signer,
  serverAcceptsDataPut,
  validateControlChain,
  verifyKeyPackage,
} from "@openlfcp/wire";
import type {
  IdentityAnswer,
  IdentityChannel,
  IdentityNetwork,
  OpenAnswer,
} from "../../src/identity/network.js";
import { IdentityRefused, IdentityUnavailable } from "../../src/identity/network.js";
import type { LinearChain } from "../../src/identity/phases.js";

/** What a fault does to one upload: lose the request, or commit it and lose the answer. */
export type Fault = "drop-request" | "drop-answer" | { readonly nack: string };

export interface UploadEvent {
  readonly op: "host" | "control" | "key-package" | "data-unit";
  readonly resource: ResourceId;
  readonly bytes: Uint8Array;
  readonly signer: Signer;
}

interface Hosted {
  records: Uint8Array[];
  units: Map<string, Uint8Array>;
  packages: Uint8Array[];
  seen: InMemorySeenUnits;
}

/**
 * An in-memory coordinator for the identity flows (test only): Control
 * Records with compare-and-swap and exact-byte replay (W §47, §70), Key
 * Packages checked by W §25.2, Data Units checked by W §26.3 and §75,
 * reads gated by `holds(session, 1)` (W §41) with the revoked-reader
 * prefix of W §41. `fault` injects lost requests and lost answers; while
 * `offline` every connection fails.
 */
export class MemoryCoordinator {
  readonly hosted = new Map<string, Hosted>();
  extensions: readonly string[] = ["identity-01"];
  offline = false;
  /** Resources (hex) whose coordinator does not answer. */
  readonly down = new Set<string>();
  fault: (e: UploadEvent) => Fault | undefined = () => undefined;
  readonly uploads: UploadEvent[] = [];

  chain(resource: ResourceId): LinearChain {
    const h = this.hosted.get(toHex(resource));
    if (h === undefined) throw new Error("not hosted");
    const c = validateControlChain(h.records);
    if (c.kind !== "linear") throw new Error(`hosted chain is ${c.kind}`);
    return c;
  }

  /** Seeds a Resource with an existing chain (e.g. from a vector). */
  seed(records: readonly Uint8Array[]): ResourceId {
    const c = validateControlChain([...records]);
    if (c.kind !== "linear") throw new Error(c.kind);
    this.hosted.set(toHex(c.state.resourceId), {
      records: [...records],
      units: new Map(),
      packages: [],
      seen: new InMemorySeenUnits(),
    });
    return c.state.resourceId;
  }

  /** Stores a unit as a server that accepted it would, equivocation included (no checks). */
  inject(resource: ResourceId, bytes: Uint8Array): void {
    const h = this.hosted.get(toHex(resource));
    if (h === undefined) throw new Error("not hosted");
    h.units.set(`${toHex(bytes)}`, bytes);
  }

  packagesOf(resource: ResourceId) {
    return (this.hosted.get(toHex(resource))?.packages ?? []).map(
      (b) => parseKeyPackage(b).payload,
    );
  }

  /** The exact bytes of the units held for a Resource, by actor and sequence. */
  unitsBytes(resource: ResourceId): Uint8Array[] {
    return [...(this.hosted.get(toHex(resource))?.units.values() ?? [])].sort((a, b) => {
      const x = parseDataUnit(a).payload;
      const y = parseDataUnit(b).payload;
      const ax = toHex(x.actor);
      const ay = toHex(y.actor);
      if (ax !== ay) return ax < ay ? -1 : 1;
      return x.actorSeq < y.actorSeq ? -1 : 1;
    });
  }

  unitsOf(resource: ResourceId) {
    return [...(this.hosted.get(toHex(resource))?.units.values() ?? [])].map(
      (b) => parseDataUnit(b).payload,
    );
  }

  network(): IdentityNetwork {
    return {
      connect: async (signer, url) => {
        if (this.offline) throw new IdentityUnavailable(`${url} is offline`);
        return this.#channel(signer);
      },
    };
  }

  #reader(h: Hosted, signer: Signer): LinearChain | "prefix" | undefined {
    const c = validateControlChain(h.records);
    if (c.kind !== "linear") return undefined;
    const p = signer.descriptor.principalId;
    if (hasAbility(c.state, p, ABILITY.DATA_READ) || hasAbility(c.state, p, ABILITY.INVITE_CLAIM))
      return c;
    return revokedReaderPrefix(c, p as never) === undefined ? undefined : "prefix";
  }

  async #upload(
    target: ResourceId | undefined,
    e: UploadEvent,
    apply: () => IdentityAnswer | Promise<IdentityAnswer>,
  ): Promise<IdentityAnswer> {
    if (this.offline || (target !== undefined && this.down.has(toHex(target))))
      throw new IdentityUnavailable("offline");
    this.uploads.push(e);
    const f = this.fault(e);
    if (f === "drop-request") throw new IdentityUnavailable("the request was lost");
    if (typeof f === "object") return { kind: "nack", code: f.nack };
    const answer = await apply();
    if (f === "drop-answer") throw new IdentityUnavailable("the answer was lost");
    return answer;
  }

  #channel(signer: Signer): IdentityChannel {
    const self = this;
    const hosted = (r: ResourceId) => this.hosted.get(toHex(r));
    const nack = (code: string): IdentityAnswer => ({ kind: "nack", code });
    const reach = (r: ResourceId) => {
      if (this.offline || this.down.has(toHex(r))) throw new IdentityUnavailable("unreachable");
    };
    return {
      get extensions() {
        return self.extensions;
      },
      host: (genesis) =>
        this.#upload(
          undefined,
          {
            op: "host",
            resource: parseControlRecord(genesis).payload.resourceId,
            bytes: genesis,
            signer,
          },
          () => {
            const c = validateControlChain([genesis]);
            if (c.kind !== "linear")
              return nack(c.kind === "invalid" ? c.wireCode : "MALFORMED_MESSAGE");
            const key = toHex(c.state.resourceId);
            const h = this.hosted.get(key);
            if (h !== undefined)
              return bytesEqual(h.records[0] as Uint8Array, genesis)
                ? { kind: "ack" }
                : nack("HOSTING_DENIED");
            this.hosted.set(key, {
              records: [genesis],
              units: new Map(),
              packages: [],
              seen: new InMemorySeenUnits(),
            });
            return { kind: "ack" };
          },
        ),
      open: async (r): Promise<OpenAnswer> => {
        reach(r);
        if (this.offline) throw new IdentityUnavailable("offline");
        const h = hosted(r);
        if (h === undefined) return { kind: "nack", code: "RESOURCE_NOT_HOSTED" };
        const access = this.#reader(h, signer);
        if (access === undefined) return { kind: "nack", code: "AUTHORIZATION_FAILED" };
        if (access === "prefix") {
          const c = validateControlChain(h.records) as LinearChain;
          const at = revokedReaderPrefix(c, signer.descriptor.principalId)?.index as number;
          const rec = c.records[at];
          return {
            kind: "opened",
            heads: [{ seq: BigInt(at), recordId: rec?.signed.id as never }],
            haves: [],
          };
        }
        const haves = new Map<string, bigint>();
        for (const b of h.units.values()) {
          const p = parseDataUnit(b).payload;
          const k = toHex(p.actor);
          if ((haves.get(k) ?? 0n) < p.actorSeq) haves.set(k, p.actorSeq);
        }
        return {
          kind: "opened",
          heads: [{ seq: access.state.seq, recordId: access.state.head }],
          haves: [...h.units.values()]
            .map((b) => parseDataUnit(b).payload.actor)
            .filter((a, i, all) => all.findIndex((x) => bytesEqual(x, a)) === i)
            .map((a) => ({ principalId: a, contiguous: haves.get(toHex(a)) ?? 0n })),
        };
      },
      control: async (r, start) => {
        reach(r);
        if (this.offline) throw new IdentityUnavailable("offline");
        const h = hosted(r);
        // A NACK, as the connection network reports it (CONTROL_GET of W §45).
        if (h === undefined)
          throw new IdentityRefused("RESOURCE_NOT_HOSTED", "CONTROL_GET was refused");
        const access = this.#reader(h, signer);
        if (access === undefined) {
          throw new IdentityRefused("AUTHORIZATION_FAILED", "CONTROL_GET was refused");
        }
        if (access === "prefix") {
          const c = validateControlChain(h.records) as LinearChain;
          const at = revokedReaderPrefix(c, signer.descriptor.principalId)?.index as number;
          return h.records.slice(Number(start), at + 1);
        }
        return h.records.slice(Number(start));
      },
      putControl: (r, expectedHead, record) =>
        this.#upload(r, { op: "control", resource: r, bytes: record, signer }, () => {
          const h = hosted(r);
          if (h === undefined) return nack("RESOURCE_NOT_HOSTED");
          if (h.records.some((x) => bytesEqual(x, record))) return { kind: "ack" };
          const c = validateControlChain(h.records) as LinearChain;
          if (!bytesEqual(c.state.head, expectedHead))
            return { kind: "nack", code: "CONTROL_HEAD_MISMATCH", head: c.state.head };
          const next = validateControlChain([...h.records, record]);
          if (next.kind !== "linear")
            return nack(next.kind === "invalid" ? next.wireCode : "CONTROL_CONFLICT");
          h.records.push(record);
          return { kind: "ack" };
        }),
      keyPackages: async (r, recipient, epochs) => {
        reach(r);
        if (this.offline) throw new IdentityUnavailable("offline");
        const h = hosted(r);
        if (h === undefined) return [];
        const access = this.#reader(h, signer);
        if (access === undefined || access === "prefix") {
          throw new IdentityRefused("AUTHORIZATION_FAILED", "KEY_PACKAGE_GET was refused");
        }
        return h.packages.filter((b) => {
          const p = parseKeyPackage(b).payload;
          return bytesEqual(p.recipient, recipient) && epochs.includes(p.dataEpoch);
        });
      },
      putKeyPackage: (r, bytes) =>
        this.#upload(r, { op: "key-package", resource: r, bytes, signer }, () => {
          const h = hosted(r);
          if (h === undefined) return nack("RESOURCE_NOT_HOSTED");
          const c = validateControlChain(h.records) as LinearChain;
          const check = verifyKeyPackage(c, parseKeyPackage(bytes));
          if (check.kind !== "authorized") return nack("AUTHORIZATION_FAILED");
          if (!h.packages.some((p) => bytesEqual(p, bytes))) h.packages.push(bytes);
          return { kind: "ack" };
        }),
      dataUnits: async (r, ranges) => {
        reach(r);
        if (this.offline) throw new IdentityUnavailable("offline");
        const h = hosted(r);
        if (h === undefined) return [];
        const access = this.#reader(h, signer);
        if (access === undefined || access === "prefix") {
          throw new IdentityRefused("AUTHORIZATION_FAILED", "DATA_GET was refused");
        }
        return [...h.units.values()].filter((b) => {
          const p = parseDataUnit(b).payload;
          return ranges.some(
            (g) => bytesEqual(g.actor, p.actor) && p.actorSeq >= g.start && p.actorSeq <= g.end,
          );
        });
      },
      putDataUnit: (r, bytes) =>
        this.#upload(r, { op: "data-unit", resource: r, bytes, signer }, () =>
          this.#putUnit(hosted(r), bytes),
        ),
      close: () => undefined,
    };
  }

  async #putUnit(h: Hosted | undefined, bytes: Uint8Array): Promise<IdentityAnswer> {
    if (h === undefined) return { kind: "nack", code: "RESOURCE_NOT_HOSTED" };
    const p = parseDataUnit(bytes).payload;
    const key = `${toHex(p.actor)}:${p.actorSeq}`;
    const existing = h.units.get(key);
    if (existing !== undefined)
      return bytesEqual(existing, bytes)
        ? { kind: "ack" }
        : { kind: "nack", code: "ACTOR_EQUIVOCATION" };
    const c = validateControlChain(h.records) as LinearChain;
    const epoch = serverAcceptsDataPut(c, p);
    if (!epoch.ok) return { kind: "nack", code: epoch.nack };
    const check = await checkDataUnit(c, bytes, new InMemorySeenUnits());
    if (check.kind !== "valid") return { kind: "nack", code: "AUTHORIZATION_FAILED" };
    h.units.set(key, bytes);
    return { kind: "ack" };
  }
}
