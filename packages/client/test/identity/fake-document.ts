import { type PrincipalId, toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import type {
  DeviceEntryValue,
  IdentityAuthor,
  IdentityDocumentPort,
  IdentityIntent,
  PairingRequestValue,
  RosterEntryValue,
} from "../../src/identity/document.js";
import { principalRefOf } from "../../src/identity/document.js";

const enc = new TextEncoder();
const dec = new TextDecoder();
const json = (v: unknown) => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? Number(x) : x));

/**
 * A stand-in for IdentityReplica in client tests (the client package
 * never binds to Automerge): each change is the JSON of its intents. It
 * keeps the rules the flows rely on: the initial change only from the root
 * at actor sequence 1 (AI0), a pairing or other writer only creating or
 * writing its own request (AI4), and a device's `missing_keys` written only
 * by that device (AI5).
 */
export class FakeIdentityDocument implements IdentityDocumentPort {
  readonly #roster = new Map<string, RosterEntryValue>();
  readonly #devices = new Map<string, DeviceEntryValue>();
  readonly #requests = new Map<string, PairingRequestValue>();
  readonly #requestOwner = new Map<string, string>();
  #initialized = false;
  readonly #applied = new Set<string>();
  readonly #origins = new Map<string, { hash: string; signer: PrincipalId }[]>();
  readonly applied: { author: IdentityAuthor; intents: IdentityIntent[] }[] = [];

  write(author: IdentityAuthor, intents: readonly IdentityIntent[]): Uint8Array {
    // The change depends on every change applied so far, like an Automerge change on its heads.
    const plaintext = enc.encode(json({ intents, deps: [...this.#applied] }));
    if (!this.receive(plaintext, author)) throw new Error("the document refused the change");
    return plaintext;
  }

  receive(plaintext: Uint8Array, author: IdentityAuthor): boolean {
    const { intents, deps = [] } = JSON.parse(dec.decode(plaintext)) as {
      intents: IdentityIntent[];
      deps?: string[];
    };
    // Held until its dependencies are applied (SOP §14.1); a duplicate is admitted once.
    if (this.#applied.has(toHex(sha256(plaintext)))) return true;
    if (deps.some((d) => !this.#applied.has(d))) return false;
    const me = principalRefOf(author.signer);
    for (const i of intents) {
      if (i.intent === "identity.initialize") {
        if (this.#initialized || author.writerClass !== "root" || author.actorSeq !== 1n)
          return false;
        continue;
      }
      if (!this.#initialized) return false;
      if (i.intent === "device.put" && i.entry.missing_keys !== undefined && i.key !== me)
        return false;
      if (author.writerClass === "pairing" || author.writerClass === "other") {
        if (i.intent !== "request.put" || i.entry.pairing !== me) return false;
        const owner = this.#requestOwner.get(i.key);
        if (owner !== undefined && owner !== toHex(author.signer)) return false;
      }
    }
    const hash = toHex(sha256(plaintext));
    for (const i of intents) {
      if ("key" in i) {
        const k = `${i.intent.split(".")[0] === "device" ? "devices" : i.intent.split(".")[0] === "request" ? "requests" : "roster"}:${i.key}`;
        // As IdentityReplica.origins: a deleted value's changes are not the next value's.
        if (i.intent.endsWith(".delete")) this.#origins.delete(k);
        else {
          const list = this.#origins.get(k) ?? [];
          if (!list.some((o) => o.hash === hash)) list.push({ hash, signer: author.signer });
          this.#origins.set(k, list);
        }
      }
      if (i.intent === "identity.initialize") this.#initialized = true;
      else if (i.intent === "roster.put") this.#roster.set(i.key, i.entry);
      else if (i.intent === "device.put")
        this.#devices.set(i.key, { ...this.#devices.get(i.key), ...i.entry });
      else if (i.intent === "request.put") {
        if (!this.#requestOwner.has(i.key)) this.#requestOwner.set(i.key, toHex(author.signer));
        this.#requests.set(i.key, i.entry);
      } else if (i.intent === "roster.delete") this.#roster.delete(i.key);
      else if (i.intent === "device.delete") this.#devices.delete(i.key);
      else if (i.intent === "request.delete") {
        this.#requests.delete(i.key);
        this.#requestOwner.delete(i.key);
      }
    }
    this.applied.push({ author, intents });
    this.#applied.add(hash);
    return true;
  }

  /** The device's own hint, as IdentityReplica's `hints` option: only `missing_keys` is written. */
  readonly keyHints = {
    write: (
      author: IdentityAuthor,
      hints: ReadonlyMap<string, readonly bigint[] | null>,
    ): Uint8Array => {
      const key = principalRefOf(author.signer);
      const entry = this.#devices.get(key);
      if (entry === undefined) throw new Error(`no device entry ${key}`);
      const next: Record<string, readonly bigint[]> = { ...(entry.missing_keys ?? {}) } as never;
      for (const [ref, epochs] of hints)
        if (epochs === null || epochs.length === 0) delete next[ref];
        else next[ref] = epochs;
      this.hintWrites++;
      // An empty map stands for the removed field (the stand-in merges entries field by field).
      return this.write(author, [
        { intent: "device.put", key, entry: { ...entry, missing_keys: next } },
      ]);
    },
  };
  /** How many hint units were written. */
  hintWrites = 0;

  initialized(): boolean {
    return this.#initialized;
  }
  roster(): ReadonlyMap<string, RosterEntryValue> {
    return this.#roster;
  }
  devices(): ReadonlyMap<string, DeviceEntryValue> {
    return this.#devices;
  }
  requests(): ReadonlyMap<string, PairingRequestValue> {
    return this.#requests;
  }
  origins(table: "roster" | "devices" | "requests", key: string) {
    return this.#origins.get(`${table}:${key}`) ?? [];
  }
}
