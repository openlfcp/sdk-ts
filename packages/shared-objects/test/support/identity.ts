import * as A from "@automerge/automerge";
import { principalId, resourceId, toBase64url, toHex } from "@openlfcp/core";
import { importSigningKey, sha256 } from "@openlfcp/crypto";
import {
  deriveIdentityActorId,
  IDENTITY_PROFILE_ID,
  type IdentityUnit,
  type IdentityWriter,
} from "../../src/identity/index.js";
import { principalRef } from "../../src/values.js";

// Deliberately invalid documents and operations are built by the fixtures.
// biome-ignore lint/suspicious/noExplicitAny: malformed Automerge fixtures
export type Doc = Record<string, any>;
export const S = (text: string) => new A.ImmutableString(text);
export const U = (value: number) => new A.Uint(value);
export const root = principalId(new Uint8Array(32).fill(1));
export const personal = principalId(new Uint8Array(32).fill(2));
export const pairing = principalId(new Uint8Array(32).fill(3));
export const other = principalId(new Uint8Array(32).fill(4));
export const resource = resourceId(new Uint8Array(32).fill(5));
export const resourceRef = toBase64url(resource);
export const options = { root, resource };
export const rootWriter: IdentityWriter = { signer: root, actorSeq: 1, writerClass: "root" };
export const personalWriter: IdentityWriter = {
  signer: personal,
  actorSeq: 1,
  writerClass: "personal",
};
export const pairingWriter: IdentityWriter = {
  signer: pairing,
  actorSeq: 1,
  writerClass: "pairing",
};
export const otherWriter: IdentityWriter = { signer: other, actorSeq: 1, writerClass: "other" };
export const actor = (writer: IdentityWriter) =>
  toHex(deriveIdentityActorId(resource, writer.signer));
export const last = (doc: A.Doc<Doc>) => A.getLastLocalChange(doc) as Uint8Array;
export const unit = (doc: A.Doc<Doc>, writer = rootWriter): IdentityUnit => ({
  ...writer,
  bytes: last(doc),
});
export function initial(writer = rootWriter, edit?: (d: Doc) => void): A.Doc<Doc> {
  return A.change(A.init<Doc>({ actor: actor(writer) }), { time: 0 }, (d) => {
    d.profile = S(IDENTITY_PROFILE_ID);
    d.identity = { root: S(principalRef(root)) };
    d.roster = {};
    d.devices = {};
    d.requests = {};
    d.extensions = {};
    edit?.(d);
  });
}
export function edit(doc: A.Doc<Doc>, fn: (d: Doc) => void, writer = personalWriter): A.Doc<Doc> {
  return A.change(A.clone(doc, { actor: actor(writer) }), { time: 0 }, (d) => {
    fn(d);
    // Automerge 3.5.0 imports nested Uint wrappers as maps; assign uints on live proxies.
    for (const table of ["devices", "requests"])
      for (const entry of Object.values(d[table] ?? {}) as Doc[])
        if (entry && entry.kind === undefined) entry.kind = U(0);
  });
}
export function descriptor(seed = 7) {
  const ed = importSigningKey(new Uint8Array(32).fill(seed)).publicKey;
  const x = new Uint8Array(32).fill(seed + 1);
  const domain = Uint8Array.from("LFCP-PRINCIPAL-v1", (c) => c.charCodeAt(0));
  const hash = sha256(Uint8Array.from([...domain, ...ed, ...x]));
  const bytes = Uint8Array.from([
    0xa3,
    0,
    0x58,
    32,
    ...hash,
    1,
    0x58,
    32,
    ...ed,
    2,
    0x58,
    32,
    ...x,
  ]);
  return { key: principalRef(principalId(hash)), text: toBase64url(bytes), bytes };
}
export const device = descriptor();
export const secondDevice = descriptor(8);
export const request = (who = pairing) => ({
  descriptor: S(device.text),
  pairing: S(principalRef(who)),
  label: S("phone"),
});
export const roster = () => ({
  profile: S("org.openlfcp.shared-sections.v1"),
  endpoints: [S("https://example.test")],
  coordinator: S("https://example.test"),
  name: S("notes"),
});
export function filled() {
  const first = initial();
  const doc = edit(
    first,
    (d) => {
      d.roster[resourceRef] = roster();
      d.devices[device.key] = { label: S("phone") };
    },
    { ...rootWriter, actorSeq: 2 },
  );
  return { first, doc, units: [unit(first), unit(doc, { ...rootWriter, actorSeq: 2 })] as const };
}
