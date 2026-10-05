import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  fromBase64url,
  LfcpError,
  type ResourceId,
  resourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import {
  exportSecretKeyBytes,
  InvitationSecret,
  importAgreementKey,
  importSigningKey,
} from "@openlfcp/crypto";
import { ABILITY } from "./capability.js";
import { cborMap, decodeDeterministic, encode } from "./cbor/index.js";
import { strictUtf8Decoder, utf8Encoder } from "./cbor/text.js";
import type { ControlState } from "./chain.js";
import type { Signer } from "./cose.js";
import { checkReceivedUrl, checkWriterUrl } from "./endpoint.js";
import { Fields } from "./fields.js";
import { type PrincipalDescriptor, principalDescriptorFromKeys } from "./principal.js";

/**
 * Invitations (LFCP-WIRE-01 §18, §18.2, LFCP-039b): the invitation secret
 * (deterministic CBOR of the Invitation Principal's private keys), the
 * Invitation Principal it determines, and the canonical lfcp://join URI in
 * its targeted and bearer forms. Pure building blocks; the claim flow
 * (CAPABILITY_CLAIM, the claimant's Key Package) is LFCP-053.
 *
 * §18.2: the secret "MUST NOT be logged, placed in analytics, stored in
 * browser history by an LFCP web landing page, or transmitted to the
 * synchronization server as an opaque URL." An InvitationSecret is
 * redacted when printed or serialized, and no error raised here includes
 * a URI, a secret or key bytes: messages name the part that is wrong only.
 * A bearer URI string itself carries the secret; treat it like a key.
 */

/** §18.2 invite-secret field 0: the only secret format version. */
export const INVITE_SECRET_VERSION = 1n;

const KEY_LENGTH = 32;
const ID_LENGTH = 32;
const PREFIX = "lfcp://join/";

const invalid = (why: string): never => {
  throw new LfcpError("INVALID_INVITATION", `invalid invitation: ${why}`);
};

/**
 * The §18.2 invite-secret: deterministic CBOR {0: 1, 1: Ed25519 seed,
 * 2: X25519 private key}.
 *
 * WARNING: the result is secret. It belongs only in the `#secret=`
 * fragment of a bearer invitation URI handed to the invitee.
 */
export function encodeInviteSecret(secret: InvitationSecret): Uint8Array {
  return encode(
    cborMap([
      [0, INVITE_SECRET_VERSION],
      [1, exportSecretKeyBytes(secret.signingKey)],
      [2, exportSecretKeyBytes(secret.agreementKey)],
    ]),
  );
}

/**
 * Decodes a §18.2 invite-secret: deterministic CBOR, exactly fields 0-2,
 * version 1 and two 32-byte keys. Throws INVALID_INVITATION, never with
 * the bytes in the message.
 */
export function decodeInviteSecret(bytes: Uint8Array): InvitationSecret {
  let fields: Fields;
  try {
    fields = new Fields(decodeDeterministic(bytes), "invite-secret", [0, 1, 2]);
    if (fields.uint(0) !== INVITE_SECRET_VERSION)
      fields.fail(0, `must be secret format version ${INVITE_SECRET_VERSION}`);
    return InvitationSecret.fromKeys(
      importSigningKey(fields.bytes(1, KEY_LENGTH)),
      importAgreementKey(fields.bytes(2, KEY_LENGTH)),
    );
  } catch (e) {
    // Only the error code: no message that could quote a value.
    const code = e instanceof LfcpError ? e.code : "UNKNOWN";
    return invalid(`the secret is not a §18.2 invite-secret (${code})`);
  }
}

/** The Invitation Principal's public descriptor, recomputed from its secret (§7, §18.2). */
export function invitationPrincipal(secret: InvitationSecret): PrincipalDescriptor {
  return principalDescriptorFromKeys(secret.signingKey, secret.agreementKey);
}

/**
 * §18.2: "The receiving client MUST recompute the corresponding public
 * Principal Descriptor and MUST verify that it matches the subject of the
 * referenced Invitation Grant before using the secret."
 *
 * `grantId` must name a grant of `state` (MISSING_DEPENDENCY otherwise: the
 * client lacks Control Records) that lists invite/claim (§18: an
 * invitation grant), whose subject is the recomputed Invitation Principal
 * (INVALID_INVITATION otherwise). Returns the Invitation Principal as a
 * signer, for the claim record (§18.1). Whether the grant is still active
 * and claimable is decided where it is used (§18.1, §25.2).
 */
export function verifyInvitationSecret(
  state: ControlState,
  grantId: ControlRecordId,
  secret: InvitationSecret,
): Signer {
  const grant = state.grants.get(toHex(grantId));
  if (grant === undefined)
    throw new LfcpError(
      "MISSING_DEPENDENCY",
      "the invitation's grant is not in the known Control Chain",
    );
  if (!grant.abilities.includes(ABILITY.INVITE_CLAIM))
    invalid("the referenced grant is not an invitation grant (no invite/claim, §18)");
  const descriptor = invitationPrincipal(secret);
  if (!bytesEqual(descriptor.principalId, grant.subject))
    invalid("the secret's Invitation Principal is not the subject of the grant (§18.2)");
  return Object.freeze({ key: secret.signingKey, descriptor });
}

/** An invitation: the targeted form, or the bearer form when `secret` is present (§18.2). */
export interface Invitation {
  readonly resourceId: ResourceId;
  /** One or more endpoint URLs, in URI order. */
  readonly endpoints: readonly string[];
  /** The Control Record ID of the invitation grant. */
  readonly grantId: ControlRecordId;
  readonly secret?: InvitationSecret;
}

const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/** §18.2 (G-RS4): every UTF-8 byte outside the RFC 3986 unreserved set as %XX, upper-case hex. */
function percentEncode(text: string): string {
  let out = "";
  for (const ch of text) {
    if (UNRESERVED.test(ch)) out += ch;
    else
      for (const b of utf8Encoder.encode(ch))
        out += `%${b.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

/** RFC 3986 percent-decoding of a query value into UTF-8 text. */
function percentDecode(text: string, what: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (ch === "%") {
      const hex = text.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) invalid(`${what} has a broken percent-encoding`);
      bytes.push(Number.parseInt(hex, 16));
      i += 2;
    } else {
      const code = ch.charCodeAt(0);
      if (code < 0x21 || code > 0x7e)
        invalid(`${what} has a character that must be percent-encoded`);
      bytes.push(code);
    }
  }
  try {
    return strictUtf8Decoder.decode(Uint8Array.from(bytes));
  } catch {
    return invalid(`${what} is not UTF-8`);
  }
}

/** A canonical unpadded base64url 32-byte ID (§18.2). */
function id32(text: string, what: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64url(text);
  } catch {
    return invalid(`${what} is not canonical unpadded base64url`);
  }
  if (bytes.length !== ID_LENGTH) invalid(`${what} is not ${ID_LENGTH} bytes`);
  return bytes;
}

/**
 * The canonical §18.2 URI: lfcp://join/<resource>?endpoint=…[&endpoint=…]&grant=<grant>,
 * plus #secret=<secret> for a bearer invitation. IDs and the secret are
 * unpadded base64url; each endpoint must pass the §16 writer rules and is
 * percent-encoded (G-RS4).
 */
export function assembleInviteUri(invitation: Invitation): string {
  if (invitation.endpoints.length === 0) invalid("at least one endpoint is required (§18.2)");
  for (const url of invitation.endpoints) {
    try {
      checkWriterUrl(url);
    } catch {
      invalid("an endpoint is not a URL a writer may use (§16)");
    }
  }
  const query = [
    ...invitation.endpoints.map((url) => `endpoint=${percentEncode(url)}`),
    `grant=${toBase64url(invitation.grantId)}`,
  ].join("&");
  const fragment =
    invitation.secret === undefined
      ? ""
      : `#secret=${toBase64url(encodeInviteSecret(invitation.secret))}`;
  return `${PREFIX}${toBase64url(invitation.resourceId)}?${query}${fragment}`;
}

/**
 * Parses a §18.2 invitation URI. The scheme and host compare
 * case-insensitively (RFC 3986 §3.1, §3.2.2); the path is one Resource ID;
 * the query has one or more `endpoint` parameters and exactly one `grant`,
 * nothing else; a fragment, if present, is exactly `secret=<b64url>`.
 * Endpoints are percent-decoded and must use ws or wss (§16). Throws
 * INVALID_INVITATION, never with the URI or the secret in the message.
 * Verify a bearer secret against the grant (verifyInvitationSecret) before
 * using it.
 */
export function parseInviteUri(uri: string): Invitation {
  if (typeof uri !== "string") invalid("the URI is not a string");
  if (uri.slice(0, PREFIX.length).toLowerCase() !== PREFIX)
    invalid("the URI does not start with lfcp://join/");
  const hash = uri.indexOf("#");
  const beforeFragment = hash === -1 ? uri : uri.slice(0, hash);
  const question = beforeFragment.indexOf("?");
  if (question === -1) invalid("the URI has no query");
  const path = beforeFragment.slice(PREFIX.length, question);
  const resource = resourceId(id32(path, "the Resource ID"));

  const endpoints: string[] = [];
  let grant: ControlRecordId | undefined;
  for (const parameter of beforeFragment.slice(question + 1).split("&")) {
    const eq = parameter.indexOf("=");
    const name = eq === -1 ? parameter : parameter.slice(0, eq);
    const value = eq === -1 ? "" : parameter.slice(eq + 1);
    if (value === "") invalid(`the query parameter ${JSON.stringify(name)} has no value`);
    if (name === "endpoint") {
      const url = percentDecode(value, "an endpoint");
      try {
        checkReceivedUrl(url);
      } catch {
        invalid("an endpoint is not a ws or wss URL (§16)");
      }
      endpoints.push(url);
    } else if (name === "grant") {
      if (grant !== undefined) invalid("the grant parameter appears twice");
      grant = controlRecordId(id32(value, "the grant ID"));
    } else invalid(`the query parameter ${JSON.stringify(name)} is not defined by §18.2`);
  }
  if (endpoints.length === 0) invalid("the URI has no endpoint parameter");
  if (grant === undefined) invalid("the URI has no grant parameter");

  let secret: InvitationSecret | undefined;
  if (hash !== -1) {
    const fragment = uri.slice(hash + 1);
    if (!fragment.startsWith("secret=")) invalid("the fragment is not secret=<b64url>");
    let bytes: Uint8Array;
    try {
      bytes = fromBase64url(fragment.slice("secret=".length));
    } catch {
      return invalid("the secret is not canonical unpadded base64url");
    }
    secret = decodeInviteSecret(bytes);
  }
  return Object.freeze({
    resourceId: resource,
    endpoints: Object.freeze(endpoints),
    grantId: grant as ControlRecordId,
    ...(secret !== undefined ? { secret } : {}),
  });
}
