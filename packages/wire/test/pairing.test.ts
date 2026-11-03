import {
  bytesEqual,
  controlRecordId,
  LfcpError,
  principalId,
  resourceId,
  toBase64url,
} from "@openlfcp/core";
import { InvitationSecret, importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import {
  assembleInviteUri,
  assemblePairingUri,
  deviceFingerprint,
  invitationPrincipal,
  type PairingLink,
  pairingDeviceSigner,
  parseInviteUri,
  parsePairingUri,
} from "../src/index.js";
import { seq32 } from "./synthetic.js";

// Pairing links and device fingerprints (IDENTITY-PROFILE-01 §5.2).

const SECRET = InvitationSecret.fromKeys(
  importSigningKey(seq32(40)),
  importAgreementKey(seq32(140)),
);
const J = invitationPrincipal(SECRET).principalId;
const I = seq32(200);
const LINK: PairingLink = {
  identityResourceId: resourceId(I),
  endpoints: ["wss://sync.example.test/v1/ws", "wss://b.example.test/ws?x=1"],
  pairingDevice: J,
  secret: SECRET,
};
const codeOf = (fn: () => unknown) => {
  try {
    fn();
    return "ACCEPTED";
  } catch (e) {
    return e instanceof LfcpError ? e.code : String(e);
  }
};

describe("pairing link (IDENTITY-PROFILE-01 §5.2)", () => {
  it("assembles the canonical form and parses it back", () => {
    const uri = assemblePairingUri(LINK);
    expect(uri).toBe(
      `lfcp://pair/${toBase64url(I)}?endpoint=wss%3A%2F%2Fsync.example.test%2Fv1%2Fws&endpoint=wss%3A%2F%2Fb.example.test%2Fws%3Fx%3D1&device=${toBase64url(J)}#secret=${uri.slice(uri.indexOf("#secret=") + 8)}`,
    );
    const parsed = parsePairingUri(uri);
    expect(bytesEqual(parsed.identityResourceId, I)).toBe(true);
    expect(parsed.endpoints).toEqual(LINK.endpoints);
    expect(bytesEqual(parsed.pairingDevice, J)).toBe(true);
    const signer = pairingDeviceSigner(parsed);
    expect(bytesEqual(signer.descriptor.principalId, J)).toBe(true);
    // The §18.2 rules: case-insensitive scheme and host, unknown parameters ignored.
    expect(
      bytesEqual(
        parsePairingUri(`LFCP://PAIR/${uri.slice(12).replace("?", "?later=1&")}`).pairingDevice,
        J,
      ),
    ).toBe(true);
  });

  it("requires the secret, and the secret must be the device's", () => {
    const uri = assemblePairingUri(LINK);
    const query = uri.slice(0, uri.indexOf("#"));
    expect(codeOf(() => parsePairingUri(query))).toBe("INVALID_INVITATION");
    const other = principalId(seq32(9));
    expect(codeOf(() => parsePairingUri(uri.replace(toBase64url(J), toBase64url(other))))).toBe(
      "INVALID_INVITATION",
    );
    expect(codeOf(() => assemblePairingUri({ ...LINK, pairingDevice: other }))).toBe(
      "INVALID_INVITATION",
    );
    expect(
      codeOf(() => parsePairingUri(uri.replace("&device=", `&device=${toBase64url(J)}&device=`))),
    ).toBe("INVALID_INVITATION");
    expect(codeOf(() => parsePairingUri(uri.replace(/&device=[^#]*/, "")))).toBe(
      "INVALID_INVITATION",
    );
    expect(codeOf(() => parsePairingUri(uri.replace(/endpoint=[^&]*&/g, "")))).toBe(
      "INVALID_INVITATION",
    );
  });

  it("keeps pairing and invitation links apart", () => {
    const invite = assembleInviteUri({
      resourceId: resourceId(I),
      endpoints: ["wss://sync.example.test/v1/ws"],
      grantId: controlRecordId(seq32(1)),
      secret: SECRET,
    });
    expect(codeOf(() => parsePairingUri(invite))).toBe("INVALID_INVITATION");
    expect(codeOf(() => parseInviteUri(assemblePairingUri(LINK)))).toBe("INVALID_INVITATION");
  });

  it("never puts the URI or the secret in an error message", () => {
    const uri = assemblePairingUri(LINK);
    const secret = uri.slice(uri.indexOf("#secret=") + 8);
    try {
      parsePairingUri(uri.replace(toBase64url(J), toBase64url(seq32(9))));
    } catch (e) {
      expect(String(e)).not.toContain(secret);
      expect(String(e)).not.toContain("lfcp://pair/A");
    }
  });
});

describe("device fingerprint (IDENTITY-PROFILE-01 §5.2)", () => {
  it("is base32-lower-nopad of the first 80 bits of SHA-256(label || id), in four groups", () => {
    // Expected values computed independently (Python hashlib + base64.b32encode).
    expect(deviceFingerprint(principalId(new Uint8Array(32)))).toBe("7a76-ei3b-4igh-myhn");
    expect(deviceFingerprint(principalId(Uint8Array.from({ length: 32 }, (_, i) => i)))).toBe(
      "bkpo-gmyh-77dh-towx",
    );
    expect(deviceFingerprint(J)).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/);
    expect(codeOf(() => deviceFingerprint(new Uint8Array(31) as never))).toBe("INVALID_LENGTH");
  });
});
