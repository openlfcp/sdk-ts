import { fromHex, toHex } from "@openlfcp/core";
import { importAgreementKey, importSigningKey, verifyEd25519 } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import {
  decodePrincipalDescriptor,
  encodePrincipalDescriptor,
  principalDescriptorFromKeys,
} from "../src/index.js";

// LFCP-TEST-VECTORS-01 at spec tag mvp-0.1-baseline (769c7dd), cases principal_owner, principal_bob,
// principal_carol, principal_invite (inputs.ed25519_seed, inputs.x25519_private, expected.*). The seeds and X25519 private keys are public test fixtures,
// never use in production.
const PRINCIPALS = [
  {
    id: "principal_owner",
    ed25519Seed: "3df1a3457c0fc0d78c89cb4cdcd3c5912322cdc199f7a35a843e0e82ea9aa38b",
    x25519Private: "792bb0d4a2752e97583e603235b07ece323d2f65f1285907fc20c95da91ed874",
    ed25519Public: "f6fb6b8184ca17efdf2ca12486d3ba89fd4253efe9e1ae746fe0f93817c8851a",
    x25519Public: "53e766cd910b4dbc67f0d850bdcf235402f5e708e85b5223a307f65cb92e4f0a",
    principalId: "172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d",
    descriptorCbor:
      "a3005820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d015820f6fb6b8184ca17efdf2ca12486d3ba89fd4253efe9e1ae746fe0f93817c8851a02582053e766cd910b4dbc67f0d850bdcf235402f5e708e85b5223a307f65cb92e4f0a",
  },
  {
    id: "principal_bob",
    ed25519Seed: "3e7bc1815b7518d38d8d240970d8e1e8032483a5681434190cbf0ec635353a0f",
    x25519Private: "95f8f14ba1f1c117a6f78f8ac92c2d5afc7d0ffb50e5579a22cea1909c97fa3d",
    ed25519Public: "1953f4ada1cb4e0f8662108152c82e7e074cbf4859c487461cbe41e5d623e3c2",
    x25519Public: "b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5aca7528fdd5eefb94f26c",
    principalId: "3ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5",
    descriptorCbor:
      "a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50158201953f4ada1cb4e0f8662108152c82e7e074cbf4859c487461cbe41e5d623e3c2025820b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5aca7528fdd5eefb94f26c",
  },
  {
    id: "principal_carol",
    ed25519Seed: "b2a3c42376fe97aa221f63f6280200976eb9619f52b8d9edc9dfc998491a75d5",
    x25519Private: "b33a94ec0fde36e333ab4aa4364857544bc1f6148b417f92564ea77a79896257",
    ed25519Public: "e85e0878a5ef3cac47224c5ad65466d1d9ce8f5da0531bcfd44f4801eca9d862",
    x25519Public: "f0a5fba7ce3f994d3225a96a6e7a2a93a0f49bdffa27587faabbcf885dc64062",
    principalId: "a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48",
    descriptorCbor:
      "a3005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48015820e85e0878a5ef3cac47224c5ad65466d1d9ce8f5da0531bcfd44f4801eca9d862025820f0a5fba7ce3f994d3225a96a6e7a2a93a0f49bdffa27587faabbcf885dc64062",
  },
  {
    id: "principal_invite",
    ed25519Seed: "95d8068c889e24843a533db9d233863c0dae1bda7c32a83fd21606d5a113ac08",
    x25519Private: "8cf3fea326c315bfca2286cfc9036d66432632c6c8a3026ec28f97887e184185",
    ed25519Public: "3bcc05261bc40609f528e983a23cd356af2e739b36787ab6ccf58e4befaeb133",
    x25519Public: "da9ae6b26e5e3618bb6b6e7380c00f8995bd31a34115425ea65bfcac1ea17f39",
    principalId: "fd11cff30b5f51be630be47798a656119335d5ef0a41ebc0032335a6b2f6d6ba",
    descriptorCbor:
      "a3005820fd11cff30b5f51be630be47798a656119335d5ef0a41ebc0032335a6b2f6d6ba0158203bcc05261bc40609f528e983a23cd356af2e739b36787ab6ccf58e4befaeb133025820da9ae6b26e5e3618bb6b6e7380c00f8995bd31a34115425ea65bfcac1ea17f39",
  },
] as const;

describe.each(PRINCIPALS)("$id", (p) => {
  const signing = importSigningKey(fromHex(p.ed25519Seed));
  const agreement = importAgreementKey(fromHex(p.x25519Private));
  const descriptor = principalDescriptorFromKeys(signing, agreement);

  it("derives both public keys from the published private keys", () => {
    expect(toHex(signing.publicKey)).toBe(p.ed25519Public);
    expect(toHex(agreement.publicKey)).toBe(p.x25519Public);
  });

  it("derives the Principal ID and descriptor bytes exactly", () => {
    expect(toHex(descriptor.principalId)).toBe(p.principalId);
    expect(toHex(encodePrincipalDescriptor(descriptor))).toBe(p.descriptorCbor);
  });

  it("validates the published descriptor bytes", () => {
    const decoded = decodePrincipalDescriptor(fromHex(p.descriptorCbor));
    expect(toHex(decoded.principalId)).toBe(p.principalId);
  });

  it("signs and verifies with the fixture key", () => {
    const message = Uint8Array.from(p.id, (c) => c.charCodeAt(0));
    const signature = signing.sign(message);
    expect(verifyEd25519(fromHex(p.ed25519Public), message, signature)).toBe(true);
    signature[0] = (signature[0] as number) ^ 1;
    expect(verifyEd25519(fromHex(p.ed25519Public), message, signature)).toBe(false);
  });
});
