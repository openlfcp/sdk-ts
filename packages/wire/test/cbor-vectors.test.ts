import { fromHex, LfcpError, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  type CborMap,
  type CborValue,
  decodeStrict,
  encode,
  isDeterministic,
} from "../src/cbor/index.js";

// Byte-exact values copied from spec tag mvp-0.1-baseline (769c7dd),
// test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json. LFCP-017 loads the
// suite itself; these literals only pin the codec.

// case principal_bob, expected.descriptor_cbor
const BOB_DESCRIPTOR = [
  "a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50158201953f4ada1cb4e0f86",
  "62108152c82e7e074cbf4859c487461cbe41e5d623e3c2025820b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5a",
  "ca7528fdd5eefb94f26c",
].join("");
// case C0_genesis, expected.protected_header_cbor ({1: -8, 4: kid}: a negative integer, as COSE needs)
const C0_PROTECTED = [
  "a20127045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d",
].join("");
// case C0_genesis, expected.payload_cbor
const C0_PAYLOAD = [
  "a6005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc241010002f60300045820172d2f",
  "c24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d05a500746f72672e6c6663702e746573742e72",
  "61772e763101a3005820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d015820f6fb6b",
  "8184ca17efdf2ca12486d3ba89fd4253efe9e1ae746fe0f93817c8851a02582053e766cd910b4dbc67f0d850bdcf2354",
  "02f5e708e85b5223a307f65cb92e4f0a0258209239077c0c32fc80bc1a51b8aad2917aebb1316853b85ffda562b1800c",
  "0ced300381a300781f7773733a2f2f73796e632d612e6578616d706c652e746573742f76312f7773010002183f04781f",
  "7773733a2f2f73796e632d612e6578616d706c652e746573742f76312f7773",
].join("");
// case D1_bob_epoch0_seq1, expected.payload_cbor
const D1_PAYLOAD = [
  "a7005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274",
  "bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5030104f6055820c8c476e22f99108b17034bea13fd7ad7",
  "a66d5bc1f0687ed06a036656e41594b80658266e3daad24229f9d890fc1eabe054c0dd46b45804aead812ca31e51d9b6",
  "2a572bf8376ef32671",
].join("");
// case D1_bob_epoch0_seq1, expected.cose_sign1
const D1_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a05899a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5030104f6055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1",
  "f0687ed06a036656e41594b80658266e3daad24229f9d890fc1eabe054c0dd46b45804aead812ca31e51d9b62a572bf8",
  "376ef3267158408adb5052b4f93358a1d5397fd05f591b47b20724afd186d42368caba11bd1f7e2d7ab3e43ad96d124e",
  "08ac17968d6cfc558a67ddc564ed538070d9dad0329508",
].join("");
// case HELLO, expected.message_cbor
const HELLO = [
  "a300000150041de94a275dca0103f0ffe8b54d936304a400816c4c4643502d574952452d303101a30058203ddf22ff14",
  "5274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50158201953f4ada1cb4e0f8662108152c82e7e074c",
  "bf4859c487461cbe41e5d623e3c2025820b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5aca7528fdd5eefb94f2",
  "6c025073dc4bd75464530922db519005d7d1f10381746f72672e6c6663702e746573742e7261772e7631",
].join("");
// case SNAPSHOT-01, expected.frontier_cbor
const SNAPSHOT_01_FRONTIER = [
  "82a20058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50102a2005820a6e402657a",
  "505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da480101",
].join("");
// case SNAPSHOT-01, expected.aad_cbor
const SNAPSHOT_01_AAD = [
  "87704c4643502d534e415053484f542d76315820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4c",
  "fc3cc2410158203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5015820e67fb23dc530",
  "252680216aecfeadb0951b1d3f8726c49afefd724b182dddc51882a20058203ddf22ff145274bcc59c56ffddaab8c123",
  "ffea4ac95ff8e9cedbeb788bf0a9c50102a2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe94",
  "3c1282da480101",
].join("");
// case SNAPSHOT-02, expected.frontier_cbor (with an extra sequence range)
const SNAPSHOT_02_FRONTIER = [
  "82a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50118640281821869186ba2",
  "005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da480101",
].join("");
// case noncanonical_payload_D1, inputs.cose_sign1 (N7: payload with a non-shortest integer)
const NONCANONICAL_PAYLOAD_D1_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a0589aa7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410118000258203ddf22ff145274bcc59c",
  "56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5030104f6055820c8c476e22f99108b17034bea13fd7ad7a66d5b",
  "c1f0687ed06a036656e41594b80658266e3daad24229f9d890fc1eabe054c0dd46b45804aead812ca31e51d9b62a572b",
  "f8376ef326715840c61e8713b42895fc0f64fc0e7573e7dbd2770dc5235b911a6c08a8c19668eb4e7db6128e8caafc4b",
  "228151836168012f2d970f6c0fb45d725d7ffc7b8b782106",
].join("");

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : "not-an-LfcpError";
  }
  return undefined;
};

describe("LFCP-TEST-VECTORS-01 deterministic CBOR", () => {
  it.each([
    ["principal_bob descriptor", BOB_DESCRIPTOR],
    ["C0_genesis protected header", C0_PROTECTED],
    ["C0_genesis payload", C0_PAYLOAD],
    ["D1_bob_epoch0_seq1 payload", D1_PAYLOAD],
    ["D1_bob_epoch0_seq1 COSE_Sign1", D1_COSE],
    ["HELLO message", HELLO],
    ["SNAPSHOT-01 frontier", SNAPSHOT_01_FRONTIER],
    ["SNAPSHOT-01 AAD", SNAPSHOT_01_AAD],
    ["SNAPSHOT-02 frontier", SNAPSHOT_02_FRONTIER],
  ])("%s decodes strictly and re-encodes byte for byte", (_name, h) => {
    const bytes = fromHex(h);
    expect(toHex(encode(decodeStrict(bytes)))).toBe(h);
    expect(isDeterministic(bytes)).toBe(true);
  });

  it("decodes the COSE protected header as {1: -8, 4: kid}", () => {
    const header = decodeStrict(fromHex(C0_PROTECTED)) as CborMap;
    expect(header.entries.map(([k]) => k)).toEqual([1, 4]);
    expect(header.entries[0]?.[1]).toBe(-8);
  });

  it("rejects the N7 non-canonical payload but accepts its COSE envelope", () => {
    const cose = fromHex(NONCANONICAL_PAYLOAD_D1_COSE);
    // The untagged COSE_Sign1 array itself is deterministic...
    expect(isDeterministic(cose)).toBe(true);
    const payload = (decodeStrict(cose) as CborValue[])[2] as Uint8Array;
    // ...but its payload encodes the data epoch 0 as 0x18 0x00 (LFCP-WIRE-01 §5.2, SPEC-PATCH-01 / N7).
    expect(isDeterministic(payload)).toBe(false);
    expect(codeOf(() => decodeStrict(payload))).toBe("CBOR_NON_CANONICAL");
    // Dropping the extra 0x18 (offset 37: map head, key 0, resource id, key 1) gives D1's payload exactly.
    expect(payload[37]).toBe(0x18);
    const canonical = Uint8Array.from([...payload.subarray(0, 37), ...payload.subarray(38)]);
    expect(toHex(canonical)).toBe(D1_PAYLOAD);
  });
});
