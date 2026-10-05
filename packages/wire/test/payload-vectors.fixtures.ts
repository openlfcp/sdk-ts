// Literals from spec tag mvp-0.1-baseline.2 (1527fed),
// test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json. Each comment names the case and field.
// Values already in cose-vectors.fixtures.ts are reused from there (they are unchanged at
// this tag); public keys and signed objects only, no private keys.

import {
  C0_COSE,
  C0_ID,
  C0_PAYLOAD,
  D1_COSE,
  D1_ID,
  D1_PAYLOAD,
  INVALID_SIGNATURE_D1,
  NONCANONICAL_PAYLOAD_D1,
  S1_COSE,
  S1_ID,
  S1_PAYLOAD,
  TAGGED_COSE_D1,
  TAMPERED_D1,
  WRONG_KID_D1,
} from "./cose-vectors.fixtures.js";

export {
  C0_COSE,
  C0_ID,
  C0_PAYLOAD,
  D1_COSE,
  D1_ID,
  D1_PAYLOAD,
  INVALID_SIGNATURE_D1,
  NONCANONICAL_PAYLOAD_D1,
  S1_COSE,
  S1_ID,
  S1_PAYLOAD,
  TAGGED_COSE_D1,
  TAMPERED_D1,
  WRONG_KID_D1,
};

// principal_owner expected.descriptor_cbor
export const OWNER_DESCRIPTOR = [
  "a3005820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d015820f6fb6b8184ca17efdf",
  "2ca12486d3ba89fd4253efe9e1ae746fe0f93817c8851a02582053e766cd910b4dbc67f0d850bdcf235402f5e708e85b",
  "5223a307f65cb92e4f0a",
].join("");

// principal_bob expected.descriptor_cbor
export const BOB_DESCRIPTOR = [
  "a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50158201953f4ada1cb4e0f86",
  "62108152c82e7e074cbf4859c487461cbe41e5d623e3c2025820b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5a",
  "ca7528fdd5eefb94f26c",
].join("");

// principal_carol expected.descriptor_cbor
export const CAROL_DESCRIPTOR = [
  "a3005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48015820e85e0878a5ef3cac47",
  "224c5ad65466d1d9ce8f5da0531bcfd44f4801eca9d862025820f0a5fba7ce3f994d3225a96a6e7a2a93a0f49bdffa27",
  "587faabbcf885dc64062",
].join("");

// principal_invite expected.descriptor_cbor
export const INVITE_DESCRIPTOR = [
  "a3005820fd11cff30b5f51be630be47798a656119335d5ef0a41ebc0032335a6b2f6d6ba0158203bcc05261bc40609f5",
  "28e983a23cd356af2e739b36787ab6ccf58e4befaeb133025820da9ae6b26e5e3618bb6b6e7380c00f8995bd31a34115",
  "425ea65bfcac1ea17f39",
].join("");

// C1_grant_bob expected.cose_sign1
export const C1_COSE = [
  "845826a20127045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121da058e2a6005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203b141a9d660b274f73a042",
  "dbe47dcb1fe5b9f1d8d96f782cc8e4728695704adc0301045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125",
  "093976f6e906cd80121d05a300a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9",
  "c50158201953f4ada1cb4e0f8662108152c82e7e074cbf4859c487461cbe41e5d623e3c2025820b5a22f5f5cbdc3a6f8",
  "742ec8b2bc9665d0170478bf5aca7528fdd5eefb94f26c01830102030280584014e4d0fae4599143f6d6aff613384cca",
  "a2e9556fce48082b4fbaef67b9062011879b2d4b7912693bed073ff1d94bb9b4477f1882071afd944f8bd694d2d32b07",
].join("");

// C1_grant_bob expected.record_id
export const C1_ID = ["0b5dc558b8104686d5d6b0063629f1cfaf48049dee3580ca6e253d27f3359e33"].join("");

// C1_grant_bob expected.payload_cbor
export const C1_PAYLOAD = [
  "a6005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203b141a9d660b27",
  "4f73a042dbe47dcb1fe5b9f1d8d96f782cc8e4728695704adc0301045820172d2fc24d2192ed5703279a49d5db9f7fe8",
  "935b0125093976f6e906cd80121d05a300a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb",
  "788bf0a9c50158201953f4ada1cb4e0f8662108152c82e7e074cbf4859c487461cbe41e5d623e3c2025820b5a22f5f5c",
  "bdc3a6f8742ec8b2bc9665d0170478bf5aca7528fdd5eefb94f26c01830102030280",
].join("");

// C2_invite_grant expected.cose_sign1
export const C2_COSE = [
  "845826a20127045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121da058e4a6005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101020258200b5dc558b8104686d5d6b0",
  "063629f1cfaf48049dee3580ca6e253d27f3359e330301045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125",
  "093976f6e906cd80121d05a400a3005820fd11cff30b5f51be630be47798a656119335d5ef0a41ebc0032335a6b2f6d6",
  "ba0158203bcc05261bc40609f528e983a23cd356af2e739b36787ab6ccf58e4befaeb133025820da9ae6b26e5e3618bb",
  "6b6e7380c00f8995bd31a34115425ea65bfcac1ea17f39018301020b028004015840f8a18ce1fe2837f6cdd806133740",
  "abcb855acd8609b637cd3df3a62eceac6745867f264bed78a3be6a0e8d133b86cae7a3d3281a1602bb1995b3ad15b774",
  "8908",
].join("");

// C2_invite_grant expected.record_id
export const C2_ID = ["a77e8c2cebad4458e9ca036bef606cd9a7305395127b6a8479e7a088506334c2"].join("");

// C2_invite_grant expected.payload_cbor
export const C2_PAYLOAD = [
  "a6005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101020258200b5dc558b81046",
  "86d5d6b0063629f1cfaf48049dee3580ca6e253d27f3359e330301045820172d2fc24d2192ed5703279a49d5db9f7fe8",
  "935b0125093976f6e906cd80121d05a400a3005820fd11cff30b5f51be630be47798a656119335d5ef0a41ebc0032335",
  "a6b2f6d6ba0158203bcc05261bc40609f528e983a23cd356af2e739b36787ab6ccf58e4befaeb133025820da9ae6b26e",
  "5e3618bb6b6e7380c00f8995bd31a34115425ea65bfcac1ea17f39018301020b02800401",
].join("");

// C3_invite_claim_carol expected.cose_sign1
export const C3_COSE = [
  "845826a20127045820fd11cff30b5f51be630be47798a656119335d5ef0a41ebc0032335a6b2f6d6baa0590102a60058",
  "20c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410103025820a77e8c2cebad4458e9ca",
  "036bef606cd9a7305395127b6a8479e7a088506334c20303045820fd11cff30b5f51be630be47798a656119335d5ef0a",
  "41ebc0032335a6b2f6d6ba05a3005820a77e8c2cebad4458e9ca036bef606cd9a7305395127b6a8479e7a088506334c2",
  "01a3005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48015820e85e0878a5ef3cac",
  "47224c5ad65466d1d9ce8f5da0531bcfd44f4801eca9d862025820f0a5fba7ce3f994d3225a96a6e7a2a93a0f49bdffa",
  "27587faabbcf885dc6406202820102584020168d48cc6eca8b32a262c6e7a33a779325c181c6956087b62ddb9abcdf5d",
  "aeba814aeafea2e63493fc155e2e67482ca44658b5a5c5fe31365d86a6f2275105",
].join("");

// C3_invite_claim_carol expected.record_id
export const C3_ID = ["c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594b8"].join("");

// C3_invite_claim_carol expected.payload_cbor
export const C3_PAYLOAD = [
  "a6005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410103025820a77e8c2cebad44",
  "58e9ca036bef606cd9a7305395127b6a8479e7a088506334c20303045820fd11cff30b5f51be630be47798a656119335",
  "d5ef0a41ebc0032335a6b2f6d6ba05a3005820a77e8c2cebad4458e9ca036bef606cd9a7305395127b6a8479e7a08850",
  "6334c201a3005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48015820e85e0878a5",
  "ef3cac47224c5ad65466d1d9ce8f5da0531bcfd44f4801eca9d862025820f0a5fba7ce3f994d3225a96a6e7a2a93a0f4",
  "9bdffa27587faabbcf885dc6406202820102",
].join("");

// C4_owner_transfer_commit expected.cose_sign1
export const C4_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a0590283a60058",
  "20c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410104025820c8c476e22f99108b1703",
  "4bea13fd7ad7a66d5bc1f0687ed06a036656e41594b803060458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac9",
  "5ff8e9cedbeb788bf0a9c505a200590134845826a20127045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125",
  "093976f6e906cd80121da058c6a5005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2",
  "41015820c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594b8020403a30058203ddf22ff14",
  "5274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50158201953f4ada1cb4e0f8662108152c82e7e074c",
  "bf4859c487461cbe41e5d623e3c2025820b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5aca7528fdd5eefb94f2",
  "6c0450c4659b052b4850b974087b8aabc0456158402cc2b2e48c1366dc280cbd0d29eade8b4f6769245eb4b226bb29d4",
  "34f35fedc5c6901cfd1081698fab7c82f1e25dfb8f657b25d9af0201762859030ac2f9740e0158d8845826a201270458",
  "203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a0586aa3005820c8c3041cd1e87009",
  "c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101582071c4b2d5833b2f4d66be935a85a36cb4467d6d8553",
  "c744adff30bbca55e8e06f0258203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c55840",
  "b9ae2075a208408bdcc649d40712caa000312d9117637a5d5d0be122a81228e5a6cb6ced17fc641418d913abbbf8ebb1",
  "52cb2eeb775c2df47a20b8ebe308e20a58409dc9d7bf1ee0fd851d00b75881df3d44208bf3f489a43fa6a204a0efecd6",
  "a02305f2124d5e22eec7b93f68816606b1f924d88d561fa3779a6ec54941cd01ee05",
].join("");

// C4_owner_transfer_commit expected.record_id
export const C4_ID = ["be67407af4130b61d2df1da9ad2a59daa24eaab1387529a7eaa14c27e1a14879"].join("");

// C4_owner_transfer_commit expected.payload_cbor
export const C4_PAYLOAD = [
  "a6005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410104025820c8c476e22f9910",
  "8b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594b803060458203ddf22ff145274bcc59c56ffddaab8c123ff",
  "ea4ac95ff8e9cedbeb788bf0a9c505a200590134845826a20127045820172d2fc24d2192ed5703279a49d5db9f7fe893",
  "5b0125093976f6e906cd80121da058c6a5005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4c",
  "fc3cc241015820c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594b8020403a30058203ddf",
  "22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50158201953f4ada1cb4e0f8662108152c82e",
  "7e074cbf4859c487461cbe41e5d623e3c2025820b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5aca7528fdd5ee",
  "fb94f26c0450c4659b052b4850b974087b8aabc0456158402cc2b2e48c1366dc280cbd0d29eade8b4f6769245eb4b226",
  "bb29d434f35fedc5c6901cfd1081698fab7c82f1e25dfb8f657b25d9af0201762859030ac2f9740e0158d8845826a201",
  "270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a0586aa3005820c8c3041cd1",
  "e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101582071c4b2d5833b2f4d66be935a85a36cb4467d",
  "6d8553c744adff30bbca55e8e06f0258203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9",
  "c55840b9ae2075a208408bdcc649d40712caa000312d9117637a5d5d0be122a81228e5a6cb6ced17fc641418d913abbb",
  "f8ebb152cb2eeb775c2df47a20b8ebe308e20a",
].join("");

// C5_route_update expected.cose_sign1
export const C5_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058e5a6005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410105025820be67407af4130b61d2df1d",
  "a9ad2a59daa24eaab1387529a7eaa14c27e1a1487903050458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95f",
  "f8e9cedbeb788bf0a9c505a300010182a300781f7773733a2f2f73796e632d622e6578616d706c652e746573742f7631",
  "2f7773010a0217a300781f7773733a2f2f73796e632d612e6578616d706c652e746573742f76312f7773010002183f02",
  "781f7773733a2f2f73796e632d622e6578616d706c652e746573742f76312f77735840fc37224d10705b6bad3f9e922f",
  "5e86b29841c9e5ce302ad64412b417fc661f73ce969eb6606644ca3026453e31c2077620f7f90d162a44543436e921fc",
  "935d02",
].join("");

// C5_route_update expected.record_id
export const C5_ID = ["1189b7d19ac6d09a8128d3967a4fdd80ea2a6180efaa8a9f15bf2ee5c32cda46"].join("");

// C5_route_update expected.payload_cbor
export const C5_PAYLOAD = [
  "a6005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410105025820be67407af4130b",
  "61d2df1da9ad2a59daa24eaab1387529a7eaa14c27e1a1487903050458203ddf22ff145274bcc59c56ffddaab8c123ff",
  "ea4ac95ff8e9cedbeb788bf0a9c505a300010182a300781f7773733a2f2f73796e632d622e6578616d706c652e746573",
  "742f76312f7773010a0217a300781f7773733a2f2f73796e632d612e6578616d706c652e746573742f76312f77730100",
  "02183f02781f7773733a2f2f73796e632d622e6578616d706c652e746573742f76312f7773",
].join("");

// C6_key_epoch_1 expected.cose_sign1
export const C6_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058bfa6005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101060258201189b7d19ac6d09a8128d3",
  "967a4fdd80ea2a6180efaa8a9f15bf2ee5c32cda4603040458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95f",
  "f8e9cedbeb788bf0a9c505a4000101582027df3173462d19512f2224f54bdc894a8c7e81c212301ed1f2bb8ccee0ce71",
  "510281a20058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c501020303584071b309",
  "518143fd640aff64033ba76503c985f1509398202ff6dfa1e4315ed29f06e305774d467adb142a8fbeec0a10eae2b390",
  "eac527d92b7849a60e85cf520f",
].join("");

// C6_key_epoch_1 expected.record_id
export const C6_ID = ["e67fb23dc530252680216aecfeadb0951b1d3f8726c49afefd724b182dddc518"].join("");

// C6_key_epoch_1 expected.payload_cbor
export const C6_PAYLOAD = [
  "a6005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101060258201189b7d19ac6d0",
  "9a8128d3967a4fdd80ea2a6180efaa8a9f15bf2ee5c32cda4603040458203ddf22ff145274bcc59c56ffddaab8c123ff",
  "ea4ac95ff8e9cedbeb788bf0a9c505a4000101582027df3173462d19512f2224f54bdc894a8c7e81c212301ed1f2bb8c",
  "cee0ce71510281a20058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c501020303",
].join("");

// KP0_bob_epoch0 expected.cose_sign1
export const KP0_COSE = [
  "845826a20127045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121da058e5a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50358200b5dc558b8104686d5d6b0063629f1cfaf48049dee3580ca",
  "6e253d27f3359e33045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d05582090ca",
  "4ed22f5b693d842711cd8c3d692e1002a3a84730926abd4e3eed9342ee0a065830e7a2257711c7244d0f333986ceab7b",
  "aabdace14b42d179d3768648c535b3abed0ca41207be0e7157c31d6c073106e03758400c177d41281146bdadfd8a2a08",
  "bdcc8a9c40741ac1c1baec2e7766be4dc3c50f4e8c52c650e79c8857a076718c9c10d2b5abd6004f265f3cd1874f21cc",
  "5fb604",
].join("");

// KP0_bob_epoch0 expected.package_id
export const KP0_ID = ["d1e2e34aa2f426588dbcdd91b51d9fdc1c714a8d4f6e76022dbe24bdbc26289f"].join("");

// KP0_bob_epoch0 expected.payload_cbor
export const KP0_PAYLOAD = [
  "a7005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274",
  "bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50358200b5dc558b8104686d5d6b0063629f1cfaf48049d",
  "ee3580ca6e253d27f3359e33045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d05",
  "582090ca4ed22f5b693d842711cd8c3d692e1002a3a84730926abd4e3eed9342ee0a065830e7a2257711c7244d0f3339",
  "86ceab7baabdace14b42d179d3768648c535b3abed0ca41207be0e7157c31d6c073106e037",
].join("");

// KPI_invite_epoch0 expected.cose_sign1
export const KPI_COSE = [
  "845826a20127045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121da058e5a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410100025820fd11cff30b5f51be630be4",
  "7798a656119335d5ef0a41ebc0032335a6b2f6d6ba035820a77e8c2cebad4458e9ca036bef606cd9a7305395127b6a84",
  "79e7a088506334c2045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d0558207935",
  "c81b8976b4a0dde4c0a3bbcbfb8c550d2ea43b03b6b1d91b58b78368506f065830fd3038c8f6ae0a7c64d9d779ad8958",
  "9e58df6b62f9142e33c7cf43cab145361b4a21a7477058992c9a85d763479f8e6858403413ee0ec742a28ba2e08a5db0",
  "1a808685852e810307e28a90dc6ea2418856fe792d76e932280cefb25e2ee62f84dd75f36c7c72dbe52fd9adb6b695af",
  "9cee06",
].join("");

// KPI_invite_epoch0 expected.package_id
export const KPI_ID = ["b9ed6bb754518a4e75fd2a72f4d5f5af31a65da8d1a797bfaeb9f5df458ee700"].join("");

// KPI_invite_epoch0 expected.payload_cbor
export const KPI_PAYLOAD = [
  "a7005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410100025820fd11cff30b5f51",
  "be630be47798a656119335d5ef0a41ebc0032335a6b2f6d6ba035820a77e8c2cebad4458e9ca036bef606cd9a7305395",
  "127b6a8479e7a088506334c2045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d05",
  "58207935c81b8976b4a0dde4c0a3bbcbfb8c550d2ea43b03b6b1d91b58b78368506f065830fd3038c8f6ae0a7c64d9d7",
  "79ad89589e58df6b62f9142e33c7cf43cab145361b4a21a7477058992c9a85d763479f8e68",
].join("");

// KPC_carol_epoch1 expected.cose_sign1
export const KPC_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058e5a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410101025820a6e402657a505a183a2c26",
  "85ecc3a0457fef86d4e251abd48efe943c1282da48035820e67fb23dc530252680216aecfeadb0951b1d3f8726c49afe",
  "fd724b182dddc5180458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50558206974",
  "f9a0bb2d8e91e498871d820fc1db32970f30ad6a697923fc6873eef7c5700658304423f72dec72cb32393858fa15912a",
  "cb3cdc926a414fdfc1310439c4553bc775670db33d1887436fae2b40ef595bb7e8584017d44d926f540424a435e15ca6",
  "5ad1aca70630b88e8748d8515f237585aa5607f3dcd0036d96288c48a3fd7c8c3d83d414fead7334df8dadff39877b2d",
  "98980f",
].join("");

// KPC_carol_epoch1 expected.package_id
export const KPC_ID = ["eb0cce4209d00cc79970b7579ba88e87eb3f58c5baa5ce8316c2f5f08b6e96dc"].join("");

// KPC_carol_epoch1 expected.payload_cbor
export const KPC_PAYLOAD = [
  "a7005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410101025820a6e402657a505a",
  "183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48035820e67fb23dc530252680216aecfeadb0951b1d3f87",
  "26c49afefd724b182dddc5180458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c505",
  "58206974f9a0bb2d8e91e498871d820fc1db32970f30ad6a697923fc6873eef7c5700658304423f72dec72cb32393858",
  "fa15912acb3cdc926a414fdfc1310439c4553bc775670db33d1887436fae2b40ef595bb7e8",
].join("");

// D2_bob_epoch0_seq2 expected.cose_sign1
export const D2_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058baa7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820708b5a5f1ab7b7c9146b3bd7e4902831aa6666913608",
  "502c13b1d32c3650be9f055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594b8065826",
  "2c71204ff89488f5daac5c09f573e03207cc6c0de1cf213dd6151d8c8ee6dcd1e26f8ca396c7584088b18f58c20c3089",
  "e437d95753d24b8ba36bd5f1d328d0dae7d948bc1f5b2ab5abf70428456d43fc7059b4b0d03581f09a0de55d0ebbb957",
  "fba701637f4c4109",
].join("");

// D2_bob_epoch0_seq2 expected.unit_id
export const D2_ID = ["7745a3beb83838797591a1121e932799a5fb28b83890a3a9377f6c0d5cc34cd1"].join("");

// D2_bob_epoch0_seq2 expected.payload_cbor
export const D2_PAYLOAD = [
  "a7005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274",
  "bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820708b5a5f1ab7b7c9146b3bd7e4902831aa66",
  "66913608502c13b1d32c3650be9f055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594",
  "b80658262c71204ff89488f5daac5c09f573e03207cc6c0de1cf213dd6151d8c8ee6dcd1e26f8ca396c7",
].join("");

// D3_bob_epoch0_seq3_stale expected.cose_sign1
export const D3_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058bea7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c503030458207745a3beb83838797591a1121e932799a5fb28b83890",
  "a3a9377f6c0d5cc34cd1055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594b806582a",
  "c9051e489923824cb1cd793576ac478bc873f9b2ffdf1d8019b17d393c227e2b023987579ff3c9db1c745840b9071986",
  "97194ece5efcfdfc5c025a188d603d6e6741f51ef5b319a62097eee65c192ec9609ff0a65e20fd7e11cf464d097caaf3",
  "6ff6a62d7520600f6dc41400",
].join("");

// D3_bob_epoch0_seq3_stale expected.unit_id
export const D3_ID = ["39c10fe1e07c34d052b71c8196e53e8b42c3d2e06b5bb94ae3a3c0ada55b4683"].join("");

// D3_bob_epoch0_seq3_stale expected.payload_cbor
export const D3_PAYLOAD = [
  "a7005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274",
  "bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c503030458207745a3beb83838797591a1121e932799a5fb",
  "28b83890a3a9377f6c0d5cc34cd1055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594",
  "b806582ac9051e489923824cb1cd793576ac478bc873f9b2ffdf1d8019b17d393c227e2b023987579ff3c9db1c74",
].join("");

// D4_carol_epoch1_seq1 expected.cose_sign1
export const D4_COSE = [
  "845826a20127045820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48a0589fa7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410101025820a6e402657a505a183a2c26",
  "85ecc3a0457fef86d4e251abd48efe943c1282da48030104f6055820e67fb23dc530252680216aecfeadb0951b1d3f87",
  "26c49afefd724b182dddc51806582c4dd85825362439c8e0cc06be7de0a147073dfa0869091441ec2830928ff8e13873",
  "145f9f61ad1cd487e7ea815840006bcbc4432511ee53a5fce412083d91764875ce676bfe691a931d1547a8068c4bfba3",
  "182be1bddd5d5983f8f55c0859b1004214bcee6ec545f2c034c1d77b04",
].join("");

// D4_carol_epoch1_seq1 expected.unit_id
export const D4_ID = ["9b0c864dbee938ab1f0a106d32947004c7bb444d2924211fede31f8bcf411743"].join("");

// D4_carol_epoch1_seq1 expected.payload_cbor
export const D4_PAYLOAD = [
  "a7005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410101025820a6e402657a505a",
  "183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48030104f6055820e67fb23dc530252680216aecfeadb095",
  "1b1d3f8726c49afefd724b182dddc51806582c4dd85825362439c8e0cc06be7de0a147073dfa0869091441ec2830928f",
  "f8e13873145f9f61ad1cd487e7ea81",
].join("");

// SNAPSHOT-02 expected.cose_sign1
export const SNAPSHOT_02_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058eca7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820e67fb23dc530252680216aecfeadb0951b1d3f8726c4",
  "9afefd724b182dddc5180582a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5",
  "0118640281821869186ba2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da480101",
  "065825a4c0b8bc8173d8df3ebc22780f532125084f7008ce7e70f4bcdc9d1d3b4c4e78c2d571aff758400e6a3d82ee21",
  "7cc341f97d28b01a085dbaa6b99f24e18fc77313efc6fa6696f912fde473ba435f63689b7f3c8efba82599137316e33f",
  "5a120495e48eecbbe40c",
].join("");

// SNAPSHOT-02 expected.snapshot_id
export const SNAPSHOT_02_ID = [
  "5a4f0652181f0cb04eecf9e91e488e7f4052d3b406f2f7503911459084048750",
].join("");

// SNAPSHOT-02 expected.payload_cbor
export const SNAPSHOT_02_PAYLOAD = [
  "a7005820c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274",
  "bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820e67fb23dc530252680216aecfeadb0951b1d",
  "3f8726c49afefd724b182dddc5180582a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb78",
  "8bf0a9c50118640281821869186ba2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282",
  "da480101065825a4c0b8bc8173d8df3ebc22780f532125084f7008ce7e70f4bcdc9d1d3b4c4e78c2d571aff7",
].join("");

// noncanonical_aad_D1 inputs.cose_sign1
export const NONCANONICAL_AAD_D1 = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a05899a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5030104f6055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1",
  "f0687ed06a036656e41594b80658266e3daad24229f9d890fc1eabe054c0dd46b45804aead8c23b6b8e66403566f94fa",
  "11126cfd785840ceb668343f6ca82263e057b75390bf93030f4e7b1e58e4c5de885f029f93e8f59996e45b6cc658560e",
  "4156042fe995290f6be0d99371083bb45f0255d12e7e09",
].join("");

// aead_failure_D1 inputs.cose_sign1
export const AEAD_FAILURE_D1 = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a05899a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5030104f6055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1",
  "f0687ed06a036656e41594b80658266e3daad24229f9d890fc1eabe054c0dd46b45804aeadfa4c94672f853eab1f5857",
  "8e579f6ccc58409fffb58d10720976aa661d2f00f908ba7e2e518afed45e024dc0acb04c99d488244f9d548f49ac11a6",
  "1645c4c8ffd545394112c92dd47860daae68f074ad8c02",
].join("");

// control_fork_C6 inputs.cose_sign1
export const CONTROL_FORK_C6 = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058bfa6005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101060258201189b7d19ac6d09a8128d3",
  "967a4fdd80ea2a6180efaa8a9f15bf2ee5c32cda4603040458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95f",
  "f8e9cedbeb788bf0a9c505a4000101582027df3173462d19512f2224f54bdc894a8c7e81c212301ed1f2bb8ccee0ce71",
  "510281a20058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c501030303584067a145",
  "8144801485ceaea71dbab2ae346f350cceb7c93c8cd61ada0c0f08441645843a8b91e9f0cdf79929eedddbb53eccff4e",
  "b264edd632959e55782332790d",
].join("");

// actor_seq_zero_D1 inputs.cose_sign1
export const ACTOR_SEQ_ZERO_D1 = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a05899a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5030004f6055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1",
  "f0687ed06a036656e41594b8065826aeaeda7927384999a4de8d68689695ee07c6f89482faed18c8068d2f16e2104800",
  "28d255c2f75840e4e3fa3176ec8e4616e14063468843d7b7145a15219f93eadc0a92ee6a5a04e46e10abb96b1a6294a5",
  "dc90959e0a0c1dde00b5d61c9559b183a8f389b18e9904",
].join("");

// actor_seq1_prev_not_null_D1 inputs.cose_sign1
export const ACTOR_SEQ1_PREV_NOT_NULL_D1 = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058baa7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c503010458207745a3beb83838797591a1121e932799a5fb28b83890",
  "a3a9377f6c0d5cc34cd1055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594b8065826",
  "6e3daad24229f9d890fc1eabe054c0dd46b45804aead80cdbeebbca9afb5a1272381cde6b1615840e443e2635d7f965a",
  "a219b447656a69cd313e1eacbecd2e52bad5b1f0188c8b2c2e24d79c0eb07866c67a6b249e6a845c3ecb335ed59f8ad2",
  "1449c7fdc85bcb04",
].join("");

// hpke_recipient_mismatch_KP0 inputs.cose_sign1
export const HPKE_RECIPIENT_MISMATCH_KP0 = [
  "845826a20127045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121da058e5a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410100025820a6e402657a505a183a2c26",
  "85ecc3a0457fef86d4e251abd48efe943c1282da480358200b5dc558b8104686d5d6b0063629f1cfaf48049dee3580ca",
  "6e253d27f3359e33045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121d05582090ca",
  "4ed22f5b693d842711cd8c3d692e1002a3a84730926abd4e3eed9342ee0a065830e7a2257711c7244d0f333986ceab7b",
  "aabdace14b42d179d3768648c535b3abed0ca41207be0e7157c31d6c073106e03758408802ca1c0b3a00ed98f3550c67",
  "9e1e2d9a0d18b0b96075717cb31365c93f6e928642bb9bbc43cb7e1732172ebf5b90cbe2964d1f646aa0b5b76f120fa5",
  "99c003",
].join("");

// have_empty_extra_list inputs.cose_sign1
export const HAVE_EMPTY_EXTRA_LIST = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058e6a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50301045820e67fb23dc530252680216aecfeadb0951b1d3f8726c4",
  "9afefd724b182dddc5180582a20058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5",
  "0102a3005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da4801010280065825826d0c",
  "f4f6208b1daa2c8f0589916e0e7c68103ca43327922202cada2e6d19bb677f9ace7f5840c39f66939c22c25f314e4413",
  "205b9e6f5cb73418b84b7a293a4dddec7d1fc2ada7c3e7de030e06de5282447b59838f8b955ca5a16a5d7c631abeacd6",
  "9543e804",
].join("");

// have_range_reversed inputs.cose_sign1
export const HAVE_RANGE_REVERSED = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058eca7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820e67fb23dc530252680216aecfeadb0951b1d3f8726c4",
  "9afefd724b182dddc5180582a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5",
  "011864028182186b1869a2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da480101",
  "065825a4c0b8bc8173d8df3ebc22780f532125084f7008cea757160cd39be158c48d75bee9e62f62584083d027013085",
  "25858406d1ba90699cf94a043e4b82eb6ee627bc2a8d1dc3a350573ac1494e5bde8577eca8ca8782d753e3b0837269bc",
  "c655677cb30e1b573901",
].join("");

// have_range_not_above_contiguous inputs.cose_sign1
export const HAVE_RANGE_NOT_ABOVE_CONTIGUOUS = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058eca7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820e67fb23dc530252680216aecfeadb0951b1d3f8726c4",
  "9afefd724b182dddc5180582a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5",
  "011864028182185f186ba2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da480101",
  "065825a4c0b8bc8173d8df3ebc22780f532125084f7008ce1993e653ff3e6c47421d7ca5750bcd7c584010f1f96b4fe7",
  "38dd5e9fd330ba49079d375243a3273ea604d27b6d1605f547965f959d7244ce486dd676ddf7da35b37fe2cad729bed2",
  "a33b9c6cc820d07e0705",
].join("");

// have_ranges_unsorted inputs.cose_sign1
export const HAVE_RANGES_UNSORTED = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058f1a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820e67fb23dc530252680216aecfeadb0951b1d3f8726c4",
  "9afefd724b182dddc5180582a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5",
  "011864028282186e1870821869186ba2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c12",
  "82da480101065825a4c0b8bc8173d8df3ebc22780f532125084f7008ce8eb51a5fa98d05fee976b8a7b1bb7ee05840b0",
  "aebf4ca511cb59476bc4fd9eb253e20037b2dbb9938a69ee5abf0a527ba44b2dafe326d7b1b1f77acde7573f8cd16978",
  "7c74dd4e873586c032de197f36c502",
].join("");

// have_ranges_overlapping inputs.cose_sign1
export const HAVE_RANGES_OVERLAPPING = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058f1a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820e67fb23dc530252680216aecfeadb0951b1d3f8726c4",
  "9afefd724b182dddc5180582a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5",
  "0118640282821869186b82186a186ea2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c12",
  "82da480101065825a4c0b8bc8173d8df3ebc22780f532125084f7008ce06c674da23c64da16c37ea04bb7faaf958408e",
  "deb4c1fba57b7a45baab536c503d402384fdc308d03187d6d4a4bd5f8b64c425a389bea6642e4604ecb524958ff49ce2",
  "6fc47ab6eb65793a7a1ad8e2d9340a",
].join("");

// have_ranges_adjacent inputs.cose_sign1
export const HAVE_RANGES_ADJACENT = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058f1a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820e67fb23dc530252680216aecfeadb0951b1d3f8726c4",
  "9afefd724b182dddc5180582a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5",
  "0118640282821869186b82186c186ea2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c12",
  "82da480101065825a4c0b8bc8173d8df3ebc22780f532125084f7008ce9ff8421b1f961400d3888abb0287f83b584072",
  "fb9cfc983227edf07424b793252c2734b5a29b8ed43beaec78df2013f6d59bcf5467443a2126dd77daf9ae11e33ce847",
  "ad913da8fe178f8710eb70ac104209",
].join("");

// frontier_duplicate_principal inputs.cose_sign1
export const FRONTIER_DUPLICATE_PRINCIPAL = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a059010aa70058",
  "20c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c",
  "56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50301045820e67fb23dc530252680216aecfeadb0951b1d3f8726",
  "c49afefd724b182dddc5180583a20058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9",
  "c50102a20058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50102a2005820a6e402",
  "657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da480101065825826d0cf4f6208b1daa2c8f058991",
  "6e0e7c68103ca42b8f1243055602078a9c90def2b345b158405c89c34cfc485bf4f4ad50d13f90b4f24e529e0d606123",
  "f670bfde1440c720608227c380d2a5283876991f6fb5ecdc791619400db9201a2175b6f654cea15e0e",
].join("");

// frontier_unsorted inputs.cose_sign1
export const FRONTIER_UNSORTED = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058e4a7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101010258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50301045820e67fb23dc530252680216aecfeadb0951b1d3f8726c4",
  "9afefd724b182dddc5180582a2005820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48",
  "0101a20058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50102065825826d0cf4f6",
  "208b1daa2c8f0589916e0e7c68103ca412d2680307b40bbe6a54ed77594fb38c584088fe24e01ac3686d83cb282e9ee3",
  "f02562f989f3df39c026b58d2403a61a96305a9cd69d48e65ffb71ea7317884f8680f732fa65bb75a2909afe1656cad7",
  "c50d",
].join("");

// stale_epoch_absent_actor inputs.cose_sign1
export const STALE_EPOCH_ABSENT_ACTOR = [
  "845826a20127045820a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48a0589fa7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc2410100025820a6e402657a505a183a2c26",
  "85ecc3a0457fef86d4e251abd48efe943c1282da48030104f6055820e67fb23dc530252680216aecfeadb0951b1d3f87",
  "26c49afefd724b182dddc51806582c0799992a22830a7795a36ac1d55e602ce79871deee577330216419ce71e44aa101",
  "4ca2efa24fb1b0fdc554755840ae4947fc9b1adfe571f7c826432c9a7316b8d6be5c694a4c336d590df66b71bb284d5c",
  "2107385908a18154b908b383efd0341d9c959f92161e468633724abc0b",
].join("");

// Published positives: signed object, object ID and payload.
export const POSITIVES = [
  { id: "C0_genesis", kind: "control_record", cose: C0_COSE, objectId: C0_ID, payload: C0_PAYLOAD },
  {
    id: "C1_grant_bob",
    kind: "control_record",
    cose: C1_COSE,
    objectId: C1_ID,
    payload: C1_PAYLOAD,
  },
  {
    id: "C2_invite_grant",
    kind: "control_record",
    cose: C2_COSE,
    objectId: C2_ID,
    payload: C2_PAYLOAD,
  },
  {
    id: "C3_invite_claim_carol",
    kind: "control_record",
    cose: C3_COSE,
    objectId: C3_ID,
    payload: C3_PAYLOAD,
  },
  {
    id: "C4_owner_transfer_commit",
    kind: "control_record",
    cose: C4_COSE,
    objectId: C4_ID,
    payload: C4_PAYLOAD,
  },
  {
    id: "C5_route_update",
    kind: "control_record",
    cose: C5_COSE,
    objectId: C5_ID,
    payload: C5_PAYLOAD,
  },
  {
    id: "C6_key_epoch_1",
    kind: "control_record",
    cose: C6_COSE,
    objectId: C6_ID,
    payload: C6_PAYLOAD,
  },
  {
    id: "KP0_bob_epoch0",
    kind: "key_package",
    cose: KP0_COSE,
    objectId: KP0_ID,
    payload: KP0_PAYLOAD,
  },
  {
    id: "KPI_invite_epoch0",
    kind: "key_package",
    cose: KPI_COSE,
    objectId: KPI_ID,
    payload: KPI_PAYLOAD,
  },
  {
    id: "KPC_carol_epoch1",
    kind: "key_package",
    cose: KPC_COSE,
    objectId: KPC_ID,
    payload: KPC_PAYLOAD,
  },
  {
    id: "D1_bob_epoch0_seq1",
    kind: "data_unit",
    cose: D1_COSE,
    objectId: D1_ID,
    payload: D1_PAYLOAD,
  },
  {
    id: "D2_bob_epoch0_seq2",
    kind: "data_unit",
    cose: D2_COSE,
    objectId: D2_ID,
    payload: D2_PAYLOAD,
  },
  {
    id: "D3_bob_epoch0_seq3_stale",
    kind: "data_unit",
    cose: D3_COSE,
    objectId: D3_ID,
    payload: D3_PAYLOAD,
  },
  {
    id: "D4_carol_epoch1_seq1",
    kind: "data_unit",
    cose: D4_COSE,
    objectId: D4_ID,
    payload: D4_PAYLOAD,
  },
  { id: "SNAPSHOT-01", kind: "snapshot", cose: S1_COSE, objectId: S1_ID, payload: S1_PAYLOAD },
  {
    id: "SNAPSHOT-02",
    kind: "snapshot",
    cose: SNAPSHOT_02_COSE,
    objectId: SNAPSHOT_02_ID,
    payload: SNAPSHOT_02_PAYLOAD,
  },
] as const;

// Every validation case with an inputs.cose_sign1: expected.disposition and expected.error.code.
export const NEGATIVES = [
  {
    id: "tampered_D1",
    kind: "data_unit",
    cose: TAMPERED_D1,
    disposition: "reject",
    code: "INVALID_SIGNATURE",
  },
  {
    id: "noncanonical_aad_D1",
    kind: "data_unit",
    cose: NONCANONICAL_AAD_D1,
    disposition: "reject",
    code: null,
  },
  {
    id: "tagged_cose_D1",
    kind: "data_unit",
    cose: TAGGED_COSE_D1,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "invalid_signature_D1",
    kind: "data_unit",
    cose: INVALID_SIGNATURE_D1,
    disposition: "reject",
    code: "INVALID_SIGNATURE",
  },
  {
    id: "wrong_kid_D1",
    kind: "data_unit",
    cose: WRONG_KID_D1,
    disposition: "reject",
    code: "INVALID_SIGNATURE",
  },
  {
    id: "aead_failure_D1",
    kind: "data_unit",
    cose: AEAD_FAILURE_D1,
    disposition: "reject",
    code: null,
  },
  {
    id: "control_fork_C6",
    kind: "control_record",
    cose: CONTROL_FORK_C6,
    disposition: "conflict",
    code: "CONTROL_CONFLICT",
  },
  {
    id: "actor_seq_zero_D1",
    kind: "data_unit",
    cose: ACTOR_SEQ_ZERO_D1,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "actor_seq1_prev_not_null_D1",
    kind: "data_unit",
    cose: ACTOR_SEQ1_PREV_NOT_NULL_D1,
    disposition: "report",
    code: null,
  },
  {
    id: "hpke_recipient_mismatch_KP0",
    kind: "key_package",
    cose: HPKE_RECIPIENT_MISMATCH_KP0,
    disposition: "reject",
    code: null,
  },
  {
    id: "have_empty_extra_list",
    kind: "snapshot",
    cose: HAVE_EMPTY_EXTRA_LIST,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "have_range_reversed",
    kind: "snapshot",
    cose: HAVE_RANGE_REVERSED,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "have_range_not_above_contiguous",
    kind: "snapshot",
    cose: HAVE_RANGE_NOT_ABOVE_CONTIGUOUS,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "have_ranges_unsorted",
    kind: "snapshot",
    cose: HAVE_RANGES_UNSORTED,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "have_ranges_overlapping",
    kind: "snapshot",
    cose: HAVE_RANGES_OVERLAPPING,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "have_ranges_adjacent",
    kind: "snapshot",
    cose: HAVE_RANGES_ADJACENT,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "frontier_duplicate_principal",
    kind: "snapshot",
    cose: FRONTIER_DUPLICATE_PRINCIPAL,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "frontier_unsorted",
    kind: "snapshot",
    cose: FRONTIER_UNSORTED,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
  {
    id: "stale_epoch_absent_actor",
    kind: "data_unit",
    cose: STALE_EPOCH_ABSENT_ACTOR,
    disposition: "quarantine",
    code: "STALE_DATA_EPOCH",
  },
  {
    id: "noncanonical_payload_D1",
    kind: "data_unit",
    cose: NONCANONICAL_PAYLOAD_D1,
    disposition: "reject",
    code: "MALFORMED_MESSAGE",
  },
] as const;

// owner_transfer expected.offer_cose_sign1
export const OFFER_COSE = [
  "845826a20127045820172d2fc24d2192ed5703279a49d5db9f7fe8935b0125093976f6e906cd80121da058c6a5005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc241015820c8c476e22f99108b17034bea13",
  "fd7ad7a66d5bc1f0687ed06a036656e41594b8020403a30058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95f",
  "f8e9cedbeb788bf0a9c50158201953f4ada1cb4e0f8662108152c82e7e074cbf4859c487461cbe41e5d623e3c2025820",
  "b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5aca7528fdd5eefb94f26c0450c4659b052b4850b974087b8aabc0",
  "456158402cc2b2e48c1366dc280cbd0d29eade8b4f6769245eb4b226bb29d434f35fedc5c6901cfd1081698fab7c82f1",
  "e25dfb8f657b25d9af0201762859030ac2f9740e",
].join("");

// owner_transfer expected.accept_cose_sign1
export const ACCEPT_COSE = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a0586aa3005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101582071c4b2d5833b2f4d66be935a85",
  "a36cb4467d6d8553c744adff30bbca55e8e06f0258203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedb",
  "eb788bf0a9c55840b9ae2075a208408bdcc649d40712caa000312d9117637a5d5d0be122a81228e5a6cb6ced17fc6414",
  "18d913abbbf8ebb152cb2eeb775c2df47a20b8ebe308e20a",
].join("");

// actor_equivocation inputs.conflicting_D2_cose
export const EQUIVOCATING_D2 = [
  "845826a201270458203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5a058baa7005820",
  "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc24101000258203ddf22ff145274bcc59c56",
  "ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50302045820708b5a5f1ab7b7c9146b3bd7e4902831aa6666913608",
  "502c13b1d32c3650be9f055820c8c476e22f99108b17034bea13fd7ad7a66d5bc1f0687ed06a036656e41594b8065826",
  "2c71204ff8a4a4c0e8c96a2dcf46e03207cc6c0de1cf4e0c05962ac3c9ada3a19ddfcf0c4e485840e66598f457853e4f",
  "73eba35fa2d36174b688c1477edbd693659d7dd1cc92b409fd06eb27fc1cf08d86f6b02c7c8043508ec976fe7cade50b",
  "aff0ea92efef570c",
].join("");

// descriptor_extra_field inputs.descriptor_cbor
export const DESCRIPTOR_EXTRA_FIELD = [
  "a40058203ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c50158201953f4ada1cb4e0f86",
  "62108152c82e7e074cbf4859c487461cbe41e5d623e3c2025820b5a22f5f5cbdc3a6f8742ec8b2bc9665d0170478bf5a",
  "ca7528fdd5eefb94f26c0340",
].join("");
