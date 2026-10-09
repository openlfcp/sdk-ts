import type { LocalStateCipher } from "@openlfcp/storage";

/**
 * A stand-in for @openlfcp/crypto's localStateCipher, with the envelope's
 * shape and bindings (key, AAD, generation) and NO cryptography: the
 * storage packages may not depend on @openlfcp/crypto (LFCP-014). The real
 * cipher is tested in @openlfcp/crypto, and end to end, with canaries in
 * the database files, in conformance/storage.
 */
let nextKey = 0;
const same = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);
export const standInCipher: LocalStateCipher<number> = {
  generateKey: () => ++nextKey,
  importKey: (bytes) => new DataView(bytes.buffer, bytes.byteOffset).getUint32(0),
  exportKey: (key) => {
    const out = new Uint8Array(32);
    new DataView(out.buffer).setUint32(0, key);
    return out;
  },
  seal: (key, generation, aad, plaintext) => {
    const out = new Uint8Array(12 + 4 + aad.length + plaintext.length + 16);
    const view = new DataView(out.buffer);
    out.set([0x6c, 0x73, 0x65, 0x31]);
    view.setUint32(4, generation);
    view.setUint32(8, key);
    view.setUint32(12, aad.length);
    out.set(aad, 16);
    out.set(plaintext, 16 + aad.length);
    return out;
  },
  open: (key, aad, envelope) => {
    const view = new DataView(envelope.buffer, envelope.byteOffset);
    const length = view.getUint32(12);
    if (view.getUint32(8) !== key || !same(envelope.subarray(16, 16 + length), aad))
      throw new Error("does not authenticate");
    return envelope.slice(16 + length, envelope.length - 16);
  },
  isSealed: (bytes) => bytes.length >= 32 && bytes[0] === 0x6c && bytes[3] === 0x31,
  generationOf: (bytes) =>
    standInCipher.isSealed(bytes)
      ? new DataView(bytes.buffer, bytes.byteOffset).getUint32(4)
      : undefined,
};
