/**
 * Low-level deterministic CBOR for LFCP-WIRE-01 §5.2.
 *
 * This is a building block for COSE, Wire structures and vectors; it is not
 * the LFCP API. Import it from `@openlfcp/wire/cbor`.
 */
export { decodeStrict, isDeterministic } from "./decode.js";
export { compareEncodedKeys, encode } from "./encode.js";
export {
  type CborKey,
  type CborMap,
  type CborValue,
  cborMap,
  isCborMap,
  MAX_DEPTH,
} from "./value.js";
