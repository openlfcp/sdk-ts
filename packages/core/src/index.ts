/** Name of this package. */
export const PACKAGE = "@openlfcp/core";

export { bytesEqual, fromBase64url, fromHex, toBase64url, toHex } from "./bytes.js";
export { LfcpError, type LfcpErrorCode } from "./errors.js";
export {
  type ControlRecordId,
  compareCanonicalFrontierOrder,
  controlRecordId,
  type DataUnitId,
  dataUnitId,
  generateResourceId,
  type Hash32,
  hash32,
  ID32_LENGTH,
  idEquals,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
} from "./ids.js";
export {
  formatObjectId,
  type GenerateObjectIdOptions,
  generateObjectId,
  isObjectId,
  type ObjectId,
  parseObjectId,
} from "./object-id.js";
export {
  type ActorSequence,
  actorSequence,
  type DataEpoch,
  dataEpoch,
  UINT64_MAX,
  uint64BE,
} from "./uint64.js";
