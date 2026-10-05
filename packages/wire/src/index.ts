/** Name of this package. */
export const PACKAGE = "@openlfcp/wire";

export {
  COSE_ALG_EDDSA,
  objectId,
  parseSignedObject,
  type SignedBytes,
  type SignedObject,
  type Signer,
  signObject,
  sigStructureBytes,
  type VerifyResult,
  verifySignedObject,
} from "./cose.js";
export { type Endpoint, endpointFromCbor } from "./endpoint.js";
export {
  type ActorHave,
  actorHaveFromCbor,
  canonicalFrontierFromCbor,
  type SequenceRange,
} from "./have.js";
export {
  CONTROL_TYPE,
  type ControlRecordPayload,
  controlRecordPayloadFromCbor,
  type DataUnitPayload,
  dataUnitPayloadFromCbor,
  decodeControlRecordPayload,
  decodeDataUnitPayload,
  decodeKeyPackagePayload,
  decodeSnapshotPayload,
  expectedSignerOf,
  type KeyPackagePayload,
  keyPackagePayloadFromCbor,
  type Parsed,
  parseControlRecord,
  parseDataUnit,
  parseKeyPackage,
  parseSnapshot,
  type SnapshotPayload,
  snapshotPayloadFromCbor,
} from "./objects.js";
export {
  decodePrincipalDescriptor,
  derivePrincipalId,
  encodePrincipalDescriptor,
  type PrincipalDescriptor,
  principalDescriptor,
  principalDescriptorFromCbor,
  principalDescriptorFromKeys,
  principalDescriptorToCbor,
} from "./principal.js";
