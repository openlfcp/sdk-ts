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
