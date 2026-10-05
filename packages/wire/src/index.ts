/** Name of this package. */
export const PACKAGE = "@openlfcp/wire";

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
