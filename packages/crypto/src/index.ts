/**
 * Cryptographic primitives for LFCP, as a thin wrapper over the audited
 * @noble libraries. No other package imports @noble directly.
 */
export const PACKAGE = "@openlfcp/crypto";

export { decryptDataUnit, encryptDataUnit } from "./aead.js";
export {
  ActorDataKey,
  dataUnitNonce,
  dekCommitment,
  deriveActorDataKey,
  deriveSnapshotKey,
  generateResourceDEK,
  importResourceDEK,
  ResourceDEK,
  SnapshotKey,
  snapshotNonce,
} from "./epoch.js";
export { sha256 } from "./hash.js";
export { hkdfExpand, hkdfExtract } from "./hkdf.js";
export { openDek, type SealedDek, sealDek } from "./hpke.js";
export {
  AgreementKeyPair,
  exportSecretKeyBytes,
  generateAgreementKeyPair,
  generateSigningKeyPair,
  importAgreementKey,
  importSigningKey,
  isValidEd25519PublicKey,
  SigningKeyPair,
  verifyEd25519,
} from "./keys.js";
