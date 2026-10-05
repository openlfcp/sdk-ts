import {
  type AgreementKeyPair,
  generateAgreementKeyPair,
  generateSigningKeyPair,
  type SigningKeyPair,
} from "./keys.js";

/**
 * The key material of an Invitation Principal (LFCP-WIRE-01 §18, §18.2):
 * the ephemeral Principal an inviter creates for one invitation, whose
 * private keys travel in the `#secret=` fragment of a bearer invitation
 * URI.
 *
 * Like every key in this package, it is redacted: `toJSON`, `toString`
 * and Node's inspect hook print "[redacted]", and the two key pairs it
 * holds are redacted themselves. The secret is encoded only by the
 * invitation codec of @openlfcp/wire, for the URI fragment. §18.2: it MUST
 * NOT be logged, placed in analytics or transmitted to a synchronization
 * server.
 */
export class InvitationSecret {
  readonly #signing: SigningKeyPair;
  readonly #agreement: AgreementKeyPair;

  private constructor(signing: SigningKeyPair, agreement: AgreementKeyPair) {
    this.#signing = signing;
    this.#agreement = agreement;
  }

  /** A fresh Invitation Principal: independent Ed25519 and X25519 keys from the platform CSPRNG. */
  static generate(): InvitationSecret {
    return new InvitationSecret(generateSigningKeyPair(), generateAgreementKeyPair());
  }

  /** An Invitation Principal from its key pairs (for example, decoded from a URI fragment). */
  static fromKeys(signing: SigningKeyPair, agreement: AgreementKeyPair): InvitationSecret {
    return new InvitationSecret(signing, agreement);
  }

  /** The Ed25519 key pair: signs the CAPABILITY_CLAIM record (§18.1). */
  get signingKey(): SigningKeyPair {
    return this.#signing;
  }

  /** The X25519 key pair: opens the Key Package sealed to the Invitation Principal (§18, §25). */
  get agreementKey(): AgreementKeyPair {
    return this.#agreement;
  }

  toJSON(): string {
    return "[redacted]";
  }

  toString(): string {
    return "[redacted]";
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "[redacted]";
  }
}
