// The Identity Resource document (IDENTITY-PROFILE-01 §§2–4) for the
// headless identity flows: @openlfcp/client's IdentityDocumentPort over
// @openlfcp/shared-objects' IdentityReplica, the same document every
// identity-aware client reads and writes.

import type {
  IdentityAuthor,
  IdentityDocumentFactory,
  IdentityDocumentPort,
  IdentityIntent,
} from "@openlfcp/client";
import type { PrincipalId, ResourceId } from "@openlfcp/core";
import {
  IdentityReplica,
  identityCodec,
  type IdentityIntent as ReplicaIntent,
} from "@openlfcp/shared-objects/identity";

/** A fresh document of Identity Resource `resource` owned by `root`, for one flow. */
export const identityDocument: IdentityDocumentFactory = (
  resource: ResourceId,
  root: PrincipalId,
): IdentityDocumentPort => {
  const replica = IdentityReplica.empty({ resource, root });
  const writer = (a: IdentityAuthor) => ({
    signer: a.signer,
    actorSeq: a.actorSeq,
    writerClass: a.writerClass,
  });
  const map = <T>(o: Readonly<Record<string, T>>) => new Map(Object.entries(o));
  return {
    write: (author, intents: readonly IdentityIntent[]) =>
      identityCodec.encode(replica.write(writer(author), intents as readonly ReplicaIntent[])),
    receive: (plaintext, author) => {
      const r = replica.receive(plaintext, writer(author));
      return r.admitted.length + r.duplicates.length > 0;
    },
    initialized: () => replica.validate().usable && replica.heads().length > 0,
    roster: () => map(replica.validate().roster),
    devices: () => map(replica.validate().devices) as never,
    requests: () => map(replica.validate().requests),
    origins: (table, key) => replica.origins(table, key),
    // §7.1 step 4, §8.2: a retired entry's flag field by field, every concurrent value seen.
    retirement: {
      revokedValues: (key) => replica.fieldValues("devices", key, "revoked"),
      write: (author, intents, retire) =>
        identityCodec.encode(
          replica.write(writer(author), intents as readonly ReplicaIntent[], { retire }),
        ),
    },
    // §7.1 step 3, AI5 (0.5.2): the device's own missing_keys hint, no other field written.
    keyHints: {
      write: (author, hints) => identityCodec.encode(replica.write(writer(author), [], { hints })),
    },
  };
};
