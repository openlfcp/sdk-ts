// The IdentityDocumentPort of @openlfcp/client over @openlfcp/shared-objects'
// IdentityReplica: how an application wires the identity flows to the real
// Identity Resource document (IDENTITY-PROFILE-01 §§2–4).

import type { IdentityAuthor, IdentityDocumentPort, IdentityIntent } from "@openlfcp/client";
import type { PrincipalId, ResourceId } from "@openlfcp/core";
import {
  IdentityReplica,
  identityCodec,
  type IdentityIntent as ReplicaIntent,
} from "@openlfcp/shared-objects/identity";

export function replicaPort(
  resource: ResourceId,
  root: PrincipalId,
): IdentityDocumentPort & { readonly replica: () => IdentityReplica } {
  const replica = IdentityReplica.empty({ resource, root });
  const writer = (a: IdentityAuthor) => ({
    signer: a.signer,
    actorSeq: a.actorSeq,
    writerClass: a.writerClass,
  });
  const map = <T>(o: Readonly<Record<string, T>>) => new Map(Object.entries(o));
  return {
    replica: () => replica,
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
  };
}
