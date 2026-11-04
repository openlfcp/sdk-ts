import { pairingDeviceSigner, parsePairingUri } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import {
  fetchDeks,
  loadIdentityDocument,
  sealIdentityUnit,
  syncChain,
} from "../../src/identity/context.js";
import { principalRefOf } from "../../src/identity/document.js";
import { OperationJournal } from "../../src/identity/journal.js";
import {
  approvePairing,
  createPairingSession,
  pairingRequests,
} from "../../src/identity/pairing.js";
import { requestPairing } from "../../src/identity/pairing-request.js";
import { party, URL } from "./support.js";
import { node, world } from "./world.js";

describe("the request a managing device reviews (IDENTITY-PROFILE-01 §5.3 step 4)", {
  timeout: 60_000,
}, () => {
  test("a request changed after the review asks for confirmation again (11.4)", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    const B = node(w.server, party(3));
    await requestPairing({ ...B, link: s.link, label: "phone", kind: 0 });
    const [review] = await pairingRequests({ ...w.P, session: s.session });
    if (review === undefined) throw new Error("no review");
    expect(review.requestChanges.length).toBe(1);
    // J rewrites only requested_at: the listed fields are equal, the change is not.
    const J = pairingDeviceSigner(parsePairingUri(s.link.reveal()));
    const channel = await w.server.network().connect(J, URL);
    const chain = await syncChain(B.storage, channel, w.I);
    const pairing = { signer: J, agreement: parsePairingUri(s.link.reveal()).secret.agreementKey };
    const deks = await fetchDeks(B.storage, B.secrets, channel, chain, pairing);
    const doc = B.document(w.I, party(1).signer.descriptor.principalId);
    const load = await loadIdentityDocument({ channel, chain, deks, doc });
    const key = principalRefOf(party(3).signer.descriptor.principalId);
    const entry = doc.requests().get(key);
    if (entry === undefined) throw new Error("no entry");
    const bytes = await sealIdentityUnit({
      storage: B.storage,
      chain,
      deks,
      signer: J,
      doc,
      latest: load.latest,
      seq: 2n,
      intents: [
        { intent: "request.put", key, entry: { ...entry, requested_at: "2026-11-04T10:00:00Z" } },
      ],
    });
    expect((await channel.putDataUnit(w.I, bytes)).kind).toBe("ack");
    const r = await approvePairing({ ...w.P, review, preset: "edit" });
    expect(r.kind).toBe("reconfirm");
    const fresh = r.kind === "reconfirm" ? r.review : undefined;
    expect(fresh?.requestChanges.length).toBe(2);
    const approved = await approvePairing({ ...w.P, review: fresh as never, preset: "edit" });
    expect(approved.kind).toBe("approved");
    const op = (await new OperationJournal(w.P.storage).list({ kind: "pairing-approval" }))[0];
    expect(op?.intent.requestChanges).toEqual(fresh?.requestChanges);
  });
  test("a request entry written by another device than the session's is never shown (11.3)", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    // The root writes a request naming J: it is not J's.
    const channel = await w.server.network().connect(w.P.installation.signer, URL);
    const chain = await syncChain(w.P.storage, channel, w.I);
    const deks = await fetchDeks(w.P.storage, w.P.secrets, channel, chain, w.P.installation);
    const doc = w.P.document(w.I, party(1).signer.descriptor.principalId);
    const load = await loadIdentityDocument({ channel, chain, deks, doc });
    const B = party(3).signer.descriptor;
    const { encodePrincipalDescriptor } = await import("@openlfcp/wire");
    const { toBase64url } = await import("@openlfcp/core");
    const bytes = await sealIdentityUnit({
      storage: w.P.storage,
      chain,
      deks,
      signer: w.P.installation.signer,
      doc,
      latest: load.latest,
      intents: [
        {
          intent: "request.put",
          key: principalRefOf(B.principalId),
          entry: {
            descriptor: toBase64url(encodePrincipalDescriptor(B)),
            pairing: principalRefOf(s.pairingDevice),
            label: "forged",
            kind: 0,
          },
        },
      ],
    });
    expect((await channel.putDataUnit(w.I, bytes)).kind).toBe("ack");
    expect(await pairingRequests({ ...w.P, session: s.session })).toEqual([]);
  });
});
