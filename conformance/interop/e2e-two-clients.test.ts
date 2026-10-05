// LFCP-056: the canonical two-client secure network E2E, SDK-driven. Two
// TypeScript clients (SyncClient) and the Rust reference server, over real
// LFCP WebSocket sessions, through the backlog's list in order:
//
//  1. Alice and Bob initialize their own Principals (fresh random keys).
//  2. Alice creates a Shared Objects Resource (random ID, epoch-0 DEK,
//     Genesis) and hosts it: RESOURCE_HOST → RESOURCE_HOSTED.
//  3. Alice invites; Bob, who has no grant and is not known to the server,
//     claims the invitation (LFCP-053) and gets the DEK through HPKE.
//  4. Alice → Bob and Bob → Alice: encrypted, signed Task changes, live.
//  5. Bob disconnects; Alice changes the Task twice; Bob reconnects and
//     catches up with a Have-driven DATA_GET (not a live push).
//  6. Both replicas converge to the same state and conflict sets.
//  7. Exact bytes: every Data Unit Alice created is, byte for byte, what
//     Bob stored, what the server sent him, and what the server persisted.
//  8. Opaqueness: no Task title, no Task status, and a private marker that
//     never enters a Task (§71) occur in any LFCP message either client
//     sent or received, in any server file (database, WAL, SHM, …) or in
//     the server log; nor do the DEK or any private key bytes. Protocol
//     metadata (IDs, sequences, epochs, sizes) is not claimed hidden.
//
// The server is the real binary the harness builds and starts (shared cargo
// target). Skipped when cargo or the server checkout is missing, unless
// LFCP_REQUIRE_LIVE=1.

import { acceptInvitation, createInvitation } from "@openlfcp/client";
import { generateResourceId, type ObjectId, toBase64url, toHex } from "@openlfcp/core";
import {
  exportSecretKeyBytes,
  generateAgreementKeyPair,
  generateResourceDEK,
  generateSigningKeyPair,
} from "@openlfcp/crypto";
import {
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setStatus,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import { InMemoryLfcpStorage, InMemorySecretStore } from "@openlfcp/storage";
import { principalDescriptorFromKeys } from "@openlfcp/wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createResource, type Party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";
import { containsBytes, WireTap } from "./wire-tap.js";

declare const console: { warn(...a: unknown[]): void };

const utf8 = (s: string) => new TextEncoder().encode(s);
/** A fresh, independently generated Principal (no seed shared with anything). */
const fresh = (): Party => {
  const key = generateSigningKeyPair();
  const agreement = generateAgreementKeyPair();
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};
const marker = `lfcp056-${toHex(generateSigningKeyPair().publicKey).slice(0, 12)}`;
const TITLES = [1, 2, 3, 4].map((i) => `${marker} title ${i}`);
const STATUSES = [1, 2, 3].map((i) => `x/com.example.lfcp056/${marker}-status-${i}`);
/** A string that never enters any Task: it lives only in Alice's local labels. */
const PRIVATE = `${marker} private note, never shared`;

let server: RunningRustServer | undefined;
let skip: string | undefined;

beforeAll(async () => {
  const started = await startRustServer();
  if ("skip" in started) skip = started.skip;
  else server = started;
}, 600_000);

afterAll(async () => {
  await server?.stop();
});

describe("LFCP-056: two headless clients ↔ Rust reference server (live)", () => {
  it("joins securely, replicates both ways, catches up by Have, converges, and keeps the server opaque", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: LFCP-056 (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    const stage = { now: "setup" };
    const sides: Side[] = [];
    const R = generateResourceId();
    try {
      // 1-2. Alice: Principal, Resource, Genesis, host.
      stage.now = "create and host";
      const alice = fresh();
      const bob = fresh();
      const dek = generateResourceDEK();
      const aliceTap = new WireTap();
      const { replica, change: init } = SharedObjectsReplica.create({
        resource: R,
        principal: alice.signer.descriptor.principalId,
      });
      const A = new Side({
        url,
        resource: R,
        who: alice,
        profile: new SharedObjectsDataProfile(replica),
        webSocket: aliceTap.factory,
        snapshots: false,
      });
      sides.push(A);
      const genesis = await createResource(A, url, dek);
      // A private local label: stored on Alice's side only.
      await A.storage.commit([
        {
          op: "put-resource",
          row: {
            resourceId: R,
            dataProfile: "org.openlfcp.shared-objects.v1",
            localPrincipal: null,
            labels: { note: PRIVATE },
          },
        },
      ]);
      await A.write(init);
      A.start({ open: false });
      await waitFor("Alice READY", () => A.client.connectionState === "READY");
      await A.client.host(genesis.bytes);
      A.open();
      await waitFor("Alice LIVE", () => A.client.resourceState(R) === "LIVE");
      expect(aliceTap.messages("HELLO", "out")).toHaveLength(1);
      expect(aliceTap.messages("AUTH", "out")).toHaveLength(1);
      expect(aliceTap.messages("RESOURCE_HOSTED", "in")).toHaveLength(1);

      // 3. Invitation and claim (Bob is unknown to the server until his claim).
      stage.now = "invite and claim";
      const invitation = await createInvitation({
        storage: A.storage,
        resourceId: R,
        inviter: alice.signer,
        dek,
        endpoints: [url],
      });
      A.client.flush();
      await waitFor("the invitation is ACKed", () => A.queueEmpty());
      const bobTap = new WireTap();
      const bobStorage = new InMemoryLfcpStorage();
      const bobSecrets = new InMemorySecretStore();
      const claimed = await acceptInvitation({
        link: invitation.link,
        claimant: bob,
        storage: bobStorage,
        secrets: bobSecrets,
        now: () => Date.now(),
        webSocket: bobTap.factory,
      });
      expect(claimed).toMatchObject({ kind: "claimed", attempts: ["ACK"] });
      const B = new Side({
        url,
        resource: R,
        who: bob,
        profile: new SharedObjectsDataProfile(
          SharedObjectsReplica.empty({ resource: R, principal: bob.signer.descriptor.principalId }),
        ),
        storage: bobStorage,
        secrets: bobSecrets,
        webSocket: bobTap.factory,
        snapshots: false,
      });
      sides.push(B);
      B.start();
      await waitFor("Bob LIVE", () => B.client.resourceState(R) === "LIVE");

      // 4. Alice → Bob, Bob → Alice.
      stage.now = "replicate";
      const created = createTask({
        title: TITLES[0] as string,
        createdBy: alice.signer.descriptor.principalId,
      });
      const ID = created.task.id as ObjectId;
      await A.write(A.profile.replica.apply(created.intent) as LocalChange);
      await waitFor(
        "Bob sees Alice's Task",
        () => B.profile.replica.task(ID)?.task?.title === TITLES[0],
      );
      const bt = B.profile.replica.task(ID)?.task as Task;
      await B.write(
        B.profile.replica.apply(setTitle(bt, TITLES[1] as string).intent) as LocalChange,
      );
      await B.write(
        B.profile.replica.apply(
          setStatus(B.profile.replica.task(ID)?.task as Task, STATUSES[0] as never).intent,
        ) as LocalChange,
      );
      await waitFor(
        "Alice sees Bob's edits",
        () =>
          A.profile.replica.task(ID)?.task?.title === TITLES[1] &&
          A.profile.replica.task(ID)?.task?.status === STATUSES[0],
      );

      // 5. Bob offline; Alice changes twice; Bob catches up with Have + DATA_GET.
      stage.now = "offline and catch-up";
      await waitFor("Bob's edits ACKed", () => B.queueEmpty());
      await B.stop();
      const getsBefore = bobTap.messages("DATA_GET", "out").length;
      const at = () => A.profile.replica.task(ID)?.task as Task;
      await A.write(
        A.profile.replica.apply(setTitle(at(), TITLES[2] as string).intent) as LocalChange,
      );
      await A.write(
        A.profile.replica.apply(setStatus(at(), STATUSES[1] as never).intent) as LocalChange,
      );
      await A.write(
        A.profile.replica.apply(setTitle(at(), TITLES[3] as string).intent) as LocalChange,
      );
      await A.write(
        A.profile.replica.apply(setStatus(at(), STATUSES[2] as never).intent) as LocalChange,
      );
      await waitFor("Alice's offline-period edits ACKed", () => A.queueEmpty());
      B.start();
      await waitFor("Bob caught up", () => B.profile.replica.task(ID)?.task?.title === TITLES[3]);
      const gets = bobTap.messages("DATA_GET", "out").slice(getsBefore);
      expect(gets.length).toBeGreaterThan(0);
      const alicePrincipal = toHex(alice.signer.descriptor.principalId);
      expect(
        gets.some(
          (f) =>
            f.message?.type === "DATA_GET" &&
            f.message.body.ranges.some((r) => toHex(r.actor) === alicePrincipal),
        ),
      ).toBe(true);

      // 6. Convergence.
      stage.now = "convergence";
      await waitFor(
        "convergence",
        () => JSON.stringify(A.profile.replica.root()) === JSON.stringify(B.profile.replica.root()),
      );
      expect(B.profile.replica.conflicts()).toEqual(A.profile.replica.conflicts());
      expect(B.profile.replica.task(ID)?.task?.status).toBe(STATUSES[2]);

      // 7. Exact bytes: Alice's units = Bob's stored = what Bob received = what the server persisted.
      stage.now = "exact bytes";
      const aliceUnits = await A.storage.dataUnits.range(
        R,
        alice.signer.descriptor.principalId,
        1n as never,
        (2n ** 64n - 1n) as never,
      );
      expect(aliceUnits.length).toBe(6); // init, create, 4 offline-period edits
      const received = [
        ...bobTap.messages("DATA_BATCH", "in"),
        ...bobTap.messages("DATA_PUT", "in"),
      ].flatMap((f) =>
        f.message?.type === "DATA_BATCH" || f.message?.type === "DATA_PUT"
          ? f.message.body.objects
          : [],
      );
      const files = server.files();
      const persisted = (bytes: Uint8Array) => files.some((f) => containsBytes(f.bytes, bytes));
      for (const u of aliceUnits) {
        const atBob = await bobStorage.dataUnits.get(u.unitId);
        expect(toHex(atBob?.bytes ?? new Uint8Array())).toBe(toHex(u.bytes));
        expect(received.some((r) => toHex(r) === toHex(u.bytes))).toBe(true);
        expect(persisted(u.bytes)).toBe(true);
      }

      // 8. Opaqueness: plaintext never on the wire, on the server, or in its log.
      stage.now = "opaqueness";
      const secrets = [
        ...[...TITLES, ...STATUSES, PRIVATE].map((s) => ({ what: s, bytes: utf8(s) })),
        { what: "the DEK", bytes: exportSecretKeyBytes(dek) },
        { what: "Alice's signing key", bytes: exportSecretKeyBytes(alice.signer.key) },
        { what: "Alice's agreement key", bytes: exportSecretKeyBytes(alice.agreement) },
        { what: "Bob's signing key", bytes: exportSecretKeyBytes(bob.signer.key) },
        { what: "Bob's agreement key", bytes: exportSecretKeyBytes(bob.agreement) },
      ];
      const wire = [...aliceTap.frames, ...bobTap.frames];
      expect(wire.length).toBeGreaterThan(20);
      const log = utf8(server.log());
      const leaks: string[] = [];
      for (const s of secrets) {
        for (const f of wire)
          if (containsBytes(f.bytes, s.bytes))
            leaks.push(`${s.what} in a ${f.message?.type ?? "?"} message (${f.direction})`);
        for (const f of files)
          if (containsBytes(f.bytes, s.bytes)) leaks.push(`${s.what} in server file ${f.path}`);
        if (containsBytes(log, s.bytes)) leaks.push(`${s.what} in the server log`);
      }
      expect(leaks).toEqual([]);
      // Positive control: the scan finds what is NOT claimed hidden (§71): metadata such
      // as Alice's Principal ID is on the wire and in the server's files.
      const aliceId = alice.signer.descriptor.principalId;
      expect(wire.some((f) => containsBytes(f.bytes, aliceId))).toBe(true);
      expect(files.some((f) => containsBytes(f.bytes, aliceId))).toBe(true);
      // The invitation secret never travels: no message carries the link's fragment.
      const fragment = utf8(invitation.link.reveal().split("#secret=")[1] as string);
      expect(wire.filter((f) => containsBytes(f.bytes, fragment))).toEqual([]);
      expect(files.some((f) => f.path.length > 0)).toBe(true);
      expect(A.errors()).toEqual([]);
      expect(B.errors()).toEqual([]);
    } catch (e) {
      throw new Error(
        `stage "${stage.now}", Resource ${toBase64url(R)}: ${e instanceof Error ? e.message : String(e)}\n` +
          `--- server log (tail) ---\n${server.log().slice(-3000)}`,
      );
    } finally {
      for (const s of sides) await s.stop();
    }
  }, 180_000);
});
