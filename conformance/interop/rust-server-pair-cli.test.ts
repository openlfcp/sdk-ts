// LFCP-04-412: the headless `lfcp-node pair` of @openlfcp/storage-node, the
// service device of a bridge (IDENTITY-PROFILE-01 §5.3 "Headless
// installation", §12.4 scenario 3), against the Rust reference server at
// server.lock. The root P hosts Notes, Tasks and Mail and lists them in its
// Identity Resource; the command, given P's link on standard input, asks to
// join Notes and Tasks as a service device and prints its fingerprint; P
// sees the same fingerprint and the requested sections, removes Tasks and
// approves the Service preset. The command reports Notes ready and Tasks not
// granted and exits 0; the bridge opens Notes, and neither Mail nor I.
//
// The built CLI (packages/storage-node/dist/cli.js) runs as a child
// process, so `pnpm build` comes first. Skipped without a server unless
// LFCP_REQUIRE_LIVE=1; LFCP_SERVER_BIN runs a prebuilt server.

import {
  approvePairing,
  cancelPairing,
  createIdentityResource,
  createPairingSession,
  deviceIdentity,
  IdentityRefused,
  pairedResources,
  pairingRequests,
  syncChain,
} from "@openlfcp/client";
import { toHex } from "@openlfcp/core";
import { InMemoryLfcpStorage } from "@openlfcp/storage";
import {
  FileSecretStore,
  openInstallation,
  openNodeInstallation,
  PAIR_EXIT,
} from "@openlfcp/storage-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { waitFor } from "./harness.js";
import { hostResource, installation } from "./identity-live.js";
import { removeDir, startPairCli, stateDir } from "./pair-cli.mjs";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

let server: RunningRustServer | undefined;
let skip: string | undefined;
const dirs: string[] = [];

beforeAll(async () => {
  const started = await startRustServer();
  if ("skip" in started) skip = started.skip;
  else server = started;
}, 600_000);

afterAll(async () => {
  await server?.stop();
  for (const d of dirs) removeDir(d);
});

describe("lfcp-node pair against the Rust reference server", { timeout: 300_000 }, () => {
  it("pairs a service device for two named sections; the approver trims one; it prints its fingerprint and the result", async (ctx) => {
    if (server === undefined) return ctx.skip(`no reference server: ${skip}`);
    const url = server.url;
    const P = installation(51);
    const notes = await hostResource(P, url, "Notes");
    const tasks = await hostResource(P, url, "Tasks");
    const mail = await hostResource(P, url, "Mail");
    const created = await createIdentityResource({
      ...P,
      url,
      label: "laptop",
      roster: [notes, tasks, mail],
    });
    if (created.kind !== "created") throw new Error(JSON.stringify(created));
    const session = await createPairingSession(P);
    if (session.kind !== "created") throw new Error(JSON.stringify(session));

    const state = stateDir();
    dirs.push(state);
    const cli = startPairCli(
      [
        "-",
        "--state",
        state,
        "--label",
        "bridge",
        "--section",
        "Notes",
        "--section",
        "Tasks",
        "--wait",
        "120",
        "--poll",
        "1",
      ],
      session.link.reveal(),
    );
    try {
      // The request line comes after the fingerprint (two writes): wait for both.
      await waitFor("the request line", () => /Requested: .*\n/.test(cli.output()), 60_000);
      const shown = /Fingerprint: (\S+)/.exec(cli.output())?.[1];
      expect(cli.output()).toContain('"bridge" (service) asks to join Notes, Tasks');
      // The link is a bearer secret: it is never printed.
      expect(cli.output()).not.toContain("#secret=");

      let review: Awaited<ReturnType<typeof pairingRequests>>[number] | undefined;
      await waitFor(
        "the request on the managing device",
        async () => {
          [review] = await pairingRequests({ ...P, session: session.session });
          return review !== undefined;
        },
        60_000,
      );
      if (review === undefined) throw new Error("no request");
      expect(review.fingerprint).toBe(shown);
      expect(review.kind).toBe(1);
      expect(review.requestedScope.map(toHex).sort()).toEqual(
        [toHex(notes.resource), toHex(tasks.resource)].sort(),
      );
      // §5.3 step 4: the approver MAY remove Resources from a service scope.
      const approved = await approvePairing({
        ...P,
        review,
        preset: "service",
        scope: [notes.resource],
      });
      if (approved.kind !== "approved") throw new Error(JSON.stringify(approved));

      const exit = await cli.exited;
      expect([exit.code, cli.stderr()]).toEqual([PAIR_EXIT.DONE, ""]);
      expect(cli.output()).toContain("Approved: Service (service device).");
      expect(cli.output()).toContain("  Notes: ready");
      expect(cli.output()).toContain("  Tasks: not granted");
    } finally {
      await cli.kill();
    }

    // 504: the state directory lists what the pairing brought, offline.
    const node = await openNodeInstallation(state);
    try {
      expect((await node.storage.resources.list()).map((r) => toHex(r.resourceId))).toEqual([
        toHex(notes.resource),
      ]);
      expect(
        (await pairedResources(node))
          .map((p) => [p.name, p.ready, toHex(p.resource)])
          // In the request's order, which is the roster's: not fixed.
          .sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
      ).toEqual([
        ["Notes", true, toHex(notes.resource)],
        ["Tasks", false, toHex(tasks.resource)],
      ]);
      const me = await deviceIdentity(node);
      if (me?.kind !== "device") throw new Error(String(me?.kind));
      expect([me.deviceKind, me.mask, me.scope.map(toHex), me.label]).toEqual([
        1,
        [1n, 2n],
        [toHex(notes.resource)],
        "bridge",
      ]);
      expect(toHex(me.root)).toBe(toHex(P.installation.signer.descriptor.principalId));
    } finally {
      node.close();
    }

    // The bridge, with the installation the command created: Notes opens, Mail and I do not.
    const bridge = {
      ...installation(0),
      installation: await openInstallation(state, new FileSecretStore(`${state}/secrets`)),
      storage: new InMemoryLfcpStorage(),
    };
    const channel = await bridge.network.connect(bridge.installation.signer, url);
    try {
      const n = await syncChain(bridge.storage, channel, notes.resource);
      expect(n.state.head.length).toBe(32);
      await expect(syncChain(bridge.storage, channel, mail.resource)).rejects.toBeInstanceOf(
        IdentityRefused,
      );
      await expect(syncChain(bridge.storage, channel, created.identity)).rejects.toBeInstanceOf(
        IdentityRefused,
      );
    } finally {
      channel.close();
    }
  });

  it("an unknown section writes no request; a request resumed after --wait is rejected when the session is cancelled", async (ctx) => {
    if (server === undefined) return ctx.skip(`no reference server: ${skip}`);
    const url = server.url;
    const P = installation(52);
    const notes = await hostResource(P, url, "Notes");
    const created = await createIdentityResource({ ...P, url, label: "laptop", roster: [notes] });
    if (created.kind !== "created") throw new Error(JSON.stringify(created));
    const session = await createPairingSession(P);
    if (session.kind !== "created") throw new Error(JSON.stringify(session));
    const state = stateDir();
    dirs.push(state);
    const run = async (args: readonly string[], link?: string) => {
      const cli = startPairCli(["-", "--state", state, "--label", "bot", ...args], link);
      const exit = await cli.exited;
      return { code: exit.code, output: cli.output() };
    };

    const unknown = await run(["--section", "Mail"], session.link.reveal());
    expect(unknown.code).toBe(PAIR_EXIT.UNKNOWN_SECTIONS);
    expect(unknown.output).toContain("Not in the roster, or ambiguous: Mail");
    expect(unknown.output).toContain("Sections this device may ask for: Notes");
    expect(await pairingRequests({ ...P, session: session.session })).toEqual([]);

    const first = await run(["--section", "Notes", "--wait", "0"], session.link.reveal());
    expect(first.code).toBe(PAIR_EXIT.WAITING);
    expect(first.output).toContain("run the same command again to resume");
    expect((await pairingRequests({ ...P, session: session.session })).length).toBe(1);

    const cancelled = await cancelPairing({ ...P, session: session.session, reject: "not mine" });
    expect(cancelled.kind).not.toBe("unavailable");
    // Resumed from the journal, without the link: the chain says the session was cancelled.
    const again = await run(["--section", "Notes", "--wait", "30", "--poll", "1"]);
    expect(again.code).toBe(PAIR_EXIT.REJECTED);
    expect(again.output).toContain("Resuming the pairing request of this installation.");
    expect(again.output).toContain("Rejected: the managing device cancelled the session.");
  });
});
