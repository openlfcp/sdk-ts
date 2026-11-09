// `lfcp-node pair`: headless pairing of a new installation, the service
// device of a bridge or bot (IDENTITY-PROFILE-01 §5.3 "Headless
// installation", §10 service devices, decision I6). The label and the
// requested sections (by roster name) are arguments, the fingerprint is
// printed for the human to compare with the approving device's screen,
// and the result is learned from the chain alone (§5.3 step 8); a timeout
// is never a decision, and a rerun resumes from the journal.
//
// Public @openlfcp/client API only: requestPairing, completePairing and
// the operation journal, over SQLite storage and a file SecretStore.

import { readFileSync } from "node:fs";
import {
  completePairing,
  type IdentityNetwork,
  MASK_PRESETS,
  OperationJournal,
  PairingLinkText,
  type PairingOutcome,
  requestPairing,
} from "@openlfcp/client";
import { toBase64url } from "@openlfcp/core";
import { DEVICE_KIND, deviceFingerprint } from "@openlfcp/wire";
import { openNodeInstallation } from "./node-installation.js";

/** Exit codes of `lfcp-node pair`. */
export const PAIR_EXIT = Object.freeze({
  /** Approved, and every requested section is ready or not granted. */
  DONE: 0,
  /** An error: the link is rejected, the request refused, the state unusable. */
  FAILED: 1,
  /** The session was cancelled by the managing device: rejected (final). */
  REJECTED: 2,
  /** Still waiting (approval, registration or keys) when --wait ran out: run again to resume. */
  WAITING: 3,
  /** A requested section is not in the roster, or names several Resources. */
  UNKNOWN_SECTIONS: 4,
  /** Bad arguments. */
  USAGE: 64,
} as const);

export interface PairArguments {
  /** The pairing link, or "-" to read it from standard input (never from the shell history). */
  readonly link: string;
  /** The state directory: SQLite storage, secrets and the installation's Principal. */
  readonly state: string;
  readonly label: string;
  /** 1 service (the default), 0 personal. */
  readonly kind: 0 | 1;
  /** Service: the requested sections by roster name. */
  readonly sections: readonly string[];
  readonly platform: string;
  /** Seconds to wait for the result before exiting with WAITING; 0 sends the request only. */
  readonly wait: number;
  /** Seconds between two checks of the result. */
  readonly poll: number;
}

export const PAIR_USAGE = `usage: lfcp-node pair <link|-> --state <dir> --label <label>
                      [--section <roster name>]... [--personal]
                      [--platform <name>] [--wait <seconds>] [--poll <seconds>]

Pairs this installation as a service device of the human whose managing
device shows the link (IDENTITY-PROFILE-01 §5.3). Prints the fingerprint to
compare with that device's screen, then waits for the approval. "-" reads the
link from standard input. Run the same command again to resume.`;

/** Parses the arguments after "pair"; a string is the usage error. */
export function parsePairArguments(argv: readonly string[]): PairArguments | string {
  let link: string | undefined;
  let state: string | undefined;
  let label: string | undefined;
  let kind: 0 | 1 = 1;
  let platform = "server";
  let wait = 600;
  let poll = 5;
  const sections: string[] = [];
  const seconds = (name: string, v: string | undefined): number | string => {
    const n = Number(v);
    return v !== undefined && Number.isInteger(n) && n >= 0 ? n : `${name} needs whole seconds`;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    const value = () => argv[++i];
    switch (a) {
      case "--state":
        state = value();
        break;
      case "--label":
        label = value();
        break;
      case "--section": {
        const s = value();
        if (s === undefined || s === "") return "--section needs a roster name";
        sections.push(s);
        break;
      }
      case "--personal":
        kind = 0;
        break;
      case "--platform": {
        const p = value();
        if (p === undefined || p === "") return "--platform needs a name";
        platform = p;
        break;
      }
      case "--wait": {
        const n = seconds("--wait", value());
        if (typeof n === "string") return n;
        wait = n;
        break;
      }
      case "--poll": {
        const n = seconds("--poll", value());
        if (typeof n === "string") return n;
        if (n === 0) return "--poll needs at least one second";
        poll = n;
        break;
      }
      default:
        if (a.startsWith("--")) return `unknown option ${a}`;
        if (link !== undefined) return "one link only";
        link = a;
    }
  }
  if (link === undefined) return "the pairing link is missing";
  if (state === undefined || state === "") return "--state is missing";
  if (label === undefined || label === "") return "--label is missing";
  if (kind === 1 && sections.length === 0)
    return "a service device needs at least one --section (or --personal)";
  if (kind === 0 && sections.length > 0) return "--section is for a service device only";
  return { link, state, label, kind, sections, platform, wait, poll };
}

export interface PairEnvironment {
  /** One line of output for the human (never the link). */
  readonly out: (line: string) => void;
  /** Standard input, for a link given as "-". */
  readonly stdin?: () => string;
  readonly network?: IdentityNetwork;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
/** The preset a certificate's kind and mask are, by IDENTITY-PROFILE-01 §5.4. */
function presetOf(kind: number, mask: readonly bigint[]): string {
  const same = (a: readonly bigint[]) =>
    a.length === mask.length && a.every((c) => mask.includes(c));
  for (const [name, p] of Object.entries(MASK_PRESETS))
    if (p.kind === kind && same(p.mask)) return `${name[0]?.toUpperCase()}${name.slice(1)}`;
  return `kind ${kind}, mask {${[...mask].sort((a, b) => (a < b ? -1 : 1)).join(", ")}}`;
}

const STATUS: Readonly<Record<string, string>> = {
  ready: "ready",
  "waiting-for-keys": "waiting for keys",
  "pending-registration": "pending registration",
  "not-granted": "not granted",
  unproven: "approval not provable here",
  unreachable: "unreachable, retrying",
  unsupported: "on a server without device support",
};
const FINAL = new Set(["ready", "not-granted"]);

/** Runs `lfcp-node pair` with parsed arguments; returns its exit code. */
export async function pair(args: PairArguments, env: PairEnvironment): Promise<number> {
  const out = env.out;
  const now = env.now ?? (() => Date.now());
  const sleep = env.sleep ?? defaultSleep;
  const node = await openNodeInstallation(args.state, {
    now,
    ...(env.network === undefined ? {} : { network: env.network }),
  });
  const { installation, storage, flow } = node;
  try {
    const fingerprint = deviceFingerprint(installation.signer.descriptor.principalId);
    const journal = new OperationJournal(storage);
    // A request already made by this installation is resumed from the journal, link or not.
    let operation = (await journal.list({ kind: "pairing-request", status: "open" }))[0]?.id;
    if (operation === undefined) {
      const text = args.link === "-" ? (env.stdin?.() ?? "").trim() : args.link;
      const r = await requestPairing({
        ...flow,
        link: new PairingLinkText(text),
        label: args.label,
        kind: args.kind,
        ...(args.kind === 1 ? { sections: args.sections } : {}),
        platform: args.platform,
        requestedAt: new Date(now()).toISOString().replace(/\.\d{3}Z$/, "Z"),
      });
      switch (r.kind) {
        case "requested":
          operation = r.operation;
          break;
        case "unknown-sections":
          out(`Not in the roster, or ambiguous: ${r.unknown.join(", ")}`);
          out(`Sections this device may ask for: ${r.available.join(", ") || "(none)"}`);
          return PAIR_EXIT.UNKNOWN_SECTIONS;
        case "invalid-link":
        case "not-a-session":
          out(`The link is rejected: ${r.reason}`);
          return PAIR_EXIT.FAILED;
        case "missing-material":
          out(`The managing device has not made the session usable yet: ${r.missing.join(", ")}`);
          return PAIR_EXIT.FAILED;
        case "refused":
          out(`The request was refused (${r.code}).`);
          return PAIR_EXIT.FAILED;
        case "unavailable":
          out(`The server could not be reached: ${r.reason}. Run again to retry.`);
          return PAIR_EXIT.WAITING;
      }
      out(`Fingerprint: ${fingerprint}`);
      out("Compare it with the fingerprint the approving device shows before approving.");
      out(
        args.kind === 1
          ? `Requested: "${args.label}" (service) asks to join ${args.sections.join(", ")}; access: read and write.`
          : `Requested: "${args.label}" (personal device).`,
      );
    } else {
      out(`Fingerprint: ${fingerprint}`);
      out("Resuming the pairing request of this installation.");
    }
    const deadline = now() + args.wait * 1000;
    let last = "";
    const say = (line: string) => {
      if (line !== last) out(line);
      last = line;
    };
    for (;;) {
      // The ready sections get Resource rows: what the bridge lists them from (storage.resources).
      const r: PairingOutcome = await completePairing({ ...flow, operation, storeResources: true });
      if (r.kind === "rejected") {
        say("Rejected: the managing device cancelled the session.");
        return PAIR_EXIT.REJECTED;
      }
      if (r.kind === "waiting") say("Waiting for the approval on the managing device…");
      else if (r.kind === "unknown" || r.kind === "unavailable")
        say(`Waiting: ${r.reason} (retrying).`);
      else if (r.certificate === null) say("Approved, waiting for registration…");
      else {
        const leaf = r.certificate.leaf.payload;
        const lines = [
          `Approved: ${presetOf(leaf.kind, leaf.mask)}${leaf.kind === DEVICE_KIND.SERVICE ? " (service device)" : ""}.`,
          ...r.candidates.map(
            (c) => `  ${c.name ?? toBase64url(c.resource)}: ${STATUS[c.status] ?? c.status}`,
          ),
        ];
        if (r.foreignCertificates > 0)
          lines.push(`  ${r.foreignCertificates} certificate(s) with another approval: not used.`);
        say(lines.join("\n"));
        if (r.candidates.length > 0 && r.candidates.every((c) => FINAL.has(c.status)))
          return PAIR_EXIT.DONE;
      }
      if (now() >= deadline) {
        out("Not finished yet; run the same command again to resume.");
        return PAIR_EXIT.WAITING;
      }
      await sleep(args.poll * 1000);
    }
  } finally {
    node.close();
  }
}

/** `lfcp-node <command> ...`: the entry point of the bin; returns the exit code. */
export async function main(argv: readonly string[], env: PairEnvironment): Promise<number> {
  const [command, ...rest] = argv;
  if (command !== "pair") {
    env.out(PAIR_USAGE);
    return PAIR_EXIT.USAGE;
  }
  const args = parsePairArguments(rest);
  if (typeof args === "string") {
    env.out(`${args}\n\n${PAIR_USAGE}`);
    return PAIR_EXIT.USAGE;
  }
  return pair(args, env);
}

/** Standard input as text (for "-"). */
export const readStdin = (): string => readFileSync(0, "utf8");
