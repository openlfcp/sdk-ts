// Runs the built `lfcp-node pair` of @openlfcp/storage-node as a child
// process for the live headless pairing test (typed in pair-cli.d.mts:
// sdk-ts has no Node type definitions). The link goes in on standard
// input, as an operator would pipe it, never on the command line.

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ROOT } from "../spec.mjs";
import { guardChild } from "./reaper.mjs";

const CLI = join(ROOT, "packages", "storage-node", "dist", "cli.js");

export function stateDir() {
  return mkdtempSync(join(tmpdir(), "lfcp-pair-cli-"));
}

export function removeDir(dir) {
  rmSync(dir, { recursive: true, force: true });
}

export function startPairCli(args, link) {
  const child = spawn(process.execPath, [CLI, "pair", ...args], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const release = guardChild(child, []);
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => {
    out += d.toString();
  });
  child.stderr.on("data", (d) => {
    err += d.toString();
  });
  child.stdin.end(link === undefined ? "" : `${link}\n`);
  const exited = new Promise((r) =>
    child.once("exit", (code, signal) => {
      release();
      r({ code, signal });
    }),
  );
  return {
    output: () => out,
    stderr: () => err,
    exited,
    kill: async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      await exited;
    },
  };
}
