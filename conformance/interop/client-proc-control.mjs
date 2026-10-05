// Drives client-proc.mjs children for the live restart test (typed in
// client-proc-control.d.mts: sdk-ts has no Node type definitions).

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLIENT = fileURLToPath(new URL("./client-proc.mjs", import.meta.url));

export function startClientProc(args) {
  const child = spawn(process.execPath, [CLIENT, ...args], { stdio: ["pipe", "pipe", "pipe"] });
  const events = [];
  let buffer = "";
  let stderr = "";
  child.stderr.on("data", (d) => {
    stderr += d.toString();
  });
  child.stdout.on("data", (d) => {
    buffer += d.toString();
    const parts = buffer.split("\n");
    buffer = parts.pop() ?? "";
    for (const l of parts) if (l.trim() !== "") events.push(JSON.parse(l));
  });
  const exited = new Promise((r) => child.once("exit", (code, signal) => r({ code, signal })));
  return {
    events,
    stderr: () => stderr,
    send: (line) => child.stdin.write(`${line}\n`),
    kill: async () => {
      child.kill("SIGKILL");
      await exited;
    },
    alive: () => child.exitCode === null && child.signalCode === null,
  };
}
