// Child processes for the LFCP-038 restart tests (typed in proc.d.mts:
// sdk-ts has no Node type definitions).

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const WRITER = fileURLToPath(new URL("./writer-proc.mjs", import.meta.url));

/**
 * Runs writer-proc.mjs with `args`. With `killAt`, SIGKILLs it as soon as a
 * line starting with that step appears; otherwise waits for it to exit.
 * Resolves with every line it printed.
 */
export function runWriter(args, killAt) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [WRITER, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    const lines = [];
    let buffer = "";
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.stdout.on("data", (d) => {
      buffer += d.toString();
      const parts = buffer.split("\n");
      buffer = parts.pop() ?? "";
      for (const l of parts) {
        lines.push(l);
        if (killAt !== undefined && l.split(" ")[0] === killAt) child.kill("SIGKILL");
      }
    });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (killAt !== undefined ? signal === "SIGKILL" : code === 0) resolve(lines);
      else reject(new Error(`writer exited with ${code ?? signal}: ${stderr.slice(-2000)}`));
    });
  });
}
