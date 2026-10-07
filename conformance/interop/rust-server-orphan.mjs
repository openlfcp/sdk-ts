// The orphan check for rust-server-orphan.test.ts (typed in
// rust-server-orphan.d.mts: sdk-ts has no Node type definitions).
//
// Run as a script, this file is the parent: it starts a server with
// startRustServer, prints {pid, dir} (or {skip}) as one JSON line, and waits
// to be killed. checkOrphan starts that parent, SIGKILLs it (no exit handler
// runs), and reports whether the server and its directory outlived it.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SELF = fileURLToPath(import.meta.url);

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

export async function checkOrphan(withinMs) {
  const parent = spawn(process.execPath, [SELF], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  parent.stderr.on("data", (d) => {
    err += d.toString();
  });
  const exited = new Promise((r) => parent.once("exit", () => r(undefined)));
  const started = await new Promise((ok, fail) => {
    parent.stdout.on("data", (d) => {
      out += d.toString();
      const nl = out.indexOf("\n");
      if (nl >= 0) ok(JSON.parse(out.slice(0, nl)));
    });
    parent.once("exit", (code) =>
      fail(new Error(`the parent exited (${code}): ${err.slice(-2000)}`)),
    );
  });
  if (started.skip !== undefined) {
    parent.kill("SIGKILL");
    await exited;
    return { skip: started.skip };
  }
  const before = alive(started.pid);
  parent.kill("SIGKILL");
  await exited;
  const killed = Date.now();
  while ((alive(started.pid) || existsSync(started.dir)) && Date.now() - killed < withinMs)
    await new Promise((r) => setTimeout(r, 50));
  return {
    aliveBefore: before,
    serverAlive: alive(started.pid),
    dirExists: existsSync(started.dir),
  };
}

if (process.argv[1] === SELF) {
  const { startRustServer } = await import("./rust-server.mjs");
  const server = await startRustServer();
  if ("skip" in server) {
    process.stdout.write(`${JSON.stringify({ skip: server.skip })}\n`);
  } else {
    process.stdout.write(`${JSON.stringify({ pid: server.pid, dir: dirname(server.stateDir) })}\n`);
    setInterval(() => {}, 60_000);
  }
}
