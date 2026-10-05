// Starts the openlfcp Rust reference server for live interop tests
// (LFCP-039a). JavaScript with hand-written types (rust-server.d.mts):
// sdk-ts has no Node type definitions.
//
// The server checkout is $LFCP_SERVER_DIR, or ../server next to sdk-ts. It
// is built with `cargo build` into a shared temporary target directory
// ($LFCP_SERVER_TARGET_DIR, default <tmp>/openlfcp-sdk-ts-server-target),
// so only the first run compiles. When cargo or the checkout is missing,
// startRustServer resolves { skip: "<why>" } and the test is skipped,
// unless LFCP_REQUIRE_LIVE=1: then it throws, so a gate that must run the
// live tests cannot pass by skipping them.

import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ROOT } from "../spec.mjs";

const SERVER_DIR = resolve(ROOT, process.env.LFCP_SERVER_DIR ?? "../server");
const TARGET_DIR =
  process.env.LFCP_SERVER_TARGET_DIR ?? join(tmpdir(), "openlfcp-sdk-ts-server-target");

function cargoAvailable() {
  try {
    execFileSync("cargo", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** Builds the server once (cargo is incremental) and returns the binary path, or a skip reason. */
function build() {
  if (!existsSync(join(SERVER_DIR, "Cargo.toml")))
    return { skip: `no server checkout at ${SERVER_DIR} (set LFCP_SERVER_DIR)` };
  if (!cargoAvailable()) return { skip: "cargo is not installed" };
  try {
    execFileSync("cargo", ["build", "--quiet", "--manifest-path", join(SERVER_DIR, "Cargo.toml")], {
      env: { ...process.env, CARGO_TARGET_DIR: TARGET_DIR },
      stdio: ["ignore", "ignore", "pipe"],
    });
  } catch (e) {
    return { skip: `cargo build failed: ${String(e.stderr ?? e).slice(0, 400)}` };
  }
  const bin = join(
    TARGET_DIR,
    "debug",
    process.platform === "win32" ? "lfcp-server.exe" : "lfcp-server",
  );
  return existsSync(bin) ? { bin } : { skip: `no binary at ${bin}` };
}

function freePort() {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.once("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const port = s.address().port;
      s.close(() => ok(port));
    });
  });
}

async function waitHealthy(base, child, deadline) {
  while (Date.now() < deadline) {
    if (child.exitCode !== null) return false;
    try {
      const r = await fetch(`${base}/health`);
      if (r.ok) return true;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

/** Every file under `root`, recursively, with its bytes (what the server persisted). */
function readTree(root) {
  if (!existsSync(root)) return [];
  return readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => {
      const path = join(e.parentPath ?? e.path, e.name);
      return { path: path.slice(root.length + 1), bytes: new Uint8Array(readFileSync(path)) };
    });
}

/** Starts a fresh server on a free loopback port with its own state directory. */
export async function startRustServer() {
  const built = build();
  if (built.skip !== undefined) {
    if (process.env.LFCP_REQUIRE_LIVE === "1")
      throw new Error(`LFCP_REQUIRE_LIVE=1 but the live tests would skip: ${built.skip}`);
    return { skip: built.skip };
  }
  const port = await freePort();
  const dir = mkdtempSync(join(tmpdir(), "lfcp-rust-server-"));
  const url = `ws://127.0.0.1:${port}/v1/ws`;
  writeFileSync(
    join(dir, "server.toml"),
    [
      `bind = "127.0.0.1:${port}"`,
      `state_dir = ${JSON.stringify(join(dir, "state"))}`,
      `public_urls = [${JSON.stringify(url)}]`,
      "heartbeat_ms = 5000",
      `log_level = "debug"`,
      "",
    ].join("\n"),
  );
  let log = "";
  const child = spawn(built.bin, ["--config", join(dir, "server.toml")], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (d) => {
    log += d.toString();
  });
  child.stderr.on("data", (d) => {
    log += d.toString();
  });
  const healthy = await waitHealthy(`http://127.0.0.1:${port}`, child, Date.now() + 20_000);
  if (!healthy) {
    child.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`the Rust server did not become healthy:\n${log.slice(-2000)}`);
  }
  return {
    url,
    stateDir: join(dir, "state"),
    files: () => readTree(join(dir, "state")),
    log: () => log,
    stop: async () => {
      if (child.exitCode === null) {
        child.kill("SIGTERM");
        await new Promise((r) => {
          const t = setTimeout(() => {
            child.kill("SIGKILL");
            r(undefined);
          }, 5000);
          child.once("exit", () => {
            clearTimeout(t);
            r(undefined);
          });
        });
      }
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
