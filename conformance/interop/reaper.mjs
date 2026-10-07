// No server outlives the test process that started it.
//
// A test that fails still runs afterAll, which stops its server. A test
// process that dies without running anything (SIGKILL, a crash, a runner
// timeout) leaves its child running: the server ignores SIGPIPE, so closing
// its stdout and stderr does not stop it. guardChild covers both cases:
// - an exit handler SIGKILLs the child when this process exits normally;
// - on POSIX, a watchdog `sh` reads a pipe that only this process holds.
//   When this process dies, the pipe reaches EOF, and the watchdog SIGKILLs
//   the child and removes `paths`.

import { spawn } from "node:child_process";

const WATCHDOG = 'read _line; kill -9 "$1" 2>/dev/null; shift; rm -rf -- "$@"';

/**
 * Guards a started child. Returns `release`: call it before stopping the
 * child on purpose, so the watchdog never kills a reused pid or removes
 * files a restarted child uses.
 */
export function guardChild(child, paths = []) {
  const onExit = () => {
    try {
      child.kill("SIGKILL");
    } catch {
      // already gone
    }
  };
  process.once("exit", onExit);
  let watchdog;
  if (process.platform !== "win32" && child.pid !== undefined) {
    watchdog = spawn("/bin/sh", ["-c", WATCHDOG, "lfcp-reaper", String(child.pid), ...paths], {
      stdio: ["pipe", "ignore", "ignore"],
    });
    watchdog.on("error", () => {});
    watchdog.stdin.on("error", () => {});
    // Neither keeps this process alive.
    watchdog.unref();
    watchdog.stdin.unref();
  }
  return () => {
    process.removeListener("exit", onExit);
    if (watchdog !== undefined && watchdog.exitCode === null && watchdog.signalCode === null)
      watchdog.kill("SIGKILL");
  };
}
