#!/usr/bin/env node
// lfcp-node: the headless commands of @openlfcp/storage-node. `pair` pairs
// this installation as a service device (IDENTITY-PROFILE-01 §5.3).

import { main, readStdin } from "./pair.js";

process.exitCode = await main(process.argv.slice(2), {
  out: (line) => process.stdout.write(`${line}\n`),
  stdin: readStdin,
});
