#!/usr/bin/env node
// worldsignals-scan: the security part of the worldsignals CLI as its own package. The same code (ws.mjs and
// scan.mjs, copied in when packed), so `npx worldsignals-scan` is `ws scan`, and the machine commands come along:
//   worldsignals-scan [options]            check this computer (ws scan)
//   worldsignals-scan --alerts             opt in to alerts for it
//   worldsignals-scan machine … | machines manage many machines
//   worldsignals-scan signup | upgrade | connect | status | billing   the account they use
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { run } from "./ws.mjs";

/** Commands that belong to the account and the machines, passed through as they are. */
const PASS = new Set(["machine", "machines", "signup", "upgrade", "connect", "status", "billing", "disconnect", "logout", "recover", "keys", "feedback", "version", "--version", "-v"]);

/** worldsignals-scan's arguments as ws's: everything else is a scan. */
export function toWs(argv) {
  if (argv[0] === "scan") return argv;
  if (argv[0] === "help" || argv[0] === "--help" || argv[0] === "-h") return ["scan", "--help"];
  if (argv[0] && PASS.has(argv[0])) return argv;
  return ["scan", ...argv];
}

/** How messages name the command: as it was run. */
export const nameOf = (env = {}) => (env.npm_command === "exec" ? "npx worldsignals-scan" : "worldsignals-scan");

function isMain() {
  try {
    return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isMain()) {
  const stop = new AbortController();
  for (const sig of ["SIGINT", "SIGTERM"]) process.once(sig, () => stop.abort());
  const tty = { out: process.stdout.isTTY, err: process.stderr.isTTY };
  run(toWs(process.argv.slice(2)), { signal: stop.signal, name: nameOf(process.env), tty, stdin: process.stdin.isTTY ? process.stdin : null }).then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      console.error(e instanceof Error ? e.message : e);
      process.exitCode = 1;
    },
  );
}
