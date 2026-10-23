#!/usr/bin/env node
// worldsignals (or ws): the WorldSignals command line tool. One file, no dependencies, Node 18 or later.
// npx worldsignals help, or download https://worldsignals.io/cli/ws.mjs and run node ws.mjs.
//
//   node ws.mjs signup --email ana@example.com --agent "My agent" [--company … --type … --country … --plan … --billing …]
//   node ws.mjs key --link <confirm_url>       (after your person confirmed: prints the access key)
//   node ws.mjs events [--type …] [--country ES] [--after <time>] [--limit 50] [--json]   (needs WS_KEY or --key)
//
// WS_API overrides the server (default https://worldsignals.io). WS_KEY is the access key from signing up.
import { parseArgs } from "node:util";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

const DEFAULT_API = "https://worldsignals.io";
export const VERSION = "0.1.1";

const HELP = `worldsignals ${VERSION}, the WorldSignals command line tool (also installed as ws;
run it with npx worldsignals, or node ws.mjs from https://worldsignals.io/cli/ws.mjs)

Usage:
  ws signup --email <person's email> --agent <your agent's name> [options]
      Ask to sign up your person or company. Prints a link they must open to confirm;
      nothing is signed up until they do.
      --company <name>   --role <role>   --use-case <text>
      --type <ids>       comma-separated event types, e.g. company.registered,procurement.tender_published
      --country <codes>  comma-separated ISO codes, e.g. PT,ES (default: worldwide)
      --plan <plan>      free, developer, team, business or enterprise
      --billing <period> monthly or yearly
      --agent-version <version>

  ws key --link <confirm_url>
      Once your person has confirmed, print the access key that reads events for them.

  ws events [--type <ids>] [--country <code>] [--after <time>] [--limit <1-200>] [--json] [--key <key>]
      Print the newest collected public events. Needs the access key from signing up
      (--key, or the WS_KEY environment variable).

  ws watch
      Coming with early access: listen and run a program, write files or start an agent.

Environment:
  WS_API   server to talk to (default ${DEFAULT_API})
  WS_KEY   your access key, from signing up
`;

const list = (value) => (value ? value.split(",").map((s) => s.trim()).filter(Boolean) : undefined);

/** The request body for `ws signup`, from parsed options. */
export function signupBody(o) {
  return {
    email: o.email,
    company: o.company,
    role: o.role,
    useCase: o["use-case"],
    eventTypes: list(o.type),
    countries: list(o.country)?.map((c) => c.toUpperCase()),
    plan: o.plan,
    billing: o.billing,
    agent: { name: o.agent, version: o["agent-version"] },
  };
}

/** Runs one command. Returns the exit code; writes to `out` and `err`. */
export async function run(argv, { fetch = globalThis.fetch, env = process.env, out = console.log, err = console.error } = {}) {
  const api = (env.WS_API || DEFAULT_API).replace(/\/$/, "");
  const [command, ...rest] = argv;
  if (command === "version" || command === "--version" || command === "-v") {
    out(VERSION);
    return 0;
  }
  if (!command || command === "help" || command === "--help" || command === "-h") {
    out(HELP);
    return 0;
  }

  if (command === "signup") {
    const { values } = parseArgs({
      args: rest,
      options: Object.fromEntries(
        ["email", "agent", "agent-version", "company", "role", "use-case", "type", "country", "plan", "billing"].map((k) => [k, { type: "string" }]),
      ),
    });
    if (!values.email || !values.agent) {
      err("ws signup needs --email (your person's email) and --agent (your agent's name).");
      return 2;
    }
    const res = await fetch(`${api}/api/signup-requests`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "ws-cli/1" },
      body: JSON.stringify(signupBody(values)),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      err(`Sign-up request failed (${res.status}): ${body.error ?? "no details"}`);
      return 1;
    }
    out(body.message_for_human);
    out("");
    out(`Confirm link: ${body.confirm_url}`);
    out(`Expires:      ${body.expires_at}`);
    return 0;
  }

  if (command === "key") {
    const { values } = parseArgs({ args: rest, options: { link: { type: "string" } } });
    let token = values.link;
    try {
      token = new URL(values.link).searchParams.get("t");
    } catch {} // a bare code works too
    if (!token) {
      err("ws key needs --link with the confirm link from ws signup.");
      return 2;
    }
    const res = await fetch(`${api}/api/signup-requests/${encodeURIComponent(token)}`, { headers: { "user-agent": "ws-cli/1" } });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      err(`Couldn't read the request (${res.status}): ${body.error ?? "no details"}`);
      return 1;
    }
    if (!body.access_key) {
      err(
        body.status === "pending"
          ? "Your person hasn't confirmed yet. Ask them to open the link."
          : body.status === "confirmed"
            ? "Your person confirmed, but not their email yet. Ask them to open the link we emailed them."
            : `This request was ${body.status}.`,
      );
      return 1;
    }
    out(body.access_key);
    return 0;
  }

  if (command === "events") {
    const { values } = parseArgs({
      args: rest,
      options: { type: { type: "string" }, country: { type: "string" }, after: { type: "string" }, limit: { type: "string" }, json: { type: "boolean" }, key: { type: "string" } },
    });
    const key = values.key ?? env.WS_KEY;
    if (!key) {
      err("ws events needs your access key: --key <key> or WS_KEY. You get one by signing up (ws signup, then ws key --link …).");
      return 2;
    }
    const params = new URLSearchParams();
    if (values.type) params.set("types", values.type);
    if (values.country) params.set("country", values.country.toUpperCase());
    if (values.after) params.set("after", values.after);
    params.set("limit", values.limit ?? "20");
    const res = await fetch(`${api}/api/events?${params}`, { headers: { "user-agent": "ws-cli/1", authorization: `Bearer ${key}` } });
    if (!res.ok) {
      err(res.status === 401 ? "That access key isn't valid. Sign up again with the same email to get it back." : `Couldn't read events (${res.status}).`);
      return 1;
    }
    const { events } = await res.json();
    if (values.json) {
      for (const e of events) out(JSON.stringify(e));
    } else {
      for (const e of events) out(`${e.time.slice(0, 10)}  ${e.type.padEnd(30)}  ${(e.country ?? "").padEnd(2)}  ${e.title}`);
      if (!events.length) out("No events match.");
    }
    return 0;
  }

  if (command === "watch") {
    err("ws watch ships with early access. Until then, poll with: ws events --after <observed_at of the newest event you have>");
    return 2;
  }

  err(`Unknown command "${command}". Run ws help.`);
  return 2;
}

// Run when started as a program. npm and npx start it through a symlink in node_modules/.bin, so compare
// real paths. Set the exit code rather than exiting, so output to a pipe is never cut short.
function isMain() {
  try {
    return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isMain()) {
  run(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      console.error(e instanceof Error ? e.message : e);
      process.exitCode = 1;
    },
  );
}
