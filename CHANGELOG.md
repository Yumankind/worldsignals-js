# Changelog

Versions of the `worldsignals` package on npm. Not every tagged or committed version was published: 0.2.0, 0.2.1,
0.4.0 and 0.4.1 never reached npm, and their changes first shipped in the next version that did.

## Unreleased

- New: `disconnect` (also `logout`) starts from scratch: a connected agent leaves the account it acts for (as a
  revoke in the console would, `POST /api/agent/disconnect`), then this device forgets the agent key and where
  `watch` stopped, so the next `signup` or `watch` makes a new agent. An agent with a live plan of its own is refused
  until that plan ends (cancel it with `billing`; `--force` forgets the key anyway; `recover` binds a new one). With
  `WS_KEY` set (or `WS_API` elsewhere) the watch position is kept, as it may be another watch's, and it says to unset
  `WS_KEY`, as it isn't the CLI's to forget. Needs the server's `POST /api/agent/disconnect`.
- `watch --type` help says `all` is every type.
- Help and README say when a saved-stream change reaches a running `watch` (its next reconnect, within about five
  minutes) and that `events` doesn't use the saved stream.

## 0.5.0 (2026-10-27)

- New: `request "<what>"` asks for data WorldSignals doesn't collect yet (`--countries`, `--use`, `--source` with an
  https:// link). The answer says how many have asked for the same and which collected event types come closest,
  where they're collected and where not yet.
- New: `feedback "<message>"` sends a bug, a problem (the default) or an idea (`--kind`), with the CLI's version.
- New: `stream set --match '<type>[@<codes>]:<condition>[;<condition>…]'` saves matches with the stream, one per
  `--match` (e.g. `--match 'procurement.tender_published:data.cpv^=72'`); `--matches` takes the JSON list (text,
  `@file` or `-`), and `--match none` removes them. They replace the saved matches. Past the plan's matches, the
  server's sentence is printed, exit 1. `stream` and `stream --json` show the saved matches.
- New: `stream preview [--match …]` shows what each match would have sent among the latest events of its type,
  with up to three examples; with no `--match`, the saved matches.
- New: `types [--family …]` lists the event types and where each is collected (country codes, worldwide (XX), or
  planned); `fields <type>` lists a type's fields for conditions (path, kind, an enum's values). Both need no key.
- New: `estimate [--type] [--country] [--since 7d] [--where …] [--match …]` says how many events filters find
  since a time, how many count toward the month, how many are always free or would arrive locked, and the
  allowance left. It uses none of the monthly events.
- New: `api <METHOD> <path> [<body>]` sends any call under `/api/`, signed with the agent key or sent with the
  access key; the body is JSON text, `@file` or `-`. It prints the answer's JSON (`--raw`: one line); 400 and up
  also go to stderr with the status, exit 1. Links to other hosts, and `/mcp`, are refused.
- `events` with conditions pages back (`before`) while the server says older events may match, up to `--limit`
  events or `--pages` answers (default 30), instead of stopping at the first empty window; it says how far back it
  looked and how to carry on (`--before <number>`).
- `--country` help mentions the groups `EU`, `EEA` and `EUROPE`, passed on as given.
- Both work with no account: with `--key` or `WS_KEY` they come from that key's account, else signed with the agent
  key if the machine has one, else anonymously. `--json` prints the answer as one object. A refused request (400)
  or one too many (429, with when to try again) is said on stderr, with exit 1.
- `--json` for agents on `watch`, `upgrade`, `connect` and `signup`: the payment link and the connect code as one
  JSON object, with the API's field names (`pay.url`, `pay.plan`, `pay.billing`, `connect.user_code`,
  `connect.verification_uri`, `connect.verification_uri_complete`, `connect.expires_at`) and a `next` sentence.
- `watch --no-wait --json` prints that object and nothing else on stdout, and exits 0. Waiting, `watch --json`
  writes it as a line of its own on stderr, so stdout stays one standard event per line.
- `upgrade --wait --json` and a waiting `connect --json` add a second line once done: the agent, as
  `status --json` shows it. `status --json` also carries the connect code still waiting on this machine.
- JSON output is never styled, even at a terminal. Errors stay plain text on stderr with a non-zero exit.
  Output without `--json` is unchanged.

## 0.4.4 (2026-10-27)

- `watch`, for an agent not yet paid for or connected, lays out its two ways forward with a label each (Pay,
  Connect) and each link on a line of its own.
- At a terminal, the labels are in WorldSignals' orange, the connect code is bold, and links stay clickable as a
  whole where they wrap (OSC 8). Press Enter to open the payment page, or `c` and Enter for the connect page.
- Pipes, agents' shells, CI, `NO_COLOR` and `TERM=dumb` get plain text, with nothing to press: what agents read is
  the same layout without styling.
- `upgrade`, `billing`, `connect` and `recover` print their links clickable too, at a terminal.

## 0.4.3 (2026-10-26)

No change to the command line tool: a new README for npm (banner, terminal demo, quick start, the MCP server as
live), the package description and keywords, and releases published from GitHub Actions with npm provenance.

## 0.4.2 (2026-10-26)

The first npm release of agent accounts; 0.4.0 and 0.4.1 were tagged but not published.

- `watch` waits out the plan's limit on live connections open at once: it shows the server's message, waits as long
  as the server asks (`Retry-After`) and connects again.
- Everything from 0.4.0 and 0.4.1 below.

## 0.4.1 (2026-10-26, tagged, not published)

- `help` lists the place conditions for `--where`: `place.near=lat,lon,km` and `place.within=south,west,north,east`.

## 0.4.0 (2026-10-26, tagged, not published)

Agent accounts.

- `signup` makes the agent's account and an Ed25519 key pair on the device, with no email; every request is signed
  with it.
- `upgrade` prints a Stripe payment link for the agent's own plan; `connect` prints a code a person approves at
  worldsignals.dev/link to let the agent use their account.
- New: `status`, `billing`, `keys rotate`, `recover`, and `stream` / `stream set` for the saved stream.
- `watch` signs the agent up by itself the first time and waits for the payment or the approval.
- New filters: `--language`, and text (`*=` `!*=` `^=` `$=`) and regular-expression (`~=` `!~=`) operators for
  `--where`.
- Removed: the email sign-up and `key --link`. `init`, `pay` and `portal` remain as aliases.

## 0.3.2 (2026-10-24)

- `--country` takes `XX`, the events about the whole world, like any other code, and the CLI shows the server's hint
  when a chosen type only comes as `XX`.
- `signup` keeps an Ed25519 pickup key that `key` signs with; `upgrade` prints a Stripe payment link.

## 0.3.1 (2026-10-23)

- `key` explains the waiting list.
- worldsignals.dev is the default server, homepage and links.

## 0.3.0 (2026-10-23)

- Filters for `events` and `watch`: `--platform`, `--ecosystem`, `--tag` and `--where` (any field).
- Includes 0.2.0 and 0.2.1, which weren't published:
  - `watch`: live events to a program (`--exec`), a folder (`--out`) or an agent (`--agent claude|codex`), resuming
    after restarts; `--batch` runs once for many events, `--once` is for cron.
  - `events --after <number>` polls without skipping anything.
  - `watch` moves past event numbers the server says didn't match, so rare filters don't reread them.

## 0.1.1 (2026-10-23)

- Runs when started through npm's symlink (`npx`, global installs); 0.1.0 did nothing there. Output is never cut
  short.

## 0.1.0 (2026-10-23)

- The first release: `signup`, `key`, `events` and `version`. One file, no dependencies, Node 18 or later.
