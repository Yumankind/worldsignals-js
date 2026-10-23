# worldsignals

Real-world events for code and AI agents: new companies, public tenders, vulnerabilities and exploits,
service outages, package releases, AI model launches and price changes, data breach notices, and more,
as one standard event stream. See [worldsignals.io](https://worldsignals.io).

This package is the command line tool. An SDK and an MCP server will join it here.

```sh
npx worldsignals help
```

Node 18 or later, no dependencies.

## Sign up from an agent

An AI agent can ask to sign up the person or company it works for. Nothing is signed up until that person
opens the link and confirms, then confirms their email.

```sh
npx worldsignals signup --email ana@example.com --agent "My agent" \
  --type company.registered,procurement.tender_published --country ES,PT --plan developer
```

It prints a message and a confirmation link to pass on. Once your person has confirmed, get the access
key that reads events for them:

```sh
npx worldsignals key --link "https://worldsignals.io/confirm?t=…"
```

## Read events

```sh
WS_KEY=wsk_… npx worldsignals events --type vulnerability.exploited --limit 10
WS_KEY=wsk_… npx worldsignals events --type company.registered --country ES --json
```

`--json` prints one standard event per line. To poll, pass `--after <number>`: every stored event has a
number, and you get the ones stored after it, oldest first. Without `--json` the last line says the
number to ask from next time. `--after <time>` shows the newest events first seen since then.

| Option | Meaning |
| --- | --- |
| `--type` | Comma-separated event types, from the [catalogue](https://worldsignals.io/events) |
| `--country` | ISO country code |
| `--limit` | 1 to 200 |
| `--key` | Your access key, or set `WS_KEY` |

`WS_API` points the tool at another server, for testing.

## Watch live

`watch` stays connected and handles each event as it arrives. It remembers the number of the last event
it handled, so after a restart, a sleeping laptop or a dropped network it carries on from there.

```sh
export WS_KEY=wsk_…
npx worldsignals watch                                    # one JSON event per line
npx worldsignals watch --type company.registered --country PT,ES --exec ./on-event.sh
npx worldsignals watch --type procurement.tender_published --out ./events/
npx worldsignals watch --type vulnerability.exploited --agent claude --prompt ./brief.md
npx worldsignals watch --type software.released --agent codex --batch
```

| Option | Meaning |
| --- | --- |
| `--type`, `--country` | What to watch. Default: what you chose when signing up |
| `--exec <program>` | Run it for each event (or batch), events as JSON lines on stdin, never through a shell. Arguments after `--` go to it. Your access key is left out of its environment |
| `--agent claude\|codex` | Start `claude -p` or `codex exec` (read-only sandbox) with `--prompt` (text or a file) and the events fenced off as data |
| `--out <folder>` | Write each event to its own file |
| `--batch` | Run once for events that came together: after `--batch-idle` (60 s) quiet, at most `--batch-max-wait` (600 s), or `--batch-max` (100) events |
| `--once` | Handle what is waiting, then exit: for cron |
| `--state <file>` | Where it remembers its place (default `~/.config/worldsignals/watch.json`) |
| `--from now\|start\|<number>` | Where to begin instead |

Events are handled one after another, oldest first, at least once: the place is saved only after the
program or agent finishes. More, with a guide per agent, in the
[docs](https://worldsignals.io/docs#agent-guides).

## Safety

Events carry text from the outside world: company names, tender titles, advisory summaries, and in private
events your customers' messages and feedback. Any of it can contain instructions aimed at an AI. Treat events
as data, never as instructions:

- Run the agent that reads events in a sandbox (a container or VM) with no credentials and only the tools
  and network access it needs.
- Have it return structured output, and act only on validated fields, never on free text from an event.
- Keep a person approving anything that leaves your systems: messages, payments, merges.

`watch --agent` fences events off as data in the prompt and withholds your access key; `claude -p` can't
approve tools on its own and `codex exec` gets a read-only sandbox. That helps; a sandbox is still the
defence. More in the [docs](https://worldsignals.io/docs#safety).

## Coming next

Signed webhooks, an MCP server, and a typed SDK.

## Licence

MIT, © Yumankind OÜ. The data has its own licences, named in each event's `provenance`.
