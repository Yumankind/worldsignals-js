# worldsignals

[![npm](https://img.shields.io/npm/v/worldsignals)](https://www.npmjs.com/package/worldsignals) [![tests](https://github.com/Yumankind/worldsignals-js/actions/workflows/test.yml/badge.svg)](https://github.com/Yumankind/worldsignals-js/actions/workflows/test.yml) [![MIT](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Real-world events for code and AI agents: new companies, public tenders, vulnerabilities and exploits,
service outages, package releases, AI model launches and price changes, data breach notices, and more,
as one standard event stream. See [worldsignals.dev](https://worldsignals.dev).

This package is the command line tool. An SDK and an MCP server will join it here.

```sh
npx worldsignals help
```

Node 18 or later, no dependencies.

## Start from an agent

An AI agent gets an account of its own. No email is needed, and none is ever sent:

```sh
npx worldsignals signup --name "My agent" --label laptop
```

`signup` makes an Ed25519 key pair on this machine (`~/.config/worldsignals/agent.json`, readable only by
you) and signs every request with it; the private key never leaves the machine. Agent accounts have no
free plan, so next, either:

```sh
npx worldsignals upgrade --plan developer   # a Stripe payment link to pass on: your person pays, you never see a card
npx worldsignals connect                    # a code your person approves at worldsignals.dev/link, to use their account
```

Or just start watching: `watch` signs the agent up the first time, prints the payment link and the connect
code, and starts once one of them is done.

```sh
npx worldsignals watch --type company.registered --agent claude
```

| Command | What it does |
| --- | --- |
| `signup` | The agent's account and its key on this machine (`--name`, `--label`, optional `--email`) |
| `upgrade` | A payment link for the agent's own plan (`--plan developer\|team\|business`, `--yearly`, `--wait`) |
| `connect` | Act for your person's account, once they approve the code (`--email` also puts the request in their console) |
| `status` | The agent, its plan or the account it's connected to |
| `billing` | Stripe's billing portal for an agent that pays for its own plan: change plan or card, invoices, cancel |
| `keys rotate` | A new key for this agent; the old one stops working |
| `recover` | A new key for an agent whose key was lost, approved by the person who pays for it or connected it |

An agent with no plan and no connection is deleted seven days after it was made, or after its plan ends;
`signup` then makes a new one with a new key. A named or personal access key from the console still works
everywhere: `--key wsk_…` or `WS_KEY=wsk_…`.

`XX` is the events about the whole world (vulnerabilities, outages, AI models): a country like the
others. Without `--country` you get every country, `XX` included; with a list, add it to get them too:
`--country ES,PT,XX`. When a type you chose only comes as `XX` and the list leaves it out, the CLI says so.

## Read events

```sh
npx worldsignals events --type vulnerability.exploited --limit 10
npx worldsignals events --type company.registered --country ES --json
```

`--json` prints one standard event per line. To poll, pass `--after <number>`: every stored event has a
number, and you get the ones stored after it, oldest first. Without `--json` the last line says the
number to ask from next time. `--after <time>` shows the newest events first seen since then.

| Option | Meaning |
| --- | --- |
| `--type` | Comma-separated event types, from the [catalogue](https://worldsignals.dev/events) |
| `--country` | One ISO country code or several, comma-separated; `XX` for the events about the whole world |
| `--limit` | 1 to 200 |
| `--key` | An access key from the console instead of the agent key, or set `WS_KEY` |

`WS_API` points the tool at another server, for testing.

## Filters

`events` and `watch` both narrow events beyond type and country. Values in one filter are
alternatives; different filters all apply.

| Option | Meaning |
| --- | --- |
| `--platform` | Operating systems: `windows`, `macos`, `linux`, `android`, `ios`, `chromeos`, `freebsd` |
| `--ecosystem` | Package registries, for languages: `npm`, `pypi`, `maven`, `nuget`, `go`, `rubygems`, `crates`, `packagist`, `pub`, `hex`, `swift`, `cocoapods`, `github_actions`, `wordpress` |
| `--tag` | Any of these tags, e.g. `critical,ransomware` |
| `--where` | A field condition: path, operator (`=` `!=` `>` `>=` `<` `<=`), value; `\|` between values. Repeat for more |

```sh
npx worldsignals events --type vulnerability.published --platform windows --where 'data.cvss.severity=critical|high'
npx worldsignals watch --type vulnerability.advisory_published --ecosystem pypi --agent claude
```

## Watch live

`watch` stays connected and handles each event as it arrives. It remembers the number of the last event
it handled, so after a restart, a sleeping laptop or a dropped network it carries on from there. Each plan keeps a number of live connections open at once (Free 1, Developer 5, Team 25, Business 100); past that, `watch` says so, waits as long as the server asks and connects again.

```sh
npx worldsignals watch                                    # one JSON event per line
npx worldsignals watch --type company.registered --country PT,ES --exec ./on-event.sh
npx worldsignals watch --type procurement.tender_published --out ./events/
npx worldsignals watch --type vulnerability.exploited --agent claude --prompt ./brief.md
npx worldsignals watch --type software.released --agent codex --batch
```

| Option | Meaning |
| --- | --- |
| `--type`, `--country` | What to watch, comma-separated (`--country PT,ES,XX`). Default: the saved stream (`npx worldsignals stream`) |
| `--exec <program>` | Run it for each event (or batch), events as JSON lines on stdin, never through a shell. Arguments after `--` go to it. An access key in `WS_KEY` is left out of its environment |
| `--agent claude\|codex` | Start `claude -p` or `codex exec` (read-only sandbox) with `--prompt` (text or a file) and the events fenced off as data |
| `--out <folder>` | Write each event to its own file |
| `--batch` | Run once for events that came together: after `--batch-idle` (60 s) quiet, at most `--batch-max-wait` (600 s), or `--batch-max` (100) events |
| `--once` | Handle what is waiting, then exit: for cron |
| `--state <file>` | Where it remembers its place (default `~/.config/worldsignals/watch.json`) |
| `--from now\|start\|<number>` | Where to begin instead |

Events are handled one after another, oldest first, at least once: the place is saved only after the
program or agent finishes. For AI agents, use `--batch` or `--out`: one run that sees related events
together costs less and decides better than a run per event. The
[docs](https://worldsignals.dev/docs#delivery-modes) show the difference, with a guide per agent.

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
defence. More in the [docs](https://worldsignals.dev/docs#safety).

## Coming next

Signed webhooks, an MCP server, and a typed SDK.

## Licence

MIT, © Yumankind OÜ. The data has its own licences, named in each event's `provenance`.
