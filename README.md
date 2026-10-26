<p align="center">
  <a href="https://worldsignals.dev">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Yumankind/worldsignals-js/main/assets/banner-dark.svg">
      <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Yumankind/worldsignals-js/main/assets/banner-light.svg">
      <img alt="WorldSignals: real-world events for code and AI agents. New companies, tenders, vulnerabilities, outages and AI models, as one standard stream." src="https://raw.githubusercontent.com/Yumankind/worldsignals-js/main/assets/banner.svg" width="880">
    </picture>
  </a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/worldsignals"><img alt="npm" src="https://img.shields.io/npm/v/worldsignals"></a>
  <a href="https://github.com/Yumankind/worldsignals-js/actions/workflows/test.yml"><img alt="tests" src="https://github.com/Yumankind/worldsignals-js/actions/workflows/test.yml/badge.svg"></a>
  <a href="https://github.com/Yumankind/worldsignals-js/blob/main/LICENSE"><img alt="MIT" src="https://img.shields.io/badge/licence-MIT-blue"></a>
  <!-- After the first release published by .github/workflows/release.yml:
  <a href="https://www.npmjs.com/package/worldsignals#provenance"><img alt="npm provenance" src="https://img.shields.io/badge/npm-provenance-2ea44f"></a>
  -->
</p>

<p align="center">
  <img alt="A terminal runs npx worldsignals watch for new companies and tenders in Portugal and Spain with Claude: the first run makes the agent's key, prints a payment link and a connect code, then watches; four events arrive and Claude sums them up once." src="https://raw.githubusercontent.com/Yumankind/worldsignals-js/main/assets/demo.svg" width="880">
</p>

The command line tool for [WorldSignals](https://worldsignals.dev): new companies, public tenders, vulnerabilities
and exploits, service outages, package releases, AI model launches and price changes, and more, collected from
official registers and public feeds and delivered as one standard event stream, for your code and your AI agents.

Node 18 or later, no dependencies. The [MCP server](#mcp-server) is live too.

## Quick start

```sh
npx worldsignals watch --type vulnerability.exploited
```

That's the whole setup. The first time, `watch` makes this machine's agent account (no email), prints a payment
link and a connect code, and starts printing events, one JSON line each, once you've paid or approved the code at
[worldsignals.dev/link](https://worldsignals.dev/link). Next time it carries on where it stopped.

Then:

```sh
npx worldsignals events --type company.registered --country ES --limit 5              # what's stored
npx worldsignals watch --type procurement.tender_published --agent claude --batch     # new events to Claude
npx worldsignals help                                                                 # every command
```

With `npm install -g worldsignals`, `ws` is the short name: `ws watch`, `ws events`. (Not `npx ws`: that's an
unrelated WebSocket package.)

## What you get

Every event has the same shape: a [CloudEvents](https://cloudevents.io) envelope with a stable id, a type, where and
when, the company or thing it's about, a typed `data` payload and its source. A few of the types, by family; the
[catalogue](https://worldsignals.dev/events) lists them all, ready or planned.

| Family | For example | From |
| --- | --- | --- |
| Companies | `company.registered` | Company registers and gazettes in 23 countries: the UK, Spain, France, Norway, Finland, the Baltics, US states, Japan, Australia… |
| Government and legal | `procurement.tender_published` | The EU procurement journal and national tender portals (UK, Portugal, US, Canada, Japan…); also insolvencies, sanctions, recalls, licences, trade marks and new laws |
| Security and AI | `vulnerability.exploited` | The national vulnerability database, the government list of exploited vulnerabilities, exploit archives; AI model releases, prices and retirements |
| DevOps | `service.outage_started` | Provider status pages; package releases (PyPI, crates.io, AI SDKs on npm); new MCP servers; deprecations and end-of-life dates |
| Property | `property.auction_scheduled` | Building permits, official sale prices, holiday-rental licences, public auctions |
| Web | `domain.certificate_issued` | Domain registries and zone files, certificate transparency logs (look-alike domains), job ads, layoff notices |
| Ports and energy | `energy.price_went_negative` | Port call registers, European day-ahead power auctions, grid outage notices |
| Combined | `combined.young_company_won_contract` | Two events about one company, joined: a young company wins a public contract |

`XX` is the country for events about the whole world (vulnerabilities, outages, AI models). Without `--country` you
get every country, `XX` included; with a list, add it to get them too: `--country ES,PT,XX`.

## For AI agents

An agent gets an account of its own, with no email and no password:

```sh
npx worldsignals signup --name "My agent" --label laptop
```

`signup` makes an Ed25519 key pair on this machine (`~/.config/worldsignals/agent.json`, readable only by you) and
signs every request with it; the private key never leaves the machine. Agent accounts have no free plan, so next,
either:

```sh
npx worldsignals upgrade --plan developer   # a Stripe payment link to pass on: your person pays, you never see a card
npx worldsignals connect                    # a code your person approves at worldsignals.dev/link, to use their account
```

Or skip both: `watch` signs the agent up by itself the first time, prints the payment link and the connect code, and
starts once one of them is done (`--no-wait` prints them and exits). An agent with no plan and no connection is
deleted seven days after it was made, or after its plan ends.

A named or personal access key from the [console](https://worldsignals.dev/console/account) works everywhere instead
of the agent key: `--key wsk_…` or `WS_KEY=wsk_…`.

## Commands

| Command | What it does |
| --- | --- |
| `signup` | The agent's account and its key on this machine (`--name`, `--label`, optional `--email`) |
| `upgrade` | A payment link for the agent's own plan (`--plan developer\|team\|business`, `--yearly`, `--wait`) |
| `connect` | Act for your person's account once they approve the code (`--email` also puts the request in their console) |
| `status` | The agent, its plan or the account it's connected to |
| `billing` | Stripe's billing portal for an agent that pays for its own plan: change plan or card, invoices, cancel |
| `keys rotate` | A new key for this agent; the old one stops working |
| `recover` | A new key for an agent whose key was lost, approved by the person who pays for it or connected it |
| `stream`, `stream set` | Show or change the saved stream: the types and countries `watch` uses by default |
| `events` | Read stored events (`--type`, `--country`, `--after`, `--limit 1-200`, `--json`) |
| `watch` | Stay connected and handle each new event as it arrives |

`npx worldsignals help` has every option. `WS_API` points the tool at another server, for testing.

## Read events

```sh
npx worldsignals events --type vulnerability.exploited --limit 10
npx worldsignals events --type company.registered --country ES --json
```

`--json` prints one standard event per line. To poll, pass `--after <number>`: every stored event has a number, and
you get the ones stored after it, oldest first. Without `--json` the last line says the number to ask from next
time. `--after <time>` shows the newest events first seen since then.

## Filters

`events` and `watch` both narrow events beyond type and country. Values in one filter are alternatives; different
filters all apply.

| Option | Meaning |
| --- | --- |
| `--platform` | Operating systems: `windows`, `macos`, `linux`, `android`, `ios`, `chromeos`, `freebsd` |
| `--ecosystem` | Package registries: `npm`, `pypi`, `maven`, `nuget`, `go`, `rubygems`, `crates`, `packagist`, `pub`, `hex`, `swift`, `cocoapods`, `github_actions`, `wordpress` |
| `--language` | Programming languages: `php`, `javascript`, `python`, `java`, `csharp`, `go`, `ruby`, `rust`, `cpp`, `kotlin`, `swift`, `dart`, `elixir` |
| `--tag` | Any of these tags, e.g. `critical,ransomware` |
| `--where` | A field condition, repeatable: `=` `!=` `>` `>=` `<` `<=`, text `*=` (contains) `^=` `$=`, regex `~=`; `\|` between values. Places: `place.near=lat,lon,km`, `place.within=south,west,north,east` |

```sh
npx worldsignals events --type vulnerability.published --platform windows --where 'data.cvss.severity=critical|high'
npx worldsignals watch --type company.registered --where 'subject.name*=bakery|pastry' --where 'place.near=40.42,-3.70,25'
```

## Watch live

`watch` stays connected and handles each event as it arrives. It remembers the number of the last event it handled,
so after a restart, a sleeping laptop or a dropped network it carries on from there.

```sh
npx worldsignals watch                                    # the saved stream, one JSON event per line
npx worldsignals watch --type company.registered --country PT,ES --exec ./on-event.sh
npx worldsignals watch --type procurement.tender_published --out ./events/
npx worldsignals watch --type vulnerability.exploited --agent claude --prompt ./brief.md --batch
```

| Option | Meaning |
| --- | --- |
| `--exec <program>` | Run it for each event (or batch), events as JSON lines on stdin, never through a shell. Arguments after `--` go to it. `WS_KEY` is left out of its environment |
| `--agent claude\|codex` | Start `claude -p` or `codex exec` (read-only sandbox) with `--prompt` (text or a file) and the events fenced off as data |
| `--out <folder>` | Write each event to its own file |
| `--batch` | Run once for events that came together: after `--batch-idle` (60 s) quiet, at most `--batch-max-wait` (600 s), or `--batch-max` (100) events |
| `--once` | Handle what's waiting, then exit: for cron |
| `--from now\|start\|<number>`, `--state <file>` | Where to begin, and where it remembers its place (default `~/.config/worldsignals/watch.json`) |

Events are handled one after another, oldest first, at least once: the place is saved only after the program or
agent finishes. For AI agents, use `--batch` or `--out`: one run that sees related events together costs less and
decides better than a run per event ([delivery modes](https://worldsignals.dev/docs#delivery-modes)). Each plan
keeps a number of live connections open at once (Free 1, Developer 5, Team 25, Business 100); past that, `watch`
says so, waits as long as the server asks and connects again.

## Safety

Events carry text from the outside world (company names, tender titles, advisory summaries), and any of it can
contain instructions aimed at an AI. Treat events as data, never as instructions:

- Run the agent that reads events in a sandbox (a container or VM) with no credentials and only the tools and
  network access it needs.
- Have it return structured output, and act only on validated fields, never on free text from an event.
- Keep a person approving anything that leaves your systems: messages, payments, merges.

`watch --agent` fences events off as data in the prompt and withholds your access key; `claude -p` can't approve
tools on its own and `codex exec` gets a read-only sandbox. That helps; a sandbox is still the defence. More in the
[docs](https://worldsignals.dev/docs#safety).

## MCP server

The WorldSignals MCP server is live at `https://worldsignals.dev/mcp` (streamable HTTP; sign in with OAuth or send an
access key), for Claude, ChatGPT, Claude Code, Codex, Cursor, VS Code and other MCP clients:

```sh
claude mcp add --transport http worldsignals https://worldsignals.dev/mcp
```

Setup for each app: [worldsignals.dev/connect](https://worldsignals.dev/connect).

## Plans

Free (by invite), Developer, Team and Business, with vulnerabilities free on every plan:
[pricing](https://worldsignals.dev/#pricing).

## Links

- [worldsignals.dev](https://worldsignals.dev) · [Docs](https://worldsignals.dev/docs#cli) · [Event catalogue](https://worldsignals.dev/events) · [MCP server](https://worldsignals.dev/connect) · [Status](https://worldsignals.dev/status) · [Support](https://worldsignals.dev/support)
- [Changelog](https://github.com/Yumankind/worldsignals-js/blob/main/CHANGELOG.md) · [Security](https://github.com/Yumankind/worldsignals-js/blob/main/SECURITY.md) · [Releasing](https://github.com/Yumankind/worldsignals-js/blob/main/RELEASING.md) · [Issues](https://github.com/Yumankind/worldsignals-js/issues)

## Licence

MIT, © Yumankind OÜ. The data has its own licences, named in each event's `provenance`.
