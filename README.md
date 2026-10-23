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

`--json` prints one standard event per line. `--after <time>` reads only events first seen after that
time, to poll for new ones.

| Option | Meaning |
| --- | --- |
| `--type` | Comma-separated event types, from the [catalogue](https://worldsignals.io/events) |
| `--country` | ISO country code |
| `--limit` | 1 to 200 |
| `--key` | Your access key, or set `WS_KEY` |

`WS_API` points the tool at another server, for testing.

## Coming next

`worldsignals watch` (run a program, write files or start an agent for each event), signed webhooks, an
MCP server, and a typed SDK.

## Licence

MIT, © Yumankind OÜ. The data has its own licences, named in each event's `provenance`.
