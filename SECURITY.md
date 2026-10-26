# Security

## Reporting a vulnerability

Please report it privately, not in a public issue: email **hello@worldsignals.dev** with "Security" in the subject; it's also on
[worldsignals.dev/support#security](https://worldsignals.dev/support#security). Please give us a chance to fix
it before telling others.

Say what you found, how to reproduce it, and what someone could do with it. A proof of concept helps; please don't
access other people's data, degrade the service or keep anything you come across while testing.

## What's in scope

- **This package**: the `worldsignals` command line tool (`bin/ws.mjs`), for example how it stores the agent key,
  signs requests, runs programs and agents for `watch`, or handles what the server and events send it.
- **The WorldSignals service** (worldsignals.dev: the API, the stream, the MCP server, the console, agent accounts):
  report it the same way.

Out of scope here: instructions or misleading text inside events. Events carry text from public sources, and the
README's [Safety](README.md#safety) section explains how to treat it as data. If the CLI itself fails to fence events
off or withhold your key as documented, that is in scope.

## What to expect

WorldSignals is run by a small team, so we don't promise fixed deadlines. We aim to confirm we've received your report
within a few working days, keep you posted while we look into it, and tell you when a fix is out. Fixes to the CLI
ship as a new npm version, noted in the [changelog](CHANGELOG.md). We're glad to credit you once it's fixed, if you'd
like.

## Supported versions

Only the latest version on npm gets fixes. Run `npx worldsignals@latest`, or update a global install with
`npm install -g worldsignals@latest`.
