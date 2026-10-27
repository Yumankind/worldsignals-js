# Publish notes (not committed)

Everything below is prepared on the local `polish` branch only: nothing has been pushed, released or published.

## First: 0.4.2 is already on npm

`npm view worldsignals time` shows **0.4.2 published on 2026-10-26 at 16:53 UTC** (by hand, no provenance), and its
tarball is byte-identical to `npm pack` of `v0.4.2` (`367fdac`; shasum `5551256b…`). npm's versions are 0.1.0,
0.1.1, 0.3.0, 0.3.1, 0.3.2 and 0.4.2; 0.2.x, 0.4.0 and 0.4.1 were never published.

So the "publish 0.4.2 first?" choice no longer exists. It moves to **0.4.3**, the version that would carry the new
README and the fixed description to npm (npm shows the README and description of the latest version, so npm keeps
saying "SDK and MCP server next" until a new version ships). `polish` keeps `version` at 0.4.2.

## Publish order for the next version (0.4.3)

- **A. From the laptop, before merging `publishConfig.provenance`:** quickest, no setup, but 0.4.3 has no provenance
  and the token or password path stays open until you lock it down afterwards.
- **B. Trusted publishing (recommended):** do the npm one-time setup in `RELEASING.md` (trusted publisher:
  GitHub Actions, `Yumankind` / `worldsignals-js`, workflow `release.yml`, environment `npm`), merge `polish`, bump to
  0.4.3 and push the `v0.4.3` tag; the workflow tests, publishes with provenance and makes the GitHub release. It
  needs a few minutes on npmjs.com, and the first tag is what tests the setup.

With `publishConfig.provenance: true` on `main`, A only works from a commit before that merge (or with
`npm publish --provenance=false`, which defeats the point).

Suggested sequence:

1. Push `polish`, open a PR, merge into `main`. Merging runs only `test.yml`; `release.yml` runs on `v*` tags only,
   and the existing tags (v0.3.2 to v0.4.2) were pushed before it existed, so nothing publishes.
2. Apply the repo description, topics and social preview below; create the GitHub releases for v0.4.0 to v0.4.2.
3. npm one-time setup (RELEASING.md), then cut 0.4.3 (VERSION in `bin/ws.mjs` too) and push its tag.
4. After it's published with provenance, uncomment the provenance badge at the top of README.md (in the next release).

The README's images load from `raw.githubusercontent.com/Yumankind/worldsignals-js/main/assets/…`, so they appear on
GitHub once `polish` is merged into `main`, and on npm from 0.4.3.

## Repository settings (`gh`)

Description (238 characters):

> Real-world events for code and AI agents: new companies, public tenders, vulnerabilities, outages and AI models as one standard stream. The worldsignals command line tool (npx worldsignals); the MCP server is live at worldsignals.dev/mcp.

Topics (20; every current topic is kept): `ai-agents`, `mcp`, `cli`, `nodejs`, `events`, `real-time`,
`event-stream`, `server-sent-events`, `cloudevents`, `webhooks`, `osint`, `threat-intelligence`, `cve`,
`vulnerabilities`, `brand-protection`, `company-data`, `public-data`, `open-data`, `public-procurement`,
`claude-code`.

```sh
gh repo edit Yumankind/worldsignals-js \
  --description "Real-world events for code and AI agents: new companies, public tenders, vulnerabilities, outages and AI models as one standard stream. The worldsignals command line tool (npx worldsignals); the MCP server is live at worldsignals.dev/mcp." \
  --add-topic ai-agents,mcp,cli,nodejs,events,real-time,event-stream,server-sent-events,cloudevents,webhooks,osint,threat-intelligence,cve,vulnerabilities,brand-protection,company-data,public-data,open-data,public-procurement,claude-code

# The source request form labels issues "source request"; GitHub skips labels that don't exist.
gh label create "source request" -R Yumankind/worldsignals-js --color FF6A33 --description "A source or event type to collect"
```

The homepage stays `https://worldsignals.dev/docs#cli`.

**Social preview:** there's no `gh` command or API for it. Settings → General → Social preview → Edit → Upload
`assets/social-preview.png` (1280×640, 425 KB).

## GitHub releases

v0.3.2 is currently the only release, marked Latest. Create the older two first, not as latest, then v0.4.2 as
latest. Save each block below to the named file (without the fence), then run:

```sh
gh release create v0.4.0 -R Yumankind/worldsignals-js --verify-tag --title "v0.4.0 (not published)" --latest=false --notes-file notes-0.4.0.md
gh release create v0.4.1 -R Yumankind/worldsignals-js --verify-tag --title "v0.4.1 (not published)" --latest=false --notes-file notes-0.4.1.md
gh release create v0.4.2 -R Yumankind/worldsignals-js --verify-tag --title "v0.4.2: agent accounts" --latest --notes-file notes-0.4.2.md
```

`notes-0.4.2.md`:

````markdown
The first npm release of agent accounts: an AI agent gets a WorldSignals account of its own, with no email.

```sh
npx worldsignals watch --type company.registered --agent claude
```

**Agent accounts**
- `signup` makes the agent's account and an Ed25519 key pair on this device; the private key never leaves it, and every request is signed with it.
- `upgrade` prints a Stripe payment link for the agent's own plan (Developer, Team or Business); `connect` prints a code a person approves at worldsignals.dev/link, so the agent uses their account.
- `status`, `billing`, `keys rotate` and `recover` (a new key for an agent whose key was lost, approved by its person).
- `watch` signs the agent up by itself the first time, prints the payment link and the connect code, and starts once one is done.

**Also**
- `stream` / `stream set`: the saved stream `watch` uses by default.
- Filters: `--language`; text (`*=` `!*=` `^=` `$=`), regular-expression (`~=` `!~=`) and place (`place.near`, `place.within`) conditions for `--where`.
- `watch` waits out the plan's limit on live connections open at once, with the server's message, and connects again.
- Removed: the email sign-up and `key --link`; `init`, `pay` and `portal` remain as aliases.

0.4.0 and 0.4.1 were tagged but never published; this release includes them. Published by hand, without provenance; later versions are published by the release workflow with npm provenance.

npm: https://www.npmjs.com/package/worldsignals/v/0.4.2 · Changelog: https://github.com/Yumankind/worldsignals-js/blob/main/CHANGELOG.md
````

`notes-0.4.1.md`:

```markdown
Tagged but never published to npm: superseded by [v0.4.2](https://github.com/Yumankind/worldsignals-js/releases/tag/v0.4.2), which includes it.

- `help` lists the place conditions for `--where`: `place.near` and `place.within`.
```

`notes-0.4.0.md`:

```markdown
Tagged but never published to npm: superseded by [v0.4.2](https://github.com/Yumankind/worldsignals-js/releases/tag/v0.4.2), which includes it.

- Agent accounts: `signup` (a device key, no email), `upgrade`, `connect`, `status`, `billing`, `keys rotate`, `recover`; `watch` signs up by itself.
```

## npm package metadata on `polish`

- `description` (185 characters): "Real-world events for code and AI agents: new companies, tenders, vulnerabilities,
  outages and AI models as one standard stream. The CLI; the MCP server is live at worldsignals.dev/mcp."
- keywords added: `real-time`, `company-data`, `threat-intelligence`, `osint`, `brand-protection`, `public-data`.
- `npm pack --dry-run` ships 4 files: `LICENSE`, `README.md`, `bin/ws.mjs`, `package.json` (26.2 kB). `assets/` stays
  out (the `files` allow-list is unchanged).
