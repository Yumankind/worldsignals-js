# Changelog

Versions of the `worldsignals` package on npm. Not every tagged or committed version was published: 0.2.0, 0.2.1,
0.4.0 and 0.4.1 never reached npm, and their changes first shipped in the next version that did.

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
