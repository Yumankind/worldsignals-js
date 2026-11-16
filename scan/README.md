# worldsignals-scan

**Check this computer for known and actively exploited vulnerabilities.** One command, free, and every finding in
full. Each one comes with the single update that fixes it, in plain language. Nothing is sent to us unless you ask.

```sh
npx worldsignals-scan
```

```
WorldSignals machine check · macOS 27.1 · 16 Nov 2026
Checked 1293 programs and packages against OSV.dev, CISA's exploited list, endoflife.date.
Sent package names and versions to OSV.dev (Google); product names to endoflife.date. Nothing went to WorldSignals.

3 updates fix all 46 known vulnerabilities that have a fix. One of them is urgent: being exploited right now.

1. Google Chrome 157.0.8103.51 → 157.0.8103.78 or later  [EXPLOITED NOW]
   44 known vulnerabilities (3 critical, 26 high, 10 medium, 5 low).
   CVE-2026-50311 is on CISA's list of exploited vulnerabilities since 12 Nov 2026.
   How: Chrome menu ⋮ → Help → About Google Chrome, then Relaunch

2. Python packages (pip): 2 packages to update
   …
No longer supported (no more security fixes from the maker):
   - Python 3.9.6: support ended 31 Oct 2025. Move to Python 3.11 or later.
```

(The output above is an example.)

## What it checks

| Where | What it reads | Matched against |
|---|---|---|
| Linux | dpkg (Debian, Ubuntu), rpm (Rocky, AlmaLinux), apk (Alpine), snap, flatpak | the distribution's own advisories (OSV.dev), so backported fixes count as fixed |
| macOS | Homebrew formulae and casks, the apps in `/Applications` | NVD by version, with `--nvd` (about 40 common apps: browsers, Zoom, VS Code, Docker, VPN clients…) |
| Everywhere | global npm and pip packages; with `--here`, the lockfiles in this folder | OSV.dev |
| All of it | | CISA's Known Exploited Vulnerabilities first, and endoflife.date for what no longer gets fixes |

Windows programs aren't read yet. Nothing needs admin rights.

## What leaves your computer

- Package names and versions go to [OSV.dev](https://osv.dev), run by Google.
- Product names such as `nodejs` go to endoflife.date.
- With `--nvd`, app names and versions go to NVD (NIST).
- CISA's catalogue is downloaded whole, so nothing is sent there.
- **Nothing goes to WorldSignals.**

`--dry-run` prints every request and its exact body and sends none. `--inventory` lists what is installed without
any request.

## Options

```
--report scan.md   every vulnerability with its score, fix and link, as Markdown
--json             the findings as one JSON object (for scripts and agents)
--here             also check package-lock.json, requirements.txt, Cargo.lock, poetry.lock, uv.lock,
                   Gemfile.lock, composer.lock in this folder
--nvd              also check known desktop apps and Homebrew formulae against NVD
--dry-run          show what would be sent; send nothing
--inventory        only list what is installed
--unchecked        list what couldn't be checked
```

It also runs over SSH (`ssh server 'npx worldsignals-scan'`), checking the machine it runs on. It needs Node 18 or
later there.

## Alerts when a new vulnerability hits a machine (optional)

The scan above is free and complete, and needs no account. If you want to hear about the next CVE, WorldSignals
can keep each machine's list of names and versions and tell you when a new vulnerability or a newly exploited one
hits it. It sends email, Slack, Teams or webhooks, and the console shows every machine.

```sh
npx worldsignals-scan --alerts --token <token>     # shows every line it would send, then asks
npx worldsignals-scan --schedule daily             # keeps the list current, as you, no admin rights
npx worldsignals-scan --forget                     # deletes it at WorldSignals and stops the schedule
```

Many machines, from the command line:

```sh
worldsignals-scan signup && worldsignals-scan upgrade          # on the paying machine
worldsignals-scan machine token --uses 10 --expires 7d         # prints the line for each machine
WS_ENROL_TOKEN=wsm_… npx worldsignals-scan machine enrol --yes # on each machine: by hand, MDM, GPO, Ansible
worldsignals-scan machines                                     # list them and the tokens still working
```

Only names and versions are sent: never file paths, user names or host names. Every request is signed with a key
made on the machine.

## How it compares

OSV-Scanner, Trivy and Grype are excellent and free, and better than this for lockfiles, containers and CI. Use
them there. This tool is for the computers themselves, people's laptops and servers:
- desktop apps are included;
- it says what is exploited now, first;
- it warns about software that no longer gets fixes;
- it groups what it finds by the update that fixes it, written for someone without a security team.

It's also published inside the [`worldsignals`](https://www.npmjs.com/package/worldsignals) CLI as `ws scan`.
Source: [github.com/Yumankind/worldsignals-js](https://github.com/Yumankind/worldsignals-js). MIT licence.
Security issues: see [SECURITY.md](https://github.com/Yumankind/worldsignals-js/blob/main/SECURITY.md).
