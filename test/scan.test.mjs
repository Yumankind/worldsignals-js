// ws scan: the pure part (versions, scores, parsers, matching, report) on fixtures, then whole scans with a fake
// machine and fake databases: what it prints, and that --dry-run sends nothing and nothing goes to WorldSignals.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { run } from "../bin/ws.mjs";
import {
  EOL_API,
  KEV_URL,
  OSV_API,
  appFor,
  appFromInfo,
  compareDpkg,
  compareGeneric,
  compareRpm,
  cvss3Score,
  distroEcosystem,
  eolFinding,
  eolTargets,
  exploitedAs,
  groupFindings,
  nvdFindings,
  osvFindings,
  osvFix,
  osvSeverity,
  parseApk,
  parseBrew,
  parseDpkg,
  parseGemfileLock,
  parseNpmLs,
  parseOsRelease,
  parsePackageLock,
  parseRequirements,
  parseRpm,
  parseTomlPackages,
  scan,
  machineCommand,
  cronTable,
  launchdPlist,
  machinePath,
  readMachine,
  schtasksArgs,
  scheduleTime,
  systemdUnits,
  uploadPayload,
} from "../bin/scan.mjs";
import { readFileSync, statSync } from "node:fs";
const statMode = (p) => statSync(p).mode;
import { generateKeyPairSync, createPublicKey, verify, createHash } from "node:crypto";

test("dpkg order: tilde before release, epochs first, backported revisions", () => {
  assert.equal(compareDpkg("1.0~rc1", "1.0"), -1);
  assert.equal(compareDpkg("1:0.9", "2.0"), 1);
  assert.equal(compareDpkg("3.0.13-0ubuntu3.1", "3.0.13-0ubuntu3.5"), -1);
  assert.equal(compareDpkg("2.36.1-8+deb11u1", "2.36.1-8+deb11u2"), -1);
  assert.equal(compareDpkg("1.2.3+dfsg-1", "1.2.3-1"), 1);
  assert.equal(compareDpkg("1.0-1", "1.0-1"), 0);
  assert.equal(compareDpkg("3.0.11-1~deb12u2", "3.0.13-1~deb12u1"), -1);
});

test("rpm order: epoch, version, release, ~ and ^", () => {
  assert.equal(compareRpm("1:3.0.7-24.el9", "1:3.0.7-25.el9_3"), -1);
  assert.equal(compareRpm("3.0.7-24.el9", "1:3.0.1-1"), -1);
  assert.equal(compareRpm("1.0a", "1.0"), 1);
  assert.equal(compareRpm("1.0~rc1", "1.0"), -1);
  assert.equal(compareRpm("2.0^post", "2.0"), 1);
  assert.equal(compareRpm("1.10", "1.9"), 1);
});

test("other versions: pre-releases before, post-releases and -rN after, numbers as numbers", () => {
  assert.equal(compareGeneric("1.0rc1", "1.0"), -1);
  assert.equal(compareGeneric("1.0", "1.0.0"), 0);
  assert.equal(compareGeneric("1.0.post1", "1.0"), 1);
  assert.equal(compareGeneric("1.0.dev1", "1.0a1"), -1);
  assert.equal(compareGeneric("1.2.3-beta.1", "1.2.3"), -1);
  assert.equal(compareGeneric("3.3.1-r0", "3.3.1-r10"), -1);
  assert.equal(compareGeneric("10.0", "9.9"), 1);
  assert.equal(compareGeneric("v2.1", "2.0.9"), 1);
  assert.equal(compareGeneric("1.0.1", "1.0rc1"), 1);
  assert.equal(compareGeneric("1.0+build.5", "1.0"), 0);
});

test("CVSS 3 base scores from vectors", () => {
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"), 8.8);
  assert.equal(cvss3Score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8);
  assert.equal(cvss3Score("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"), 5.9);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"), 6.4);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  assert.equal(cvss3Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), null);
});

test("severity: CVSS 3 first, then the database's or the distribution's rating", () => {
  assert.deepEqual(osvSeverity({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }), { severity: "critical", score: 9.8 });
  assert.equal(osvSeverity({ database_specific: { severity: "MODERATE" } }).severity, "medium");
  assert.equal(osvSeverity({ severity: [{ type: "Ubuntu", score: "high" }] }).severity, "high");
  assert.equal(osvSeverity({}, { ecosystem_specific: { urgency: "unimportant" } }).severity, "low");
  assert.equal(osvSeverity({}, { ecosystem_specific: { urgency: "not yet assigned" } }).severity, "unrated");
});

test("distributions map to OSV's ecosystems; ones OSV lacks map to none", () => {
  const eco = (text) => distroEcosystem(parseOsRelease(text));
  assert.equal(eco('ID=debian\nVERSION_ID="12"\n'), "Debian:12");
  assert.equal(eco('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\n'), "Ubuntu:24.04:LTS");
  assert.equal(eco('ID=ubuntu\nVERSION_ID="25.10"\nVERSION="25.10 (Questing Quokka)"\n'), "Ubuntu:25.10");
  assert.equal(eco("ID=alpine\nVERSION_ID=3.20.3\n"), "Alpine:v3.20");
  assert.equal(eco('ID="rocky"\nVERSION_ID="9.4"\n'), "Rocky Linux:9");
  assert.equal(eco('ID=fedora\nVERSION_ID=41\n'), null);
});

test("dpkg: one item per source package, installed rows only", () => {
  const text = ["libssl3\t3.0.13-0ubuntu3.1\topenssl\t3.0.13-0ubuntu3.1\tii ", "openssl\t3.0.13-0ubuntu3.1\topenssl\t3.0.13-0ubuntu3.1\tii ", "curl\t8.5.0-2ubuntu10.1\t\t\tii ", "oldpkg\t1.0\t\t\trc "].join("\n");
  const items = parseDpkg(text, "Ubuntu:24.04:LTS");
  assert.deepEqual(
    items.map((i) => [i.name, i.version, i.binaries.join(",")]),
    [
      ["openssl", "3.0.13-0ubuntu3.1", "libssl3,openssl"],
      ["curl", "8.5.0-2ubuntu10.1", "curl"],
    ],
  );
  assert.equal(items[0].ecosystem, "Ubuntu:24.04:LTS");
});

test("rpm: epoch kept, (none) dropped, keys skipped", () => {
  const items = parseRpm("openssl\t1\t3.0.7\t24.el9\topenssl-3.0.7-24.el9.src.rpm\nbash\t(none)\t5.1.8\t9.el9\tbash-5.1.8-9.el9.src.rpm\ngpg-pubkey\t(none)\tabc\tdef\t(none)", "Rocky Linux:9");
  assert.deepEqual(items.map((i) => [i.name, i.version, i.group]), [["openssl", "1:3.0.7-24.el9", "openssl"], ["bash", "5.1.8-9.el9", "bash"]]);
});

test("apk: grouped by origin", () => {
  const db = "C:Q1abc=\nP:libcrypto3\nV:3.3.1-r0\no:openssl\n\nC:Q1def=\nP:libssl3\nV:3.3.1-r0\no:openssl\n\nP:busybox\nV:1.36.1-r29\no:busybox\n";
  assert.deepEqual(parseApk(db, "Alpine:v3.20").map((i) => [i.name, i.version, i.binaries.length]), [["openssl", "3.3.1-r0", 2], ["busybox", "1.36.1-r29", 1]]);
});

test("Homebrew, app bundles and npm's global tree", () => {
  const brew = parseBrew({ formulae: [{ name: "openssl@3", installed: [{ version: "3.6.3_1" }] }], casks: [{ token: "google-chrome", installed: "157.0.8103.51", name: ["Google Chrome"] }] });
  assert.deepEqual(brew.map((i) => [i.source, i.name, i.version]), [["brew", "openssl@3", "3.6.3"], ["brew-cask", "google-chrome", "157.0.8103.51"]]);
  assert.equal(appFor(brew[0]).label, "OpenSSL");
  assert.equal(appFor(brew[1]).label, "Google Chrome");
  const zoom = appFromInfo({ CFBundleIdentifier: "us.zoom.xos", CFBundleShortVersionString: "6.4.10 (60000)", CFBundleName: "zoom.us" }, "/Applications/zoom.us.app");
  assert.deepEqual([zoom.name, zoom.version], ["us.zoom.xos", "6.4.10"]);
  assert.deepEqual(appFor(zoom).cpes, ["zoom:zoom", "zoom:workplace_desktop", "zoom:meetings"]);
  const npm = parseNpmLs({ dependencies: { wrangler: { version: "4.0.0", dependencies: { undici: { version: "5.0.0" } } }, vercel: { version: "40.0.0", dependencies: { undici: { version: "5.0.0" } } } } });
  assert.deepEqual(npm.find((i) => i.name === "undici").via, ["wrangler", "vercel"]);
});

test("lockfiles", () => {
  const lock = parsePackageLock({ lockfileVersion: 3, packages: { "": { name: "app" }, "node_modules/lodash": { version: "4.17.20" }, "node_modules/a/node_modules/@scope/b": { version: "1.0.0" }, "node_modules/local": { version: "file:../x" } } });
  assert.deepEqual(lock.map((i) => `${i.name}@${i.version}`), ["lodash@4.17.20", "@scope/b@1.0.0"]);
  assert.deepEqual(parseRequirements("requests==2.31.0\nflask>=2.0\nDjango[argon2] == 4.2.1 ; python_version>'3.8'\n# pinned==1.0\n").map((i) => `${i.name}@${i.version}`), ["requests@2.31.0", "Django@4.2.1"]);
  assert.deepEqual(parseTomlPackages('[[package]]\nname = "serde"\nversion = "1.0.100"\n\n[[package]]\nname = "rand"\nversion = "0.8.5"\n', "Cargo.lock", "crates.io").map((i) => i.name), ["serde", "rand"]);
  assert.deepEqual(parseGemfileLock("GEM\n  specs:\n    rack (2.2.3)\n    nokogiri (1.13.0-x86_64-linux)\n      racc (~> 1.4)\n").map((i) => `${i.name}@${i.version}`), ["rack@2.2.3", "nokogiri@1.13.0"]);
});

// One Debian advisory as OSV writes it: the same source package in two releases, each with its own fix.
const DEBIAN_VULN = {
  id: "DEBIAN-CVE-2026-1111",
  upstream: ["CVE-2026-1111"],
  affected: [
    { package: { name: "openssl", ecosystem: "Debian:12" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.0.17-1~deb12u3" }] }], ecosystem_specific: { urgency: "high" } },
    { package: { name: "openssl", ecosystem: "Debian:13" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.5.1-1" }] }] },
  ],
};

test("the fix is this release's, the lowest above what is installed", () => {
  const item = { name: "openssl", version: "3.0.17-1~deb12u2", ecosystem: "Debian:12" };
  assert.equal(osvFix(DEBIAN_VULN, item).fixed, "3.0.17-1~deb12u3");
  const many = { id: "X", affected: [{ package: { name: "pkg", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.2.0" }, { introduced: "2.0" }, { fixed: "2.3.1" }, { introduced: "3.0" }, { fixed: "3.0.2" }] }] }] };
  assert.equal(osvFix(many, { name: "pkg", version: "2.1", ecosystem: "PyPI" }).fixed, "2.3.1");
  const none = { id: "Y", affected: [{ package: { name: "pkg", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }] }] };
  assert.equal(osvFix(none, { name: "pkg", version: "2.1", ecosystem: "PyPI" }).fixed, null);
});

test("KEV marks a finding exploited through the advisory's CVE", () => {
  const kev = new Map([["CVE-2026-1111", { cveID: "CVE-2026-1111", dateAdded: "2026-11-12", knownRansomwareCampaignUse: "Known" }]]);
  const [f] = osvFindings({ name: "openssl", version: "3.0.17-1~deb12u2", ecosystem: "Debian:12" }, [DEBIAN_VULN], kev);
  assert.deepEqual(f.exploited, { since: "2026-11-12", ransomware: true });
  assert.equal(f.severity, "high");
  assert.equal(f.link, "https://nvd.nist.gov/vuln/detail/CVE-2026-1111");
});

test("NVD: configurations for another OS are left out; the fix is versionEndExcluding", () => {
  const app = appFor({ source: "app", name: "com.google.Chrome" });
  const cve = (id, nodes) => ({ cve: { id, metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 8.8 } }] }, descriptions: [{ lang: "en", value: id }], configurations: [{ nodes }] } });
  const chrome = (end) => ({ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding: end }] });
  const on = (os) => ({ cpeMatch: [{ vulnerable: false, criteria: `cpe:2.3:o:${os}:-:*:*:*:*:*:*:*` }] });
  const answer = [cve("CVE-A", [chrome("158.0.1")]), cve("CVE-B", [chrome("158.0.2"), on("google:android")]), cve("CVE-C", [chrome("158.0.3"), on("apple:macos")])];
  const found = nvdFindings(app, { version: "157.0.8103.51" }, answer, new Map(), "macos");
  assert.deepEqual(found.map((f) => [f.id, f.fixed, f.severity, f.confidence]), [["CVE-A", "158.0.1", "high", "likely"], ["CVE-C", "158.0.3", "high", "likely"]]);
});

test("NVD: ranges written as dates (git snapshots) don't match a release number", () => {
  const app = appFor({ source: "brew", name: "ffmpeg" });
  const answer = [{ cve: { id: "CVE-D", metrics: {}, configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*", versionEndExcluding: "2025-01-13" }] }] }] } }];
  assert.deepEqual(nvdFindings(app, { version: "8.1.2" }, answer, new Map(), "macos"), []);
});

test("exploited through another product: said so, and ranked after exploits of this one", () => {
  const kev = { cveID: "CVE-2026-97229", vendorProject: "GitLab", product: "Community Edition and Enterprise Edition", dateAdded: "2026-10-29" };
  assert.deepEqual(exploitedAs(kev, ["Ruby", "ruby-lang", "ruby"]), { since: "2026-10-29", ransomware: false, elsewhere: "GitLab Community Edition and Enterprise Edition" });
  assert.equal(exploitedAs({ ...kev, vendorProject: "Google", product: "Chromium V8" }, ["Google Chrome", "google", "chrome"]).elsewhere, undefined);
  const f = (id, exploited) => ({ id, cves: [id], severity: "high", score: null, fixed: "2", exploited, summary: "", link: "", confidence: "likely" });
  const app = (name) => ({ source: "brew", name, version: "1" });
  const { groups } = groupFindings([
    { item: app("ruby"), app: appFor(app("ruby")), findings: [f("CVE-R", { since: "2026-10-29", elsewhere: "GitLab" })] },
    { item: app("curl"), app: appFor(app("curl")), findings: [f("CVE-C", { since: "2026-11-01" })] },
  ]);
  assert.deepEqual(groups.map((g) => g.title), ["curl", "Ruby"]);
});

test("end of life: the oldest newer release still supported", () => {
  const now = new Date("2026-11-16T00:00:00Z");
  const answer = { result: { releases: [{ name: "4.0", label: "4.0", isMaintained: true }, { name: "3.6", isEol: true, eolFrom: "2026-11-01" }, { name: "3.5", label: "3.5 (LTS)", isMaintained: true }, { name: "1.0.2", label: "1.0.2", isMaintained: true }] } };
  const [t] = eolTargets({ items: [{ source: "brew", name: "openssl@3", version: "3.6.3" }] });
  assert.deepEqual([t.product, t.cycle], ["openssl", "3.6"]);
  const f = eolFinding(t, answer, now);
  assert.equal(f.move_to, "OpenSSL 4.0");
  assert.equal(f.eol_on, "2026-11-01");
  assert.equal(eolFinding({ ...t, cycle: "3.5" }, answer, now), null);
});

test("groups: exploited first, one command per kind, no-fix findings apart", () => {
  const f = (id, severity, fixed, exploited = null) => ({ id, cves: [id], severity, score: null, fixed, exploited, summary: "", link: "", confidence: "confirmed" });
  const { groups, noFix } = groupFindings([
    { item: { source: "pip", name: "requests", version: "2.0", ecosystem: "PyPI" }, findings: [f("CVE-1", "medium", "2.32.4")] },
    { item: { source: "pip", name: "jinja2", version: "3.1.2", ecosystem: "PyPI" }, findings: [f("CVE-2", "high", "3.1.6"), f("CVE-3", "low", null)] },
    { item: { source: "app", name: "com.google.Chrome", version: "157.0" }, app: appFor({ source: "app", name: "com.google.Chrome" }), findings: [f("CVE-4", "medium", "158.0", { since: "2026-11-12" })] },
  ]);
  assert.deepEqual(groups.map((g) => g.title), ["Google Chrome", "Python packages (pip)"]);
  assert.equal(groups[1].how, "python3 -m pip install -U requests jinja2");
  assert.deepEqual(noFix.map((x) => [x.id, x.package]), [["CVE-3", "jinja2"]]);
});

// ------------------------------------------------------------------------------------------------------------
// Whole scans on a fake Ubuntu machine.

const OS_RELEASE = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\nID=ubuntu\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n';
const DPKG = "libssl3t64\t3.0.13-0ubuntu3.1\topenssl\t3.0.13-0ubuntu3.1\tii \ncurl\t8.5.0-2ubuntu10.6\t\t\tii \n";
const PIP = JSON.stringify([{ name: "requests", version: "2.31.0" }]);
const UBUNTU_VULN = {
  id: "UBUNTU-CVE-2026-2222",
  upstream: ["CVE-2026-2222"],
  summary: "openssl: crafted certificate crashes the server",
  severity: [{ type: "Ubuntu", score: "high" }],
  affected: [{ package: { name: "openssl", ecosystem: "Ubuntu:24.04:LTS" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.0.13-0ubuntu3.5" }] }] }],
};
const PYPI_VULN = {
  id: "GHSA-aaaa-bbbb-cccc",
  aliases: ["CVE-2026-3333"],
  summary: "Requests leaks credentials on redirect",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N" }],
  affected: [{ package: { name: "requests", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.32.4" }] }] }],
};

function fakeMachine() {
  const ran = [];
  return {
    ran,
    sys: {
      which: (name) => (["dpkg-query", "python3"].includes(name) ? `/usr/bin/${name}` : null),
      read: (path) => (path === "/etc/os-release" ? OS_RELEASE : null),
      ls: () => [],
      run: async (cmd, args) => {
        ran.push([cmd, ...args].join(" "));
        if (cmd === "dpkg-query") return DPKG;
        if (cmd.endsWith("python3") && args[0] === "--version") return "Python 3.12.3\n";
        if (cmd.endsWith("python3") && args.includes("pip")) return PIP;
        return null;
      },
    },
  };
}

function fakeDatabases() {
  const calls = [];
  const json = (body, status = 200) => ({ ok: status < 400, status, json: async () => body, headers: new Headers() });
  const fetch = async (url, init = {}) => {
    calls.push({ url, body: init.body ? JSON.parse(init.body) : null });
    if (url === KEV_URL) return json({ vulnerabilities: [{ cveID: "CVE-2026-2222", dateAdded: "2026-11-12", knownRansomwareCampaignUse: "Unknown" }] });
    if (url === `${OSV_API}/querybatch`) {
      const { queries } = JSON.parse(init.body);
      return json({ results: queries.map((q) => (["openssl", "requests"].includes(q.package.name) ? { vulns: [{ id: "x" }] } : {})) });
    }
    if (url === `${OSV_API}/query`) {
      const q = JSON.parse(init.body);
      return json({ vulns: q.package.name === "openssl" ? [UBUNTU_VULN] : q.package.name === "requests" ? [PYPI_VULN] : [] });
    }
    if (url.startsWith(`${EOL_API}/`)) return json({ result: { releases: [{ name: "24.04", isMaintained: true }, { name: "3.12", isMaintained: true }] } });
    return json({}, 404);
  };
  return { fetch, calls };
}

async function scanWith(argv) {
  const machine = fakeMachine();
  const dbs = fakeDatabases();
  const out = [];
  const err = [];
  const env = { HOME: mkdtempSync(join(tmpdir(), "ws-scan-")), XDG_CACHE_HOME: mkdtempSync(join(tmpdir(), "ws-cache-")), PATH: "/usr/bin" };
  const code = await scan(argv, { fetch: dbs.fetch, env, out: (s) => out.push(s), err: (s) => err.push(s), platform: "linux", sys: machine.sys, now: () => new Date("2026-11-16T10:00:00Z"), version: "test" });
  return { code, out: out.join("\n"), err: err.join("\n"), calls: dbs.calls, ran: machine.ran };
}

test("a scan: exploited first, the distribution's own update, the pip command, what was sent", async () => {
  const r = await scanWith([]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /WorldSignals machine check · Ubuntu 24\.04\.1 LTS · 16 Nov 2026/);
  assert.match(r.out, /Sent package names and versions to OSV\.dev \(Google\); product names to endoflife\.date\. Nothing went to WorldSignals\./);
  assert.match(r.out, /2 updates fix all 2 known vulnerabilities that have a fix\. One of them is urgent/);
  const first = r.out.indexOf("1. Ubuntu packages: 1 package to update");
  assert.ok(first > 0 && first < r.out.indexOf("2. requests 2.31.0 → 2.32.4 (pip)"), r.out);
  assert.match(r.out, /\[EXPLOITED NOW\]/);
  assert.match(r.out, /CVE-2026-2222 is on CISA's list of exploited vulnerabilities since 12 Nov 2026/);
  assert.match(r.out, /openssl 3\.0\.13-0ubuntu3\.1 → 3\.0\.13-0ubuntu3\.5/);
  assert.match(r.out, /How: sudo apt update && sudo apt upgrade/);
  assert.match(r.out, /How: python3 -m pip install -U requests/);
  // Distro packages went to OSV under Ubuntu's ecosystem, by source package; nothing to WorldSignals.
  const batch = r.calls.find((c) => c.url.endsWith("/querybatch")).body.queries;
  assert.deepEqual(batch.find((q) => q.package.name === "openssl"), { package: { ecosystem: "Ubuntu:24.04:LTS", name: "openssl" }, version: "3.0.13-0ubuntu3.1" });
  assert.ok(r.calls.every((c) => !/worldsignals/.test(new URL(c.url).host)));
  // Only the packages OSV matched are fetched in full.
  assert.deepEqual(r.calls.filter((c) => c.url.endsWith("/v1/query")).map((c) => c.body.package.name).sort(), ["openssl", "requests"]);
});

test("--dry-run prints the requests and makes none", async () => {
  const r = await scanWith(["--dry-run"]);
  assert.equal(r.code, 0);
  assert.equal(r.calls.length, 0);
  assert.match(r.out, /POST https:\/\/api\.osv\.dev\/v1\/querybatch/);
  assert.match(r.out, /\{"package":\{"ecosystem":"Ubuntu:24\.04:LTS","name":"openssl"\},"version":"3\.0\.13-0ubuntu3\.1"\}/);
  assert.match(r.out, /GET https:\/\/endoflife\.date\/api\/v1\/products\/ubuntu/);
  assert.match(r.out, /Nothing is sent to WorldSignals\./);
});

test("--inventory makes no request; --json is one object", async () => {
  const inv = await scanWith(["--inventory"]);
  assert.equal(inv.calls.length, 0);
  assert.match(inv.out, /dpkg\tUbuntu:24\.04:LTS\topenssl\t3\.0\.13-0ubuntu3\.1/);
  const j = await scanWith(["--json"]);
  const report = JSON.parse(j.out);
  assert.equal(report.groups.length, 2);
  assert.equal(report.groups[0].exploited[0].cves[0], "CVE-2026-2222");
  assert.equal(report.sent.worldsignals, false);
});

test("OSV unreachable: said plainly, not as a clean bill of health", async () => {
  const machine = fakeMachine();
  const out = [];
  const env = { HOME: tmpdir(), XDG_CACHE_HOME: mkdtempSync(join(tmpdir(), "ws-cache-")), PATH: "/usr/bin" };
  const fetch = async () => ({ ok: false, status: 503, json: async () => ({}) });
  await scan([], { fetch, env, out: (s) => out.push(s), err: () => {}, platform: "linux", sys: machine.sys });
  assert.match(out.join("\n"), /OSV\.dev: couldn't be reached \(api\.osv\.dev answered 503\): packages weren't checked/);
});

test("ws scan is reachable from ws, with its own help", async () => {
  const out = [];
  const code = await run(["scan", "--help"], { out: (s) => out.push(s), err: () => {}, env: {} });
  assert.equal(code, 0);
  assert.match(out.join("\n"), /ws scan \[--report <file\.md>\]/);
  const bad = [];
  assert.equal(await run(["scan", "--nope"], { out: () => {}, err: (s) => bad.push(s), env: {} }), 2);
  assert.match(bad.join("\n"), /Unknown option '--nope'/);
});

// ------------------------------------------------------------------------------------------------------------
// Alerts: enrol, show what is sent, send, schedule, forget.

const API = "https://ws.test";

/** A fake WorldSignals that enrols with a token and checks each machine signature. */
function fakeWorldSignals() {
  const calls = [];
  const keys = new Map();
  const pairs = new Map();
  let polls = 0;
  const json = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    const body = init.body ?? "";
    calls.push({ method: init.method, path: u.pathname, headers: init.headers, body: body ? JSON.parse(body) : null });
    if (u.hostname !== "ws.test") return fakeDatabases().fetch(url, init);
    if (u.pathname === "/api/machines/enrol") {
      const b = JSON.parse(body);
      if (b.token !== "wsm_good") return json({ error: "That enrolment token doesn't work." }, 401);
      keys.set("m_1", b.public_key);
      return json({ machine_id: "m_1", label: b.label ?? null, account: { name: "Ribeiro & Costa" } }, 201);
    }
    // The account's own API (ws machine …), with a bearer credential.
    if (init.headers?.authorization === "Bearer acct") {
      const route = `${init.method} ${u.pathname}`;
      if (route === "GET /api/machines") return json({ machines: [...keys.keys()].map((m) => ({ id: m, label: "web-1", os: { label: "Debian 12" }, last_report_at: "2026-11-16T10:00:00Z", findings: { open: 3, exploited: 1 }, updates: 2, alerts_open: 1 })), limit: { plan: "developer", used: keys.size, limit: 10 } });
      if (route === "GET /api/machines/tokens") return json({ tokens: [{ id: "mtk_1", label: null, used: 1, max_uses: 10, expires_at: "2099-01-01T00:00:00Z", revoked_at: null }] });
      if (route === "POST /api/machines/tokens") return json({ id: "mtk_1", token: "wsm_good", uses: 10, expires_at: "2026-11-23T10:00:00Z", command: "npx worldsignals machine enrol --token wsm_good" }, 201);
      if (route === "DELETE /api/machines/tokens/mtk_1") return json({ id: "mtk_1", revoked: true });
      if (route === "POST /api/machines/approve") {
        const pairing = [...pairs.values()].find((x) => x.code === JSON.parse(body).code);
        if (!pairing) return json({ error: "No machine is waiting with that code." }, 404);
        pairing.machine = "m_2";
        keys.set("m_2", pairing.key);
        return json({ machine_id: "m_2", label: pairing.label, os: { label: "Debian 12" } }, 201);
      }
      if (init.method === "DELETE" && u.pathname.startsWith("/api/machines/")) {
        keys.delete(u.pathname.split("/").pop());
        return json({ deleted: true });
      }
    }
    if (u.pathname === "/api/machines/pair" && init.method === "POST") {
      const b = JSON.parse(body);
      pairs.set("mpr_1", { code: "BCDF-GHJK", key: b.public_key, label: b.label ?? null, machine: null });
      return json({ pair_id: "mpr_1", code: "BCDF-GHJK", expires_at: new Date(Date.now() + 900_000).toISOString() }, 201);
    }
    if (u.pathname === "/api/machines/pair/mpr_1") {
      const pairing = pairs.get("mpr_1");
      const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pairing.key }, format: "jwk" });
      const ok = verify(null, Buffer.from(`GET ${u.pathname} ${init.headers["x-ws-timestamp"]} `), pub, Buffer.from(init.headers["x-ws-signature"], "base64url"));
      if (!ok) return json({ error: "bad signature" }, 401);
      polls++;
      // Approved on the second look, as if someone ran ws machine approve meanwhile.
      if (polls >= 2 && !pairing.machine) {
        pairing.machine = "m_2";
        keys.set("m_2", pairing.key);
      }
      return json(pairing.machine ? { status: "approved", machine_id: pairing.machine } : { status: "pending" });
    }
    const id = init.headers["x-ws-machine"];
    const key = keys.get(id);
    if (!key) return json({ error: "unknown machine" }, 401);
    const hash = body ? createHash("sha256").update(body).digest("base64url") : "";
    const text = `${init.method} ${u.pathname}${u.search} ${init.headers["x-ws-timestamp"]} ${hash}`;
    const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key }, format: "jwk" });
    if (!verify(null, Buffer.from(text), pub, Buffer.from(init.headers["x-ws-signature"], "base64url"))) return json({ error: "bad signature" }, 401);
    if (u.pathname === "/api/machine/report") return json({ machine_id: id, label: "Reception PC", account: { name: "Ribeiro & Costa" }, changes: { added: 3, removed: 0, upgraded: 0 }, console_url: `${API}/console/machines/${id}` });
    if (u.pathname === "/api/machine" && init.method === "DELETE") {
      keys.delete(id);
      return json({ deleted: true });
    }
    return json({}, 404);
  };
  return { fetch, calls };
}

async function alertsWith(argv, { ws = fakeWorldSignals(), env = { HOME: mkdtempSync(join(tmpdir(), "ws-home-")), XDG_CACHE_HOME: mkdtempSync(join(tmpdir(), "ws-cache-")), WS_API: API, PATH: "/usr/bin" }, stdin = null, sysExtra = {} } = {}) {
  const machine = fakeMachine();
  const out = [];
  const err = [];
  const code = await scan(argv, { fetch: ws.fetch, env, out: (s) => out.push(s), err: (s) => err.push(s), platform: "linux", sys: { ...machine.sys, ...sysExtra }, version: "test", stdin, scriptPath: "/usr/local/lib/node_modules/worldsignals/bin/ws.mjs", nodePath: "/usr/local/bin/node" });
  return { code, out: out.join("\n"), err: err.join("\n"), ws, env };
}

test("the upload carries names and versions only, never paths", () => {
  const payload = uploadPayload(
    { os: { family: "macos", version: "27.1", label: "macOS 27.1" }, items: [{ source: "app", name: "com.google.Chrome", version: "157.0", label: "Google Chrome", path: "/Users/ana/Applications/Google Chrome.app" }, { source: "pip", ecosystem: "PyPI", name: "requests", version: "2.31.0", python: "/Users/ana/.venv/bin/python3", user: true }] },
    "0.6.0",
  );
  assert.deepEqual(payload.items[0], { source: "app", name: "com.google.Chrome", version: "157.0", label: "Google Chrome", cpes: ["google:chrome"], how: "Chrome menu ⋮ → Help → About Google Chrome, then Relaunch" });
  assert.deepEqual(payload.items[1], { source: "pip", ecosystem: "PyPI", name: "requests", version: "2.31.0" });
  assert.doesNotMatch(JSON.stringify(payload), /ana/);
});

test("--alerts with no terminal and no --yes shows the list and sends nothing", async () => {
  const r = await alertsWith(["--alerts", "--token", "wsm_good"]);
  assert.equal(r.code, 2);
  assert.match(r.out, /This is everything that goes to WorldSignals \(POST https:\/\/ws\.test\/api\/machine\/report\)/);
  assert.match(r.out, /\{"source":"dpkg","ecosystem":"Ubuntu:24\.04:LTS","name":"openssl","version":"3\.0\.13-0ubuntu3\.1"\}/);
  assert.match(r.err, /Not sent: there is no terminal to ask/);
  assert.equal(r.ws.calls.length, 0);
  assert.equal(readMachine(r.env, API), null);
});

test("--alerts --yes enrols with a token, keeps the key private, and sends a signed list", async () => {
  const r = await alertsWith(["--alerts", "--token", "wsm_good", "--label", "Reception PC", "--yes"]);
  assert.equal(r.code, 0, r.err);
  const [enrol, report] = r.ws.calls;
  assert.equal(enrol.path, "/api/machines/enrol");
  assert.equal(enrol.body.label, "Reception PC");
  assert.equal(enrol.body.consent, true);
  assert.equal(report.path, "/api/machine/report");
  assert.equal(report.headers["x-ws-machine"], "m_1");
  assert.ok(report.body.items.some((i) => i.name === "openssl"));
  assert.match(r.out, /Sent\. Reception PC is enrolled in Ribeiro & Costa/);
  assert.match(r.out, /ws scan --schedule daily/);
  const saved = readMachine(r.env, API);
  assert.equal(saved.machine_id, "m_1");
  assert.match(saved.private_key, /BEGIN PRIVATE KEY/);
  assert.equal(readFileSync(machinePath(r.env)).length > 0 && (process.platform === "win32" || (statMode(machinePath(r.env)) & 0o077) === 0), true);
  // A second run uploads with the same key, without enrolling again.
  const again = await alertsWith(["--upload"], { ws: r.ws, env: r.env });
  assert.equal(again.code, 0, again.err);
  assert.match(again.out, /sent \d+ items \(3 added, 0 removed, 0 upgraded\)/);
  assert.equal(r.ws.calls.filter((c) => c.path === "/api/machines/enrol").length, 1);
  // --forget deletes it there and here.
  const gone = await alertsWith(["--forget"], { ws: r.ws, env: r.env, sysExtra: { runWithInput: async () => true } });
  assert.equal(gone.code, 0, gone.err);
  assert.match(gone.out, /WorldSignals no longer holds this machine/);
  assert.equal(readMachine(r.env, API), null);
  assert.equal(r.ws.calls.at(-1).method, "DELETE");
});

test("a bad token is refused and nothing is kept", async () => {
  const r = await alertsWith(["--alerts", "--token", "wsm_bad", "--yes"]);
  assert.equal(r.code, 1);
  assert.match(r.err, /Not enrolled: That enrolment token doesn't work\./);
  assert.equal(readMachine(r.env, API), null);
});

test("--upload and --schedule need an enrolled machine", async () => {
  const up = await alertsWith(["--upload"]);
  assert.equal(up.code, 2);
  assert.match(up.err, /isn't enrolled for alerts/);
  const sch = await alertsWith(["--schedule", "daily"]);
  assert.equal(sch.code, 2);
  assert.match(sch.err, /isn't enrolled yet/);
});

test("--schedule writes the crontab line once, as the user, and off removes it", async () => {
  const r = await alertsWith(["--alerts", "--token", "wsm_good", "--yes"]);
  let table = "MAILTO=me\n0 1 * * * backup\n";
  const sysExtra = { run: async (cmd, args) => (cmd === "crontab" ? table : cmd === "systemctl" ? null : fakeMachine().sys.run(cmd, args)), runWithInput: async (cmd, args, input) => ((table = input), true) };
  const on = await alertsWith(["--schedule", "daily"], { ws: r.ws, env: r.env, sysExtra });
  assert.equal(on.code, 0, on.err);
  assert.match(table, /^MAILTO=me\n0 1 \* \* \* backup\n\d+ \d+ \* \* \* '\/usr\/local\/bin\/node' '\/usr\/local\/lib\/node_modules\/worldsignals\/bin\/ws\.mjs' scan --upload >\/dev\/null 2>&1 # worldsignals-scan\n$/);
  await alertsWith(["--schedule", "weekly"], { ws: r.ws, env: r.env, sysExtra });
  assert.equal(table.match(/worldsignals-scan/g).length, 1);
  assert.match(table, / \* \* 1 '/);
  assert.equal(readMachine(r.env, API).schedule, "weekly");
  await alertsWith(["--schedule", "off"], { ws: r.ws, env: r.env, sysExtra });
  assert.equal(table, "MAILTO=me\n0 1 * * * backup\n");
});

test("scheduling refuses npx's temporary folder", async () => {
  const r = await alertsWith(["--alerts", "--token", "wsm_good", "--yes"]);
  const out = [];
  const err = [];
  const code = await scan(["--schedule", "daily"], { fetch: r.ws.fetch, env: r.env, out: (s) => out.push(s), err: (s) => err.push(s), platform: "linux", sys: fakeMachine().sys, scriptPath: "/home/ana/.npm/_npx/abc/node_modules/worldsignals/bin/ws.mjs" });
  assert.equal(code, 2);
  assert.match(err.join("\n"), /npm install -g worldsignals/);
});

test("schedule files for launchd, systemd and Task Scheduler", () => {
  const spec = { node: "/opt/homebrew/bin/node", script: "/opt/homebrew/lib/node_modules/worldsignals/bin/ws.mjs", every: "weekly", hour: 10, minute: 7 };
  const plist = launchdPlist({ ...spec, log: "/Users/x/Library/Logs/worldsignals-scan.log" });
  assert.match(plist, /<key>Label<\/key><string>dev\.worldsignals\.scan<\/string>/);
  assert.match(plist, /<string>scan<\/string><string>--upload<\/string>/);
  assert.match(plist, /<key>Hour<\/key><integer>10<\/integer><key>Minute<\/key><integer>7<\/integer><key>Weekday<\/key><integer>1<\/integer>/);
  const units = systemdUnits(spec);
  assert.match(units.service, /^ExecStart="\/opt\/homebrew\/bin\/node" "\/opt\/homebrew\/lib\/node_modules\/worldsignals\/bin\/ws\.mjs" scan --upload$/m);
  // systemd's own quoting: $ and % doubled; cron's: % escaped.
  assert.match(systemdUnits({ ...spec, node: "/opt/n$1/node", script: "/x/100%/ws.mjs" }).service, /^ExecStart="\/opt\/n\$\$1\/node" "\/x\/100%%\/ws\.mjs" scan --upload$/m);
  assert.match(cronTable("", { ...spec, every: "daily", script: "/x/100%/ws.mjs" }), /'\/x\/100\\%\/ws\.mjs'/);
  assert.match(units.timer, /^OnCalendar=Mon \*-\*-\* 10:07:00$/m);
  assert.match(units.timer, /^Persistent=true$/m);
  assert.deepEqual(schtasksArgs({ ...spec, every: "daily", node: "C:\\node.exe", script: "C:\\ws.mjs" }), ["/Create", "/F", "/SC", "DAILY", "/ST", "10:07", "/TN", "WorldSignals scan", "/TR", '"C:\\node.exe" "C:\\ws.mjs" scan --upload']);
  assert.equal(cronTable("", { ...spec, every: "off" }), "");
  const t = scheduleTime("m_1");
  assert.ok(t.hour >= 9 && t.hour <= 16 && t.minute >= 0 && t.minute < 60);
  assert.deepEqual(scheduleTime("m_1"), t);
});

test("--schedule on Linux uses cron unless systemd keeps the user's timers running (linger)", async () => {
  const r = await alertsWith(["--alerts", "--token", "wsm_good", "--yes"]);
  const env = { ...r.env, USER: "ana" };
  for (const [linger, expected] of [["Linger=no\n", "cron"], ["Linger=yes\n", "systemd"]]) {
    let table = "";
    const wrote = [];
    const sysExtra = {
      run: async (cmd, args) => (cmd === "loginctl" ? linger : cmd === "systemctl" ? "PATH=/usr/bin\n" : cmd === "crontab" ? table : fakeMachine().sys.run(cmd, args)),
      runWithInput: async (cmd, args, input) => ((table = input), true),
      write: (path) => wrote.push(path),
    };
    const on = await alertsWith(["--schedule", "daily"], { ws: r.ws, env, sysExtra });
    assert.equal(on.code, 0, on.err);
    if (expected === "cron") {
      assert.match(table, /# worldsignals-scan/);
      assert.equal(wrote.length, 0);
      assert.match(on.out, /your crontab/);
    } else {
      assert.equal(table, "");
      assert.ok(wrote.some((p) => p.endsWith("worldsignals-scan.timer")));
      assert.match(on.out, /systemd user timer/);
    }
  }
});

// ------------------------------------------------------------------------------------------------------------
// ws machine …: many machines from the command line.

async function machineWith(argv, { ws = fakeWorldSignals(), env, credential = true, sysExtra = {}, uid } = {}) {
  env ??= { HOME: mkdtempSync(join(tmpdir(), "ws-home-")), XDG_CACHE_HOME: mkdtempSync(join(tmpdir(), "ws-cache-")), WS_API: API, PATH: "/usr/bin", USER: "ana" };
  const out = [];
  const err = [];
  const code = await machineCommand(argv, {
    fetch: ws.fetch, env, out: (x) => out.push(x), err: (x) => err.push(x), platform: "linux", sys: { ...fakeMachine().sys, ...sysExtra }, version: "test", pause: async () => {},
    credentialHeaders: credential ? () => ({ authorization: "Bearer acct" }) : null,
    scriptPath: "/usr/local/lib/node_modules/worldsignals/bin/ws.mjs", nodePath: "/usr/local/bin/node", ...(uid !== undefined ? { uid } : {}),
  });
  return { code, out: out.join("\n"), err: err.join("\n"), ws, env };
}

test("ws machine token prints the line to run elsewhere, and --revoke stops it; ws machines lists both", async () => {
  const t = await machineWith(["token", "--uses", "10", "--expires", "7d"]);
  assert.equal(t.code, 0, t.err);
  assert.match(t.out, /npx worldsignals machine enrol --token wsm_good/);
  assert.equal(t.ws.calls[0].body.days, 7);
  const list = await machineWith(["list"], { ws: t.ws });
  assert.match(list.out, /0 machines of 10 on the developer plan/);
  assert.match(list.out, /mtk_1 .*1 of 10 used/);
  const r = await machineWith(["token", "--revoke", "mtk_1"], { ws: t.ws });
  assert.match(r.out, /Revoked/);
  const none = await machineWith(["list"], { credential: false });
  assert.equal(none.code, 2);
  assert.match(none.err, /signup .*connect.*WS_KEY/);
});

test("ws machine enrol --token (or WS_ENROL_TOKEN) enrols, sends and schedules daily; remove forgets it here too", async () => {
  let table = "";
  const sysExtra = { run: async (cmd, args) => (cmd === "crontab" ? table : cmd === "loginctl" || cmd === "systemctl" ? null : fakeMachine().sys.run(cmd, args)), runWithInput: async (cmd, args, input) => ((table = input), true) };
  const env = { HOME: mkdtempSync(join(tmpdir(), "ws-home-")), XDG_CACHE_HOME: mkdtempSync(join(tmpdir(), "ws-cache-")), WS_API: API, PATH: "/usr/bin", USER: "ana", WS_ENROL_TOKEN: "wsm_good" };
  const e = await machineWith(["enrol", "--yes"], { env, sysExtra });
  assert.equal(e.code, 0, e.err);
  assert.equal(readMachine(env, API).machine_id, "m_1");
  assert.equal(readMachine(env, API).schedule, "daily");
  assert.match(table, /scan --upload/);
  const rm = await machineWith(["remove", "mch_" + "1".repeat(32)], { ws: e.ws, env, sysExtra });
  assert.equal(rm.code, 0, rm.err);
  assert.match(rm.out, /Removed/);
});

test("ws machine add shows a code, waits for approval, then sends the list signed with its own key", async () => {
  const a = await machineWith(["add", "--label", "db-1", "--yes"]);
  assert.equal(a.code, 0, a.err);
  assert.match(a.out, /ws machine approve BCDF-GHJK/);
  assert.match(a.out, /Approved\. db-1 is enrolled/);
  assert.equal(readMachine(a.env, API).machine_id, "m_2");
  assert.equal(a.ws.calls.at(-1).path, "/api/machine/report");
  assert.equal(a.ws.calls.at(-1).headers["x-ws-machine"], "m_2");
});

test("ws machine approve <code> adds the waiting machine", async () => {
  const ws = fakeWorldSignals();
  await machineWith(["add", "--yes"], { ws });
  const ok = await machineWith(["approve", "nope"], { ws });
  assert.equal(ok.code, 1);
  assert.match(ok.err, /No machine is waiting/);
});

test("scheduling as root refuses a script others can change", async () => {
  const r = await alertsWith(["--alerts", "--token", "wsm_good", "--yes"]);
  const out = [];
  const err = [];
  const code = await scan(["--schedule", "daily"], { fetch: r.ws.fetch, env: r.env, out: (x) => out.push(x), err: (x) => err.push(x), platform: "linux", sys: fakeMachine().sys, uid: 0, scriptPath: join(tmpdir(), "not-root-owned-ws.mjs"), nodePath: process.execPath });
  assert.equal(code, 2);
  assert.match(err.join("\n"), /runs as root/);
});

test("ws upgrade --machines shows the cost and changes nothing without a yes; --yes confirms", async () => {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push(body);
    const quote = { plan: "developer", included: 5, extra_now: 0, extra: body.machines, limit: 5 + body.machines, unit_amount: 200, currency: "eur", interval: "month", total: 200 * body.machines };
    return { status: 200, json: async () => (body.confirm ? { ...quote, changed: true } : quote), headers: new Headers() };
  };
  const out = [];
  const err = [];
  const env = { WS_KEY: "wsk_test", WS_API: API, HOME: mkdtempSync(join(tmpdir(), "ws-home-")) };
  const asked = await run(["upgrade", "--machines", "3"], { fetch, env, out: (x) => out.push(x), err: (x) => err.push(x) });
  assert.equal(asked, 2);
  assert.match(out.join("\n"), /Your developer plan includes 5 machines\. 3 extra at €2\.00 a month each: €6\.00 a month, VAT on top where it applies, billed with your plan and prorated from today\. Your limit becomes 8 machines\./);
  assert.match(err.join("\n"), /Not changed: there is no terminal to ask/);
  assert.equal(calls.some((c) => c.confirm), false);
  out.length = 0;
  assert.equal(await run(["upgrade", "--machines", "3", "--yes"], { fetch, env, out: (x) => out.push(x), err: (x) => err.push(x) }), 0);
  assert.equal(calls.at(-1).confirm, true);
  assert.match(out.join("\n"), /Done: your plan now covers 8 machines \(5 included, 3 extra\)/);
});
