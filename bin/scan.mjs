// ws scan: what is installed on this machine, checked against public vulnerability databases, written up as a
// free warning in plain language. No dependencies, Node 18 or later; loaded by ws.mjs only when `scan` runs.
//
// What it reads (read-only, never as root, each with a time limit; a source that fails is listed as not checked):
//   Linux: /etc/os-release, dpkg, rpm, apk, snap, flatpak.  macOS: sw_vers, Homebrew, the apps in /Applications.
//   Everywhere: global npm and pip packages, and with --here the lockfiles in the current folder.
// With --alerts (opt-in, after showing exactly what it will send): the list of names and versions goes to
// WorldSignals, which matches it against every new vulnerability and alerts the account the machine is enrolled in;
// --schedule keeps it current, --forget deletes it there. Without --alerts, nothing ever goes to WorldSignals.
// What it sends, and to whom (--dry-run prints every request and sends none):
//   - OSV.dev (Google): ecosystem, package name and version, for distro and language packages.
//   - CISA: nothing; the exploited-vulnerabilities catalogue is downloaded whole and cached for 12 hours.
//   - endoflife.date: product names only (nodejs, python, macos…), to tell what no longer gets security fixes.
//   - NVD (NIST), only with --nvd: a CPE name and version for each desktop app it knows.
//   - WorldSignals: nothing.
// Matching rules: a package the distribution installed is checked only against that distribution's own advisories
// (they know which fixes were backported), never by upstream version. The report groups vulnerabilities by the one
// upgrade that fixes them, puts what is being exploited now first, and every finding is shown in full.
import { execFile, spawn } from "node:child_process";
import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { parseArgs } from "node:util";

export const OSV_API = "https://api.osv.dev/v1";
export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const EOL_API = "https://endoflife.date/api/v1/products";
export const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_MAX_AGE_MS = 12 * 3_600_000;
const OSV_BATCH = 1000;

// ---------------------------------------------------------------------------------------------------------------
// Versions: each ecosystem's own order. OSV decides what is affected; these only pick the fix to upgrade to.

const isDigit = (c) => c >= "0" && c <= "9";

/** dpkg's character order: ~ before everything, even the end; letters before other symbols. */
function dpkgOrder(c) {
  if (!c || isDigit(c)) return 0;
  if (/[A-Za-z]/.test(c)) return c.charCodeAt(0);
  if (c === "~") return -1;
  return c.charCodeAt(0) + 256;
}

/** dpkg's verrevcmp, for the upstream version or the revision. */
function verrevcmp(a = "", b = "") {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let first = 0;
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = dpkgOrder(a[i]);
      const bc = dpkgOrder(b[j]);
      if (ac !== bc) return ac - bc;
      i++;
      j++;
    }
    while (a[i] === "0") i++;
    while (b[j] === "0") j++;
    while (isDigit(a[i] ?? "") && isDigit(b[j] ?? "")) {
      if (!first) first = a.charCodeAt(i) - b.charCodeAt(j);
      i++;
      j++;
    }
    if (isDigit(a[i] ?? "")) return 1;
    if (isDigit(b[j] ?? "")) return -1;
    if (first) return first;
  }
  return 0;
}

function dpkgParts(v) {
  const s = String(v).trim();
  const colon = s.indexOf(":");
  const epoch = colon > 0 && /^\d+$/.test(s.slice(0, colon)) ? Number(s.slice(0, colon)) : 0;
  const rest = colon > 0 && /^\d+$/.test(s.slice(0, colon)) ? s.slice(colon + 1) : s;
  const dash = rest.lastIndexOf("-");
  return { epoch, upstream: dash >= 0 ? rest.slice(0, dash) : rest, revision: dash >= 0 ? rest.slice(dash + 1) : "" };
}

/** Debian and Ubuntu package versions: epoch, then upstream, then revision. */
export function compareDpkg(a, b) {
  const x = dpkgParts(a);
  const y = dpkgParts(b);
  if (x.epoch !== y.epoch) return Math.sign(x.epoch - y.epoch);
  return Math.sign(verrevcmp(x.upstream, y.upstream) || verrevcmp(x.revision, y.revision));
}

/** rpm's rpmvercmp, for one of version or release. */
function rpmvercmp(a = "", b = "") {
  if (a === b) return 0;
  let i = 0;
  let j = 0;
  const alnum = (c) => /[A-Za-z0-9]/.test(c ?? "");
  for (;;) {
    while (i < a.length && !alnum(a[i]) && a[i] !== "~" && a[i] !== "^") i++;
    while (j < b.length && !alnum(b[j]) && b[j] !== "~" && b[j] !== "^") j++;
    if (a[i] === "~" || b[j] === "~") {
      if (a[i] !== "~") return 1;
      if (b[j] !== "~") return -1;
      i++;
      j++;
      continue;
    }
    if (a[i] === "^" || b[j] === "^") {
      if (i >= a.length) return -1;
      if (j >= b.length) return 1;
      if (a[i] !== "^") return 1;
      if (b[j] !== "^") return -1;
      i++;
      j++;
      continue;
    }
    if (i >= a.length || j >= b.length) break;
    const numeric = isDigit(a[i]);
    const take = (s, k) => {
      let e = k;
      while (e < s.length && (numeric ? isDigit(s[e]) : /[A-Za-z]/.test(s[e]))) e++;
      return [s.slice(k, e), e];
    };
    const [sa, ni] = take(a, i);
    const [sb, nj] = take(b, j);
    if (!sb) return numeric ? 1 : -1;
    if (numeric) {
      const na = sa.replace(/^0+/, "");
      const nb = sb.replace(/^0+/, "");
      if (na.length !== nb.length) return na.length > nb.length ? 1 : -1;
      if (na !== nb) return na > nb ? 1 : -1;
    } else if (sa !== sb) return sa > sb ? 1 : -1;
    i = ni;
    j = nj;
  }
  if (i >= a.length && j >= b.length) return 0;
  return i < a.length ? 1 : -1;
}

/** RHEL, Rocky, Alma and SUSE versions: [epoch:]version[-release]. */
export function compareRpm(a, b) {
  const parts = (v) => {
    const m = String(v).match(/^(?:(\d+):)?([^-]*)(?:-(.*))?$/) ?? [];
    return { epoch: Number(m[1] ?? 0), version: m[2] ?? "", release: m[3] ?? "" };
  };
  const x = parts(a);
  const y = parts(b);
  if (x.epoch !== y.epoch) return Math.sign(x.epoch - y.epoch);
  return rpmvercmp(x.version, y.version) || rpmvercmp(x.release, y.release);
}

/** Two runs of digits as numbers of any length: -1, 0 or 1. */
function compareDigits(p, q) {
  const a = p.replace(/^0+/, "");
  const b = q.replace(/^0+/, "");
  if (a.length !== b.length) return a.length > b.length ? 1 : -1;
  return a === b ? 0 : a > b ? 1 : -1;
}

/** Pre-release words, oldest first; any other word (post, p, r, patch) comes after the release. */
const PRE_RANK = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, pre: 3, preview: 3, rc: 4, c: 4 };
const isPre = (t) => t !== undefined && t in PRE_RANK;

/**
 * Every other ecosystem (npm and crates semver, PEP 440, RubyGems, apk, app versions): numbers compared as numbers,
 * pre-release words before the release, other words (post, -r1) after it, build metadata after + ignored.
 */
export function compareGeneric(a, b) {
  const tokens = (v) => String(v).toLowerCase().replace(/^v(?=\d)/, "").split("+")[0].match(/\d+|[a-z]+/g) ?? [];
  const x = tokens(a);
  const y = tokens(b);
  for (let k = 0; k < Math.max(x.length, y.length); k++) {
    const p = x[k];
    const q = y[k];
    if (p === undefined) return y.slice(k).every((t) => /^0+$/.test(t)) ? 0 : isPre(q) ? 1 : -1;
    if (q === undefined) return x.slice(k).every((t) => /^0+$/.test(t)) ? 0 : isPre(p) ? -1 : 1;
    const pn = isDigit(p[0]);
    const qn = isDigit(q[0]);
    if (pn && qn) {
      const d = compareDigits(p, q);
      if (d) return d;
      continue;
    }
    // A number outranks a word in the same place: 1.0.1 > 1.0rc1, 1.0.1 > 1.0.post1, 3.1.1 > 3.1-r5.
    if (pn !== qn) return pn ? 1 : -1;
    const rp = PRE_RANK[p] ?? 9;
    const rq = PRE_RANK[q] ?? 9;
    if (rp !== rq) return Math.sign(rp - rq);
    if (p !== q) return p > q ? 1 : -1;
  }
  return 0;
}

/** The comparator for an OSV ecosystem name ("Debian:12", "Rocky Linux:9", "PyPI", …). */
export function comparatorFor(ecosystem = "") {
  const base = ecosystem.split(":")[0];
  if (base === "Debian" || base === "Ubuntu") return compareDpkg;
  if (["Red Hat", "Rocky Linux", "AlmaLinux", "SUSE", "openSUSE", "openEuler", "Mageia"].includes(base)) return compareRpm;
  return compareGeneric;
}

// ---------------------------------------------------------------------------------------------------------------
// CVSS 3.x base score from a vector, as OSV gives it (CVSS:3.1/AV:N/AC:L/...).

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

/** CVSS 3.1's Roundup: the smallest one-decimal number at or above x, free of floating-point noise. */
function roundup(x) {
  const n = Math.round(x * 100000);
  return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10;
}

export function cvss3Score(vector) {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(String(vector ?? ""));
  if (!m) return null;
  const v = Object.fromEntries(m[1].split("/").map((p) => p.split(":")));
  const changed = v.S === "C";
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[v.PR];
  const [av, ac, ui, c, i, a] = [W.AV[v.AV], W.AC[v.AC], W.UI[v.UI], W.CIA[v.C], W.CIA[v.I], W.CIA[v.A]];
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined) || !["U", "C"].includes(v.S)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return roundup(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

export const SEVERITIES = ["critical", "high", "medium", "low", "unrated"];
export const severityOfScore = (s) => (s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : s > 0 ? "low" : "unrated");
const RATING = { critical: "critical", important: "high", high: "high", moderate: "medium", medium: "medium", low: "low", negligible: "low", unimportant: "low" };

/** A vulnerability's severity: its CVSS 3 score, else the database's or the distribution's own rating. */
export function osvSeverity(vuln, affected) {
  for (const s of vuln.severity ?? []) {
    if (s.type !== "CVSS_V3") continue;
    const score = cvss3Score(s.score);
    if (score !== null) return { severity: severityOfScore(score), score };
  }
  const ratings = [
    vuln.database_specific?.severity,
    ...(vuln.severity ?? []).filter((s) => !/^CVSS/.test(s.type)).map((s) => s.score),
    affected?.ecosystem_specific?.urgency,
    affected?.ecosystem_specific?.severity,
    affected?.database_specific?.severity,
  ];
  for (const r of ratings) {
    const sev = RATING[String(r ?? "").toLowerCase().trim()];
    if (sev) return { severity: sev, score: null };
  }
  return { severity: "unrated", score: null };
}

// ---------------------------------------------------------------------------------------------------------------
// Inventory parsers: text in, items out. An item: {source, name, version, ecosystem?, label?, ...}.

/** /etc/os-release as an object of its fields. */
export function parseOsRelease(text = "") {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) out[m[1]] = m[2].replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
  }
  return out;
}

/**
 * The OSV ecosystem for a Linux distribution's packages, or null where OSV has none we can use.
 * Debian and Ubuntu advisories name source packages; Alpine its origin packages; Rocky and Alma binary rpms.
 */
export function distroEcosystem(os) {
  const id = (os.ID ?? "").toLowerCase();
  const v = os.VERSION_ID ?? "";
  if (id === "debian" && v) return `Debian:${v.split(".")[0]}`;
  if (id === "ubuntu" && v) return /LTS/i.test(os.VERSION ?? "") ? `Ubuntu:${v}:LTS` : `Ubuntu:${v}`;
  if (id === "alpine" && v) return `Alpine:v${v.split(".").slice(0, 2).join(".")}`;
  if (id === "rocky" && v) return `Rocky Linux:${v.split(".")[0]}`;
  if (id === "almalinux" && v) return `AlmaLinux:${v.split(".")[0]}`;
  return null;
}

/** dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n' */
export function parseDpkg(text, ecosystem) {
  const bySource = new Map();
  for (const line of text.split("\n")) {
    const [pkg, version, srcName, srcVersion, status] = line.split("\t");
    if (!pkg || !version || !/^[ih]i/.test(status ?? "ii")) continue;
    const name = srcName || pkg;
    const ver = srcVersion || version;
    const key = `${name}@${ver}`;
    const item = bySource.get(key) ?? { source: "dpkg", name, version: ver, ...(ecosystem ? { ecosystem } : {}), binaries: [] };
    item.binaries.push(pkg);
    bySource.set(key, item);
  }
  return [...bySource.values()];
}

/** rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{SOURCERPM}\n' */
export function parseRpm(text, ecosystem) {
  const out = [];
  for (const line of text.split("\n")) {
    const [name, epoch, version, release, srpm] = line.split("\t");
    if (!name || !version || name === "gpg-pubkey") continue;
    const evr = `${epoch && epoch !== "(none)" ? `${epoch}:` : ""}${version}${release ? `-${release}` : ""}`;
    const source = (srpm ?? "").replace(/-[^-]+-[^-]+\.src\.rpm$/, "") || name;
    out.push({ source: "rpm", name, version: evr, ...(ecosystem ? { ecosystem } : {}), group: source });
  }
  return out;
}

/** /lib/apk/db/installed: blocks of P: (package), V: (version), o: (origin), blank line between. */
export function parseApk(text, ecosystem) {
  const byOrigin = new Map();
  for (const block of text.split(/\n\s*\n/)) {
    const f = Object.fromEntries(block.split("\n").filter((l) => /^[A-Za-z]:/.test(l)).map((l) => [l[0], l.slice(2)]));
    if (!f.P || !f.V) continue;
    const name = f.o || f.P;
    const key = `${name}@${f.V}`;
    const item = byOrigin.get(key) ?? { source: "apk", name, version: f.V, ...(ecosystem ? { ecosystem } : {}), binaries: [] };
    item.binaries.push(f.P);
    byOrigin.set(key, item);
  }
  return [...byOrigin.values()];
}

/** brew info --json=v2 --installed: formulae (their installed version, revision suffix _N dropped) and casks. */
export function parseBrew(json) {
  const out = [];
  for (const f of json?.formulae ?? []) {
    const v = f.installed?.[f.installed.length - 1]?.version;
    if (f.name && v) out.push({ source: "brew", name: f.name, version: v.replace(/_\d+$/, "") });
  }
  for (const c of json?.casks ?? []) {
    const v = c.installed;
    if (c.token && v) out.push({ source: "brew-cask", name: c.token, version: String(v).split(",")[0], label: c.name?.[0] ?? c.token });
  }
  return out;
}

/** The version people see in an app's Info.plist ("6.4.10 (60000)" → 6.4.10), and its bundle id. */
export function appFromInfo(info, path) {
  const raw = String(info?.CFBundleShortVersionString ?? info?.CFBundleVersion ?? "").trim();
  const version = raw.match(/^\d+(?:[.\-]\d+)*[a-z]?\d*/i)?.[0] ?? raw;
  const label = info?.CFBundleDisplayName || info?.CFBundleName || path.split("/").pop().replace(/\.app$/, "");
  return info?.CFBundleIdentifier && version ? { source: "app", name: info.CFBundleIdentifier, version, label, path } : null;
}

/** npm ls -g --json --all: every package once per version, with the global tool that brings it in. */
export function parseNpmLs(json) {
  const seen = new Map();
  const walk = (deps, top) => {
    for (const [name, d] of Object.entries(deps ?? {})) {
      if (!d?.version) continue;
      const via = top ?? name;
      const key = `${name}@${d.version}`;
      if (!seen.has(key)) seen.set(key, { source: "npm", ecosystem: "npm", name, version: d.version, via: new Set() });
      seen.get(key).via.add(via);
      walk(d.dependencies, via);
    }
  };
  walk(json?.dependencies);
  return [...seen.values()].map((i) => ({ ...i, via: [...i.via] }));
}

/** python3 -m pip list --format=json */
export const parsePipList = (json) => (Array.isArray(json) ? json : []).filter((p) => p?.name && p?.version).map((p) => ({ source: "pip", ecosystem: "PyPI", name: p.name, version: p.version }));

/** snap list: a header line, then name, version, … */
export const parseSnapList = (text) =>
  text.split("\n").slice(1).map((l) => l.trim().split(/\s+/)).filter((c) => c.length >= 2 && c[0]).map(([name, version]) => ({ source: "snap", name, version }));

/** flatpak list --app --columns=application,version */
export const parseFlatpakList = (text) =>
  text.split("\n").map((l) => l.split("\t")).filter((c) => c[0]?.trim() && c[1]?.trim()).map(([name, version]) => ({ source: "flatpak", name: name.trim(), version: version.trim() }));

// Lockfiles in the current folder (--here).

export function parsePackageLock(json, file = "package-lock.json") {
  const out = new Map();
  const add = (name, version) => name && version && !/^(file|link|git)/.test(version) && out.set(`${name}@${version}`, { source: "lockfile", file, ecosystem: "npm", name, version });
  if (json?.packages) {
    for (const [path, p] of Object.entries(json.packages)) if (path) add(p.name ?? path.split("node_modules/").pop(), p.version);
  } else {
    const walk = (deps) => {
      for (const [name, d] of Object.entries(deps ?? {})) {
        add(name, d.version);
        walk(d.dependencies);
      }
    };
    walk(json?.dependencies);
  }
  return [...out.values()];
}

/** requirements.txt: only pinned lines (name==version); ranges can't be checked without resolving them. */
export function parseRequirements(text, file = "requirements.txt") {
  const out = [];
  for (const line of text.split("\n")) {
    const m = line.replace(/#.*/, "").trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,]+)/);
    if (m) out.push({ source: "lockfile", file, ecosystem: "PyPI", name: m[1], version: m[2] });
  }
  return out;
}

/** Cargo.lock, poetry.lock and uv.lock: [[package]] tables with name = "…" and version = "…". */
export function parseTomlPackages(text, file, ecosystem) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) out.push({ source: "lockfile", file, ecosystem, name, version });
  }
  return out;
}

/** Gemfile.lock: the specs under GEM, "    name (version)". */
export function parseGemfileLock(text, file = "Gemfile.lock") {
  const out = [];
  for (const m of text.matchAll(/^ {4}([A-Za-z0-9_.-]+) \(([^)\s]+)\)$/gm)) out.push({ source: "lockfile", file, ecosystem: "RubyGems", name: m[1], version: m[2].replace(/-[a-z0-9_]+-[a-z0-9_]+$/i, "") });
  return out;
}

export function parseComposerLock(json, file = "composer.lock") {
  return [...(json?.packages ?? []), ...(json?.["packages-dev"] ?? [])].filter((p) => p.name && p.version).map((p) => ({ source: "lockfile", file, ecosystem: "Packagist", name: p.name, version: p.version.replace(/^v/, "") }));
}

export const LOCKFILES = [
  ["package-lock.json", (t, f) => parsePackageLock(JSON.parse(t), f)],
  ["requirements.txt", parseRequirements],
  ["Cargo.lock", (t, f) => parseTomlPackages(t, f, "crates.io")],
  ["poetry.lock", (t, f) => parseTomlPackages(t, f, "PyPI")],
  ["uv.lock", (t, f) => parseTomlPackages(t, f, "PyPI")],
  ["Gemfile.lock", parseGemfileLock],
  ["composer.lock", (t, f) => parseComposerLock(JSON.parse(t), f)],
];

// ---------------------------------------------------------------------------------------------------------------
// Desktop apps and Homebrew formulae: the products NVD knows them by (CPE vendor:product), checked with --nvd.
// Every CPE here was checked against NVD's CPE dictionary (16 Nov 2026); an app NVD has no product for (Slack's
// desktop app) is left out rather than guessed. `how` says how to update, per OS; `eol` is the
// endoflife.date product, where it has one.

const MENU_UPDATE = (app, menu = "Help") => `${app} menu → ${menu} → About ${app}, then restart it`;
export const APPS = [
  { cpes: ["google:chrome"], label: "Google Chrome", ids: ["com.google.Chrome", "google-chrome", "com.google.Chrome@flatpak"], how: "Chrome menu ⋮ → Help → About Google Chrome, then Relaunch" },
  { cpes: ["mozilla:firefox"], label: "Firefox", ids: ["org.mozilla.firefox", "firefox", "org.mozilla.firefox@flatpak", "firefox@snap"], how: MENU_UPDATE("Firefox") },
  { cpes: ["mozilla:firefox_esr"], label: "Firefox ESR", ids: ["org.mozilla.firefoxesr", "firefox@esr"], how: MENU_UPDATE("Firefox") },
  { cpes: ["mozilla:thunderbird"], label: "Thunderbird", ids: ["org.mozilla.thunderbird", "thunderbird", "org.mozilla.Thunderbird@flatpak", "thunderbird@snap"], how: MENU_UPDATE("Thunderbird") },
  { cpes: ["microsoft:edge_chromium"], label: "Microsoft Edge", ids: ["com.microsoft.edgemac", "microsoft-edge"], how: "Edge menu … → Help and feedback → About Microsoft Edge" },
  { cpes: ["brave:brave"], label: "Brave", ids: ["com.brave.Browser", "brave-browser"], how: "Brave menu → About Brave, then Relaunch" },
  { cpes: ["opera:opera_browser"], label: "Opera", ids: ["com.operasoftware.Opera", "opera"], how: "Opera menu → Update & Recovery → Check for update" },
  { cpes: ["zoom:zoom", "zoom:workplace_desktop", "zoom:meetings"], label: "Zoom", ids: ["us.zoom.xos", "zoom", "us.zoom.Zoom@flatpak", "zoom-client@snap"], how: "Zoom → your picture → Check for updates" },
  { cpes: ["microsoft:teams"], label: "Microsoft Teams", ids: ["com.microsoft.teams2", "com.microsoft.teams", "microsoft-teams"], how: "Teams → Settings and more … → Check for updates" },
  { cpes: ["microsoft:visual_studio_code"], label: "Visual Studio Code", ids: ["com.microsoft.VSCode", "visual-studio-code", "com.visualstudio.code@flatpak", "code@snap"], how: "Code → Check for Updates…" },
  { cpes: ["docker:desktop"], label: "Docker Desktop", ids: ["com.docker.docker", "docker-desktop", "docker"], how: "Docker Desktop → Check for updates" },
  { cpes: ["videolan:vlc_media_player"], label: "VLC", ids: ["org.videolan.vlc", "vlc", "org.videolan.VLC@flatpak", "vlc@snap"], how: "VLC → Check for Update…" },
  { cpes: ["libreoffice:libreoffice"], label: "LibreOffice", ids: ["org.libreoffice.script", "libreoffice", "org.libreoffice.LibreOffice@flatpak", "libreoffice@snap"], how: "download the current release from libreoffice.org", eol: "libreoffice" },
  { cpes: ["adobe:acrobat_reader_dc", "adobe:acrobat_reader"], label: "Adobe Acrobat Reader", ids: ["com.adobe.Reader", "adobe-acrobat-reader"], how: "Acrobat Reader → Help → Check for Updates" },
  { cpes: ["wireshark:wireshark"], label: "Wireshark", ids: ["org.wireshark.Wireshark", "wireshark", "org.wireshark.Wireshark@flatpak", "wireshark-app"], how: "Wireshark → Check for Updates…" },
  { cpes: ["signal:signal-desktop"], label: "Signal", ids: ["org.whispersystems.signal-desktop", "signal", "org.signal.Signal@flatpak", "signal-desktop@snap"], how: "Signal updates itself on restart; or download it again from signal.org" },
  { cpes: ["postman:postman"], label: "Postman", ids: ["com.postmanlabs.mac", "postman", "postman@snap"], how: "Postman → Settings → Update" },
  { cpes: ["iterm2:iterm2"], label: "iTerm2", ids: ["com.googlecode.iterm2", "iterm2"], how: "iTerm2 → Check for Updates…" },
  { cpes: ["teamviewer:teamviewer"], label: "TeamViewer", ids: ["com.teamviewer.TeamViewer", "teamviewer"], how: "TeamViewer → Help → Check for new version" },
  { cpes: ["anydesk:anydesk"], label: "AnyDesk", ids: ["com.philandro.anydesk", "anydesk"], how: "AnyDesk menu → About AnyDesk → Update" },
  { cpes: ["filezilla-project:filezilla_client"], label: "FileZilla", ids: ["org.filezilla-project.filezilla", "filezilla"], how: "FileZilla → Help → Check for updates…" },
  { cpes: ["keepassxc:keepassxc"], label: "KeePassXC", ids: ["org.keepassxc.keepassxc", "keepassxc", "org.keepassxc.KeePassXC@flatpak"], how: "download the current release from keepassxc.org" },
  // Homebrew formulae: one command updates each.
  { cpes: ["git-scm:git"], label: "Git", ids: ["git@brew"] },
  { cpes: ["openssl:openssl"], label: "OpenSSL", ids: ["openssl@3@brew", "openssl@1.1@brew"], eol: "openssl" },
  { cpes: ["haxx:curl"], label: "curl", ids: ["curl@brew"] },
  { cpes: ["gnu:wget"], label: "wget", ids: ["wget@brew"] },
  { cpes: ["sqlite:sqlite"], label: "SQLite", ids: ["sqlite@brew"] },
  { cpes: ["xmlsoft:libxml2"], label: "libxml2", ids: ["libxml2@brew"] },
  { cpes: ["ffmpeg:ffmpeg"], label: "FFmpeg", ids: ["ffmpeg@brew"] },
  { cpes: ["imagemagick:imagemagick"], label: "ImageMagick", ids: ["imagemagick@brew"] },
  { cpes: ["redis:redis"], label: "Redis", ids: ["redis@brew"], eol: "redis" },
  { cpes: ["f5:nginx"], label: "nginx", ids: ["nginx@brew"], eol: "nginx" },
  { cpes: ["vim:vim"], label: "Vim", ids: ["vim@brew"] },
  { cpes: ["openbsd:openssh"], label: "OpenSSH", ids: ["openssh@brew"] },
  { cpes: ["gnupg:gnupg"], label: "GnuPG", ids: ["gnupg@brew"] },
  { cpes: ["php:php"], label: "PHP", ids: ["php@brew"], eol: "php" },
  { cpes: ["golang:go"], label: "Go", ids: ["go@brew"], eol: "go" },
  { cpes: ["ruby-lang:ruby"], label: "Ruby", ids: ["ruby@brew"], eol: "ruby" },
  { cpes: ["nodejs:node.js"], label: "Node.js", ids: ["node@brew"], eol: "nodejs" },
  { cpes: ["python:python"], label: "Python", ids: ["python@brew"], eol: "python" },
  { cpes: ["postgresql:postgresql"], label: "PostgreSQL", ids: ["postgresql@brew"], eol: "postgresql" },
];

/** The key an item is looked up by in APPS: a bundle id or cask as it is, others tagged with their source. */
function appKey(item) {
  if (item.source === "app" || item.source === "brew-cask") return item.name;
  if (item.source === "brew") return /^(python|node|postgresql|php|ruby|go)@/.test(item.name) ? `${item.name.split("@")[0]}@brew` : `${item.name}@brew`;
  return `${item.name}@${item.source}`;
}
const APP_BY_KEY = new Map(APPS.flatMap((a) => a.ids.map((id) => [id, a])));
export const appFor = (item) => APP_BY_KEY.get(appKey(item)) ?? null;

/** How to update an item matched through APPS. */
function appHow(app, item) {
  if (item.source === "brew") return `brew upgrade ${item.name}`;
  if (item.source === "brew-cask") return `brew upgrade --cask ${item.name}`;
  if (item.source === "snap") return `sudo snap refresh ${item.name}`;
  if (item.source === "flatpak") return `flatpak update ${item.name}`;
  return app.how ?? "update it from its own menu or its maker's site";
}

// ---------------------------------------------------------------------------------------------------------------
// Supported releases (endoflife.date): the products and release ("cycle") to ask about, from the inventory.

const CYCLE_BREW = [
  [/^python@(\d+\.\d+)$/, "python", (m) => m[1]],
  [/^node@(\d+)$/, "nodejs", (m) => m[1]],
  [/^node$/, "nodejs", (m, v) => v.split(".")[0]],
  [/^postgresql@(\d+)$/, "postgresql", (m) => m[1]],
  [/^mysql@(\d+\.\d+)$/, "mysql", (m) => m[1]],
  [/^php(?:@(\d+\.\d+))?$/, "php", (m, v) => m[1] ?? v.split(".").slice(0, 2).join(".")],
  [/^ruby(?:@(\d+\.\d+))?$/, "ruby", (m, v) => m[1] ?? v.split(".").slice(0, 2).join(".")],
  [/^go(?:@(\d+\.\d+))?$/, "go", (m, v) => m[1] ?? v.split(".").slice(0, 2).join(".")],
  [/^openssl@1\.1$/, "openssl", () => "1.1.1"],
  [/^openssl@3$/, "openssl", (m, v) => v.split(".").slice(0, 2).join(".")],
  [/^redis$/, "redis", (m, v) => v.split(".").slice(0, 2).join(".")],
];
const PRODUCT_LABEL = { python: "Python", nodejs: "Node.js", postgresql: "PostgreSQL", mysql: "MySQL", php: "PHP", ruby: "Ruby", go: "Go", openssl: "OpenSSL", redis: "Redis", macos: "macOS", ubuntu: "Ubuntu", debian: "Debian", alpine: "Alpine Linux", "rocky-linux": "Rocky Linux", almalinux: "AlmaLinux", rhel: "Red Hat Enterprise Linux", fedora: "Fedora", libreoffice: "LibreOffice", nginx: "nginx" };

/** The releases to check for end of life: [{product, cycle, label, what}], each once. */
export function eolTargets({ os, items, runtimes = [] }) {
  const out = new Map();
  const add = (product, cycle, what) => cycle && !out.has(`${product}@${cycle}`) && out.set(`${product}@${cycle}`, { product, cycle: String(cycle), label: PRODUCT_LABEL[product] ?? product, what });
  if (os?.family === "macos" && os.version) {
    const [major, minor] = os.version.split(".");
    add("macos", Number(major) >= 11 ? major : `${major}.${minor}`, `macOS ${os.version}`);
  }
  if (os?.family === "linux") {
    const product = { ubuntu: "ubuntu", debian: "debian", alpine: "alpine", rocky: "rocky-linux", almalinux: "almalinux", rhel: "rhel", fedora: "fedora" }[os.id];
    const cycle = os.id === "ubuntu" ? os.version : os.id === "alpine" ? os.version?.split(".").slice(0, 2).join(".") : os.version?.split(".")[0];
    if (product) add(product, cycle, `${os.name ?? product} ${os.version}`);
  }
  for (const r of runtimes) add(r.product, r.cycle, r.what);
  for (const i of items) {
    if (i.source !== "brew") continue;
    for (const [re, product, cycle] of CYCLE_BREW) {
      const m = i.name.match(re);
      if (m) add(product, cycle(m, i.version), `${i.name} ${i.version} (Homebrew)`);
    }
  }
  return [...out.values()];
}

/** One release's support, from endoflife.date's answer for its product: null when the release isn't listed. */
export function eolFinding(target, answer, now) {
  const releases = answer?.result?.releases ?? [];
  const rel = releases.find((r) => r.name === target.cycle) ?? releases.find((r) => r.name === target.cycle.split(".").slice(0, 2).join(".")) ?? releases.find((r) => r.name === target.cycle.split(".")[0]);
  if (!rel) return null;
  const ended = rel.isEol === true || (rel.eolFrom && Date.parse(rel.eolFrom) <= now.getTime());
  if (!ended) return null;
  // The oldest release newer than this one that is still supported: the smallest move that gets fixes again.
  const supported = releases.filter((r) => compareGeneric(r.name, rel.name) > 0 && (r.isMaintained || (r.eolFrom && Date.parse(r.eolFrom) > now.getTime())));
  const next = supported.sort((a, b) => compareGeneric(a.name, b.name))[0];
  return { ...target, eol_on: rel.eolFrom ?? null, move_to: next ? `${target.label} ${next.label ?? next.name}` : null, link: `https://endoflife.date/${target.product}` };
}

// ---------------------------------------------------------------------------------------------------------------
// Matching OSV's answers, NVD's answers and the KEV catalogue into findings.

/**
 * How a KEV entry is shown on a finding. CISA lists the product it saw exploited: when that isn't the one installed
 * (a Ruby flaw exploited through GitLab), `elsewhere` names it, so the report doesn't overstate it.
 */
export function exploitedAs(k, names) {
  if (!k) return null;
  const listed = `${k.vendorProject ?? ""} ${k.product ?? ""}`.trim();
  const words = names.flatMap((n) => String(n ?? "").toLowerCase().split(/[^a-z0-9]+/)).filter((w) => w.length >= 3);
  const same = words.some((w) => listed.toLowerCase().includes(w));
  return { since: k.dateAdded, ransomware: k.knownRansomwareCampaignUse === "Known", ...(same || !listed ? {} : { elsewhere: listed }) };
}

/** Every CVE a vulnerability goes by: its id, aliases and upstream ids. */
export const cvesOf = (v) => [...new Set([v.id, ...(v.aliases ?? []), ...(v.upstream ?? [])].filter((x) => /^CVE-\d{4}-\d+$/.test(x)))];

/**
 * The fix for one package from one OSV vulnerability: the lowest fixed version above the installed one, for this
 * package in this ecosystem; null when none is published.
 */
export function osvFix(vuln, item) {
  const cmp = comparatorFor(item.ecosystem);
  const mine = (vuln.affected ?? []).filter((a) => a.package?.name?.toLowerCase() === item.name.toLowerCase() && a.package?.ecosystem === item.ecosystem);
  const entries = mine.length ? mine : (vuln.affected ?? []).filter((a) => a.package?.name?.toLowerCase() === item.name.toLowerCase());
  const fixes = entries.flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter(Boolean)));
  const above = fixes.filter((f) => cmp(f, item.version) > 0).sort(cmp);
  return { fixed: above[0] ?? null, affected: entries[0] ?? null };
}

/** One finding per vulnerability of an item, from OSV's full records for that package. */
export function osvFindings(item, vulns, kev) {
  const out = [];
  for (const v of vulns) {
    if (v.withdrawn) continue;
    const { fixed, affected } = osvFix(v, item);
    const cves = cvesOf(v);
    const sev = osvSeverity(v, affected);
    const k = cves.map((c) => kev.get(c)).find(Boolean);
    out.push({
      id: v.id,
      cves,
      summary: (v.summary || v.details || "").split("\n")[0].slice(0, 240),
      severity: sev.severity,
      score: sev.score,
      fixed,
      exploited: exploitedAs(k, [item.name, item.label]),
      link: cves[0] ? `https://nvd.nist.gov/vuln/detail/${cves[0]}` : `https://osv.dev/vulnerability/${v.id}`,
      confidence: "confirmed",
    });
  }
  return out;
}

/** NVD's best score: v4, v3.1, v3.0, then v2, the NVD's own (Primary) before others. */
function nvdScore(metrics = {}) {
  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list = metrics[key];
    if (!list?.length) continue;
    const m = list.find((x) => x.type === "Primary") ?? list[0];
    if (typeof m.cvssData?.baseScore === "number") return m.cvssData.baseScore;
  }
  return null;
}

const DATE_LIKE = /^\d{4}-?\d{2}-?\d{2}\b/;
const OS_CPES = { macos: ["apple:macos", "apple:mac_os_x", "apple:mac_os"], linux: ["linux:linux_kernel"], windows: ["microsoft:windows"] };

/**
 * Findings for one app from NVD's answer to virtualMatchString=cpe:2.3:a:<cpe>:<version>. A configuration that
 * applies only when running on another OS ("Chrome running on Android") is left out; the fix is the lowest
 * versionEndExcluding above the installed version.
 */
export function nvdFindings(app, item, cves, kev, osFamily) {
  const out = [];
  const mine = OS_CPES[osFamily] ?? [];
  for (const { cve } of cves) {
    if (!cve?.id || cve.vulnStatus === "Rejected") continue;
    let applies = false;
    const fixes = [];
    for (const config of cve.configurations ?? []) {
      const matches = config.nodes.flatMap((n) => n.cpeMatch ?? []);
      const platforms = matches.filter((m) => !m.vulnerable && m.criteria.startsWith("cpe:2.3:o:")).map((m) => m.criteria.split(":").slice(3, 5).join(":"));
      if (platforms.length && mine.length && !platforms.some((p) => mine.includes(p))) continue;
      for (const m of matches) {
        if (!m.vulnerable || !app.cpes.includes(m.criteria.split(":").slice(3, 5).join(":"))) continue;
        // Some ranges are git snapshot dates (FFmpeg "before 2025-01-13"): they can't be compared with a release number.
        const bounds = [m.criteria.split(":")[5], m.versionStartIncluding, m.versionStartExcluding, m.versionEndIncluding, m.versionEndExcluding];
        if (!DATE_LIKE.test(item.version) && bounds.some((b) => DATE_LIKE.test(b ?? ""))) continue;
        applies = true;
        if (m.versionEndExcluding && compareGeneric(m.versionEndExcluding, item.version) > 0) fixes.push(m.versionEndExcluding);
      }
    }
    if (!applies) continue;
    const score = nvdScore(cve.metrics);
    const k = kev.get(cve.id);
    const description = (cve.descriptions ?? []).find((d) => d.lang === "en")?.value ?? "";
    out.push({
      id: cve.id,
      cves: [cve.id],
      summary: description.slice(0, 240),
      severity: score === null ? "unrated" : severityOfScore(score),
      score,
      fixed: fixes.sort(compareGeneric)[0] ?? null,
      exploited: exploitedAs(k, [app.label, ...app.cpes.flatMap((c) => c.split(":"))]),
      link: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      confidence: "likely",
    });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Grouping: one group per update that fixes them, so fourteen CVEs in one browser read as one job.

const DISTRO_UPDATE = { dpkg: "sudo apt update && sudo apt upgrade", rpm: "sudo dnf upgrade", apk: "sudo apk upgrade" };
const DISTRO_NAME = (os) => os?.name ?? "System";

/**
 * Findings grouped by the action that fixes them: the distribution's update for its packages, one pip or npm
 * command for each kind, one upgrade per app or formula, and the lockfile per project file. Returns the groups,
 * most urgent first, and the findings no published version fixes yet.
 */
export function groupFindings(matched, { os } = {}) {
  const groups = new Map();
  const noFix = [];
  const get = (key, make) => groups.get(key) ?? groups.set(key, { key, packages: [], ...make() }).get(key);
  for (const { item, findings, app } of matched) {
    const fixable = findings.filter((f) => f.fixed);
    for (const f of findings) if (!f.fixed) noFix.push({ ...f, package: app?.label ?? item.label ?? item.name, version: item.version });
    if (!fixable.length) continue;
    let g;
    if (item.source in DISTRO_UPDATE) g = get(`os:${item.source}`, () => ({ kind: "os", title: `${DISTRO_NAME(os)} packages`, how: DISTRO_UPDATE[item.source] }));
    else if (item.source === "pip") g = get("pip", () => ({ kind: "pip", title: "Python packages (pip)", how: null }));
    else if (item.source === "npm") g = get("npm", () => ({ kind: "npm", title: "npm packages (global)", how: null }));
    else if (item.source === "lockfile") g = get(`file:${item.file}`, () => ({ kind: "lockfile", title: `Project dependencies (${item.file})`, how: null, file: item.file }));
    else g = get(`app:${item.source}:${item.name}`, () => ({ kind: "app", title: app?.label ?? item.label ?? item.name, how: appHow(app ?? {}, item) }));
    const target = fixable.map((f) => f.fixed).sort(comparatorFor(item.ecosystem)).pop() ?? null;
    g.packages.push({ name: item.name, label: item.label, version: item.version, target, via: item.via, binaries: item.binaries, group: item.group, user: item.user, findings: fixable });
  }
  const out = [];
  for (const g of groups.values()) {
    const all = g.packages.flatMap((p) => p.findings);
    if (g.kind === "pip") g.how = `python3 -m pip install${g.packages.some((p) => p.user) ? " --user" : ""} -U ${g.packages.map((p) => p.name).join(" ")}`;
    // A global tool's own dependencies are updated by updating the tool.
    if (g.kind === "npm") g.how = `npm install -g ${[...new Set(g.packages.flatMap((p) => p.via ?? [p.name]))].map((n) => `${n}@latest`).join(" ")}`;
    if (g.kind === "lockfile") g.how = lockfileHow(g.file, g.packages);
    out.push({ ...g, findings: all, exploited: all.filter((f) => f.exploited), counts: countBy(all) });
  }
  const rank = (g) => [g.exploited.some((f) => !f.exploited.elsewhere) ? 0 : g.exploited.length ? 1 : 2, SEVERITIES.indexOf(worst(g.findings)), -g.findings.length];
  const groupsOut = out.sort((a, b) => {
    const [x, y] = [rank(a), rank(b)];
    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2] || a.title.localeCompare(b.title);
  });
  return { groups: groupsOut, noFix };
}

const KIND_SHORT = { pip: "pip", npm: "npm, global", lockfile: "" };

/** A group's heading: one app's upgrade, or how many packages one command updates. */
function groupTitle(g) {
  const one = g.packages.length === 1 ? g.packages[0] : null;
  if (g.kind === "app") return `${g.title} ${one.version} → ${one.target} or later`;
  if (one && g.kind !== "os") return `${one.label ?? one.name} ${one.version} → ${one.target} (${KIND_SHORT[g.kind] || g.file})`;
  return `${g.title}: ${plural(g.packages.length, "package")} to update`;
}

function lockfileHow(file, packages) {
  const list = packages.map((p) => `${p.name}@${p.target}`).join(" ");
  if (file === "package-lock.json") return `npm install ${list} (direct dependencies), or npm audit fix`;
  if (file === "Cargo.lock") return packages.map((p) => `cargo update -p ${p.name} --precise ${p.target}`).join("; ");
  if (file === "Gemfile.lock") return `bundle update ${packages.map((p) => p.name).join(" ")}`;
  if (file === "composer.lock") return `composer update ${packages.map((p) => p.name).join(" ")}`;
  return `raise these in ${file}: ${packages.map((p) => `${p.name} to ${p.target}`).join(", ")}`;
}

const countBy = (findings) => Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const worst = (findings) => SEVERITIES.find((s) => findings.some((f) => f.severity === s)) ?? "unrated";

// ---------------------------------------------------------------------------------------------------------------
// The report: terminal text, Markdown (--report) and JSON (--json).

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const countLine = (c) => SEVERITIES.filter((s) => c[s]).map((s) => `${c[s]} ${s === "unrated" ? "not rated" : s}`).join(", ");
const date = (iso) => (iso ? new Date(`${iso.slice(0, 10)}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }) : "");

function sentLine(r) {
  const to = [];
  if (r.sent.osv) to.push("package names and versions to OSV.dev (Google)");
  if (r.sent.eol) to.push("product names to endoflife.date");
  if (r.sent.nvd) to.push("app names and versions to NVD (NIST)");
  return to.length ? `Sent ${to.join("; ")}. Nothing went to WorldSignals.` : "Nothing was sent anywhere. Nothing went to WorldSignals.";
}

/** One exploited finding, in words: since when, in what, and whether ransomware uses it. */
const exploitedLine = (f) =>
  `${f.cves[0] ?? f.id} is on CISA's list of exploited vulnerabilities since ${date(f.exploited.since)}` +
  `${f.exploited.elsewhere ? `, exploited through ${f.exploited.elsewhere}, which shares the flawed code` : ""}${f.exploited.ransomware ? ", and is used in ransomware" : ""}.`;

/** "openssl 3.0.13-0ubuntu3.1 → 3.0.13-0ubuntu3.5" */
const pkgLine = (p) => `${p.label ?? p.name} ${p.version} → ${p.target ?? "no fix yet"}`;

export function renderText(r, style = { label: (s) => s, strong: (s) => s, dim: (s) => s }, p = "ws") {
  const L = [];
  L.push(style.label(`WorldSignals machine check · ${r.os.label} · ${date(r.checked_at)}`));
  L.push(`Checked ${plural(r.checked, "program and package", "programs and packages")} against ${r.databases.join(", ")}.`);
  L.push(style.dim(sentLine(r)), "");
  for (const s of r.sources.filter((s) => s.error)) L.push(style.dim(`(${s.source}: ${s.error})`));
  if (r.sources.some((s) => s.error)) L.push("");
  const urgent = r.groups.filter((g) => g.exploited.some((f) => !f.exploited.elsewhere)).length;
  const fixable = r.groups.reduce((n, g) => n + g.findings.length, 0);
  if (!r.groups.length) L.push(style.strong("Nothing to update: no known vulnerability with a published fix in what was checked."));
  else L.push(style.strong(`${plural(r.groups.length, "update")} fix${r.groups.length === 1 ? "es" : ""} all ${plural(fixable, "known vulnerability", "known vulnerabilities")} that have a fix.${urgent ? ` ${urgent === 1 ? "One of them is" : `${urgent} of them are`} urgent: being exploited right now.` : ""}`));
  L.push("");
  r.groups.forEach((g, i) => {
    const tag = g.exploited.some((f) => !f.exploited.elsewhere) ? "  [EXPLOITED NOW]" : g.exploited.length ? "  [EXPLOITED IN ANOTHER PRODUCT]" : "";
    const one = g.packages.length === 1 && g.kind !== "os";
    L.push(style.strong(`${i + 1}. ${groupTitle(g)}`) + (tag ? style.label(tag) : ""));
    L.push(`   ${g.findings.length === 1 ? "1 known vulnerability" : `${g.findings.length} known vulnerabilities`} (${countLine(g.counts)}).`);
    for (const f of g.exploited.slice(0, 3)) L.push(`   ${exploitedLine(f)}`);
    if (g.exploited.length > 3) L.push(`   And ${g.exploited.length - 3} more on that list.`);
    if (one && g.packages[0].via && g.packages[0].via[0] !== g.packages[0].name) L.push(`   It comes with ${g.packages[0].via.join(", ")}.`);
    if (!one) {
      for (const pk of g.packages.slice(0, 6)) L.push(`   - ${pkgLine(pk)}${pk.via && pk.via[0] !== pk.name ? ` (inside ${pk.via.join(", ")})` : ""}`);
      if (g.packages.length > 6) L.push(style.dim(`   - and ${g.packages.length - 6} more (--report lists them all)`));
    }
    if (g.how) L.push(`   How: ${g.how}`);
    if (g.findings.some((f) => f.confidence === "likely")) L.push(style.dim("   Matched by version number: check the app's own version before acting."));
    L.push("");
  });
  if (r.eol.length) {
    L.push(style.strong("No longer supported (no more security fixes from the maker):"));
    for (const e of r.eol) L.push(`   - ${e.what}: support ended${e.eol_on ? ` ${date(e.eol_on)}` : ""}.${e.move_to ? ` Move to ${e.move_to} or later.` : ""}`);
    L.push("");
  }
  if (r.no_fix.length) {
    const pk = new Set(r.no_fix.map((f) => f.package));
    const ex = r.no_fix.filter((f) => f.exploited).length;
    L.push(`No fix published yet: ${plural(r.no_fix.length, "vulnerability", "vulnerabilities")} in ${plural(pk.size, "package")}${ex ? `, ${ex} of them exploited` : " (none exploited)"}. Nothing to do but update when fixes arrive; --report lists them.`, "");
  }
  if (r.unchecked.length) L.push(style.dim(`Not checked: ${plural(r.unchecked.length, "item")} with no public vulnerability data we can match${r.nvd_available ? `; ${p} scan --nvd checks ${plural(r.nvd_available, "known app")} against NVD (it sends their names and versions there)` : ""}. ${p} scan --unchecked lists them.`), "");
  L.push(`Every finding above is free and complete. ${p} scan --report scan.md writes each one with its CVE, score and link.`);
  return L.join("\n");
}

export function renderMarkdown(r) {
  const L = [];
  L.push(`# Machine check: ${r.os.label}`, "");
  L.push(`Checked ${r.checked_at} by WorldSignals \`ws scan\` ${r.cli_version}. ${r.checked} programs and packages, against ${r.databases.join(", ")}. ${sentLine(r)}`, "");
  if (!r.groups.length) L.push("**Nothing to update:** no known vulnerabilities with a fix in what was checked.", "");
  for (const g of r.groups) {
    L.push(`## ${groupTitle(g)}${g.exploited.some((f) => !f.exploited.elsewhere) ? " (exploited now)" : g.exploited.length ? " (exploited in another product)" : ""}`, "");
    for (const f of g.exploited) L.push(`- ${exploitedLine(f)}`);
    if (g.exploited.length) L.push("");
    L.push(`${g.findings.length} known vulnerabilities: ${countLine(g.counts)}.${g.how ? ` **How to fix:** \`${g.how}\`` : ""}`, "");
    L.push("| Package | Installed | Upgrade to |", "|---|---|---|");
    for (const p of g.packages) L.push(`| ${p.label ?? p.name}${p.via && p.via[0] !== p.name ? ` (inside ${p.via.join(", ")})` : ""} | ${p.version} | ${p.target} |`);
    L.push("", "| Vulnerability | Severity | Fixed in | Exploited | Summary |", "|---|---|---|---|---|");
    for (const p of g.packages)
      for (const f of p.findings)
        L.push(`| [${f.cves[0] ?? f.id}](${f.link}) | ${f.severity}${f.score !== null ? ` ${f.score}` : ""} | ${f.fixed} | ${f.exploited ? `since ${f.exploited.since}${f.exploited.elsewhere ? ` (in ${f.exploited.elsewhere})` : ""}${f.exploited.ransomware ? ", ransomware" : ""}` : ""} | ${f.summary.replace(/\|/g, "/")} |`);
    L.push("");
  }
  if (r.eol.length) {
    L.push("## No longer supported", "");
    for (const e of r.eol) L.push(`- **${e.what}**: support ended ${e.eol_on ?? ""}.${e.move_to ? ` Move to ${e.move_to} or later.` : ""} (${e.link})`);
    L.push("");
  }
  if (r.no_fix.length) {
    L.push("## No fix published yet", "", "| Package | Version | Vulnerability | Severity | Exploited |", "|---|---|---|---|---|");
    for (const f of r.no_fix) L.push(`| ${f.package} | ${f.version} | [${f.cves[0] ?? f.id}](${f.link}) | ${f.severity} | ${f.exploited ? `since ${f.exploited.since}` : ""} |`);
    L.push("");
  }
  if (r.unchecked.length) {
    L.push("## Not checked", "", "No public vulnerability data we can match (or, for known apps, run with `--nvd`):", "");
    L.push(r.unchecked.map((u) => `${u.label ?? u.name} ${u.version}`).join(", "), "");
  }
  L.push("## How this was checked", "");
  for (const s of r.sources) L.push(`- ${s.source}: ${s.error ? `not checked (${s.error})` : `${s.count} items`}`);
  L.push(
    "- Distribution packages are checked against the distribution's own advisories in OSV.dev, which know backported fixes; language packages against OSV.dev; apps (with --nvd) by version number against NVD.",
    "- Exploited: CISA's Known Exploited Vulnerabilities catalogue. Support: endoflife.date.",
    "",
  );
  return L.join("\n");
}

// ---------------------------------------------------------------------------------------------------------------
// Gathering: read-only commands, never through a shell, each with a time limit.

/**
 * Runs a program; its stdout, or null when it isn't installed, fails or takes too long. `anyExit`: keep what it
 * printed even when it exits non-zero (npm ls does, for any warning in the tree, with its JSON complete).
 */
export function runProgram(command, args, { timeout = 60_000, env, anyExit = false } = {}) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, maxBuffer: 128 * 1024 * 1024, env: { ...process.env, ...env, LC_ALL: "C" }, windowsHide: true }, (error, stdout) =>
      resolve(!error || (anyExit && error.code !== "ENOENT" && !error.killed && stdout) ? stdout : null),
    );
  });
}

const readText = (path) => {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
};
const listDir = (path) => {
  try {
    return readdirSync(path);
  } catch {
    return [];
  }
};
const isFile = (path) => {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
};

/** Runs fn on every item, at most n at a time. */
async function pool(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) {
        const k = next++;
        out[k] = await fn(items[k], k);
      }
    }),
  );
  return out;
}

/** The first `name` on PATH, or null. */
function onPath(name, env) {
  for (const dir of String(env.PATH ?? "").split(delimiter)) if (dir && isFile(join(dir, name))) return join(dir, name);
  return null;
}

/**
 * Everything installed that can be read without admin rights: {os, items, sources, runtimes}. `sys` replaces the
 * program runner and the file reads, for tests.
 */
export async function gather({ platform = process.platform, env = process.env, here = false, cwd = process.cwd(), sys = {}, progress = () => {} } = {}) {
  const run = sys.run ?? runProgram;
  const read = sys.read ?? readText;
  const ls = sys.ls ?? listDir;
  const which = sys.which ?? ((name) => onPath(name, env));
  const items = [];
  const sources = [];
  const runtimes = [{ product: "nodejs", cycle: process.versions.node.split(".")[0], what: `Node.js ${process.versions.node} (running this scan)` }];
  const note = (source, list, error) => {
    if (list) items.push(...list);
    sources.push({ source, count: list?.length ?? 0, ...(error ? { error } : {}) });
  };
  let os = { family: platform === "darwin" ? "macos" : platform === "win32" ? "windows" : "linux", label: platform };

  if (platform === "darwin") {
    const version = (await run("sw_vers", ["-productVersion"]))?.trim() ?? "";
    os = { family: "macos", version, label: `macOS ${version}`.trim() };
    progress("Homebrew");
    if (which("brew")) {
      const out = await run("brew", ["info", "--json=v2", "--installed"], { timeout: 120_000 });
      try {
        note("Homebrew", out ? parseBrew(JSON.parse(out)) : null, out ? null : "brew info failed");
      } catch {
        note("Homebrew", null, "brew's answer wasn't JSON");
      }
    }
    progress("apps");
    const home = env.HOME || homedir();
    const bundles = ["/Applications", "/Applications/Utilities", join(home, "Applications")].flatMap((dir) => ls(dir).filter((n) => n.endsWith(".app")).map((n) => join(dir, n)));
    const apps = await pool(bundles, 8, async (path) => {
      const json = await run("plutil", ["-convert", "json", "-o", "-", join(path, "Contents", "Info.plist")], { timeout: 10_000 });
      try {
        return json ? appFromInfo(JSON.parse(json), path) : null;
      } catch {
        return null;
      }
    });
    note("Applications", apps.filter(Boolean));
  } else if (platform === "linux") {
    const rel = parseOsRelease(read("/etc/os-release") ?? read("/usr/lib/os-release") ?? "");
    const ecosystem = distroEcosystem(rel);
    os = { family: "linux", id: (rel.ID ?? "linux").toLowerCase(), version: rel.VERSION_ID ?? "", name: rel.NAME ?? "Linux", label: rel.PRETTY_NAME ?? `${rel.NAME ?? "Linux"} ${rel.VERSION_ID ?? ""}`.trim(), ecosystem };
    const unmatched = ecosystem ? null : `OSV.dev has no advisories for ${os.label}, so its packages are listed but not checked`;
    progress("system packages");
    if (which("dpkg-query")) {
      const out = await run("dpkg-query", ["-W", "-f", "${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${db:Status-Abbrev}\\n"]);
      note("dpkg", out === null ? null : parseDpkg(out, ecosystem), out === null ? "dpkg-query failed" : unmatched);
    }
    if (which("rpm")) {
      const out = await run("rpm", ["-qa", "--qf", "%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{SOURCERPM}\\n"]);
      note("rpm", out === null ? null : parseRpm(out, ecosystem), out === null ? "rpm failed" : unmatched);
    }
    const apkDb = read("/lib/apk/db/installed");
    if (apkDb) note("apk", parseApk(apkDb, ecosystem), unmatched);
    if (which("snap")) {
      const out = await run("snap", ["list"]);
      if (out) note("snap", parseSnapList(out));
    }
    if (which("flatpak")) {
      const out = await run("flatpak", ["list", "--app", "--columns=application,version"]);
      if (out) note("flatpak", parseFlatpakList(out));
    }
  } else {
    sources.push({ source: "installed programs", count: 0, error: "Windows programs aren't read yet: this version checks global npm and pip packages and lockfiles" });
    os.label = "Windows";
  }

  progress("npm");
  if (platform !== "win32" && which("npm")) {
    const out = await run("npm", ["ls", "-g", "--json", "--all"], { timeout: 60_000, anyExit: true });
    try {
      note("npm (global)", out ? parseNpmLs(JSON.parse(out)) : null, out ? null : "npm ls failed");
    } catch {
      note("npm (global)", null, "npm's answer wasn't JSON");
    }
  }

  progress("pip");
  const python = await pythonToRun({ platform, which, run });
  if (python.path) {
    const version = (await run(python.path, ["--version"]))?.match(/Python (\d+\.\d+)(\.\d+)?/);
    if (version) runtimes.push({ product: "python", cycle: version[1], what: `Python ${version[1]}${version[2] ?? ""} (${python.path})` });
    const out = await run(python.path, ["-m", "pip", "list", "--format=json", "--disable-pip-version-check"], { timeout: 60_000 });
    try {
      // The Python that came with macOS can't be changed without --user.
      const user = platform === "darwin" && python.path === "/usr/bin/python3";
      note("pip", out ? parsePipList(JSON.parse(out)).map((i) => ({ ...i, python: python.path, ...(user ? { user: true } : {}) })) : null, out ? null : "pip isn't installed for this Python");
    } catch {
      note("pip", null, "pip's answer wasn't JSON");
    }
  } else if (python.why) sources.push({ source: "pip", count: 0, error: python.why });

  if (here) {
    for (const [file, parse] of LOCKFILES) {
      const text = read(join(cwd, file));
      if (text === null) continue;
      try {
        note(file, parse(text, file));
      } catch {
        note(file, null, "couldn't be read");
      }
    }
  }
  return { os, items, sources, runtimes };
}

/**
 * The python3 to ask pip about. On a Mac without the developer tools, /usr/bin/python3 is a stub that opens an
 * "install the tools?" dialog: it is never run then.
 */
async function pythonToRun({ platform, which, run }) {
  const path = which("python3");
  if (!path) return { path: null };
  if (platform === "darwin" && path === "/usr/bin/python3" && (await run("xcode-select", ["-p"])) === null) {
    return { path: null, why: "skipped: /usr/bin/python3 would ask to install Apple's developer tools" };
  }
  return { path };
}

// ---------------------------------------------------------------------------------------------------------------
// Asking the databases. Every request goes through `ask`, which records it, so --dry-run can print them instead.

const cacheDir = (env) => join(env.XDG_CACHE_HOME || join(env.HOME || homedir(), ".cache"), "worldsignals");

async function getJson(fetch, url, init = {}) {
  const res = await fetch(url, { ...init, headers: { accept: "application/json", "user-agent": "worldsignals-cli (ws scan)", ...(init.headers ?? {}) } });
  if (!res.ok) throw new Error(`${new URL(url).host} answered ${res.status}`);
  return res.json();
}

/** CISA's catalogue as a Map of CVE → entry, cached for 12 hours (and kept when CISA can't be reached). */
export async function loadKev(fetch, env, now = Date.now()) {
  const dir = cacheDir(env);
  const path = join(dir, "kev.json");
  let cached = null;
  try {
    cached = JSON.parse(readFileSync(path, "utf8"));
  } catch {}
  let body = cached?.body;
  if (!body || now - (cached.at ?? 0) > KEV_MAX_AGE_MS) {
    try {
      body = await getJson(fetch, KEV_URL);
      try {
        mkdirSync(dir, { recursive: true });
        writeFileSync(path, JSON.stringify({ at: now, body }));
      } catch {}
    } catch (e) {
      if (!body) throw e;
    }
  }
  return new Map((body?.vulnerabilities ?? []).map((k) => [k.cveID, k]));
}

/** OSV's matches for every item with an ecosystem: Map of item → full vulnerability records. */
export async function queryOsv(fetch, items, { concurrency = 6, progress = () => {} } = {}) {
  const hits = [];
  for (let k = 0; k < items.length; k += OSV_BATCH) {
    const chunk = items.slice(k, k + OSV_BATCH);
    progress(`OSV.dev ${Math.min(k + OSV_BATCH, items.length)}/${items.length}`);
    const body = await getJson(fetch, `${OSV_API}/querybatch`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ queries: chunk.map(osvQuery) }) });
    (body.results ?? []).forEach((r, i) => r?.vulns?.length && hits.push(chunk[i]));
  }
  // Full records only for the packages that have any: one request each (paged), not one per vulnerability.
  const found = new Map();
  await pool(hits, concurrency, async (item) => {
    const vulns = [];
    let token;
    do {
      const body = await getJson(fetch, `${OSV_API}/query`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...osvQuery(item), ...(token ? { page_token: token } : {}) }) });
      vulns.push(...(body.vulns ?? []));
      token = body.next_page_token;
    } while (token);
    found.set(item, vulns);
  });
  return found;
}

const osvQuery = (item) => ({ package: { ecosystem: item.ecosystem, name: item.name }, version: item.version });

/** NVD's CVEs for one app at its version, under each name NVD knows it by; paced to NVD's limits (5 requests in
 * 30 s, 50 with a key). */
export async function queryNvd(fetch, app, item, env, pause) {
  const all = new Map();
  for (const cpe of app.cpes) {
    let start = 0;
    for (;;) {
      const params = new URLSearchParams({ virtualMatchString: `cpe:2.3:a:${cpe}:${item.version}`, resultsPerPage: "2000", startIndex: String(start) });
      const body = await getJson(fetch, `${NVD_API}?${params}`, { headers: env.NVD_API_KEY ? { apiKey: env.NVD_API_KEY } : {} });
      for (const v of body.vulnerabilities ?? []) all.set(v.cve?.id, v);
      start += body.vulnerabilities?.length ?? 0;
      await pause(env.NVD_API_KEY ? 700 : 6500);
      if (!body.vulnerabilities?.length || start >= body.totalResults) break;
    }
  }
  return [...all.values()];
}

// ---------------------------------------------------------------------------------------------------------------
// The command.

export const SCAN_HELP = (p = "ws") => `${p} scan [--report <file.md>] [--json] [--dry-run] [--here] [--nvd] [--inventory] [--unchecked]
      Check the software installed on this machine against public vulnerability databases, and say in plain
      language what to update: grouped by the one upgrade that fixes each group, what is being exploited right
      now first (CISA's list), and what no longer gets security fixes. Free and complete; no account needed.
      Reads Homebrew and the apps in /Applications (macOS), dpkg, rpm, apk, snap and flatpak (Linux), and
      global npm and pip packages. Needs no admin rights.
      Sends package names and versions to OSV.dev (Google) and product names to endoflife.date; nothing to
      WorldSignals. --dry-run shows every request and sends none.
      --report <file>   also write the full report, every vulnerability with its score and link, as Markdown
      --json            the findings as one JSON object
      --dry-run         list what would be sent, and where, and send nothing
      --here            also check the lockfiles in this folder (package-lock.json, requirements.txt,
                        Cargo.lock, poetry.lock, uv.lock, Gemfile.lock, composer.lock)
      --nvd             also check known desktop apps and Homebrew formulae against NVD (NIST), by version:
                        sends their names and versions there; slow without NVD_API_KEY (one app every 7 s)
      --inventory       only list what is installed; no network
      --unchecked       list what couldn't be checked

  Alerts (opt-in): WorldSignals keeps this machine's list of names and versions and tells your account when a new
  vulnerability hits something on it. The list is shown before anything is sent.
      --alerts          enrol this machine and send the list (asks first; with --dry-run, only shows it)
      --token <token>   an enrolment token from the console (Machines → Add a machine); without one, the
                        access key (WS_KEY) or the agent key on this device enrols it in that account
      --label <name>    the machine's name in the console (default: none; set it there later)
      --yes             send without asking, for scripts and device management
      --schedule <daily|weekly|off>  re-check and send the list on a schedule, as you (no admin rights):
                        launchd on macOS, a systemd user timer or cron on Linux, Task Scheduler on Windows
      --upload          send the current list now (what the schedule runs)
      --forget          delete this machine and its list from WorldSignals, and stop the schedule`;

/** ws scan. `ctx` is ws.mjs's: fetch, env, out, err, platform, style, p; `sys` and `pause` stand in for tests. */
export async function scan(argv, ctx) {
  const { fetch, env, out, err, p = "ws", platform = process.platform, style = {}, sys, pause = (ms) => new Promise((r) => setTimeout(r, ms)), now = () => new Date(), version = "" } = ctx;
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        report: { type: "string" },
        json: { type: "boolean" },
        "dry-run": { type: "boolean" },
        here: { type: "boolean" },
        nvd: { type: "boolean" },
        inventory: { type: "boolean" },
        unchecked: { type: "boolean" },
        alerts: { type: "boolean" },
        token: { type: "string" },
        label: { type: "string" },
        yes: { type: "boolean" },
        schedule: { type: "string" },
        upload: { type: "boolean" },
        forget: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
      strict: true,
    }));
  } catch (e) {
    err(`${e.message}\n\n${SCAN_HELP(p)}`);
    return 2;
  }
  if (values.help) {
    out(SCAN_HELP(p));
    return 0;
  }
  const api = (env.WS_API || "https://worldsignals.dev").replace(/\/$/, "");
  if (values.forget) return forgetMachine({ ...ctx, api, platform, sys }, values);
  if (values.schedule !== undefined) return scheduleScan({ ...ctx, api, platform, sys }, values.schedule);
  const tty = style.err?.on && !values.json && !values.upload;
  const progress = (what) => tty && err(style.err.dim(`  reading ${what}…`));
  const started = now();
  const inv = await gather({ platform, env, here: values.here, cwd: ctx.cwd ?? process.cwd(), sys, progress });
  if (values.alerts || values.upload) return sendInventory({ ...ctx, api, platform, sys }, values, inv);

  if (values.inventory) {
    if (values.json) out(JSON.stringify({ os: inv.os, sources: inv.sources, items: inv.items }));
    else {
      out(`${inv.os.label}: ${plural(inv.items.length, "item")}`);
      for (const s of inv.sources) out(`  ${s.source}: ${s.error ? `not read (${s.error})` : s.count}`);
      for (const i of inv.items) out(`${i.source}\t${i.ecosystem ?? ""}\t${i.label ?? i.name}\t${i.version}`);
    }
    return 0;
  }

  const osvItems = dedupe(inv.items.filter((i) => i.ecosystem));
  const appItems = inv.items.filter((i) => !i.ecosystem).map((i) => ({ item: i, app: appFor(i) }));
  const nvdItems = values.nvd ? appItems.filter((a) => a.app && /^\d/.test(a.item.version)) : [];
  const targets = eolTargets({ os: inv.os, items: inv.items, runtimes: inv.runtimes });
  for (const a of appItems) if (a.app?.eol) targets.push(...eolTargets({ items: [], runtimes: [{ product: a.app.eol, cycle: a.item.version.split(".").slice(0, 2).join("."), what: `${a.app.label} ${a.item.version}` }] }));
  dedupeInPlace(targets, (t) => `${t.product}@${t.cycle}`);

  if (values["dry-run"]) {
    out(`Would check ${plural(inv.items.length, "item")} on ${inv.os.label}. Nothing is sent by --dry-run. The requests a real scan makes:\n`);
    if (osvItems.length) {
      out(`POST ${OSV_API}/querybatch  (OSV.dev, run by Google), this body${osvItems.length > OSV_BATCH ? `, in batches of ${OSV_BATCH}` : ""}:`);
      out(`{"queries": [\n${osvItems.map((i) => `  ${JSON.stringify(osvQuery(i))}`).join(",\n")}\n]}`);
      out(`\nThen, for each of those packages OSV.dev says has known vulnerabilities: POST ${OSV_API}/query with that one entry of the body above, for the full records.\n`);
    }
    out(`GET ${KEV_URL}  (CISA's catalogue, downloaded whole; nothing about this machine is sent; cached 12 hours)`);
    for (const t of dedupeBy(targets, (t) => t.product)) out(`GET ${EOL_API}/${t.product}  (endoflife.date; only the product name)`);
    for (const { app, item } of nvdItems) for (const cpe of app.cpes) out(`GET ${NVD_API}?virtualMatchString=cpe:2.3:a:${cpe}:${item.version}  (NVD)`);
    if (!values.nvd && appItems.some((a) => a.app)) out(`\nWith --nvd, also one NVD request per known app (${appItems.filter((a) => a.app).length} here), naming the app and its version.`);
    out(`\nNothing is sent to WorldSignals.`);
    return 0;
  }

  if (values.unchecked) {
    const list = appItems.filter((a) => !values.nvd || !a.app);
    for (const { item, app } of list) out(`${item.source}\t${item.label ?? item.name}\t${item.version}${app ? `\t(--nvd checks it)` : ""}`);
    return 0;
  }

  let kev = new Map();
  const databases = ["OSV.dev"];
  try {
    progress("CISA's exploited list");
    kev = await loadKev(fetch, env, started.getTime());
    databases.push("CISA's exploited list");
  } catch (e) {
    inv.sources.push({ source: "CISA KEV", count: 0, error: `couldn't be downloaded (${e.message}); exploited vulnerabilities aren't marked` });
  }

  const matched = [];
  let osvFailed = null;
  if (osvItems.length) {
    try {
      const found = await queryOsv(fetch, osvItems, { progress });
      for (const [item, vulns] of found) matched.push({ item, findings: osvFindings(item, vulns, kev) });
    } catch (e) {
      osvFailed = e.message;
      inv.sources.push({ source: "OSV.dev", count: 0, error: `couldn't be reached (${e.message}): packages weren't checked` });
    }
  }
  for (const [n, { app, item }] of nvdItems.entries()) {
    progress(`NVD ${n + 1}/${nvdItems.length}: ${app.label}`);
    try {
      matched.push({ item, app, findings: nvdFindings(app, item, await queryNvd(fetch, app, item, env, pause), kev, inv.os.family) });
    } catch (e) {
      inv.sources.push({ source: `NVD: ${app.label}`, count: 0, error: e.message });
    }
  }
  if (nvdItems.length) databases.push("NVD");

  const eol = [];
  for (const product of [...new Set(targets.map((t) => t.product))]) {
    try {
      const answer = await getJson(fetch, `${EOL_API}/${product}`);
      for (const t of targets.filter((t) => t.product === product)) {
        const f = eolFinding(t, answer, started);
        if (f) eol.push(f);
      }
    } catch (e) {
      inv.sources.push({ source: `endoflife.date: ${product}`, count: 0, error: `support dates couldn't be read (${e.message})` });
    }
  }
  if (targets.length) databases.push("endoflife.date");

  const { groups, noFix } = groupFindings(matched, { os: inv.os });
  const report = {
    cli_version: version,
    checked_at: started.toISOString(),
    os: inv.os,
    checked: inv.items.length,
    databases,
    sent: { osv: osvItems.length > 0 && !osvFailed, eol: targets.length > 0, nvd: nvdItems.length > 0, worldsignals: false },
    sources: inv.sources,
    groups,
    eol,
    no_fix: noFix,
    unchecked: appItems.filter((a) => !nvdItems.includes(a)).map((a) => a.item),
    nvd_available: values.nvd ? 0 : appItems.filter((a) => a.app).length,
  };

  if (values.report) {
    try {
      writeFileSync(values.report, renderMarkdown(report));
    } catch (e) {
      err(`Couldn't write ${values.report}: ${e.message}`);
      return 1;
    }
  }
  if (values.json) out(JSON.stringify(report));
  else {
    out(renderText(report, style.out ?? undefined, p));
    if (values.report) out(`\nThe full report is in ${values.report}.`);
  }
  return osvFailed && !osvItems.length ? 1 : 0;
}

function dedupeInPlace(list, key) {
  const kept = dedupeBy(list, key);
  list.splice(0, list.length, ...kept);
}
const dedupe = (items) => dedupeBy(items, (i) => `${i.ecosystem}|${i.name}|${i.version}`);
function dedupeBy(list, key) {
  const seen = new Set();
  return list.filter((x) => !seen.has(key(x)) && seen.add(key(x)));
}

// ---------------------------------------------------------------------------------------------------------------
// Alerts: this machine's list of names and versions, kept by WorldSignals and matched against every new
// vulnerability. Opt-in, shown before it is sent, deleted with --forget.

const configDirOf = (env) => join(env.XDG_CONFIG_HOME || join(env.HOME || homedir(), ".config"), "worldsignals");
/** Where the machine key is kept: one entry per server, readable only by you. */
export const machinePath = (env = {}) => join(configDirOf(env), "machine.json");

function readMachines(env) {
  try {
    return JSON.parse(readFileSync(machinePath(env), "utf8")).machines ?? {};
  } catch {
    return {};
  }
}
export const readMachine = (env, api) => readMachines(env)[api] ?? null;

function saveMachine(env, api, entry) {
  const machines = readMachines(env);
  if (entry) machines[api] = entry;
  else delete machines[api];
  const path = machinePath(env);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify({ version: 1, machines }, null, 2)}\n`, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {}
}

/**
 * Exactly what --alerts sends: per item its source, ecosystem, name, version, and for an app the product names it is
 * matched by and how to update it. No file paths, user names, host name or serial number.
 */
export function uploadPayload(inv, version) {
  const items = inv.items.map((i) => {
    const app = appFor(i);
    return {
      source: i.source,
      ...(i.ecosystem ? { ecosystem: i.ecosystem } : {}),
      name: i.name,
      version: i.version,
      ...(i.label && i.label !== i.name ? { label: i.label } : {}),
      ...(app ? { cpes: app.cpes, how: appHow(app, i) } : {}),
    };
  });
  const os = { family: inv.os.family, version: inv.os.version ?? "", label: inv.os.label, ...(inv.os.ecosystem ? { ecosystem: inv.os.ecosystem } : {}) };
  return { cli_version: version, os, items: dedupeBy(items, (i) => `${i.source}|${i.ecosystem ?? ""}|${i.name}|${i.version}`) };
}

/** The payload as it is shown before sending: one item per line, so every one can be read. */
const shownPayload = (payload) =>
  `{"cli_version": ${JSON.stringify(payload.cli_version)}, "os": ${JSON.stringify(payload.os)}, "items": [\n${payload.items.map((i) => `  ${JSON.stringify(i)}`).join(",\n")}\n]}`;

/** A new Ed25519 key pair, as ws signup makes one: the public key raw and base64url, the private key as PEM. */
function newMachineKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { publicKey: publicKey.export({ format: "jwk" }).x, privateKey: privateKey.export({ format: "pem", type: "pkcs8" }) };
}

let lastSigned = 0;
/**
 * The headers that sign a machine's request: the same signed string as an agent's (method, path and query,
 * timestamp, the body's SHA-256), under X-WS-Machine.
 */
export function machineHeaders(method, url, body, privateKeyPem, machineId, now = Date.now()) {
  lastSigned = Math.max(Math.floor(now), lastSigned + 1);
  const timestamp = (lastSigned / 1000).toFixed(3);
  const u = new URL(url);
  const hash = body ? createHash("sha256").update(body).digest("base64url") : "";
  const text = `${method.toUpperCase()} ${u.pathname}${u.search} ${timestamp} ${hash}`;
  return { "x-ws-machine": machineId, "x-ws-timestamp": timestamp, "x-ws-signature": sign(null, Buffer.from(text), createPrivateKey(privateKeyPem)).toString("base64url") };
}

async function callApi(ctx, method, path, payload, headersFor) {
  const url = `${ctx.api}${path}`;
  const body = payload === undefined ? "" : JSON.stringify(payload);
  const res = await ctx.fetch(url, {
    method,
    headers: { "user-agent": `ws-cli/${ctx.version ?? ""} (scan)`, ...(body ? { "content-type": "application/json" } : {}), ...headersFor(method, url, body) },
    ...(body ? { body } : {}),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
const machineCall = (ctx, entry, method, path, payload) => callApi(ctx, method, path, payload, (m, url, body) => machineHeaders(m, url, body, entry.private_key, entry.machine_id));

/** Yes or no from the person at the terminal; null without one. */
async function askYes(stdin, question, err) {
  if (!stdin) return null;
  err(question);
  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: stdin, terminal: false });
  const line = await new Promise((resolve) => rl.once("line", resolve).once("close", () => resolve("")));
  rl.close();
  return /^y(es)?$/i.test(String(line).trim());
}

/** What the server's refusal means, in words. */
function refusal(r, p) {
  if (r.status === 402) return r.body.error ?? `This account's plan has no room for another machine. Remove one in the console, or upgrade.`;
  if (r.status === 401 || r.status === 410) return r.body.error ?? `WorldSignals no longer knows this machine (it was removed in the console). ${p} scan --alerts enrols it again.`;
  if (r.status === 403) return r.body.error ?? "That key may not enrol machines: it needs the Machines permission.";
  if (r.status === 429) return r.body.error ?? "Too many requests just now: wait a minute and try again.";
  return r.body.error ? String(r.body.error) : `WorldSignals answered ${r.status}.`;
}

/**
 * Shows exactly what will be sent and asks: true to go on, or the exit code (0 when declined or a dry run, 2 when
 * there is no terminal to ask and no --yes).
 */
async function showAndAsk(ctx, values, payload, question) {
  const { out, err, p = "ws", api } = ctx;
  out(`This is everything that goes to WorldSignals (POST ${api}/api/machine/report):\n`);
  out(shownPayload(payload));
  out(`\n${plural(payload.items.length, "item")}: for each, where it came from, its name and version (and, for apps, the product names it is matched by). No file paths, user names, host name or serial number.`);
  out(`WorldSignals keeps the latest list for as long as the machine reports, matches it against every new vulnerability, and alerts the account it is enrolled in. ${p} scan --forget deletes it.`);
  if (values["dry-run"]) {
    out(`\n--dry-run: nothing was sent.`);
    return 0;
  }
  if (values.yes) return true;
  const yes = await askYes(ctx.stdin, `\n${question} [y/N] `, err);
  if (yes === null) {
    err(`Not sent: there is no terminal to ask. After checking the list (--dry-run), add --yes to send it.`);
    return 2;
  }
  if (!yes) out("Nothing was sent.");
  return yes ? true : 0;
}

/** ws scan --alerts (enrol if needed, show, ask, send) and --upload (send, as the schedule does). */
async function sendInventory(ctx, values, inv) {
  const { env, out, err, p = "ws", api } = ctx;
  const payload = uploadPayload(inv, ctx.version ?? "");
  const reportUrl = `${api}/api/machine/report`;
  let entry = readMachine(env, api);

  if (values.upload) {
    if (!entry) {
      err(`This machine isn't enrolled for alerts. ${p} scan --alerts shows what it would send, then asks.`);
      return 2;
    }
  } else {
    const agreed = await showAndAsk(ctx, values, payload, entry ? "Send it?" : "Send it and enrol this machine?");
    if (agreed !== true) return agreed;
  }

  if (!entry) {
    // The token may come from the environment, to keep it out of the process list and the shell's history.
    values = { ...values, token: values.token ?? (env.WS_ENROL_TOKEN || undefined) };
    const credential = values.token ? { headers: () => ({}) } : ctx.credentialHeaders ? { headers: ctx.credentialHeaders } : null;
    if (!credential || (!values.token && !ctx.credentialHeaders?.("POST", `${api}/api/machines/enrol`, "{}"))) {
      err(
        `To enrol this machine, make an enrolment token in the console (Machines → Add a machine) and run\n` +
          `  ${p} scan --alerts --token <token>\n` +
          `(or set WS_KEY to an access key with the Machines permission, or connect this device's agent: ${p} connect).`,
      );
      return 2;
    }
    const key = newMachineKey();
    const enrolment = { public_key: key.publicKey, os: payload.os, ...(values.label ? { label: values.label } : {}), ...(values.token ? { token: values.token } : {}), consent: true };
    const r = await callApi(ctx, "POST", "/api/machines/enrol", enrolment, (m, url, body) => (values.token ? {} : credential.headers(m, url, body) ?? {}));
    if (r.status >= 400) {
      err(`Not enrolled: ${refusal(r, p)}`);
      return 1;
    }
    entry = { machine_id: r.body.machine_id, private_key: key.privateKey, label: r.body.label ?? values.label ?? null, account: r.body.account?.name ?? null, enrolled_at: new Date().toISOString() };
    saveMachine(env, api, entry);
  }

  const r = await machineCall(ctx, entry, "POST", "/api/machine/report", payload);
  if (r.status >= 400) {
    err(`Not sent: ${refusal(r, p)}`);
    return 1;
  }
  const b = r.body;
  const name = b.label ?? entry.label ?? "This machine";
  if (values.upload) {
    out(`${new Date().toISOString()} sent ${plural(payload.items.length, "item")}${b.changes ? ` (${b.changes.added ?? 0} added, ${b.changes.removed ?? 0} removed, ${b.changes.upgraded ?? 0} upgraded)` : ""}.`);
    return 0;
  }
  out(`\nSent. ${name} is enrolled${b.account?.name ?? entry.account ? ` in ${b.account?.name ?? entry.account}` : ""}: WorldSignals tells you when a new vulnerability hits something on it.`);
  if (b.console_url) out(`See it in the console: ${b.console_url}`);
  if (!entry.schedule) out(`To keep the list current: ${p} scan --schedule daily (as you, no admin rights).`);
  return 0;
}

/** ws scan --forget: delete it at WorldSignals, then here, and stop the schedule. */
async function forgetMachine(ctx, values) {
  const { env, out, err, p = "ws", api } = ctx;
  const entry = readMachine(env, api);
  if (!entry) {
    out("This machine isn't enrolled: WorldSignals holds nothing for it.");
    return 0;
  }
  let r;
  try {
    r = await machineCall(ctx, entry, "DELETE", "/api/machine");
  } catch (e) {
    err(`Couldn't reach WorldSignals (${e.message}); nothing was deleted. Try again, or remove the machine in the console.`);
    return 1;
  }
  if (r.status >= 400 && r.status !== 401 && r.status !== 404 && r.status !== 410) {
    err(`Not deleted: ${refusal(r, p)}`);
    return 1;
  }
  await scheduleScan({ ...ctx, quiet: true }, "off");
  saveMachine(env, api, null);
  out(`Deleted: WorldSignals no longer holds this machine or its list, the key on this device is gone${entry.schedule ? ", and the schedule is off" : ""}.`);
  return 0;
}

// ---------------------------------------------------------------------------------------------------------------
// Scheduling, as the person who runs it: launchd (macOS), a systemd user timer or cron (Linux), Task Scheduler
// (Windows). Each runs `ws scan --upload`, once a day or a week, at an hour picked from the machine id so that
// machines don't all report at once.

export const SCHEDULE_NAME = "dev.worldsignals.scan";
const CRON_MARK = "# worldsignals-scan";

/** An hour between 09:00 and 16:59 and a minute, stable for one machine. */
export function scheduleTime(machineId = "") {
  const h = createHash("sha256").update(machineId).digest();
  return { hour: 9 + (h[0] % 8), minute: h[1] % 60 };
}

const xml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function launchdPlist({ node, script, every, hour, minute, log }) {
  const when = `<dict><key>Hour</key><integer>${hour}</integer><key>Minute</key><integer>${minute}</integer>${every === "weekly" ? "<key>Weekday</key><integer>1</integer>" : ""}</dict>`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${SCHEDULE_NAME}</string>
  <key>ProgramArguments</key><array><string>${xml(node)}</string><string>${xml(script)}</string><string>scan</string><string>--upload</string></array>
  <key>StartCalendarInterval</key>${when}
  <key>StandardOutPath</key><string>${xml(log)}</string>
  <key>StandardErrorPath</key><string>${xml(log)}</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
`;
}

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
/** A word for systemd's ExecStart: its own quoting, where $ and % mean something too. */
const sdq = (s) => `"${String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\$/g, "$$$$").replace(/%/g, "%%")}"`;
/** A word for a crontab line: the shell's quoting, and cron turns a bare % into a new line. */
const cronq = (s) => shq(s).replace(/%/g, "\\%");

export function systemdUnits({ node, script, every, hour, minute }) {
  const calendar = `${every === "weekly" ? "Mon " : ""}*-*-* ${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}:00`;
  return {
    service: `[Unit]\nDescription=WorldSignals: send this machine's software list for vulnerability alerts\n\n[Service]\nType=oneshot\nExecStart=${sdq(node)} ${sdq(script)} scan --upload\n`,
    timer: `[Unit]\nDescription=WorldSignals scan, ${every}\n\n[Timer]\nOnCalendar=${calendar}\nPersistent=true\nRandomizedDelaySec=15min\n\n[Install]\nWantedBy=timers.target\n`,
  };
}

/** The crontab with our line replaced (or removed, with every = off). */
export function cronTable(current, { node, script, every, hour, minute }) {
  const kept = String(current ?? "").split("\n").filter((l) => l && !l.includes(CRON_MARK));
  if (every !== "off") kept.push(`${minute} ${hour} * * ${every === "weekly" ? "1" : "*"} ${cronq(node)} ${cronq(script)} scan --upload >/dev/null 2>&1 ${CRON_MARK}`);
  return kept.length ? `${kept.join("\n")}\n` : "";
}

export function schtasksArgs({ node, script, every, hour, minute }) {
  if (every === "off") return ["/Delete", "/F", "/TN", "WorldSignals scan"];
  const at = `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
  return ["/Create", "/F", "/SC", every === "weekly" ? "WEEKLY" : "DAILY", ...(every === "weekly" ? ["/D", "MON"] : []), "/ST", at, "/TN", "WorldSignals scan", "/TR", `"${node}" "${script}" scan --upload`];
}

/**
 * Whether scheduling as root would run a file someone else can change: node or the script not owned by root, or
 * writable by its group or everyone. Never on Windows (Task Scheduler runs it as the user who made the task).
 */
function rootRisk(node, script, ctx) {
  const uid = ctx.uid ?? (typeof process.getuid === "function" ? process.getuid() : null);
  if (uid !== 0) return false;
  for (const path of [node, script]) {
    try {
      const st = statSync(path);
      if (st.uid !== 0 || st.mode & 0o022) return true;
    } catch {
      return true;
    }
  }
  return false;
}

/** Runs a program with text on its stdin (crontab -). */
function runWithInput(command, args, input) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ["pipe", "ignore", "ignore"] });
    child.on("error", () => resolve(false));
    child.on("close", (code) => resolve(code === 0));
    child.stdin.end(input);
  });
}

/** ws scan --schedule daily|weekly|off */
async function scheduleScan(ctx, every) {
  const { env, out, err, p = "ws", api, platform = process.platform, quiet = false } = ctx;
  if (!["daily", "weekly", "off"].includes(every)) {
    err(`--schedule is daily, weekly or off.`);
    return 2;
  }
  const entry = readMachine(env, api);
  if (every !== "off" && !entry) {
    err(`This machine isn't enrolled yet: ${p} scan --alerts first (it shows what it sends and asks).`);
    return 2;
  }
  const node = ctx.nodePath ?? process.execPath;
  const script = ctx.scriptPath ?? process.argv[1] ?? "";
  if (every !== "off" && /[\u0000-\u001f\u007f]/.test(`${node}${script}`)) {
    err("The path to node or to ws has a control character in it; scheduling it isn't safe. Install it somewhere plain.");
    return 2;
  }
  if (every !== "off" && rootRisk(node, script, ctx)) {
    err(
      `Not scheduled: this runs as root, and ${script} (or node) can be changed by someone other than root, which would then run as root every day. ` +
        `Schedule it as the user who installed it, or install it where only root can write (e.g. sudo npm install -g worldsignals with a root-owned prefix).`,
    );
    return 2;
  }
  if (every !== "off" && /[\\/]_npx[\\/]/.test(script)) {
    err(`npx runs ws from a temporary folder that won't last. Install it first, then schedule:\n  npm install -g worldsignals\n  ws scan --schedule ${every}`);
    return 2;
  }
  const run = ctx.sys?.run ?? runProgram;
  const write = ctx.sys?.write ?? ((path, text) => (mkdirSync(dirname(path), { recursive: true }), writeFileSync(path, text)));
  const remove = ctx.sys?.remove ?? ((path) => rmSync(path, { force: true }));
  const withInput = ctx.sys?.runWithInput ?? runWithInput;
  const home = env.HOME || homedir();
  const { hour, minute } = scheduleTime(entry?.machine_id);
  const spec = { node, script, every, hour, minute };
  let how;

  if (platform === "darwin") {
    const plist = join(home, "Library", "LaunchAgents", `${SCHEDULE_NAME}.plist`);
    const uid = typeof process.getuid === "function" ? process.getuid() : 501;
    await run("launchctl", ["bootout", `gui/${uid}`, plist]);
    if (every === "off") remove(plist);
    else {
      write(plist, launchdPlist({ ...spec, log: join(home, "Library", "Logs", "worldsignals-scan.log") }));
      if ((await run("launchctl", ["bootstrap", `gui/${uid}`, plist])) === null) {
        err(`Couldn't load ${plist} into launchd. Load it yourself with: launchctl bootstrap gui/${uid} ${plist}`);
        return 1;
      }
    }
    how = `launchd (${plist})`;
  } else if (platform === "linux") {
    const dir = join(env.XDG_CONFIG_HOME || join(home, ".config"), "systemd", "user");
    // A systemd user timer runs only while the user is logged in, unless lingering is on (as on a server reached
    // over SSH it usually isn't): then cron, which runs whether anyone is logged in or not.
    const user = env.USER || env.LOGNAME || "";
    const linger = user ? /Linger=yes/.test((await run("loginctl", ["show-user", user, "-p", "Linger"])) ?? "") : false;
    const systemd = linger && (await run("systemctl", ["--user", "show-environment"])) !== null;
    if (systemd) {
      await run("systemctl", ["--user", "disable", "--now", "worldsignals-scan.timer"]);
      if (every === "off") {
        remove(join(dir, "worldsignals-scan.service"));
        remove(join(dir, "worldsignals-scan.timer"));
        await run("systemctl", ["--user", "daemon-reload"]);
      } else {
        const units = systemdUnits(spec);
        write(join(dir, "worldsignals-scan.service"), units.service);
        write(join(dir, "worldsignals-scan.timer"), units.timer);
        await run("systemctl", ["--user", "daemon-reload"]);
        if ((await run("systemctl", ["--user", "enable", "--now", "worldsignals-scan.timer"])) === null) {
          err("Couldn't start the systemd user timer (systemctl --user enable --now worldsignals-scan.timer).");
          return 1;
        }
      }
      how = "a systemd user timer (worldsignals-scan.timer)";
    } else {
      const current = (await run("crontab", ["-l"])) ?? "";
      if (!(await withInput("crontab", ["-"], cronTable(current, spec)))) {
        err("Couldn't update your crontab (crontab -).");
        return 1;
      }
      how = "your crontab";
    }
  } else if (platform === "win32") {
    const ok = (await run("schtasks", schtasksArgs(spec))) !== null;
    if (!ok && every !== "off") {
      err("Couldn't create the task in Task Scheduler (schtasks /Create).");
      return 1;
    }
    how = "Task Scheduler (WorldSignals scan)";
  } else {
    err(`Scheduling isn't supported on ${platform}: run ${p} scan --upload from your own scheduler.`);
    return 2;
  }

  if (entry) saveMachine(env, api, { ...entry, schedule: every === "off" ? null : every });
  if (!quiet) {
    if (every === "off") out(`The schedule is off (${how}).`);
    else out(`Scheduled ${every} at ${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}${every === "weekly" ? " on Mondays" : ""}, as you, with ${how}: it re-reads what is installed and sends the list. ${p} scan --schedule off stops it.`);
  }
  return 0;
}

// ---------------------------------------------------------------------------------------------------------------
// ws machine … and ws machines: add and manage many machines from the command line, no web console needed.
//   On the paying machine: ws signup, ws upgrade, then ws machine token (prints the line to run elsewhere).
//   On each other machine: ws machine enrol --token … (by hand, or through MDM, GPO or Ansible with --yes).
//   For a few machines: ws machine add on the new one, ws machine approve <code> on the paying one.
//   ws machines lists them and the tokens; ws machine remove <id>, ws machine token --revoke <id>.

export const MACHINE_HELP = (p = "ws") => `${p} machines [--json]
      The machines enrolled in your account: last report, known vulnerabilities, exploited, updates, alerts;
      and the enrolment tokens still working.
${p} machine token [--uses <n>] [--expires <days>d] [--label <name>] [--json]
      Make an enrolment token (default 25 machines, 7 days) and print the line to run on each machine:
        npx worldsignals machine enrol --token wsm_…
      --revoke <id>     stop a token working
${p} machine enrol --token <token> [--label <name>] [--yes] [--schedule daily|weekly|off]
      Enrol this machine with a token: shows what it sends and asks (--yes for MDM, GPO, Ansible), sends it, and
      schedules the daily check (as ${p} scan --schedule; default daily).
${p} machine add [--label <name>] [--yes]
      No token: shows a code; approve it on a machine signed in to your account with ${p} machine approve <code>.
${p} machine approve <code>
      Add the machine showing that code to your account.
${p} machine remove <id>
      Remove a machine and everything it sent.
These use the agent key on this device (${p} signup) or an access key (WS_KEY); a connected agent needs the
Machines permission to change anything.`;

function needCredential(ctx) {
  if (ctx.credentialHeaders) return null;
  const p = ctx.p ?? "ws";
  ctx.err(`This needs your account on this device: ${p} signup (then ${p} upgrade), ${p} connect, or WS_KEY=<access key>.`);
  return 2;
}
const accountCall = (ctx, method, path, payload) => callApi(ctx, method, path, payload, (m, url, body) => ctx.credentialHeaders(m, url, body) ?? {});
const days = (v) => {
  const m = String(v ?? "").match(/^(\d+)d?$/);
  return m ? Number(m[1]) : NaN;
};

/** ws machine <what> and ws machines. */
export async function machineCommand(argv, ctx) {
  const { out, err, p = "ws", env } = ctx;
  const api = (env.WS_API || "https://worldsignals.dev").replace(/\/$/, "");
  const c = { ...ctx, api };
  const [what, ...rest] = argv;
  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({
      args: rest,
      allowPositionals: true,
      options: { json: { type: "boolean" }, uses: { type: "string" }, expires: { type: "string" }, label: { type: "string" }, revoke: { type: "string" }, token: { type: "string" }, yes: { type: "boolean" }, schedule: { type: "string" }, "dry-run": { type: "boolean" }, help: { type: "boolean", short: "h" } },
      strict: true,
    }));
  } catch (e) {
    err(`${e.message}\n\n${MACHINE_HELP(p)}`);
    return 2;
  }
  if (!what || what === "help" || values.help) {
    out(MACHINE_HELP(p));
    return 0;
  }
  const failed = (r) => {
    err(r.body.error ?? `WorldSignals answered ${r.status}.`);
    return 1;
  };

  if (what === "list") {
    const no = needCredential(c);
    if (no) return no;
    const r = await accountCall(c, "GET", "/api/machines");
    if (r.status >= 400) return failed(r);
    const t = await accountCall(c, "GET", "/api/machines/tokens");
    if (values.json) {
      out(JSON.stringify({ ...r.body, tokens: t.body.tokens ?? [] }));
      return 0;
    }
    const { machines, limit } = r.body;
    out(`${plural(limit.used, "machine")} of ${limit.limit} on the ${limit.plan} plan.`);
    for (const m of machines) {
      const name = m.label ?? m.os?.label ?? "(no name)";
      out(`  ${m.id}  ${name}  ·  ${m.os?.label ?? ""}  ·  last report ${m.last_report_at ? m.last_report_at.slice(0, 16).replace("T", " ") : "never"}  ·  ${m.findings.open} known, ${m.findings.exploited} exploited, ${m.updates} updates, ${m.alerts_open} open alerts`);
    }
    const live = (t.body.tokens ?? []).filter((x) => !x.revoked_at && x.expires_at > new Date().toISOString() && x.used < x.max_uses);
    if (live.length) {
      out(`Enrolment tokens still working:`);
      for (const x of live) out(`  ${x.id}  ${x.label ?? ""}  ${x.used} of ${x.max_uses} used, until ${x.expires_at.slice(0, 10)}  (${p} machine token --revoke ${x.id})`);
    }
    return 0;
  }

  if (what === "token") {
    const no = needCredential(c);
    if (no) return no;
    if (values.revoke) {
      const r = await accountCall(c, "DELETE", `/api/machines/tokens/${encodeURIComponent(values.revoke)}`);
      if (r.status >= 400) return failed(r);
      out(`Revoked: ${values.revoke} no longer enrols machines.`);
      return 0;
    }
    const body = { ...(values.uses ? { uses: Number(values.uses) } : {}), ...(values.expires ? { days: days(values.expires) } : {}), ...(values.label ? { label: values.label } : {}) };
    const r = await accountCall(c, "POST", "/api/machines/tokens", body);
    if (r.status >= 400) return failed(r);
    if (values.json) {
      out(JSON.stringify(r.body));
      return 0;
    }
    out(`An enrolment token for up to ${r.body.uses} machines, until ${r.body.expires_at.slice(0, 10)}. Run this on each machine (it shows what it sends and asks; add --yes for MDM or scripts):\n`);
    out(`  ${r.body.command}\n`);
    out(`Keep it like a password: anyone with it can add machines to your account until it runs out. ${p} machines lists them; ${p} machine token --revoke ${r.body.id} stops it.`);
    return 0;
  }

  if (what === "enrol" || what === "enroll") {
    values.token ??= env.WS_ENROL_TOKEN || undefined;
    if (!values.token) {
      err(`${p} machine enrol needs --token <token>, or WS_ENROL_TOKEN set (from ${p} machine token, or Machines → Add a machine in the console). Without one: ${p} machine add.`);
      return 2;
    }
    const every = values.schedule ?? "daily";
    if (!["daily", "weekly", "off"].includes(every)) {
      err("--schedule is daily, weekly or off.");
      return 2;
    }
    const code = await scan(["--alerts", "--token", values.token, ...(values.label ? ["--label", values.label] : []), ...(values.yes ? ["--yes"] : []), ...(values["dry-run"] ? ["--dry-run"] : [])], ctx);
    if (code !== 0 || values["dry-run"] || !readMachine(env, api) || every === "off") return code;
    await scheduleScan({ ...c, platform: ctx.platform ?? process.platform }, every);
    return 0;
  }

  if (what === "approve") {
    const no = needCredential(c);
    if (no) return no;
    const code = positionals[0];
    if (!code) {
      err(`${p} machine approve <code>: the code ${p} machine add shows on the new machine.`);
      return 2;
    }
    const r = await accountCall(c, "POST", "/api/machines/approve", { code });
    if (r.status >= 400) return failed(r);
    out(`Added ${r.body.label ?? "the machine"}${r.body.os?.label ? ` (${r.body.os.label})` : ""} to your account: ${r.body.machine_id}. It sends its list now and gets alerts from here on.`);
    return 0;
  }

  if (what === "remove") {
    const no = needCredential(c);
    if (no) return no;
    const id = positionals[0];
    if (!/^mch_[0-9a-f]{32}$/.test(id ?? "")) {
      err(`${p} machine remove <id>: the machine's id, as ${p} machines lists it (mch_…).`);
      return 2;
    }
    const r = await accountCall(c, "DELETE", `/api/machines/${id}`);
    if (r.status >= 400) return failed(r);
    // This machine itself: forget its key and stop its schedule too.
    if (readMachine(env, api)?.machine_id === id) {
      await scheduleScan({ ...c, quiet: true, platform: ctx.platform ?? process.platform }, "off");
      saveMachine(env, api, null);
    }
    out(`Removed ${id} and everything it sent.`);
    return 0;
  }

  if (what === "add") return pairThisMachine(c, values);

  err(`Unknown: ${p} machine ${what}.\n\n${MACHINE_HELP(p)}`);
  return 2;
}

/** The headers that sign a request with a key alone (pairing, before the machine has an id). */
function keyHeaders(method, url, privateKeyPem, now = Date.now()) {
  lastSigned = Math.max(Math.floor(now), lastSigned + 1);
  const timestamp = (lastSigned / 1000).toFixed(3);
  const u = new URL(url);
  return { "x-ws-timestamp": timestamp, "x-ws-signature": sign(null, Buffer.from(`${method} ${u.pathname}${u.search} ${timestamp} `), createPrivateKey(privateKeyPem)).toString("base64url") };
}

/** ws machine add: show what it sends, ask, show a code, wait for it to be approved, then send. */
async function pairThisMachine(ctx, values) {
  const { env, out, err, p = "ws", api } = ctx;
  if (readMachine(env, api)) {
    out(`This machine is already enrolled. ${p} scan --upload sends its list now; ${p} scan --forget removes it.`);
    return 0;
  }
  const inv = await gather({ platform: ctx.platform ?? process.platform, env, sys: ctx.sys });
  const payload = uploadPayload(inv, ctx.version ?? "");
  const agreed = await showAndAsk(ctx, values, payload, "Add this machine and send it once approved?");
  if (agreed !== true) return agreed;
  const key = newMachineKey();
  const start = await callApi(ctx, "POST", "/api/machines/pair", { public_key: key.publicKey, os: payload.os, consent: true, ...(values.label ? { label: values.label } : {}) }, () => ({}));
  if (start.status >= 400) {
    err(start.body.error ?? `WorldSignals answered ${start.status}.`);
    return 1;
  }
  out(`\nOn a machine signed in to your account, run:\n\n  ${p} machine approve ${start.body.code}\n\nThe code works for 15 minutes. Waiting…`);
  const pause = ctx.pause ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const until = Date.parse(start.body.expires_at);
  for (;;) {
    await pause(3000);
    const r = await callApi(ctx, "GET", `/api/machines/pair/${start.body.pair_id}`, undefined, (m, url) => keyHeaders(m, url, key.privateKey));
    if (r.body.status === "approved") {
      const entry = { machine_id: r.body.machine_id, private_key: key.privateKey, label: values.label ?? null, account: null, enrolled_at: new Date().toISOString() };
      saveMachine(env, api, entry);
      const sent = await machineCall(ctx, entry, "POST", "/api/machine/report", payload);
      if (sent.status >= 400) {
        err(`Approved, but the list wasn't sent: ${refusal(sent, p)} ${p} scan --upload tries again.`);
        return 1;
      }
      out(`Approved. ${entry.label ?? "This machine"} is enrolled and its list is sent. To keep it current: ${p} scan --schedule daily.`);
      return 0;
    }
    if (r.body.status === "expired" || r.status === 404 || Date.now() > until + 60_000) {
      err(`The code expired before it was approved. Run ${p} machine add again.`);
      return 1;
    }
  }
}

