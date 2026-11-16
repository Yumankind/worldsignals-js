// Writes assets/scan-demo.svg: an animated terminal (CSS keyframes only, no script) of `npx worldsignals-scan`, as
// bin/scan.mjs renderText words it, with example numbers. From assets/demo.mjs. Lines starting with "#" are
// narration. Run from the repo root: node assets/scan-demo.mjs assets/scan-demo.svg
import { writeFileSync } from "node:fs";

const out = process.argv[2];
const D = 18; // seconds per loop
const FS = 14, CW = FS * 0.602, LH = 20, COLS = 100;
const W = 900, PADX = 24, BAR = 38, TOP = BAR + 26, ROWS = 22;
const H = TOP + (ROWS - 1) * LH + 22;
const MONO = `ui-monospace, 'SF Mono', 'JetBrains Mono', Menlo, Consolas, 'Liberation Mono', monospace`;
const C = { bg: "#0a0b0d", bar: "#15171a", line: "rgb(255 255 255 / 0.08)", text: "#e9e9e6", out: "#c4c7cc", muted: "#8d929a",
  key: "#ffb38f", str: "#a8e6b8", accent: "#ff6a33" };

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
/** Word-wraps plain text to COLS columns. */
function wrap(text, indent = "") {
  const lines = [];
  let cur = "";
  for (const word of text.split(" ")) {
    if (cur && (cur + " " + word).length > COLS) {
      lines.push(cur);
      cur = indent + word;
    } else cur = cur ? `${cur} ${word}` : word;
  }
  lines.push(cur);
  return lines;
}
/** Colours URLs, codes and type ids in an output line. */
function paint(line, cls = "o") {
  const parts = line.split(/(\[EXPLOITED NOW\]|How: .*$|→ \S+)/g);
  return parts.map((p, i) => (i % 2 ? `<tspan class="${p.startsWith("[") ? "p" : p.startsWith("How") ? "s" : "k"}">${esc(p)}</tspan>` : esc(p))).join("");
}

const rows = []; // {t, html, typed?: {chars, start, end}}
const at = (t, text, opts = {}) => {
  const lines = opts.raw ? [text] : wrap(text, opts.indent ?? "");
  lines.forEach((l, i) => rows.push({ t: t + i * 0.05, html: opts.html ? opts.html(l) : paint(l, opts.cls), cls: opts.cls ?? "o" }));
};

// The command, typed.
const cmd1 = "npx worldsignals-scan";
const SPEED = 0.05;
const t1 = 0.8, t1e = t1 + cmd1.length * SPEED;
rows.push({ t: 0, html: `<tspan class="p">$</tspan> ${esc(cmd1)}`, cls: "c", typed: { from: 2, chars: cmd1.length, start: t1, end: t1e } });

let t = t1e + 0.6;
at(t, "  reading Homebrew…", { cls: "n", raw: true });
at((t += 0.35), "  reading apps…", { cls: "n", raw: true });
at((t += 0.35), "  reading npm… pip… OSV.dev 612/612", { cls: "n", raw: true });
t += 0.7;
const lines = [
  ["", "o"],
  ["WorldSignals machine check · macOS 27.1 · 16 Nov 2026", "w"],
  ["Checked 612 programs and packages against OSV.dev, CISA's exploited list, endoflife.date.", "o"],
  ["Sent package names and versions to OSV.dev (Google). Nothing went to WorldSignals.", "n"],
  ["", "o"],
  ["3 updates fix all 52 known vulnerabilities that have a fix. One of them is urgent: being", "w"],
  ["exploited right now.", "w"],
  ["", "o"],
  ["1. Google Chrome 157.0.8103.51 → 157.0.8103.78 or later  [EXPLOITED NOW]", "w"],
  ["   44 known vulnerabilities (3 critical, 26 high, 10 medium, 5 low).", "o"],
  ["   CVE-2026-50311 is on CISA's list of exploited vulnerabilities since 12 Nov 2026.", "o"],
  ["   How: Chrome menu ⋮ → Help → About Google Chrome, then Relaunch", "o"],
  ["", "o"],
  ["2. OpenSSL 3.6.3 → 3.6.5 or later", "w"],
  ["   6 known vulnerabilities (1 critical, 3 high, 2 medium).", "o"],
  ["   How: brew upgrade openssl@3", "o"],
  ["", "o"],
  ["3. Python packages (pip): 2 packages to update", "w"],
  ["   How: python3 -m pip install -U requests jinja2", "o"],
  ["", "o"],
  ["No longer supported: Python 3.9.6 (support ended 31 Oct 2025). Move to Python 3.11 or later.", "o"],
];
for (const [l, cls] of lines) at((t += 0.16), l, { raw: true, cls, html: (x) => paint(x) });
const END = 15.5;
if (t > END - 1.5) throw new Error(`timeline too long: ${t}`);
rows.forEach((r) => { if (r.html.replace(/<[^>]+>/g, "").length > COLS + 4) console.warn("long:", r.html); });

// Scroll: once a row would fall below the last visible one, everything moves up a row.
const pct = (s) => +((s / D) * 100).toFixed(3);
const scrolls = [];
rows.forEach((r, i) => { if (i >= ROWS) scrolls.push({ t: r.t, by: (i - ROWS + 1) * LH }); });

let css = `text{font-family:${MONO};font-size:${FS}px;white-space:pre}
.c{fill:${C.text}}.o{fill:${C.out}}.w{fill:${C.text}}.r{fill:${C.text}}.e{fill:${C.text}}.n{fill:${C.muted};font-style:italic}
.k{fill:${C.key}}.s{fill:${C.str}}.m{fill:${C.muted}}.p{fill:${C.accent};font-weight:700}
.screen{animation:screen ${D}s linear infinite}
@keyframes screen{0%,${pct(END)}%{opacity:1}${pct(END + 0.45)}%,100%{opacity:0}}
.cur{animation:blink 1s steps(1) infinite}@keyframes blink{0%{opacity:1}50%{opacity:0}}
`;
// One keyframe set per row: hidden until its time, then shown until the loop ends.
rows.forEach((r, i) => {
  if (r.t <= 0) return;
  css += `.r${i}{animation:r${i} ${D}s linear infinite}@keyframes r${i}{0%,${pct(r.t) - 0.01}%{opacity:0}${pct(r.t)}%,100%{opacity:1}}\n`;
});
if (scrolls.length) {
  let kf = `0%,${pct(scrolls[0].t) - 0.01}%{transform:translateY(0)}`;
  scrolls.forEach((s, j) => {
    const next = scrolls[j + 1];
    kf += `${pct(s.t)}%,${next ? `${pct(next.t) - 0.01}%` : "100%"}{transform:translateY(-${s.by}px)}`;
  });
  css += `.scroll{animation:scroll ${D}s linear infinite}@keyframes scroll{${kf}}\n`;
}
// With reduced motion: no animation, the last screen of the session, standing still.
css += `@media (prefers-reduced-motion: reduce){.screen,.screen *{animation:none!important}.cov{display:none}.scroll{transform:translateY(-${scrolls.at(-1)?.by ?? 0}px)}}\n`;

// Typing: a cover in the terminal's colour slides right a character at a time, with the cursor on its edge.
let covers = "";
rows.forEach((r, i) => {
  if (!r.typed) return;
  const { from, chars, start, end } = r.typed;
  const y = TOP + i * LH;
  const x0 = PADX + from * CW;
  const dist = (chars * CW).toFixed(2);
  css += `.ty${i}{animation:ty${i} ${D}s infinite}@keyframes ty${i}{0%,${pct(start)}%{transform:translateX(0);animation-timing-function:steps(${chars},end)}${pct(end)}%,100%{transform:translateX(${dist}px)}}\n`;
  // The cursor shows while this line is being typed (and blinks before the first).
  const curFrom = i === 0 ? 0 : pct(start) - 0.01;
  css += `.cv${i}{animation:cv${i} ${D}s infinite}@keyframes cv${i}{0%{opacity:${i === 0 ? 1 : 0}}${i === 0 ? "" : `${curFrom}%{opacity:0}`}${pct(start)}%,${pct(end + 0.2)}%{opacity:1}${pct(end + 0.21)}%,100%{opacity:0}}\n`;
  covers += `<g class="cov ty${i}"><rect x="${x0.toFixed(2)}" y="${y - 15}" width="${(W - x0 + 40).toFixed(0)}" height="${LH}" fill="${C.bg}"/><g class="cv${i}"><rect class="${i === 0 ? "cur" : ""}" x="${x0.toFixed(2)}" y="${y - 13}" width="${(CW).toFixed(2)}" height="17" fill="${C.text}" opacity=".85"/></g></g>`;
});

const body = rows.map((r, i) => `<text x="${PADX}" y="${TOP + i * LH}" class="${r.cls}${r.t > 0 ? ` r${i}` : ""}">${r.html}</text>`).join("\n");

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-labelledby="dt dd">
<title id="dt">npx worldsignals-scan</title>
<desc id="dd">A terminal runs npx worldsignals-scan on a Mac. It reads what is installed, checks it against public vulnerability databases, and prints three updates: Google Chrome, exploited now, first; then OpenSSL through Homebrew; then two pip packages; and that Python 3.9 no longer gets security fixes. Example numbers.</desc>
<style>${css}</style>
<defs><clipPath id="view"><rect x="0" y="${TOP - 15}" width="${W}" height="${H - TOP + 15}"/></clipPath></defs>
<rect width="${W}" height="${H}" rx="12" fill="${C.bg}"/>
<path d="M12 0H${W - 12}A12 12 0 0 1 ${W} 12V${BAR}H0V12A12 12 0 0 1 12 0Z" fill="${C.bar}"/>
<path d="M0 ${BAR}.5H${W}" stroke="${C.line}"/>
<rect x=".5" y=".5" width="${W - 1}" height="${H - 1}" rx="11.5" fill="none" stroke="${C.line}"/>
<circle cx="22" cy="19" r="6" fill="#3a3d44"/><circle cx="42" cy="19" r="6" fill="#3a3d44"/><circle cx="62" cy="19" r="6" fill="#3a3d44"/>
<text x="${W / 2}" y="24" text-anchor="middle" style="font-size:12.5px;fill:${C.muted}">~ — worldsignals-scan</text>
<g clip-path="url(#view)"><g class="screen"><g class="scroll">
${body}
${covers}
</g></g></g>
</svg>
`;
writeFileSync(out, svg);
console.log(`rows ${rows.length}, end ${t.toFixed(2)} s, ${svg.length} bytes, ${W}x${H}`);
