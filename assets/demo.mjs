// Writes assets/demo.svg: an animated terminal (CSS keyframes only, no script) of a first `worldsignals watch`.
// The CLI's lines are worded as bin/ws.mjs 0.4.2 prints them (readyAgent, watch, standing). Lines starting with
// "#" are narration, not output. Run from the repo root: node assets/demo.mjs assets/demo.svg
import { writeFileSync } from "node:fs";

const out = process.argv[2];
const D = 18; // seconds per loop
const FS = 14, CW = FS * 0.602, LH = 20, COLS = 100;
const W = 900, PADX = 24, BAR = 38, TOP = BAR + 26, ROWS = 19;
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
  const parts = line.split(/(https:\/\/\S+?(?=[),]|$|\s)|HVRT-KMPW|company\.registered|procurement\.tender_published)/g);
  return parts.map((p, i) => (i % 2 ? `<tspan class="${p.startsWith("http") || p === "HVRT-KMPW" ? "s" : "k"}">${esc(p)}</tspan>` : esc(p))).join("");
}

const rows = []; // {t, html, typed?: {chars, start, end}}
const at = (t, text, opts = {}) => {
  const lines = opts.raw ? [text] : wrap(text, opts.indent ?? "");
  lines.forEach((l, i) => rows.push({ t: t + i * 0.05, html: opts.html ? opts.html(l) : paint(l, opts.cls), cls: opts.cls ?? "o" }));
};

// The command, typed. The prompt shows first; each line is revealed a character at a time.
const cmd1 = "npx worldsignals watch --type company.registered,procurement.tender_published \\";
const cmd2 = "    --country PT,ES --agent claude --batch";
const flag = (s) => esc(s).replace(/(--[a-z-]+)/g, '<tspan class="k">$1</tspan>');
const SPEED = 0.028;
const t1 = 0.7, t1e = t1 + cmd1.length * SPEED, t2 = t1e + 0.25, t2e = t2 + cmd2.length * SPEED;
rows.push({ t: 0, html: `<tspan class="p">$</tspan> ${flag(cmd1)}`, cls: "c", typed: { from: 2, chars: cmd1.length, start: t1, end: t1e } });
rows.push({ t: t1e, html: flag(cmd2), cls: "c", typed: { from: 0, chars: cmd2.length, start: t2, end: t2e } });

let t = t2e + 0.5;
at(t, "No agent key on this device yet: making one, as npx worldsignals signup would.");
at((t += 0.55), "Agent agt_5c1e9a07b3d24f6e8a19c2d0 created (WorldSignals CLI); its private key is in /Users/ana/.config/worldsignals/agent.json, readable only by you.");
at((t += 0.6), "This agent isn't paid for or connected yet. Either way works:");
at((t += 0.25), "Pay for its own Developer plan (monthly; Stripe asks the payer's email, for receipts): https://checkout.stripe.com/c/pay/cs_live_b1Qx…");
at((t += 0.25), "Or connect it to your account: open https://worldsignals.dev/link and enter HVRT-KMPW (or open https://worldsignals.dev/link?code=HVRT-KMPW), signed in.");
at((t += 0.4), "Waiting for the payment or the approval, then watching (Ctrl+C stops; the agent key stays saved for next time).");
at((t += 1.1), "# you approve HVRT-KMPW at worldsignals.dev/link", { cls: "n" });
at((t += 1.0), "Connected to Oficina Exemplo, Lda: it acts for that account, with its Developer plan and its streams.");
at((t += 0.45), "Watching for new events after number 48213907 (company.registered, procurement.tender_published). Ctrl+C stops.", { cls: "w" });
at((t += 0.6), "# new events arrive; --batch collects them until a quiet minute", { cls: "n" });
const events = [
  ["48213915", "company.registered", "ES", "Robótica Imaginaria, S.L. · Valencia"],
  ["48213988", "procurement.tender_published", "PT", "Vila Fictícia: limpeza urbana, €480k"],
  ["48214102", "company.registered", "ES", "Cafés del Ejemplo, S.L. · Sevilla"],
  ["48214230", "procurement.tender_published", "ES", "Villa Inventada: alumbrado LED, €1.2M"],
];
t += 0.15;
for (const [n, type, c, what] of events) {
  t += 0.55;
  rows.push({ t, cls: "e", html: `  <tspan class="m">${n}</tspan>  <tspan class="k">${type.padEnd(30)}</tspan><tspan class="o">${c}</tspan>  ${esc(what)}` });
}
at((t += 0.8), "# a quiet minute later: claude -p starts once, with the 4 events fenced off as data", { cls: "n" });
const reply = [
  "4 new events in Portugal and Spain:",
  "- New companies: Robótica Imaginaria (Valencia, software) and Cafés del Ejemplo (Sevilla).",
  "- Tenders: street cleaning for Vila Fictícia (PT, €480k, closes 28 Nov) and LED street",
  "  lighting for Villa Inventada (ES, €1.2M, closes 5 Dec).",
  "Worth a look: the Vila Fictícia tender fits your cleaning-services clients; 4 weeks left.",
];
t += 0.9;
for (const l of reply) at((t += 0.28), l, { raw: true, cls: "r", html: (x) => esc(x) });

const END = 17.2;
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
<title id="dt">npx worldsignals watch, first run</title>
<desc id="dd">A terminal runs npx worldsignals watch for new companies and public tenders in Portugal and Spain with Claude as the agent. The first run makes the agent's key, prints a payment link and a connect code, and waits; once the code is approved it starts watching. Four made-up events arrive and, after a quiet minute, Claude summarises them once.</desc>
<style>${css}</style>
<defs><clipPath id="view"><rect x="0" y="${TOP - 15}" width="${W}" height="${H - TOP + 15}"/></clipPath></defs>
<rect width="${W}" height="${H}" rx="12" fill="${C.bg}"/>
<path d="M12 0H${W - 12}A12 12 0 0 1 ${W} 12V${BAR}H0V12A12 12 0 0 1 12 0Z" fill="${C.bar}"/>
<path d="M0 ${BAR}.5H${W}" stroke="${C.line}"/>
<rect x=".5" y=".5" width="${W - 1}" height="${H - 1}" rx="11.5" fill="none" stroke="${C.line}"/>
<circle cx="22" cy="19" r="6" fill="#3a3d44"/><circle cx="42" cy="19" r="6" fill="#3a3d44"/><circle cx="62" cy="19" r="6" fill="#3a3d44"/>
<text x="${W / 2}" y="24" text-anchor="middle" style="font-size:12.5px;fill:${C.muted}">~/agents — worldsignals watch</text>
<g clip-path="url(#view)"><g class="screen"><g class="scroll">
${body}
${covers}
</g></g></g>
</svg>
`;
writeFileSync(out, svg);
console.log(`rows ${rows.length}, end ${t.toFixed(2)} s, ${svg.length} bytes, ${W}x${H}`);
