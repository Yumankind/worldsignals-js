// Writes the README banner: assets/banner-light.svg, banner-dark.svg and banner.svg (follows the viewer's colour scheme).
// Run from the repo root: node assets/banner.mjs assets. Colours and the logo follow worldsignals.dev (public/styles.css, brand.js).
import { writeFileSync } from "node:fs";
const out = process.argv[2];
const SANS = `ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif`;
const MONO = `ui-monospace, 'SF Mono', 'JetBrains Mono', Menlo, Consolas, 'Liberation Mono', monospace`;

const themes = {
  light: { bg1: "#fbfbf8", bg2: "#f4f4f1", glow: "#ff6a33", glowO: 0.10, line: "#d8d8d0", text: "#16181b", muted: "#5d636b",
    accent: "#c03c11", card: "#ffffff", cardLine: "#d8d8d0", dot: "rgb(0 0 0 / 0.05)", markLine: "none" },
  dark: { bg1: "#0d0c14", bg2: "#060609", glow: "#ff6a33", glowO: 0.16, line: "rgb(255 255 255 / 0.09)", text: "#f3f1ed", muted: "#9c97a6",
    accent: "#ff6a33", card: "rgb(255 255 255 / 0.045)", cardLine: "rgb(255 255 255 / 0.10)", dot: "rgb(255 255 255 / 0.05)", markLine: "rgb(255 255 255 / 0.16)" },
};
const css = (t) => `.bg1{stop-color:${t.bg1}}.bg2{stop-color:${t.bg2}}.gl{stop-color:${t.glow}}.gl0{stop-color:${t.glow};stop-opacity:${t.glowO}}
.edge{fill:none;stroke:${t.line}}.t{fill:${t.text}}.m{fill:${t.muted}}.a{fill:${t.accent}}.card{fill:${t.card};stroke:${t.cardLine}}.dotg{fill:${t.dot}}.mk{stroke:${t.markLine}}`;

// Wordmark: "worlds" + a drawn stem with the signal as its dot + "gnals", as the site draws it (public/brand.js).
const fs = 62, stemX = 128 + 22 + 2.922 * fs + 0.1205 * fs, base = 108;
const em = (v) => +(v * fs).toFixed(2);

const cards = [
  ["company.registered", "New company registered", "Madrid, ES", 1],
  ["vulnerability.exploited", "Exploited in the wild", "worldwide", 0.78],
  ["procurement.tender_published", "Public tender published", "Porto, PT", 0.5],
];
const cardX = 872, cardW = 352, cardH = 68, gap = 14, cardY0 = 52;

function svg(style) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="320" viewBox="0 0 1280 320" role="img" aria-labelledby="t d">
<title id="t">WorldSignals</title>
<desc id="d">Real-world events for code and AI agents: new companies, tenders, vulnerabilities, outages and AI models, as one standard stream.</desc>
<style>${style}
text{font-family:${SANS}}.mono{font-family:${MONO}}</style>
<defs>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" class="bg1"/><stop offset="1" class="bg2"/></linearGradient>
<radialGradient id="glow" cx="1000" cy="300" r="520" gradientUnits="userSpaceOnUse"><stop offset="0" class="gl0"/><stop offset="1" class="gl" stop-opacity="0"/></radialGradient>
<pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.1" class="dotg"/></pattern>
<clipPath id="r"><rect width="1280" height="320" rx="18"/></clipPath>
</defs>
<g clip-path="url(#r)">
<rect width="1280" height="320" fill="url(#bg)"/>
<rect width="1280" height="320" fill="url(#dots)"/>
<rect width="1280" height="320" fill="url(#glow)"/>
</g>
<rect x="0.5" y="0.5" width="1279" height="319" rx="17.5" class="edge"/>
<g transform="translate(64 56) scale(2)"><rect width="32" height="32" rx="7" fill="#0d0c14" class="mk" stroke-width="0.6"/><circle cx="16" cy="16" r="9.5" fill="none" stroke="#f3f1ed" stroke-width="2.2"/><path d="M6.5 16h19M16 6.5c3.3 2.8 3.3 16.2 0 19M16 6.5c-3.3 2.8-3.3 16.2 0 19" fill="none" stroke="#f3f1ed" stroke-width="1.3" opacity=".5"/><circle cx="22.7" cy="9.3" r="3.6" fill="#ff6a33"/></g>
<g font-weight="700" font-size="${fs}" letter-spacing="${em(-0.025)}">
<text x="${em(0) + stemX - 0.1205 * fs}" y="${base}" text-anchor="end" class="t">worlds</text>
<rect x="${(stemX - 0.0715 * fs).toFixed(2)}" y="${(base - 0.523 * fs).toFixed(2)}" width="${em(0.143)}" height="${em(0.523)}" class="t"/>
<circle cx="${stemX.toFixed(2)}" cy="${(base - 0.662 * fs).toFixed(2)}" r="${em(0.086)}" fill="#ff6a33"/>
<text x="${(stemX + 0.0955 * fs).toFixed(2)}" y="${base}" class="t">gnals</text>
</g>
<text x="64" y="174" font-size="34" font-weight="650" class="t" letter-spacing="-0.4">Real-world events for code and AI agents</text>
<text x="64" y="210" font-size="21" class="m">New companies, tenders, vulnerabilities, outages and AI models,</text>
<text x="64" y="238" font-size="21" class="m">as one standard stream.</text>
<text x="64" y="282" font-size="18" font-weight="600" class="a">Docs<tspan class="m" font-weight="400" dx="10">·</tspan><tspan dx="10">MCP</tspan><tspan class="m" font-weight="400" dx="10">·</tspan><tspan dx="10">Pricing</tspan><tspan class="m" font-weight="400" dx="22">worldsignals.dev</tspan></text>
${cards.map(([type, title, where, o], i) => {
  const y = cardY0 + i * (cardH + gap);
  return `<g opacity="${o}"><rect x="${cardX}" y="${y}" width="${cardW}" height="${cardH}" rx="11" class="card"/>
<text x="${cardX + 18}" y="${y + 27}" font-size="16" class="mono a">${type}</text>
<text x="${cardX + 18}" y="${y + 52}" font-size="17" class="t">${title}<tspan class="m" dx="8">${where}</tspan></text></g>`;
}).join("\n")}
<circle cx="${cardX + cardW - 22}" cy="${cardY0 + 22}" r="5" fill="#ff6a33"/>
</svg>
`;
}
writeFileSync(`${out}/banner-light.svg`, svg(css(themes.light)));
writeFileSync(`${out}/banner-dark.svg`, svg(css(themes.dark)));
writeFileSync(`${out}/banner.svg`, svg(`${css(themes.light)}\n@media (prefers-color-scheme: dark){${css(themes.dark)}}`));
console.log("ok", stemX);
