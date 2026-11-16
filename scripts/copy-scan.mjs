// Packs worldsignals-scan (scan/): copies the CLI's two files into scan/bin next to its entry point, so the
// security package and the worldsignals package ship the same code. Run by `npm pack` / `npm publish` in scan/
// (its prepack script); the copies are not committed.
import { copyFileSync, readFileSync } from "node:fs";

const root = new URL("..", import.meta.url);
for (const f of ["ws.mjs", "scan.mjs"]) copyFileSync(new URL(`bin/${f}`, root), new URL(`scan/bin/${f}`, root));
copyFileSync(new URL("LICENSE", root), new URL("scan/LICENSE", root));
const main = JSON.parse(readFileSync(new URL("package.json", root), "utf8")).version;
const scan = JSON.parse(readFileSync(new URL("scan/package.json", root), "utf8")).version;
if (main !== scan) throw new Error(`scan/package.json is ${scan}, package.json ${main}: they release together, at one version.`);
console.log(`scan/bin: ws.mjs and scan.mjs from worldsignals ${main}`);
