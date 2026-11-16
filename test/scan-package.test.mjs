// worldsignals-scan (scan/): the security package. It ships the CLI's own files, at the same version, and maps its
// arguments onto ws scan and the machine commands.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const root = new URL("..", import.meta.url);
const json = (p) => JSON.parse(readFileSync(new URL(p, root), "utf8"));

test("released together: one version for both packages", () => {
  assert.equal(json("scan/package.json").version, json("package.json").version);
  assert.equal(json("scan/package.json").bin["worldsignals-scan"], "bin/worldsignals-scan.mjs");
  assert.ok(json("scan/package.json").keywords.includes("vulnerability-scanner"));
});

test("packs its entry point with the CLI's two files, the README and the licence", () => {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json"], { cwd: new URL("scan/", root), encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  // prepack says what it copied before npm's JSON.
  const files = JSON.parse(out.slice(out.indexOf("\n[") + 1))[0].files.map((f) => f.path).sort();
  assert.deepEqual(files, ["LICENSE", "README.md", "bin/scan.mjs", "bin/worldsignals-scan.mjs", "bin/ws.mjs", "package.json"]);
  assert.equal(readFileSync(new URL("scan/bin/scan.mjs", root), "utf8"), readFileSync(new URL("bin/scan.mjs", root), "utf8"));
});

test("its arguments are a scan, or the account and machine commands", async () => {
  execFileSync("node", ["scripts/copy-scan.mjs"], { cwd: root, stdio: "ignore" });
  const { toWs, nameOf } = await import("../scan/bin/worldsignals-scan.mjs");
  assert.deepEqual(toWs([]), ["scan"]);
  assert.deepEqual(toWs(["--alerts", "--token", "t"]), ["scan", "--alerts", "--token", "t"]);
  assert.deepEqual(toWs(["scan", "--json"]), ["scan", "--json"]);
  assert.deepEqual(toWs(["--help"]), ["scan", "--help"]);
  assert.deepEqual(toWs(["machine", "token"]), ["machine", "token"]);
  assert.deepEqual(toWs(["machines"]), ["machines"]);
  assert.deepEqual(toWs(["signup"]), ["signup"]);
  assert.equal(nameOf({ npm_command: "exec" }), "npx worldsignals-scan");
  const help = execFileSync("node", ["scan/bin/worldsignals-scan.mjs", "--help"], { cwd: root, encoding: "utf8" });
  assert.match(help, /^worldsignals-scan scan \[--report <file\.md>\]/);
  assert.equal(execFileSync("node", ["scan/bin/worldsignals-scan.mjs", "--version"], { cwd: root, encoding: "utf8" }).trim(), json("package.json").version);
});
