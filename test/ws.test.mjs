// The ws command line tool, run by Node's own test runner (pnpm test:cli): it is a Node program,
// not Worker code. The server is a fake that records what the tool sent.
import assert from "node:assert/strict";
import { test } from "node:test";
import { VERSION, run } from "../bin/ws.mjs";

function fakeServer(status, body) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  };
  return { fetch, calls };
}

function capture() {
  const lines = { out: [], err: [] };
  return { lines, out: (s) => lines.out.push(s), err: (s) => lines.err.push(s) };
}

test("events passes the filters on, and explains a refused one", async () => {
  const server = fakeServer(200, { events: [], total: 0, cursor: 5 });
  await run(["events", "--ecosystem", "pypi", "--where", "data.severity=high"], { fetch: server.fetch, env: { WS_KEY: "wsk_test" }, ...capture() });
  assert.equal(server.calls[0].url, "https://worldsignals.dev/api/events?ecosystems=pypi&where=data.severity%3Dhigh&limit=20");
  const io = capture();
  assert.equal(await run(["events", "--platform", "beos"], { ...fakeServer(400, { error: '"beos" isn\'t a platform.' }), env: { WS_KEY: "k" }, ...io }), 2);
  assert.match(io.lines.err[0], /ws events: "beos" isn't a platform/);
});

test("version prints the package version", async () => {
  const io = capture();
  assert.equal(await run(["--version"], { fetch: () => assert.fail("no request"), env: {}, ...io }), 0);
  const pkg = JSON.parse(await import("node:fs").then((fs) => fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")));
  assert.deepEqual(io.lines.out, [pkg.version]);
  assert.equal(VERSION, pkg.version);
});

test("runs when started through a symlink, as npm and npx start it", async () => {
  const { mkdtempSync, symlinkSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { execFileSync } = await import("node:child_process");
  const dir = mkdtempSync(join(tmpdir(), "ws-link-"));
  const link = join(dir, "worldsignals");
  symlinkSync(new URL("../bin/ws.mjs", import.meta.url).pathname, link);
  assert.equal(execFileSync(process.execPath, [link, "--version"], { encoding: "utf8" }).trim(), VERSION);
});
