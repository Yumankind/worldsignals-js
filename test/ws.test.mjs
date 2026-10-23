// The ws command line tool, run by Node's own test runner (pnpm test:cli): it is a Node program,
// not Worker code. The server is a fake that records what the tool sent.
import assert from "node:assert/strict";
import { test } from "node:test";
import { VERSION, run, signupBody } from "../bin/ws.mjs";

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

test("signup sends the person's details and the agent's name, and prints the confirm link", async () => {
  const server = fakeServer(201, { message_for_human: "My agent asked to sign you up…", confirm_url: "https://ws.test/confirm?t=abc", expires_at: "2026-10-30T00:00:00Z" });
  const io = capture();
  const code = await run(
    ["signup", "--email", "ana@example.pt", "--agent", "My agent", "--type", "company.registered, procurement.tender_published", "--country", "pt,es", "--plan", "developer", "--billing", "yearly"],
    { fetch: server.fetch, env: { WS_API: "https://ws.test/" }, ...io },
  );
  assert.equal(code, 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/signup-requests");
  assert.deepEqual(JSON.parse(server.calls[0].init.body), {
    email: "ana@example.pt",
    eventTypes: ["company.registered", "procurement.tender_published"],
    countries: ["PT", "ES"],
    plan: "developer",
    billing: "yearly",
    agent: { name: "My agent" },
  });
  assert.ok(io.lines.out.includes("Confirm link: https://ws.test/confirm?t=abc"));
});

test("signup needs an email and the agent's name", async () => {
  const io = capture();
  assert.equal(await run(["signup", "--email", "ana@example.pt"], { fetch: () => assert.fail("no request"), env: {}, ...io }), 2);
  assert.match(io.lines.err[0], /--agent/);
});

test("signup reports the server's error", async () => {
  const io = capture();
  const code = await run(["signup", "--email", "a@b.co", "--agent", "x"], { ...fakeServer(429, { error: "At most 10 a day." }), env: {}, ...io });
  assert.equal(code, 1);
  assert.match(io.lines.err[0], /429.*At most 10 a day/);
});

test("events asks with the filters and prints one line per event", async () => {
  const server = fakeServer(200, { events: [{ time: "2026-10-23T00:00:00Z", type: "company.registered", country: "ES", title: "New company registered: X SL" }], total: 1 });
  const io = capture();
  assert.equal(await run(["events", "--type", "company.registered", "--country", "es", "--limit", "5"], { fetch: server.fetch, env: { WS_KEY: "wsk_test" }, ...io }), 0);
  assert.equal(server.calls[0].url, "https://worldsignals.dev/api/events?types=company.registered&country=ES&limit=5");
  assert.equal(server.calls[0].init.headers.authorization, "Bearer wsk_test");
  assert.match(io.lines.out[0], /^2026-10-23 {2}company\.registered +ES {2}New company registered: X SL$/);
});

test("events passes the filters on, and explains a refused one", async () => {
  const server = fakeServer(200, { events: [], total: 0, cursor: 5 });
  await run(["events", "--ecosystem", "pypi", "--where", "data.severity=high"], { fetch: server.fetch, env: { WS_KEY: "wsk_test" }, ...capture() });
  assert.equal(server.calls[0].url, "https://worldsignals.dev/api/events?ecosystems=pypi&where=data.severity%3Dhigh&limit=20");
  const io = capture();
  assert.equal(await run(["events", "--platform", "beos"], { ...fakeServer(400, { error: '"beos" isn\'t a platform.' }), env: { WS_KEY: "k" }, ...io }), 2);
  assert.match(io.lines.err[0], /ws events: "beos" isn't a platform/);
});

test("events needs an access key", async () => {
  const io = capture();
  assert.equal(await run(["events"], { fetch: () => assert.fail("no request"), env: {}, ...io }), 2);
  assert.match(io.lines.err[0], /WS_KEY/);
});

test("key prints the access key once the person confirmed, and says when they haven't", async () => {
  const link = "https://ws.test/confirm?t=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  let io = capture();
  const confirmed = fakeServer(200, { status: "confirmed", access_key: "wsk_123.abc" });
  assert.equal(await run(["key", "--link", link], { fetch: confirmed.fetch, env: { WS_API: "https://ws.test" }, ...io }), 0);
  assert.equal(confirmed.calls[0].url, "https://ws.test/api/signup-requests/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ");
  assert.deepEqual(io.lines.out, ["wsk_123.abc"]);
  io = capture();
  assert.equal(await run(["key", "--link", link], { ...fakeServer(200, { status: "pending" }), env: {}, ...io }), 1);
  assert.match(io.lines.err[0], /hasn't confirmed/);
});

test("signupBody leaves out what wasn't given", () => {
  assert.deepEqual(JSON.parse(JSON.stringify(signupBody({ email: "a@b.co", agent: "x" }))), { email: "a@b.co", agent: { name: "x" } });
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
