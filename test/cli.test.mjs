// The ws command line tool, run by Node's own test runner (pnpm test:cli): it is a Node program,
// not Worker code. The server is a fake that records what the tool sent.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, signupBody } from "../bin/ws.mjs";

// Where the tests' ws signup keeps its pickup keys: never the real ~/.config.
const CONFIG = mkdtempSync(join(tmpdir(), "ws-cli-"));

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
    { fetch: server.fetch, env: { WS_API: "https://ws.test/", XDG_CONFIG_HOME: CONFIG }, ...io },
  );
  assert.equal(code, 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/signup-requests");
  const { pickup_public_key, ...sent } = JSON.parse(server.calls[0].init.body);
  assert.match(pickup_public_key, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(sent, {
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

test("events prints the server's hint on stderr, so --json stays one event per line", async () => {
  const hint = "vulnerability.exploited only comes as events about the whole world (country XX). Add XX to the countries to get it.";
  const io = capture();
  assert.equal(await run(["events", "--type", "vulnerability.exploited", "--country", "us", "--json"], { ...fakeServer(200, { events: [], cursor: 7, hint }), env: { WS_KEY: "wsk_test" }, ...io }), 0);
  assert.deepEqual(io.lines.out, []);
  assert.deepEqual(io.lines.err, [`Note: ${hint}`]);
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

test("watch prints new events from the stream as lines of JSON and saves where it got to", async () => {
  const { mkdtempSync, readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const state = join(mkdtempSync(join(tmpdir(), "ws-cli-")), "watch.json");
  const body = 'event: ready\ndata: {"after":4,"head":5}\n\nid: 5\ndata: {"id":"evt_5","type":"company.registered"}\n\n: hb\n\n';
  const calls = [];
  const fetch = async (url, init) => (calls.push({ url, init }), new Response(body, { headers: { "content-type": "text/event-stream" } }));
  const io = capture();
  assert.equal(await run(["watch", "--once", "--state", state], { fetch, env: { WS_KEY: "wsk_test" }, ...io }), 0);
  assert.equal(calls[0].url, "https://worldsignals.dev/api/stream");
  assert.deepEqual(io.lines.out, ['{"id":"evt_5","type":"company.registered"}']);
  assert.equal(JSON.parse(readFileSync(state, "utf8")).after, 5);
});

test("signup sends a public key and keeps the private one; key signs the fetch with it", async () => {
  const { readFileSync, statSync } = await import("node:fs");
  const { createPublicKey, verify } = await import("node:crypto");
  const config = mkdtempSync(join(tmpdir(), "ws-cli-"));
  const env = { WS_API: "https://ws.test", XDG_CONFIG_HOME: config };
  const token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const created = fakeServer(201, { message_for_human: "…", confirm_url: `https://ws.test/confirm?t=${token}`, expires_at: "2026-10-30T00:00:00Z" });
  assert.equal(await run(["signup", "--email", "a@b.co", "--agent", "x"], { fetch: created.fetch, env, ...capture() }), 0);
  const publicKey = JSON.parse(created.calls[0].init.body).pickup_public_key;
  assert.match(publicKey, /^[A-Za-z0-9_-]{43}$/);
  const file = join(config, "worldsignals", "requests.json");
  assert.match(JSON.parse(readFileSync(file, "utf8"))[token].private_key, /BEGIN PRIVATE KEY/);
  assert.equal(statSync(file).mode & 0o077, 0, "only this user can read it");

  const confirmed = fakeServer(200, { status: "confirmed", email_confirmed: true, access_key: "wsk_123.abc" });
  assert.equal(await run(["key", "--link", `https://ws.test/confirm?t=${token}`], { fetch: confirmed.fetch, env, ...capture() }), 0);
  const headers = confirmed.calls[0].init.headers;
  assert.equal(headers.authorization, undefined);
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKey }, format: "jwk" });
  const message = Buffer.from(`GET /api/signup-requests/${token} ${headers["x-ws-timestamp"]}`);
  assert.ok(verify(null, message, key, Buffer.from(headers["x-ws-signature"], "base64url")), "signed with the key whose public half was sent");

  const elsewhere = capture();
  assert.equal(await run(["key", "--link", token], { ...fakeServer(200, { status: "confirmed", email_confirmed: true, signature_required: true }), env: { XDG_CONFIG_HOME: join(config, "elsewhere") }, ...elsewhere }), 1);
  assert.match(elsewhere.lines.err.join("\n"), /pickup key isn't on this machine/);
});

test("a server that answers with a pickup secret still works: it is saved, not printed, and sent in a header", async () => {
  const env = { WS_API: "https://ws.test", XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "ws-cli-")) };
  const token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const secret = "S".repeat(43);
  const io = capture();
  const created = fakeServer(201, { message_for_human: "…", confirm_url: `https://ws.test/confirm?t=${token}`, expires_at: "2026-10-30T00:00:00Z", pickup_secret: secret });
  assert.equal(await run(["signup", "--email", "a@b.co", "--agent", "x"], { fetch: created.fetch, env, ...io }), 0);
  assert.ok(!io.lines.out.join("\n").includes(secret));
  const confirmed = fakeServer(200, { status: "confirmed", email_confirmed: true, access_key: "wsk_123.abc" });
  assert.equal(await run(["key", "--link", token], { fetch: confirmed.fetch, env, ...capture() }), 0);
  assert.equal(confirmed.calls[0].init.headers.authorization, `Bearer ${secret}`);
});

test("upgrade asks for a payment link with the access key and prints it", async () => {
  const server = fakeServer(200, { url: "https://checkout.stripe.com/c/pay/cs_test_1", plan: "team", billing: "yearly" });
  const io = capture();
  assert.equal(await run(["upgrade", "--plan", "team", "--billing", "yearly"], { fetch: server.fetch, env: { WS_API: "https://ws.test", WS_KEY: "wsk_1.a", XDG_CONFIG_HOME: CONFIG }, ...io }), 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/billing/checkout");
  assert.equal(server.calls[0].init.headers.authorization, "Bearer wsk_1.a");
  assert.deepEqual(JSON.parse(server.calls[0].init.body), { plan: "team", billing: "yearly" });
  assert.ok(io.lines.out.includes("https://checkout.stripe.com/c/pay/cs_test_1"));
  assert.equal(await run(["upgrade"], { fetch: () => assert.fail("no request"), env: {}, ...capture() }), 2);
});
