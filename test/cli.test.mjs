// The ws command line tool, run by Node's own test runner (pnpm test:cli): it is a Node program,
// not Worker code. The server is a fake that records what the tool sent.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VERSION, newerVersion, noticeLine, parseNoticeHeader, releasedVersion, agentHeaders, agentPath, commandName, help, newKeyPair, readAgent, retryWhen, run as runCli, signedString, signingTime } from "../bin/ws.mjs";

// Never a real browser from a test: commands that open a link (upgrade, billing, connect) get a spawn that does
// nothing and a platform with no browser, unless the test brings its own to check that it opens.
const run = (args, ctx = {}) => runCli(args, { spawn: () => ({ on() {}, unref() {} }), platform: "test", ...ctx });

// Where the tests keep agent keys: never the real ~/.config.
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

test("events needs an agent key or an access key, and says how to make one", async () => {
  const io = capture();
  assert.equal(await run(["events"], { fetch: () => assert.fail("no request"), env: { XDG_CONFIG_HOME: CONFIG }, ...io }), 2);
  assert.match(io.lines.err[0], /^ws events needs an agent key/);
  assert.match(io.lines.err[0], /\n {2}ws signup\n/);
  assert.match(io.lines.err[0], /WS_KEY/);
});

test("messages name the command as it was run", async () => {
  const io = capture();
  assert.equal(await run(["watch", "--no-signup"], { fetch: () => assert.fail("no request"), env: { XDG_CONFIG_HOME: CONFIG }, name: "npx worldsignals", ...io }), 2);
  assert.match(io.lines.err[0], /^npx worldsignals watch needs an agent key/);
  assert.match(io.lines.err[0], /npx worldsignals signup\n/);
  assert.match(io.lines.err[0], /npx worldsignals upgrade .*npx worldsignals connect/);
  assert.doesNotMatch(io.lines.err[0], /(^|[^x] )ws /);
  const text = help("npx worldsignals");
  for (const c of ["signup", "upgrade", "connect", "status", "billing", "keys rotate", "disconnect", "recover", "stream preview", "events", "watch", "types", "fields", "estimate", "api", "request", "feedback"]) assert.match(text, new RegExp(`^ {2}npx worldsignals ${c}`, "m"));
  assert.doesNotMatch(text, /^ {2}ws /m);
  // The earlier names still work, but help shows only the new ones.
  assert.doesNotMatch(text, /worldsignals (init|pay|portal)\b|--link/);
});

test("commandName: npx worldsignals through npx, pnpm dlx or bunx; the bin name when installed; node <file> for the download", () => {
  const npxBin = "/Users/ana/.npm/_npx/02b8002cc5fd1628/node_modules/.bin/worldsignals";
  assert.equal(commandName({ npm_command: "exec", npm_lifecycle_event: "npx" }, npxBin), "npx worldsignals");
  assert.equal(commandName({ npm_command: "exec", npm_lifecycle_event: "npx" }, "/Users/ana/.npm/_npx/02b8/node_modules/.bin/ws"), "npx worldsignals");
  assert.equal(commandName({ npm_config_user_agent: "pnpm/11.9.0 npm/? node/v24.22.1 darwin arm64" }, "/Users/ana/Library/pnpm/store/v11/links/@/worldsignals/0.3.2/x/node_modules/worldsignals/bin/ws.mjs"), "pnpm dlx worldsignals");
  assert.equal(commandName({ npm_config_user_agent: "bun/1.3.0" }, "/tmp/bunx-501-worldsignals/node_modules/.bin/worldsignals"), "bunx worldsignals");
  assert.equal(commandName({}, "/opt/homebrew/bin/ws"), "ws");
  assert.equal(commandName({}, "/opt/homebrew/bin/worldsignals"), "worldsignals");
  // A package.json script that runs ws is not npx.
  assert.equal(commandName({ npm_command: "run-script", npm_lifecycle_event: "poll", npm_config_user_agent: "npm/11" }, "/app/node_modules/.bin/ws"), "ws");
  // Windows starts the installed bin by its real path.
  assert.equal(commandName({}, "C:\\Users\\ana\\AppData\\Roaming\\npm\\node_modules\\worldsignals\\bin\\ws.mjs"), "worldsignals");
  assert.equal(commandName({}, "/Users/ana/ws.mjs", "/Users/ana"), "node ws.mjs");
  assert.equal(commandName({}, "/Users/ana/repo/public/cli/ws.mjs", "/Users/ana/repo"), "node public/cli/ws.mjs");
  assert.equal(commandName({}, "/Users/ana/Down loads/ws.mjs", "/tmp"), 'node "/Users/ana/Down loads/ws.mjs"');
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

test("upgrade with an access key asks for a payment link for that key's account", async () => {
  const server = fakeServer(200, { url: "https://checkout.stripe.com/c/pay/cs_test_1", plan: "team", billing: "yearly" });
  const io = capture();
  assert.equal(await run(["upgrade", "--plan", "team", "--billing", "yearly"], { fetch: server.fetch, env: { WS_API: "https://ws.test", WS_KEY: "wsk_1.a", XDG_CONFIG_HOME: CONFIG }, ...io }), 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/billing/checkout");
  assert.equal(server.calls[0].init.headers.authorization, "Bearer wsk_1.a");
  assert.deepEqual(JSON.parse(server.calls[0].init.body), { plan: "team", billing: "yearly" });
  assert.ok(io.lines.out.includes("https://checkout.stripe.com/c/pay/cs_test_1"));
  assert.equal(await run(["upgrade"], { fetch: () => assert.fail("no request"), env: { XDG_CONFIG_HOME: CONFIG }, ...capture() }), 2);
});

test("stream shows the saved stream from /api/me, every country when none are chosen", async () => {
  const server = fakeServer(200, { email: "a@b.co", eventTypes: ["company.registered"], countries: ["PT", "XX"], delivery: ["cli"], speed: "realtime" });
  const io = capture();
  assert.equal(await run(["stream"], { fetch: server.fetch, env: { WS_API: "https://ws.test", WS_KEY: "wsk_1.a" }, ...io }), 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/me");
  assert.equal(server.calls[0].init.headers.authorization, "Bearer wsk_1.a");
  assert.deepEqual(io.lines.out, ["Event types: company.registered", "Countries:   PT, XX", "Delivery:    cli", "Speed:       realtime"]);
  const all = capture();
  assert.equal(await run(["stream", "--json"], { ...fakeServer(200, { email: "a@b.co", eventTypes: ["company.registered"], countries: ["WW"] }), env: { WS_KEY: "wsk_1.a" }, ...all }), 0);
  assert.deepEqual(JSON.parse(all.lines.out[0]), { eventTypes: ["company.registered"], countries: ["WW"], delivery: [], speed: null, matches: [] });
  const plain = capture();
  assert.equal(await run(["stream"], { ...fakeServer(200, { eventTypes: ["company.registered"], countries: ["WW"] }), env: { WS_KEY: "wsk_1.a" }, ...plain }), 0);
  assert.equal(plain.lines.out[1], "Countries:   every country");
  assert.equal(await run(["stream"], { fetch: () => assert.fail("no request"), env: { XDG_CONFIG_HOME: CONFIG }, ...capture() }), 2);
});

test("stream set sends only what was given, with PATCH, and prints what was saved", async () => {
  const hint = "vulnerability.exploited only comes as events about the whole world (country XX). Add XX to the countries to get it.";
  const server = fakeServer(200, { eventTypes: ["vulnerability.exploited"], countries: ["US"], delivery: [], speed: null, hint });
  const io = capture();
  assert.equal(await run(["stream", "set", "--type", "vulnerability.exploited", "--country", "us"], { fetch: server.fetch, env: { WS_API: "https://ws.test", WS_KEY: "wsk_1.a" }, ...io }), 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/me/stream");
  assert.equal(server.calls[0].init.method, "PATCH");
  assert.equal(server.calls[0].init.headers.authorization, "Bearer wsk_1.a");
  assert.deepEqual(JSON.parse(server.calls[0].init.body), { eventTypes: ["vulnerability.exploited"], countries: ["US"] });
  assert.deepEqual(io.lines.out, ["Saved.", "Event types: vulnerability.exploited", "Countries:   US"]);
  assert.deepEqual(io.lines.err, [`Note: ${hint}`]);
  // Nothing to change, a typo the server names, a key that doesn't work.
  assert.equal(await run(["stream", "set"], { fetch: () => assert.fail("no request"), env: { WS_KEY: "wsk_1.a" }, ...capture() }), 2);
  const bad = capture();
  assert.equal(await run(["stream", "set", "--country", "UK"], { ...fakeServer(400, { error: "Not ISO country codes we know: UK (the United Kingdom is GB)." }), env: { WS_KEY: "wsk_1.a" }, ...bad }), 2);
  assert.match(bad.lines.err[0], /^ws stream set: Not ISO country codes we know: UK/);
  const denied = capture();
  assert.equal(await run(["stream", "set", "--speed", "daily"], { ...fakeServer(401, { error: "Not signed in." }), env: { WS_KEY: "wsk_1.a" }, ...denied }), 1);
  assert.match(denied.lines.err[0], /access key doesn't work/);
});

// Agent accounts. The fake server checks every signature the way the contract says: X-WS-Signature is the Ed25519
// signature of "<METHOD> <path+query> <timestamp> <base64url sha256 of the body, or nothing>", by the key sent to
// /api/agent/init (or the one bound to X-WS-Agent).
async function agentServer(routes) {
  const { createHash, createPublicKey, verify } = await import("node:crypto");
  const keys = new Map(); // agent id → public key (raw, base64url)
  const recovering = new Map(); // a recovery's device code → its new public key, for its polls (no agent id yet)
  const calls = [];
  const verified = (method, url, init, publicKey) => {
    const h = init.headers ?? {};
    const body = init.body ?? "";
    const hash = body ? createHash("sha256").update(body).digest("base64url") : "";
    const u = new URL(url);
    const message = `${method} ${u.pathname}${u.search} ${h["x-ws-timestamp"]} ${hash}`;
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKey }, format: "jwk" });
    return Math.abs(Date.now() / 1000 - Number(h["x-ws-timestamp"])) < 300 && verify(null, Buffer.from(message), key, Buffer.from(h["x-ws-signature"] ?? "", "base64url"));
  };
  const fetch = async (url, init = {}) => {
    const method = init.method ?? "GET";
    const path = new URL(url).pathname;
    const body = init.body ? JSON.parse(init.body) : undefined;
    const agentId = init.headers?.["x-ws-agent"];
    const publicKey = agentId ? keys.get(agentId) : (body?.public_key ?? recovering.get(body?.device_code));
    const signed = Boolean(publicKey) && verified(method, url, init, publicKey);
    calls.push({ method, path, url, body, headers: init.headers, signed, agentId });
    const route = routes[`${method} ${path}`];
    let [status, answer] = !signed && !init.headers?.authorization ? [401, { error: "Bad signature." }] : route ? await route({ body, agentId, keys, calls }) : [404, { error: "No such route." }];
    if (path === "/api/agent/init" && status === 200 && answer.agent_id && !body.recover) keys.set(answer.agent_id, body.public_key);
    if (path === "/api/agent/init" && status === 200 && body.recover) recovering.set(answer.device_code, body.public_key);
    return new Response(JSON.stringify(answer), { status, headers: { "content-type": "application/json" } });
  };
  return { fetch, calls, keys };
}

const agentEnv = () => ({ WS_API: "https://ws.test", XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "ws-agent-")) });
const INIT = { "POST /api/agent/init": () => [200, { agent_id: "agt_1", status: "unpaid", name: "Claude Code" }] };

test("signup makes a key pair, keeps the private key owner-only and prints the next step; it won't replace a key without --force", async () => {
  const { statSync, readFileSync } = await import("node:fs");
  const env = { ...agentEnv(), CLAUDECODE: "1" };
  const server = await agentServer(INIT);
  const io = capture();
  assert.equal(await run(["signup", "--label", "laptop"], { fetch: server.fetch, env, name: "npx worldsignals", ...io }), 0);
  const call = server.calls[0];
  assert.equal(call.path, "/api/agent/init");
  assert.ok(call.signed, "signed with the new key");
  assert.equal(call.headers["x-ws-agent"], undefined);
  assert.match(call.body.public_key, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual({ ...call.body, public_key: undefined }, { public_key: undefined, name: "Claude Code", label: "laptop" });
  const file = agentPath(env);
  assert.equal(statSync(file).mode & 0o077, 0, "only this user can read it");
  const saved = readAgent(env, "https://ws.test");
  assert.equal(saved.agent_id, "agt_1");
  assert.match(saved.private_key, /BEGIN PRIVATE KEY/);
  assert.ok(!readFileSync(file, "utf8").includes("\"pending\""));
  const text = io.lines.out.join("\n");
  assert.match(text, /Agent agt_1 created/);
  assert.match(text, /^ {2}npx worldsignals upgrade /m);
  assert.match(text, /^ {2}npx worldsignals connect /m);

  const again = capture();
  const alive = async () => new Response(JSON.stringify({ agent_id: "agt_1", status: "unpaid" }), { status: 200 });
  assert.equal(await run(["signup"], { fetch: alive, env, ...again }), 1);
  assert.match(again.lines.err[0], /already has an agent key \(agt_1/);
  const forced = capture();
  const second = await agentServer({ "POST /api/agent/init": () => [200, { agent_id: "agt_2", status: "unpaid", name: "x" }] });
  assert.equal(await run(["signup", "--force", "--name", "x"], { fetch: second.fetch, env, ...forced }), 0);
  assert.match(forced.lines.err[0], /^Warning: replacing the agent key for agt_1/);
  assert.equal(readAgent(env, "https://ws.test").agent_id, "agt_2");
});

test("signup keeps nothing when the server refuses, and checks --email", async () => {
  const env = agentEnv();
  const io = capture();
  assert.equal(await run(["signup"], { ...(await agentServer({ "POST /api/agent/init": () => [429, { error: "Too many agents from this network today." }] })), env, ...io }), 1);
  assert.match(io.lines.err[0], /429.*Too many agents/);
  assert.equal(readAgent(env, "https://ws.test"), null);
  assert.equal(await run(["signup", "--email", "nope"], { fetch: () => assert.fail("no request"), env, ...capture() }), 2);
  // An email is optional, and goes with the request.
  const server = await agentServer(INIT);
  const withEmail = capture();
  assert.equal(await run(["signup", "--email", "ana@example.pt"], { fetch: server.fetch, env, ...withEmail }), 0);
  assert.equal(server.calls[0].body.email, "ana@example.pt");
  assert.match(withEmail.lines.out.join("\n"), /sends no email/);
});

test("key --link is gone and says what to run instead", async () => {
  const io = capture();
  assert.equal(await run(["key", "--link", "https://ws.test/confirm?t=x", "--wait"], { fetch: () => assert.fail("no request"), env: {}, name: "npx worldsignals", ...io }), 2);
  assert.deepEqual(io.lines.err, ["npx worldsignals key and its pickup by email are gone: run npx worldsignals signup to create an agent key on this device, then npx worldsignals upgrade or npx worldsignals connect."]);
});

test("signup takes the old sign-up's --agent as the name, and says where the other old flags went", async () => {
  const server = await agentServer(INIT);
  const io = capture();
  assert.equal(await run(["signup", "--email", "ana@example.pt", "--agent", "My agent", "--type", "company.registered", "--plan", "team"], { fetch: server.fetch, env: agentEnv(), ...io }), 0);
  assert.equal(server.calls[0].body.name, "My agent");
  assert.equal(server.calls[0].body.type, undefined);
  assert.match(io.lines.err[0], /^Note: ws signup no longer takes --type, --plan\. .*ws stream set .*ws upgrade --plan team/);
});

test("init, pay and portal still work as the earlier names of signup, upgrade and billing", async () => {
  const { env, server } = await withAgent({
    "POST /api/agent/checkout": () => [200, { url: "https://checkout.stripe.com/c/pay/cs_test_1" }],
    "POST /api/agent/portal": () => [200, { url: "https://billing.stripe.com/p/session/x" }],
  });
  assert.equal(await run(["pay", "--no-open"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.equal(await run(["portal", "--no-open"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.deepEqual(server.calls.map((c) => c.path), ["/api/agent/checkout", "/api/agent/portal"]);
  const fresh = await agentServer(INIT);
  assert.equal(await run(["init"], { fetch: fresh.fetch, env: agentEnv(), ...capture() }), 0);
  assert.equal(fresh.calls[0].path, "/api/agent/init");
});

/** An env with an agent made by init against a fake server that has `routes` too. */
async function withAgent(routes) {
  const env = agentEnv();
  const server = await agentServer({ ...INIT, ...routes });
  assert.equal(await run(["signup"], { fetch: server.fetch, env, ...capture() }), 0);
  server.calls.length = 0;
  return { env, server };
}

test("data commands sign with the agent key; WS_KEY and --key still send an access key", async () => {
  const { env, server } = await withAgent({
    "GET /api/events": () => [200, { events: [], cursor: 3 }],
    "GET /api/me": () => [200, { eventTypes: ["company.registered"], countries: [] }],
    "PATCH /api/me/stream": () => [200, { eventTypes: ["company.registered"], countries: ["PT"] }],
  });
  assert.equal(await run(["events", "--type", "company.registered", "--country", "pt"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.equal(await run(["stream"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.equal(await run(["stream", "set", "--country", "pt"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.deepEqual(server.calls.map((c) => [c.method, c.path, c.agentId, c.signed]), [
    ["GET", "/api/events", "agt_1", true],
    ["GET", "/api/me", "agt_1", true],
    ["PATCH", "/api/me/stream", "agt_1", true],
  ]);
  assert.equal(server.calls[0].headers.authorization, undefined);
  server.calls.length = 0;
  assert.equal(await run(["events"], { fetch: server.fetch, env: { ...env, WS_KEY: "wsk_1.a" }, ...capture() }), 0);
  assert.equal(await run(["events", "--key", "wsk_2.b"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.deepEqual(server.calls.map((c) => [c.headers.authorization, c.headers["x-ws-agent"]]), [["Bearer wsk_1.a", undefined], ["Bearer wsk_2.b", undefined]]);
});

test("watch signs each connection with the agent key", async () => {
  const { env } = await withAgent({});
  const state = join(mkdtempSync(join(tmpdir(), "ws-cli-")), "watch.json");
  const body = 'event: ready\ndata: {"after":4,"head":5}\n\nid: 5\ndata: {"id":"evt_5","type":"company.registered"}\n\n: hb\n\n';
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith("/api/agent/me")) return new Response(JSON.stringify({ agent_id: "agt_1", status: "paid", plan: "developer" }), { headers: { "content-type": "application/json" } });
    return new Response(body, { headers: { "content-type": "text/event-stream" } });
  };
  const io = capture();
  assert.equal(await run(["watch", "--once", "--state", state, "--type", "company.registered"], { fetch, env, ...io }), 0);
  assert.equal(new URL(calls[0].url).pathname, "/api/agent/me", "a paid agent is checked, then watches straight away");
  assert.deepEqual(io.lines.err.filter((l) => /paid for|Waiting/.test(l)), []);
  const h = calls[1].init.headers;
  assert.equal(h["x-ws-agent"], "agt_1");
  assert.equal(signedString("GET", calls[1].url, "", h["x-ws-timestamp"]), `GET /api/stream?types=company.registered ${h["x-ws-timestamp"]} `);
  assert.deepEqual(io.lines.out, ['{"id":"evt_5","type":"company.registered"}']);
});

test("an unpaid agent is told to run pay or connect", async () => {
  const { env, server } = await withAgent({ "GET /api/events": () => [402, { error: "Payment required.", hint: "POST /api/agent/checkout" }] });
  const io = capture();
  assert.equal(await run(["events"], { fetch: server.fetch, env, name: "ws", ...io }), 1);
  assert.deepEqual(io.lines.err, ["This agent isn't paid for yet. Run ws upgrade for a payment link, or ws connect to use the account of the person you work for. (Vulnerability alerts are free: --type vulnerability.exploited)"]);
});

test("upgrade asks for a checkout link, prints it, opens the browser and with --wait waits until paid", async () => {
  let paid = false;
  const { env, server } = await withAgent({
    "POST /api/agent/checkout": () => [200, { url: "https://checkout.stripe.com/c/pay/cs_test_1" }],
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: paid ? "paid" : "unpaid", plan: paid ? "team" : null, paid_until: paid ? "2027-10-26T00:00:00Z" : null }],
  });
  const spawned = [];
  const spawn = (cmd, args) => (spawned.push([cmd, ...args]), { on() {}, unref() {} });
  const io = capture();
  let polls = 0;
  const sleep = async () => {
    if (++polls === 2) paid = true;
  };
  assert.equal(await run(["upgrade", "--plan", "team", "--yearly", "--wait"], { fetch: server.fetch, env, spawn, sleep, platform: "darwin", ...io }), 0);
  assert.deepEqual(server.calls[0].body, { plan: "team", billing: "yearly" });
  assert.ok(server.calls.every((c) => c.signed && c.agentId === "agt_1"));
  assert.ok(io.lines.out.includes("https://checkout.stripe.com/c/pay/cs_test_1"));
  assert.deepEqual(spawned, [["open", "https://checkout.stripe.com/c/pay/cs_test_1"]]);
  assert.match(io.lines.out.join("\n"), /Paid for: the Team plan, until 2027-10-26/);
  assert.equal(polls, 2);
  // Already paid: 409, and where to manage it.
  const again = await withAgent({ "POST /api/agent/checkout": () => [409, { error: "This agent is already paid for." }] });
  const io2 = capture();
  assert.equal(await run(["upgrade", "--no-open"], { fetch: again.server.fetch, env: again.env, spawn: () => assert.fail("no browser"), ...io2 }), 1);
  assert.match(io2.lines.err[0], /already paid for\. ws status .* ws billing/);
  assert.equal(await run(["upgrade", "--plan", "free"], { fetch: () => assert.fail("no request"), env, ...capture() }), 2);
});

test("billing prints the billing portal link for a paid agent, and says why not for the others", async () => {
  const paid = await withAgent({ "POST /api/agent/portal": () => [200, { url: "https://billing.stripe.com/p/session/x" }] });
  const io = capture();
  assert.equal(await run(["billing", "--no-open"], { fetch: paid.server.fetch, env: paid.env, ...io }), 0);
  assert.equal(io.lines.out[1], "https://billing.stripe.com/p/session/x");
  const unpaidAgent = await withAgent({ "POST /api/agent/portal": () => [402, { error: "Not paid." }] });
  const no = capture();
  assert.equal(await run(["billing"], { fetch: unpaidAgent.server.fetch, env: unpaidAgent.env, ...no }), 1);
  assert.match(no.lines.err[0], /only|its own paid plan/);
});

test("connect shows the code and the link, polls at the interval, slows down when told, and says what the agent can do once approved", async () => {
  const answers = [[200, { status: "pending" }], [429, { error: "slow_down" }], [400, { error: "authorization_pending" }], [200, { status: "approved" }]];
  const { env, server } = await withAgent({
    "POST /api/agent/connect": ({ body }) => [200, { device_code: "dev_1", user_code: "ABCD-EFGH", verification_uri: "https://worldsignals.dev/link", verification_uri_complete: "https://worldsignals.dev/link?code=ABCD-EFGH", expires_in: 900, interval: 5, email: body.email }],
    "POST /api/agent/connect/poll": () => answers.shift(),
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: "connected", plan: null, connected_to: { account_label: "Acme", plan: "team", since: "2026-10-26T12:00:00Z" } }],
  });
  const waits = [];
  const io = capture();
  assert.equal(await run(["connect", "--email", "ana@example.pt"], { fetch: server.fetch, env, sleep: async (ms) => void waits.push(ms), ...io }), 0);
  assert.deepEqual(server.calls[0].body, { email: "ana@example.pt" });
  const text = io.lines.out.join("\n");
  assert.match(text, /Open https:\/\/worldsignals\.dev\/link and enter ABCD-EFGH/);
  assert.match(text, /or open https:\/\/worldsignals\.dev\/link\?code=ABCD-EFGH/);
  assert.match(text, /A request is also waiting in that person's console/);
  assert.match(text, /Connected to Acme: it acts for that account, with its Team plan and its streams\./);
  assert.deepEqual(waits, [5000, 5000, 10000, 10000]);
  assert.ok(server.calls.filter((c) => c.path === "/api/agent/connect/poll").every((c) => c.signed && c.body.device_code === "dev_1"));
  assert.equal(readAgent(env, "https://ws.test").connect, undefined, "the code is forgotten once used");
});

test("connect stops when the person denies it or the code expires; --no-wait keeps the code for the next connect", async () => {
  for (const [answer, said] of [[{ status: "denied" }, /was denied/], [{ status: "expired" }, /expired/], [{ error: "access_denied" }, /was denied/]]) {
    const { env, server } = await withAgent({
      "POST /api/agent/connect": () => [200, { device_code: "dev_1", user_code: "ABCD-EFGH", verification_uri: "https://worldsignals.dev/link", expires_in: 600, interval: 5 }],
      "POST /api/agent/connect/poll": () => [answer.error ? 400 : 200, answer],
    });
    const io = capture();
    assert.equal(await run(["connect"], { fetch: server.fetch, env, sleep: async () => {}, ...io }), 1);
    assert.match(io.lines.err.at(-1), said);
  }
  let polls = 0;
  const { env, server } = await withAgent({
    "POST /api/agent/connect": () => [200, { device_code: "dev_1", user_code: "WXYZ-1234", verification_uri: "https://worldsignals.dev/link", expires_in: 600, interval: 5 }],
    "POST /api/agent/connect/poll": () => (polls++, [200, { status: "approved" }]),
    "GET /api/agent/me": () => [200, { status: "connected", plan: "developer", connected_to: "ana@example.pt" }],
  });
  const first = capture();
  assert.equal(await run(["connect", "--no-wait"], { fetch: server.fetch, env, sleep: async () => assert.fail("no wait"), ...first }), 0);
  assert.equal(polls, 0);
  const second = capture();
  assert.equal(await run(["connect"], { fetch: server.fetch, env, sleep: async () => {}, ...second }), 0);
  assert.equal(server.calls.filter((c) => c.path === "/api/agent/connect").length, 1, "the same code, not a new one");
  assert.match(second.lines.out.join("\n"), /enter WXYZ-1234/);
});

test("status shows the agent from /api/agent/me", async () => {
  const { env, server } = await withAgent({
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", name: "Claude Code", label: "laptop", status: "paid", plan: "developer", paid_until: "2026-11-26T00:00:00Z", connected_to: null, can_portal: true }],
  });
  const io = capture();
  assert.equal(await run(["status"], { fetch: server.fetch, env, ...io }), 0);
  assert.equal(io.lines.out[0], "Agent:   agt_1 (Claude Code, laptop)");
  assert.equal(io.lines.out[1], "Status:  Paid for: the Developer plan, until 2026-11-26.");
  assert.match(io.lines.out[2], /ws billing/);
  const json = capture();
  assert.equal(await run(["status", "--json"], { fetch: server.fetch, env, ...json }), 0);
  assert.equal(JSON.parse(json.lines.out[0]).status, "paid");
  const none = capture();
  assert.equal(await run(["status"], { fetch: () => assert.fail("no request"), env: agentEnv(), ...none }), 2);
  assert.match(none.lines.err[0], /ws signup/);
});

test("disconnect leaves the account it is connected to, then forgets the key and the watch position", async () => {
  const { existsSync, writeFileSync, mkdirSync } = await import("node:fs");
  let connected = true;
  const server = await agentServer({
    ...INIT,
    "GET /api/agent/me": () => [200, connected ? { agent_id: "agt_1", status: "connected", plan: null, connected_to: { account_label: "Acme", plan: "team" } } : { agent_id: "agt_1", status: "unpaid", plan: null }],
    "POST /api/agent/disconnect": () => {
      const was = connected;
      connected = false;
      return [200, { ok: true, agent_id: "agt_1", disconnected: was, status: "unpaid" }];
    },
  });
  // The real server, so watch.json is this agent's place.
  const env = { XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "ws-agent-")) };
  assert.equal(await run(["signup"], { fetch: server.fetch, env, ...capture() }), 0);
  server.calls.length = 0;
  const watched = join(env.XDG_CONFIG_HOME, "worldsignals", "watch.json");
  mkdirSync(join(env.XDG_CONFIG_HOME, "worldsignals"), { recursive: true });
  writeFileSync(watched, '{"after": 7}\n');
  const io = capture();
  assert.equal(await run(["disconnect"], { fetch: server.fetch, env, ...io }), 0);
  assert.deepEqual(server.calls.map((c) => `${c.method} ${c.path} ${c.signed}`), ["GET /api/agent/me true", "POST /api/agent/disconnect true"]);
  assert.equal(io.lines.out[0], "Disconnected agt_1 from Acme.");
  assert.match(io.lines.out[1], /^Forgot this device's agent key \(agt_1\) and where ws watch stopped\. ws signup or ws watch starts from scratch\.$/);
  assert.equal(readAgent(env, "https://worldsignals.dev"), null);
  assert.equal(existsSync(watched), false);
  // Nothing left: says so, and asks nothing.
  const again = capture();
  assert.equal(await run(["disconnect"], { fetch: () => assert.fail("no request"), env, ...again }), 0);
  assert.match(again.lines.out[0], /no agent key: nothing to disconnect/);
});

test("disconnect keeps watch.json when WS_KEY is set, and says to unset it", async () => {
  const { existsSync, writeFileSync } = await import("node:fs");
  const { env, server } = await withAgent({
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: "unpaid", plan: null }],
    "POST /api/agent/disconnect": () => [200, { ok: true, agent_id: "agt_1", disconnected: false, status: "unpaid" }],
  });
  const watched = join(env.XDG_CONFIG_HOME, "worldsignals", "watch.json");
  writeFileSync(watched, '{"after": 7}\n');
  const io = capture();
  assert.equal(await run(["disconnect"], { fetch: server.fetch, env: { ...env, WS_KEY: "wsk_test" }, ...io }), 0);
  // Not connected: nothing to say about leaving.
  assert.match(io.lines.out[0], /^Forgot this device's agent key \(agt_1\)\. /);
  assert.match(io.lines.err[0], /WS_KEY is still set.*unset WS_KEY/);
  assert.equal(readAgent(env, "https://ws.test"), null);
  assert.ok(existsSync(watched), "that watch's place, not this agent's");
});

test("disconnect won't forget an agent with a live plan of its own, or one it can't reach, without --force", async () => {
  for (const me of [
    { agent_id: "agt_1", status: "paid", plan: "developer", paid_until: "2026-11-26T00:00:00Z", paid_status: "active" },
    // Past its paid_until but Stripe still counts it live: a renewal that hasn't reached the server.
    { agent_id: "agt_1", status: "unpaid", plan: null, paid_until: "2026-10-01T00:00:00Z", paid_status: "past_due" },
  ]) {
    const { env, server } = await withAgent({ "GET /api/agent/me": () => [200, me] });
    const io = capture();
    assert.equal(await run(["disconnect"], { fetch: server.fetch, env, ...io }), 1);
    assert.match(io.lines.err[0], /has its own .*plan.*cancel it with ws billing and run ws disconnect once the period ends.*--force/);
    assert.ok(readAgent(env, "https://ws.test"), "the key stays");
    // --force: forgotten, even though this server has no disconnect route (an agent that isn't connected has nothing to leave).
    assert.equal(await run(["disconnect", "--force"], { fetch: server.fetch, env, ...capture() }), 0);
    assert.equal(readAgent(env, "https://ws.test"), null);
  }

  const down = await withAgent({});
  const offline = async () => { throw new Error("getaddrinfo ENOTFOUND ws.test"); };
  const io2 = capture();
  assert.equal(await run(["disconnect"], { fetch: offline, env: down.env, ...io2 }), 1);
  assert.match(io2.lines.err[0], /no answer.*Nothing changed.*--force/);
  assert.ok(readAgent(down.env, "https://ws.test"));
  assert.equal(await run(["disconnect", "--force"], { fetch: offline, env: down.env, ...capture() }), 0);
  assert.equal(readAgent(down.env, "https://ws.test"), null);
});

test("disconnect stops when a connected agent can't leave", async () => {
  const { env, server } = await withAgent({
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: "connected", connected_to: { account_label: "Acme" } }],
    "POST /api/agent/disconnect": () => [503, { error: "Try again." }],
  });
  const io = capture();
  assert.equal(await run(["disconnect"], { fetch: server.fetch, env, ...io }), 1);
  assert.match(io.lines.err[0], /Couldn't disconnect agt_1 \(503\): Try again\. Nothing changed\./);
  assert.ok(readAgent(env, "https://ws.test"));
});

test("disconnect forgets an agent the server already deleted", async () => {
  const { env, server } = await withAgent({ "GET /api/agent/me": () => [401, { error: "No such agent.", reason: "agent" }] });
  assert.equal(await run(["disconnect"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.equal(readAgent(env, "https://ws.test"), null);
});

test("keys rotate sends a new public key, signed by the old key and the new one, and then signs with the new key", async () => {
  const { createPublicKey, verify } = await import("node:crypto");
  const { env, server } = await withAgent({
    "POST /api/agent/keys/rotate": ({ body, agentId, keys }) => {
      keys.set(agentId, body.new_public_key);
      return [200, { ok: true }];
    },
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: "unpaid" }],
  });
  const old = readAgent(env, "https://ws.test");
  assert.equal(await run(["keys", "rotate"], { fetch: server.fetch, env, ...capture() }), 0);
  const call = server.calls[0];
  assert.ok(call.signed, "signed by the old key");
  const message = Buffer.from(`rotate agt_1 ${call.body.new_public_key} ${call.headers["x-ws-timestamp"]}`);
  const newKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: call.body.new_public_key }, format: "jwk" });
  assert.ok(verify(null, message, newKey, Buffer.from(call.body.new_signature, "base64url")), "and by the new one");
  const now = readAgent(env, "https://ws.test");
  assert.notEqual(now.private_key, old.private_key);
  assert.equal(now.next_private_key, undefined);
  assert.equal(await run(["status"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.ok(server.calls.at(-1).signed, "the new key works");
  // Refused: the old key stays.
  const refusedRotate = await withAgent({ "POST /api/agent/keys/rotate": () => [400, { error: "Bad new_signature." }] });
  const before = readAgent(refusedRotate.env, "https://ws.test").private_key;
  assert.equal(await run(["keys", "rotate"], { fetch: refusedRotate.server.fetch, env: refusedRotate.env, ...capture() }), 1);
  assert.equal(readAgent(refusedRotate.env, "https://ws.test").private_key, before);
});

test("recover makes a new key, prints the code for the console and, once approved, signs as the old agent", async () => {
  const answers = [[200, { status: "pending" }], [200, { status: "approved", agent_id: "agt_old" }]];
  const env = agentEnv();
  const server = await agentServer({
    "POST /api/agent/init": ({ body }) => (body.recover ? [200, { user_code: "RCVR-0001", device_code: "dev_r", verification_uri: "https://worldsignals.dev/link", interval: 5, expires_in: 900 }] : [400, {}]),
    "POST /api/agent/connect/poll": () => answers.shift(),
  });
  const io = capture();
  assert.equal(await run(["recover", "--name", "Claude Code"], { fetch: server.fetch, env, sleep: async () => {}, ...io }), 0);
  assert.equal(server.calls[0].body.recover, true);
  assert.ok(server.calls[0].signed && !server.calls[0].agentId);
  assert.match(io.lines.out.join("\n"), /Open https:\/\/worldsignals\.dev\/link and enter RCVR-0001/);
  assert.match(io.lines.out.at(-1), /Recovered: this device now signs as agt_old/);
  const saved = readAgent(env, "https://ws.test");
  assert.equal(saved.agent_id, "agt_old");
  assert.equal(saved.public_key, server.calls[0].body.public_key);
});

test("keys are kept per server: a key made against one WS_API is never sent to another", async () => {
  const { env } = await withAgent({});
  const io = capture();
  assert.equal(await run(["events"], { fetch: () => assert.fail("no request"), env: { ...env, WS_API: "https://other.test" }, ...io }), 2);
  assert.match(io.lines.err[0], /needs an agent key/);
});

// ws watch onboards by itself: the homepage's one command signs the agent up and waits until it is paid for or connected.
const SSE = 'event: ready\ndata: {"after":4,"head":5}\n\nid: 5\ndata: {"id":"evt_5","type":"company.registered"}\n\n: hb\n\n';
const CONNECT = () => [200, { device_code: "dev_1", user_code: "ABCD-EFGH", verification_uri: "https://worldsignals.dev/link", verification_uri_complete: "https://worldsignals.dev/link?code=ABCD-EFGH", expires_in: 900, interval: 5 }];
/** The agent server, with /api/stream answered as Server-Sent Events. */
async function watchServer(routes) {
  const server = await agentServer(routes);
  const inner = server.fetch;
  server.fetch = async (url, init = {}) => {
    const res = await inner(url, init);
    return new URL(url).pathname === "/api/stream" && res.status === 404 ? new Response(SSE, { headers: { "content-type": "text/event-stream" } }) : res;
  };
  return server;
}

test("watch with no key signs the agent up, shows the payment link and the connect code, and watches once it's paid", async () => {
  const env = { ...agentEnv(), CLAUDECODE: "1" };
  let mes = 0;
  const server = await watchServer({
    ...INIT,
    "GET /api/agent/me": () => (++mes >= 3 ? [200, { agent_id: "agt_1", status: "paid", plan: "team", paid_until: "2026-11-26T00:00:00Z" }] : [200, { agent_id: "agt_1", status: "unpaid" }]),
    "POST /api/agent/checkout": () => [200, { url: "https://checkout.stripe.com/c/pay/cs_test_1" }],
    "POST /api/agent/connect": CONNECT,
  });
  const waits = [];
  const io = capture();
  const state = join(mkdtempSync(join(tmpdir(), "ws-cli-")), "watch.json");
  assert.equal(await run(["watch", "--once", "--state", state, "--plan", "team"], { fetch: server.fetch, env, sleep: async (ms) => void waits.push(ms), ...io }), 0);
  const steps = server.calls.map((c) => `${c.method} ${c.path}`);
  assert.deepEqual(steps.slice(0, 4), ["POST /api/agent/init", "GET /api/agent/me", "POST /api/agent/checkout", "POST /api/agent/connect"]);
  assert.equal(server.calls[0].body.name, "Claude Code");
  assert.equal(server.calls[0].body.email, undefined);
  assert.deepEqual(server.calls[2].body, { plan: "team", billing: "monthly" });
  assert.ok(server.calls.every((c) => c.signed));
  const said = io.lines.err.join("\n");
  assert.match(io.lines.err[0], /^No agent key on this device yet: making one, as ws signup would\.$/);
  // A label each, the link on a line of its own; plain text, as an agent reads it.
  assert.match(said, /^  Pay      for its own Team plan, monthly \(Stripe asks the payer's email, for receipts\)\n {11}https:\/\/checkout\.stripe\.com\/c\/pay\/cs_test_1$/m);
  assert.match(said, /^  Connect  it to your account, signed in: enter ABCD-EFGH at https:\/\/worldsignals\.dev\/link\n {11}https:\/\/worldsignals\.dev\/link\?code=ABCD-EFGH$/m);
  assert.doesNotMatch(said, /\x1b/, "no styling off a terminal");
  assert.doesNotMatch(said, /Press Enter/);
  assert.match(said, /Paid for: the Team plan/);
  for (const line of io.lines.err) assert.doesNotMatch(line, /\n/, "one plain line each");
  assert.deepEqual(waits, [5000, 7500], "gently, backing off");
  assert.equal(steps.at(-1), "GET /api/stream");
  assert.deepEqual(io.lines.out, ['{"id":"evt_5","type":"company.registered"}'], "stdout is the events only");
  assert.equal(readAgent(env, "https://ws.test").agent_id, "agt_1");
});

test("watch with an unpaid key shows the links and waits; Ctrl+C stops and keeps the key", async () => {
  const { env, server } = await withAgent({
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: "unpaid" }],
    "POST /api/agent/checkout": () => [200, { url: "https://checkout.stripe.com/c/pay/cs_test_2" }],
    "POST /api/agent/connect": CONNECT,
  });
  const stop = new AbortController();
  const io = capture();
  assert.equal(await run(["watch"], { fetch: server.fetch, env, signal: stop.signal, sleep: async () => stop.abort(), ...io }), 1);
  assert.ok(!server.calls.some((c) => c.path === "/api/agent/init"), "no new agent");
  assert.match(io.lines.err.join("\n"), /cs_test_2[\s\S]*ABCD-EFGH[\s\S]*Waiting for the payment or the approval/);
  assert.match(io.lines.err.at(-1), /^Stopped waiting\. The agent key is saved/);
  assert.equal(readAgent(env, "https://ws.test").agent_id, "agt_1");
  assert.equal(readAgent(env, "https://ws.test").connect.user_code, "ABCD-EFGH", "the code is kept for the next run");
});

test("watch for the always-free types needs no plan: an unpaid agent watches at once, told how to get the rest", async () => {
  const { env, server } = await withAgent({ "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: "unpaid" }] });
  const inner = server.fetch;
  const fetch = async (url, init = {}) => (new URL(url).pathname === "/api/stream" ? new Response(SSE, { headers: { "content-type": "text/event-stream" } }) : inner(url, init));
  const io = capture();
  const state = join(mkdtempSync(join(tmpdir(), "ws-cli-")), "watch.json");
  assert.equal(await run(["watch", "--once", "--state", state, "--type", "vulnerability.exploited,vulnerability.published"], { fetch, env, sleep: async () => assert.fail("no waiting"), ...io }), 0);
  assert.ok(!server.calls.some((c) => c.path === "/api/agent/checkout" || c.path === "/api/agent/connect"), "no payment link or code");
  assert.match(io.lines.err.join("\n"), /No plan needed: vulnerability alerts are always free\. For every other event, ws upgrade .* or ws connect/);
  assert.deepEqual(io.lines.out, ['{"id":"evt_5","type":"company.registered"}']);
});

test("watch at a terminal: orange labels, whole links clickable, and Enter opens the payment page (c, the connect page)", async () => {
  const { env, server } = await withAgent({
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: "unpaid" }],
    "POST /api/agent/checkout": () => [200, { url: "https://checkout.stripe.com/c/pay/cs_test_4" }],
    "POST /api/agent/connect": CONNECT,
  });
  const { PassThrough } = await import("node:stream");
  const stdin = new PassThrough();
  const opened = [];
  const spawn = (command, args) => (opened.push(args.at(-1)), { on() {}, unref() {} });
  const stop = new AbortController();
  const io = capture();
  let waits = 0;
  const sleep = async () => {
    if (++waits === 1) stdin.write("\n");
    else if (waits === 2) stdin.write("c\n");
    else stop.abort();
    await new Promise((r) => setImmediate(r));
  };
  const ctx = { fetch: server.fetch, env: { ...env, COLORTERM: "truecolor" }, signal: stop.signal, sleep, spawn, platform: "darwin", tty: { err: true }, stdin, ...io };
  assert.equal(await run(["watch"], ctx), 1);
  const said = io.lines.err.join("\n");
  assert.match(said, /\x1b\[1;38;2;255;106;51mPay {6}\x1b\[0m/, "the label in WorldSignals' orange");
  assert.match(said, /\x1b\]8;;https:\/\/checkout\.stripe\.com\/c\/pay\/cs_test_4\x1b\\/, "the payment link clickable as a whole");
  assert.match(said, /enter \x1b\[1mABCD-EFGH\x1b\[22m/);
  assert.match(said, /Press Enter to open the payment page, or c and Enter to connect instead\./);
  assert.deepEqual(opened, ["https://checkout.stripe.com/c/pay/cs_test_4", "https://worldsignals.dev/link?code=ABCD-EFGH"]);
  assert.equal(stdin.isPaused(), true, "the terminal is let go once it stops waiting");
  // NO_COLOR, or no terminal for input: plain, and nothing to press.
  const plain = capture();
  const stop2 = new AbortController();
  await run(["watch"], { ...ctx, env: { ...env, NO_COLOR: "1" }, stdin: null, signal: stop2.signal, sleep: async () => stop2.abort(), ...plain });
  assert.doesNotMatch(plain.lines.err.join("\n"), /\x1b|Press Enter/);
});

test("watch --no-wait prints both ways on stdout and exits 0", async () => {
  const { env, server } = await withAgent({
    "GET /api/agent/me": () => [402, { error: "Payment required." }],
    "POST /api/agent/checkout": () => [200, { url: "https://checkout.stripe.com/c/pay/cs_test_3" }],
    "POST /api/agent/connect": CONNECT,
  });
  const io = capture();
  assert.equal(await run(["watch", "--no-wait"], { fetch: server.fetch, env, sleep: async () => assert.fail("no wait"), ...io }), 0);
  const text = io.lines.out.join("\n");
  assert.match(text, /cs_test_3/);
  assert.match(text, /enter ABCD-EFGH/);
  assert.match(io.lines.out.at(-1), /run the same command again/);
  assert.ok(!server.calls.some((c) => c.path === "/api/stream"));
});

// --json, for agents: the same answers as one object per line on stdout, the API's field names, never styled.
const UNPAID = {
  "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: "unpaid" }],
  "POST /api/agent/checkout": () => [200, { url: "https://checkout.stripe.com/c/pay/cs_test_5" }],
  "POST /api/agent/connect": CONNECT,
};

test("watch --no-wait --json prints both ways as one JSON object on stdout, and nothing else there", async () => {
  const { env, server } = await withAgent(UNPAID);
  const io = capture();
  // A terminal on both streams, and colour asked for: JSON is never styled.
  const ctx = { fetch: server.fetch, env: { ...env, COLORTERM: "truecolor" }, tty: { out: true, err: true }, sleep: async () => assert.fail("no wait"), ...io };
  assert.equal(await run(["watch", "--no-wait", "--json", "--plan", "team", "--yearly"], ctx), 0);
  assert.equal(io.lines.out.length, 1, "one line");
  assert.doesNotMatch(io.lines.out[0], /\x1b/);
  const answer = JSON.parse(io.lines.out[0]);
  const { expires_at, ...connect } = answer.connect;
  assert.deepEqual({ ...answer, connect }, {
    status: "unpaid",
    agent_id: "agt_1",
    pay: { url: "https://checkout.stripe.com/c/pay/cs_test_5", plan: "team", billing: "yearly", test_mode: false },
    connect: { user_code: "ABCD-EFGH", verification_uri: "https://worldsignals.dev/link", verification_uri_complete: "https://worldsignals.dev/link?code=ABCD-EFGH" },
    next: "Run the same command again once the agent is paid for or connected: it then starts watching.",
  });
  assert.ok(Date.parse(expires_at) > Date.now());
  assert.equal(answer.connect.device_code, undefined, "the device code stays in the key file");
  assert.deepEqual(io.lines.err, []);
  assert.ok(!server.calls.some((c) => c.path === "/api/stream"));
  // A way that failed is null, and why goes to stderr.
  const half = await withAgent({ ...UNPAID, "POST /api/agent/checkout": () => [500, { error: "Stripe is down." }] });
  const io2 = capture();
  assert.equal(await run(["watch", "--no-wait", "--json"], { fetch: half.server.fetch, env: half.env, ...io2 }), 0);
  assert.equal(JSON.parse(io2.lines.out[0]).pay, null);
  assert.equal(JSON.parse(io2.lines.out[0]).connect.user_code, "ABCD-EFGH");
  assert.match(io2.lines.err[0], /^No payment link \(500\): Stripe is down\.$/);
});

test("watch --json while waiting: the object is a line of its own on stderr, and stdout is the events only", async () => {
  let mes = 0;
  const env = agentEnv();
  const server = await watchServer({ ...INIT, ...UNPAID, "GET /api/agent/me": () => (++mes >= 2 ? [200, { agent_id: "agt_1", status: "connected" }] : [200, { agent_id: "agt_1", status: "unpaid" }]) });
  assert.equal(await run(["signup"], { fetch: server.fetch, env, ...capture() }), 0);
  const io = capture();
  const state = join(mkdtempSync(join(tmpdir(), "ws-cli-")), "watch.json");
  const ctx = { fetch: server.fetch, env, tty: { out: true, err: true }, stdin: null, sleep: async () => {}, ...io };
  assert.equal(await run(["watch", "--json", "--once", "--state", state], ctx), 0);
  const objects = io.lines.err.filter((l) => l.startsWith("{"));
  assert.equal(objects.length, 1);
  const answer = JSON.parse(objects[0]);
  assert.equal(answer.pay.url, "https://checkout.stripe.com/c/pay/cs_test_5");
  assert.equal(answer.connect.user_code, "ABCD-EFGH");
  assert.match(answer.next, /^Waiting for the payment or the approval/);
  assert.doesNotMatch(io.lines.err.join("\n"), /\x1b|Press Enter|Either way works/);
  assert.deepEqual(io.lines.out, ['{"id":"evt_5","type":"company.registered"}']);
});

test("upgrade --json and connect --json answer one object; with --wait, a second line once done; errors stay on stderr", async () => {
  let paid = false;
  const { env, server } = await withAgent({
    ...UNPAID,
    "GET /api/agent/me": () => [200, { agent_id: "agt_1", status: paid ? "paid" : "unpaid", plan: paid ? "developer" : null }],
    "POST /api/agent/checkout": () => [200, { url: "https://checkout.stripe.com/c/pay/cs_test_6", test_mode: true }],
  });
  const io = capture();
  assert.equal(await run(["upgrade", "--json", "--no-open"], { fetch: server.fetch, env, tty: { out: true }, ...io }), 0);
  assert.equal(io.lines.out.length, 1);
  assert.deepEqual(JSON.parse(io.lines.out[0]), {
    agent_id: "agt_1",
    pay: { url: "https://checkout.stripe.com/c/pay/cs_test_6", plan: "developer", billing: "monthly", test_mode: true },
    next: "Once it's paid, ws status --json shows the plan.",
  });
  const waited = capture();
  assert.equal(await run(["upgrade", "--json", "--wait", "--no-open"], { fetch: server.fetch, env, sleep: async () => void (paid = true), ...waited }), 0);
  assert.equal(waited.lines.out.length, 2);
  assert.equal(JSON.parse(waited.lines.out[0]).pay.url, "https://checkout.stripe.com/c/pay/cs_test_6");
  assert.equal(JSON.parse(waited.lines.out[1]).status, "paid");

  const code = capture();
  assert.equal(await run(["connect", "--no-wait", "--json"], { fetch: server.fetch, env, tty: { out: true }, sleep: async () => assert.fail("no wait"), ...code }), 0);
  assert.equal(code.lines.out.length, 1);
  assert.doesNotMatch(code.lines.out[0], /\x1b/);
  const answer = JSON.parse(code.lines.out[0]);
  assert.equal(answer.agent_id, "agt_1");
  assert.equal(answer.connect.verification_uri_complete, "https://worldsignals.dev/link?code=ABCD-EFGH");
  assert.match(answer.next, /^Run ws connect --json again/);
  // status --json carries the code still waiting here.
  paid = false;
  const status = capture();
  assert.equal(await run(["status", "--json"], { fetch: server.fetch, env, ...status }), 0);
  assert.equal(JSON.parse(status.lines.out[0]).connect.user_code, "ABCD-EFGH");

  const already = await withAgent({ "POST /api/agent/checkout": () => [409, { error: "This agent is already paid for." }] });
  const refused = capture();
  assert.equal(await run(["upgrade", "--json", "--no-open"], { fetch: already.server.fetch, env: already.env, ...refused }), 1);
  assert.deepEqual(refused.lines.out, [], "nothing on stdout");
  assert.match(refused.lines.err[0], /already paid for/);
});

test("signup --json answers the new agent and what to run next", async () => {
  const io = capture();
  const env = agentEnv();
  assert.equal(await run(["signup", "--json", "--name", "My agent"], { ...(await agentServer(INIT)), env, ...io }), 0);
  assert.deepEqual(JSON.parse(io.lines.out[0]), {
    status: "unpaid",
    agent_id: "agt_1",
    name: "Claude Code",
    key_file: agentPath(env),
    next: "Either ws upgrade --json for a payment link, or ws connect --no-wait --json for a code the person you work for approves.",
  });
  assert.equal(io.lines.out.length, 1);
});

test("watch --no-signup, or an access key, keeps the old behaviour: no signup", async () => {
  const io = capture();
  assert.equal(await run(["watch", "--no-signup"], { fetch: () => assert.fail("no request"), env: agentEnv(), ...io }), 2);
  assert.match(io.lines.err[0], /needs an agent key/);
  const calls = [];
  const fetch = async (url, init) => (calls.push(url), new Response(SSE, { headers: { "content-type": "text/event-stream" } }));
  const state = join(mkdtempSync(join(tmpdir(), "ws-cli-")), "watch.json");
  assert.equal(await run(["watch", "--once", "--state", state], { fetch, env: { ...agentEnv(), WS_KEY: "wsk_1.a" }, ...capture() }), 0);
  assert.deepEqual(calls.map((u) => new URL(u).pathname), ["/api/stream"]);
});

test("two requests signed in the same millisecond still get different timestamps and signatures", () => {
  const { privateKey } = newKeyPair();
  const a = agentHeaders("GET", "https://worldsignals.dev/api/events", "", privateKey, "agt_1", signingTime(1761480000000));
  const b = agentHeaders("GET", "https://worldsignals.dev/api/events", "", privateKey, "agt_1", signingTime(1761480000000));
  assert.match(a["x-ws-timestamp"], /^\d{10}\.\d{3}$/);
  assert.notEqual(a["x-ws-timestamp"], b["x-ws-timestamp"]);
  assert.notEqual(a["x-ws-signature"], b["x-ws-signature"]);
});

test("signup and watch replace the key of an agent the server deleted, without --force", async () => {
  const GONE = [401, { error: "No agent account agt_1.", reason: "agent" }];
  const env = agentEnv();
  let next = 1;
  const server = await watchServer({
    "POST /api/agent/init": () => [200, { agent_id: `agt_${next++}`, status: "unpaid", name: "x" }],
    "GET /api/agent/me": ({ agentId }) => (agentId === "agt_1" ? GONE : agentId === "agt_2" ? GONE : [200, { agent_id: agentId, status: "paid", plan: "developer" }]),
  });
  assert.equal(await run(["signup"], { fetch: server.fetch, env, ...capture() }), 0);
  const io = capture();
  assert.equal(await run(["signup"], { fetch: server.fetch, env, ...io }), 0);
  assert.match(io.lines.err[0], /agt_1 no longer exists .*: making a new one with a new key\.$/);
  assert.ok(!io.lines.err.some((l) => /^Warning: replacing/.test(l)));
  const second = readAgent(env, "https://ws.test");
  assert.equal(second.agent_id, "agt_2");
  const inits = server.calls.filter((c) => c.path === "/api/agent/init");
  assert.notEqual(inits[0].body.public_key, inits[1].body.public_key, "a new key, not the deleted agent's");

  const watched = capture();
  const state = join(mkdtempSync(join(tmpdir(), "ws-cli-")), "watch.json");
  assert.equal(await run(["watch", "--once", "--state", state], { fetch: server.fetch, env, sleep: async () => {}, ...watched }), 0);
  assert.match(watched.lines.err[0], /agt_2 no longer exists .*: making a new one, as ws signup would\.$/);
  assert.equal(readAgent(env, "https://ws.test").agent_id, "agt_3");
  assert.equal(server.calls.at(-1).path, "/api/stream");
});

test("a command run by a deleted agent says so and points to signup", async () => {
  const { env, server } = await withAgent({ "GET /api/events": () => [401, { error: "No agent account agt_1.", reason: "agent" }] });
  const io = capture();
  assert.equal(await run(["events"], { fetch: server.fetch, env, ...io }), 1);
  assert.match(io.lines.err.join("\n"), /agent account agt_1 no longer exists.*Run ws signup for a new account; it makes a new key\./);
});

test("watch waits as long as a 429 asks, says why, and connects again", async () => {
  let calls = 0;
  const fetch = async () =>
    ++calls === 1
      ? new Response(JSON.stringify({ error: "This account already has its live connection open, the most the Free plan allows at once.", reason: "connections" }), { status: 429, headers: { "retry-after": "1" } })
      : new Response(SSE, { headers: { "content-type": "text/event-stream" } });
  const io = capture();
  const state = join(mkdtempSync(join(tmpdir(), "ws-cli-")), "watch.json");
  const started = Date.now();
  assert.equal(await run(["watch", "--once", "--state", state], { fetch, env: { ...agentEnv(), WS_KEY: "wsk_1.a" }, ...io }), 0);
  assert.equal(calls, 2);
  assert.ok(Date.now() - started >= 900, "waited the second it was asked to");
  assert.match(io.lines.err[0], /already has its live connection open.*Trying again in 1 s\.$/);
  assert.deepEqual(io.lines.out, ['{"id":"evt_5","type":"company.registered"}']);
});

// ws request and ws feedback: anyone may send them. With an access key they come from its account, else signed with
// the agent key if there is one, else anonymous; always with X-WS-Client: cli.
const REQUEST_ANSWER = {
  id: "req_1",
  status: "recorded",
  asked_by: 3,
  closest: [
    { type: "company.registered", label: "New companies", collected_in: ["PT", "ES", "FR"], missing: ["MT"] },
    { type: "company.insolvency", label: "Insolvencies", collected_in: ["MT"], missing: [] },
  ],
  message: "We collect what's asked for most first.",
};

/** A fake server that answers every request with `status` and `body`, and `headers`. */
function answering(status, body, headers = {}) {
  const calls = [];
  const fetch = async (url, init = {}) => (calls.push({ url, init }), new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } }));
  return { fetch, calls };
}

test("request sends what, the countries uppercased, the use and the source, anonymously, and prints the answer", async () => {
  const server = answering(201, REQUEST_ANSWER);
  const io = capture();
  const args = ["request", "company registrations in Malta", "--countries", "mt, pt", "--use", "supplier checks", "--source", "https://mbr.mt/register"];
  assert.equal(await run(args, { fetch: server.fetch, env: agentEnv(), ...io }), 0);
  const { url, init } = server.calls[0];
  assert.equal(url, "https://ws.test/api/requests");
  assert.equal(init.method, "POST");
  assert.deepEqual(JSON.parse(init.body), { what: "company registrations in Malta", countries: ["MT", "PT"], use: "supplier checks", source_url: "https://mbr.mt/register" });
  assert.equal(init.headers["x-ws-client"], "cli");
  assert.equal(init.headers["content-type"], "application/json");
  assert.equal(init.headers.authorization, undefined, "anonymous: no access key");
  assert.equal(init.headers["x-ws-agent"], undefined, "anonymous: no agent key");
  assert.equal(init.headers["x-ws-signature"], undefined);
  assert.deepEqual(io.lines.out, [
    "Recorded: company registrations in Malta.",
    "3 people asked for this.",
    "Closest collected today:",
    "  New companies (company.registered): in PT, ES, FR; not yet in MT",
    "  Insolvencies (company.insolvency): in MT",
    "We collect what's asked for most first.",
  ]);
  assert.deepEqual(io.lines.err, []);
  // Only what was given; one person; nothing close.
  const one = answering(201, { ...REQUEST_ANSWER, asked_by: 1, closest: [], message: "" });
  const io2 = capture();
  assert.equal(await run(["request", "ship", "arrivals", "in", "Sines."], { fetch: one.fetch, env: agentEnv(), ...io2 }), 0);
  assert.deepEqual(JSON.parse(one.calls[0].init.body), { what: "ship arrivals in Sines." });
  assert.deepEqual(io2.lines.out, ["Recorded: ship arrivals in Sines.", "1 person asked for this."]);
});

test("request and feedback send an access key when given, else sign with the agent key", async () => {
  const keyed = answering(201, REQUEST_ANSWER);
  assert.equal(await run(["request", "x"], { fetch: keyed.fetch, env: { ...agentEnv(), WS_KEY: "wsk_1.a" }, ...capture() }), 0);
  assert.equal(await run(["feedback", "y", "--key", "wsk_2.b"], { fetch: keyed.fetch, env: agentEnv(), ...capture() }), 0);
  assert.deepEqual(keyed.calls.map((c) => [c.init.headers.authorization, c.init.headers["x-ws-agent"], c.init.headers["x-ws-client"]]), [
    ["Bearer wsk_1.a", undefined, "cli"],
    ["Bearer wsk_2.b", undefined, "cli"],
  ]);
  const { env, server } = await withAgent({ "POST /api/requests": () => [201, REQUEST_ANSWER], "POST /api/feedback": () => [201, { id: "fb_1", status: "received", message: "Thanks." }] });
  assert.equal(await run(["request", "x", "--countries", "pt"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.equal(await run(["feedback", "y"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.deepEqual(server.calls.map((c) => [c.method, c.path, c.agentId, c.signed, c.headers.authorization, c.headers["x-ws-client"]]), [
    ["POST", "/api/requests", "agt_1", true, undefined, "cli"],
    ["POST", "/api/feedback", "agt_1", true, undefined, "cli"],
  ]);
  // A refused signature says so, as for the other commands.
  const io = capture();
  assert.equal(await run(["request", "x"], { fetch: async () => new Response(JSON.stringify({ error: "Bad signature." }), { status: 401 }), env, ...io }), 1);
  assert.match(io.lines.err[0], /didn't accept this agent's signature \(Bad signature\.\)/);
});

test("request --json prints the answer as is, one line, never styled; without it, styled only at a terminal", async () => {
  const io = capture();
  const tty = { out: true, err: true };
  assert.equal(await run(["request", "x", "--json"], { ...answering(201, REQUEST_ANSWER), env: { ...agentEnv(), COLORTERM: "truecolor" }, tty, ...io }), 0);
  assert.equal(io.lines.out.length, 1);
  assert.doesNotMatch(io.lines.out[0], /\x1b/);
  assert.deepEqual(JSON.parse(io.lines.out[0]), REQUEST_ANSWER);
  const styled = capture();
  assert.equal(await run(["request", "x"], { ...answering(201, REQUEST_ANSWER), env: { ...agentEnv(), COLORTERM: "truecolor" }, tty, ...styled }), 0);
  assert.match(styled.lines.out[0], /^\x1b\[1;38;2;255;106;51mRecorded:\x1b\[0m x\.$/);
  assert.match(styled.lines.out[3], /\x1b\[1mNew companies\x1b\[22m \(company\.registered\)/);
  const plain = capture();
  assert.equal(await run(["request", "x"], { ...answering(201, REQUEST_ANSWER), env: { ...agentEnv(), NO_COLOR: "1" }, tty, ...plain }), 0);
  assert.doesNotMatch(plain.lines.out.join("\n"), /\x1b/);
});

test("request says the server's error for a 400, and when to try again for a 429, on stderr with exit 1", async () => {
  const bad = capture();
  assert.equal(await run(["request", "x", "--countries", "UK"], { ...answering(400, { error: "Not ISO country codes we know: UK (the United Kingdom is GB)." }), env: agentEnv(), ...bad }), 1);
  assert.deepEqual(bad.lines.out, []);
  assert.deepEqual(bad.lines.err, ["ws request: Not ISO country codes we know: UK (the United Kingdom is GB)."]);
  const busy = capture();
  assert.equal(await run(["request", "x", "--json"], { ...answering(429, { error: "Ten requests an hour from one network." }, { "retry-after": "30" }), env: agentEnv(), ...busy }), 1);
  assert.deepEqual(busy.lines.out, [], "nothing on stdout, even with --json");
  assert.deepEqual(busy.lines.err, ["ws request: Ten requests an hour from one network. Try again in 30 seconds."]);
  const fb = capture();
  assert.equal(await run(["feedback", "y"], { ...answering(429, { error: "Too many." }, { "retry-after": "600" }), env: agentEnv(), ...fb }), 1);
  assert.deepEqual(fb.lines.err, ["ws feedback: Too many. Try again in 10 minutes."]);
  const down = capture();
  assert.equal(await run(["request", "x"], { fetch: async () => { throw new Error("getaddrinfo ENOTFOUND"); }, env: agentEnv(), ...down }), 1);
  assert.match(down.lines.err[0], /^Couldn't reach WorldSignals \(getaddrinfo ENOTFOUND\)/);
});

test("retryWhen reads Retry-After as seconds or as a date", () => {
  assert.equal(retryWhen("1"), "Try again in 1 second.");
  assert.equal(retryWhen("90"), "Try again in 90 seconds.");
  assert.equal(retryWhen("3600"), "Try again in 60 minutes.");
  assert.equal(retryWhen("36000"), "Try again in 10 hours.");
  const now = Date.parse("2026-10-27T12:00:00Z");
  assert.equal(retryWhen("Tue, 27 Oct 2026 12:05:00 GMT", now), "Try again in 5 minutes.");
  assert.equal(retryWhen(null), "Try again later.");
  assert.equal(retryWhen("soon"), "Try again later.");
});

test("request checks what and --source before sending anything", async () => {
  const none = () => assert.fail("no request");
  const empty = capture();
  assert.equal(await run(["request"], { fetch: none, env: agentEnv(), ...empty }), 2);
  assert.match(empty.lines.err[0], /^ws request needs what you'd like collected, e\.g\. ws request "/);
  assert.equal(await run(["request", "  "], { fetch: none, env: agentEnv(), ...capture() }), 2);
  for (const source of ["http://mbr.mt/register", "mbr.mt", "https://", ""]) {
    const io = capture();
    assert.equal(await run(["request", "x", "--source", source], { fetch: none, env: agentEnv(), ...io }), 2, source);
    assert.match(io.lines.err[0], /^--source is the https:\/\/ link/);
  }
});

test("feedback sends the kind (problem by default), the message and the CLI's version, and prints the answer", async () => {
  const answer = { id: "fb_1", status: "received", message: "Thanks: we read every one." };
  const server = answering(201, answer);
  const io = capture();
  assert.equal(await run(["feedback", "watch stops after the laptop sleeps"], { fetch: server.fetch, env: agentEnv(), ...io }), 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/feedback");
  assert.equal(server.calls[0].init.method, "POST");
  assert.equal(server.calls[0].init.headers["x-ws-client"], "cli");
  assert.equal(server.calls[0].init.headers.authorization, undefined);
  assert.deepEqual(JSON.parse(server.calls[0].init.body), { kind: "problem", message: "watch stops after the laptop sleeps", context: { client: `cli ${VERSION}` } });
  assert.deepEqual(io.lines.out, ["Sent (fb_1). Thanks: we read every one."]);
  for (const kind of ["bug", "idea", "IDEA"]) {
    assert.equal(await run(["feedback", "z", "--kind", kind], { fetch: server.fetch, env: agentEnv(), ...capture() }), 0);
    assert.equal(JSON.parse(server.calls.at(-1).init.body).kind, kind.toLowerCase());
  }
  const json = capture();
  assert.equal(await run(["feedback", "z", "--json"], { fetch: server.fetch, env: agentEnv(), tty: { out: true }, ...json }), 0);
  assert.deepEqual(json.lines.out.map((l) => JSON.parse(l)), [answer]);
  // Checked before anything is sent.
  const none = () => assert.fail("no request");
  const wrong = capture();
  assert.equal(await run(["feedback", "z", "--kind", "praise"], { fetch: none, env: agentEnv(), ...wrong }), 2);
  assert.match(wrong.lines.err[0], /^--kind is bug, problem or idea/);
  const empty = capture();
  assert.equal(await run(["feedback", "--kind", "bug"], { fetch: none, env: agentEnv(), ...empty }), 2);
  assert.match(empty.lines.err[0], /^ws feedback needs a message/);
});

// Setting up a stream from the command line alone: matches with stream set, a preview, the event types and their
// fields, an estimate, and any other API call with ws api.
test("parseMatch reads <type>[@<codes>]:<condition>[;<condition>…], and says the form when it can't", async () => {
  const { parseMatch, matchText } = await import("../bin/ws.mjs");
  assert.deepEqual(parseMatch("procurement.tender_published:data.cpv^=72"), { type: "procurement.tender_published", where: ["data.cpv^=72"] });
  assert.deepEqual(parseMatch(" company.registered@gb, ie : subject.name*=bakery|pastry; place.near=51.5,-0.12,20 "), {
    type: "company.registered",
    countries: ["GB", "IE"],
    where: ["subject.name*=bakery|pastry", "place.near=51.5,-0.12,20"],
  });
  // Group names and all pass through as given, for the server to read.
  assert.deepEqual(parseMatch("recall.issued@eu,XK:title*=toy").countries, ["EU", "XK"]);
  // A colon in a condition stays in it.
  assert.deepEqual(parseMatch("company.filing_published:data.filed_at>=2026-10-01T00:00").where, ["data.filed_at>=2026-10-01T00:00"]);
  for (const bad of ["data.cpv^=72", "place.near=41.1,-8.6,10", ":x=1", "title*=a:b", "company.registered@:x=1", "a.b@PT@ES:x=1", "company registered:x=1"]) assert.match(parseMatch(bad), /^--match is <type>:<condition>/, bad);
  assert.match(parseMatch("company.registered:"), /has no condition after the colon/);
  assert.match(parseMatch("company.registered: ; "), /has no condition/);
  assert.equal(matchText({ type: "a.b", where: ["x=1", "y*=z"] }), "a.b:x=1;y*=z");
  assert.equal(matchText({ type: "a.b", countries: ["PT", "ES"], where: ["x=1"] }), "a.b@PT,ES:x=1");
  assert.equal(matchText({ type: "a.b", countries: [], where: ["x=1"] }), "a.b@all:x=1");
});

test("matchesOption: --matches (JSON, @file or -) then each --match; none clears; nothing given is undefined", async () => {
  const { matchesOption } = await import("../bin/ws.mjs");
  const { writeFileSync } = await import("node:fs");
  assert.equal(await matchesOption({}), undefined);
  assert.deepEqual(await matchesOption({ match: ["none"] }), []);
  assert.deepEqual(await matchesOption({ matches: "none" }), []);
  assert.deepEqual(await matchesOption({ matches: "[]" }), []);
  const one = { type: "vulnerability.published", where: ["data.cvss.base_score>=9"] };
  assert.deepEqual(await matchesOption({ matches: JSON.stringify([one]), match: ["company.registered:subject.name*=bakery"] }), [one, { type: "company.registered", where: ["subject.name*=bakery"] }]);
  const file = join(mkdtempSync(join(tmpdir(), "ws-matches-")), "m.json");
  // What ws stream --json prints is read as its matches.
  writeFileSync(file, JSON.stringify({ eventTypes: [], matches: [one] }));
  assert.deepEqual(await matchesOption({ matches: `@${file}` }), [one]);
  assert.deepEqual(await matchesOption({ matches: "-" }, async () => JSON.stringify([one])), [one]);
  assert.match(await matchesOption({ matches: "{nope" }), /^--matches is a JSON list/);
  assert.match(await matchesOption({ matches: '{"type": "x"}' }), /^--matches is a JSON list/);
  assert.match(await matchesOption({ matches: "@/no/such/file.json" }), /^Couldn't read --matches @\/no\/such\/file\.json/);
  assert.match(await matchesOption({ match: ["none", "a.b:x=1"] }), /give it alone/);
  assert.match(await matchesOption({ match: ["oops"] }), /^--match is/);
});

test("stream set --match sends the matches in the same PATCH, and ws stream shows them as --match writes them", async () => {
  const saved = { eventTypes: ["procurement.tender_published", "company.registered"], countries: ["PT"], delivery: [], speed: null, matches: [{ type: "procurement.tender_published", where: ["data.cpv^=72"] }, { type: "company.registered", countries: ["GB", "IE"], where: ["subject.name*=bakery|pastry", "title*=bread"] }] };
  const server = answering(200, saved);
  const io = capture();
  const args = ["stream", "set", "--country", "pt", "--match", "procurement.tender_published:data.cpv^=72", "--match", "company.registered@GB,IE:subject.name*=bakery|pastry;title*=bread"];
  assert.equal(await run(args, { fetch: server.fetch, env: { WS_API: "https://ws.test", WS_KEY: "wsk_1.a" }, ...io }), 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/me/stream");
  assert.equal(server.calls[0].init.method, "PATCH");
  assert.deepEqual(JSON.parse(server.calls[0].init.body), { countries: ["PT"], matches: saved.matches });
  assert.deepEqual(io.lines.out, [
    "Saved.",
    "Event types: procurement.tender_published, company.registered",
    "Countries:   PT",
    "Matches:     procurement.tender_published:data.cpv^=72",
    "             company.registered@GB,IE:subject.name*=bakery|pastry;title*=bread",
  ]);
  // --match none clears them; --matches reads a JSON list from stdin; --json carries them.
  const cleared = answering(200, { ...saved, matches: [] });
  assert.equal(await run(["stream", "set", "--match", "none"], { fetch: cleared.fetch, env: { WS_KEY: "k" }, ...capture() }), 0);
  assert.deepEqual(JSON.parse(cleared.calls[0].init.body), { matches: [] });
  const piped = capture();
  assert.equal(await run(["stream", "set", "--matches", "-", "--json"], { fetch: server.fetch, env: { WS_KEY: "k" }, readStdin: async () => JSON.stringify(saved.matches), ...piped }), 0);
  assert.deepEqual(JSON.parse(server.calls.at(-1).init.body), { matches: saved.matches });
  assert.deepEqual(JSON.parse(piped.lines.out[0]).matches, saved.matches);
  // A malformed --match is said before anything is sent.
  const bad = capture();
  assert.equal(await run(["stream", "set", "--match", "data.cpv^=72"], { fetch: () => assert.fail("no request"), env: { WS_KEY: "k" }, ...bad }), 2);
  assert.match(bad.lines.err[0], /^--match is <type>:<condition>/);
});

test("stream set says the server's sentence when the plan's matches are used up (402 with limit), and a 400's", async () => {
  const error = "The Developer plan includes 25 matches across the saved stream and webhooks, and this account uses 25. Upgrade for more at https://worldsignals.dev/pricing, or remove one.";
  const io = capture();
  const over = answering(402, { error, limit: { reached: true, kind: "matches", plan: "developer", used: 25, limit: 25, upgrade_url: "https://worldsignals.dev/pricing" } });
  assert.equal(await run(["stream", "set", "--match", "vulnerability.published:data.cvss.base_score>=9"], { fetch: over.fetch, env: { WS_KEY: "k" }, ...io }), 1);
  assert.deepEqual(io.lines.err, [`ws stream set: ${error}`]);
  assert.deepEqual(io.lines.out, []);
  // An agent with no plan still hears how to get one.
  const unpaid = capture();
  assert.equal(await run(["stream", "set", "--speed", "daily"], { ...answering(402, { error: "Payment required." }), env: { WS_KEY: "k" }, ...unpaid }), 1);
  assert.match(unpaid.lines.err[0], /isn't paid for yet/);
  const wrong = capture();
  assert.equal(await run(["stream", "set", "--match", "nope.type:x=1"], { ...answering(400, { error: 'matches[0].type "nope.type" isn\'t an event type. See /api/catalogue.' }), env: { WS_KEY: "k" }, ...wrong }), 2);
  assert.deepEqual(wrong.lines.err, ['ws stream set: matches[0].type "nope.type" isn\'t an event type. See /api/catalogue.']);
});

const PREVIEW = {
  previews: [
    {
      match: { type: "procurement.tender_published", countries: ["PT"], where: ["data.cpv^=72"] },
      matched: 37,
      of: 2000,
      since: "2026-10-21T08:00:00Z",
      examples: [
        { type: "procurement.tender_published", title: "Tender: IT services for the city of Porto", country: "PT", time: "2026-10-26T10:00:00Z" },
        { type: "procurement.tender_published", title: "Tender: software licences", country: "PT", time: "2026-10-25T09:00:00Z" },
      ],
    },
  ],
};

test("stream preview posts the matches given, or none for the saved ones, and prints each one's count and examples", async () => {
  const { env, server } = await withAgent({ "POST /api/me/stream/preview": () => [200, PREVIEW] });
  const io = capture();
  assert.equal(await run(["stream", "preview", "--match", "procurement.tender_published@PT:data.cpv^=72", "--country", "pt,es"], { fetch: server.fetch, env, ...io }), 0);
  assert.deepEqual(server.calls.map((c) => [c.method, c.path, c.agentId, c.signed]), [["POST", "/api/me/stream/preview", "agt_1", true]]);
  assert.deepEqual(server.calls[0].body, { matches: [{ type: "procurement.tender_published", countries: ["PT"], where: ["data.cpv^=72"] }], countries: ["PT", "ES"] });
  assert.deepEqual(io.lines.out, [
    "procurement.tender_published@PT:data.cpv^=72",
    "  37 of the latest 2,000 procurement.tender_published events, since 2026-10-21 08:00 UTC",
    "    2026-10-26  PT  Tender: IT services for the city of Porto",
    "    2026-10-25  PT  Tender: software licences",
    "The examples count toward this month's events, as events read do.",
  ]);
  // No --match: an empty body, for the saved matches.
  assert.equal(await run(["stream", "preview", "--json"], { fetch: server.fetch, env, ...capture() }), 0);
  assert.deepEqual(server.calls[1].body, {});
  const none = capture();
  assert.equal(await run(["stream", "preview", "--match", "none"], { fetch: () => assert.fail("no request"), env, ...none }), 2);
  assert.match(none.lines.err[0], /nothing to preview/);
  const old = capture();
  assert.equal(await run(["stream", "preview"], { ...answering(400, { error: "Send matches to preview." }), env: { WS_KEY: "k" }, ...old }), 2);
  assert.match(old.lines.err[0], /^ws stream preview: Send matches to preview\. \(No saved matches\? Give some with --match/);
});

const CATALOGUE = {
  families: [
    {
      id: "company",
      label: "Companies",
      types: [
        { id: "company.registered", label: "New company registered", visibility: "public", connectors: [{ label: "UK", countries: ["GB"] }, { label: "ES", countries: ["ES"] }, { label: "More", countries: ["FR", "NO", "FI", "CH", "IE", "LV"] }] },
        { id: "company.officer_appointed", label: "Company officer appointed", visibility: "public", connectors: [] },
      ],
    },
    {
      id: "tech",
      label: "Tech",
      types: [
        { id: "vulnerability.published", label: "Vulnerability published", visibility: "public", connectors: [{ label: "NVD", countries: ["GB", "ES", "FR", "NO", "FI", "CH", "IE", "LV", "PT", "SE"] }] },
        { id: "domain.dropped", label: "Domain dropped", visibility: "public", connectors: [{ label: "SE", countries: ["SE"] }, { label: "gTLD", countries: ["XX"] }] },
      ],
    },
  ],
  countries: ["GB", "ES", "FR", "NO", "FI", "CH", "IE", "LV", "PT", "SE"],
  worldwide: "WW",
  alwaysFree: ["vulnerability.published"],
};

test("types lists the event types by family with where each is collected, needing no key", async () => {
  const server = answering(200, CATALOGUE);
  const io = capture();
  assert.equal(await run(["types"], { fetch: server.fetch, env: { WS_API: "https://ws.test", XDG_CONFIG_HOME: CONFIG }, ...io }), 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/catalogue");
  assert.equal(server.calls[0].init.headers.authorization, undefined);
  assert.equal(server.calls[0].init.headers["x-ws-signature"], undefined);
  assert.deepEqual(io.lines.out, [
    "Companies (company)",
    "  company.registered         New company registered     GB, ES, FR, NO, FI, CH +2 more",
    "  company.officer_appointed  Company officer appointed  planned",
    "Tech (tech)",
    "  vulnerability.published    Vulnerability published    any country, or worldwide (XX); always free",
    "  domain.dropped             Domain dropped             SE, worldwide (XX)",
    "Collected: 3 of 4 types. ws fields <type> lists the fields a condition can test.",
  ]);
  const json = capture();
  assert.equal(await run(["types", "--family", "tech", "--json"], { fetch: server.fetch, env: {}, ...json }), 0);
  assert.deepEqual(json.lines.out.map((l) => JSON.parse(l)), [
    { type: "vulnerability.published", label: "Vulnerability published", family: "tech", visibility: "public", collected: true, countries: [], every_country: true, worldwide: true, always_free: true },
    { type: "domain.dropped", label: "Domain dropped", family: "tech", visibility: "public", collected: true, countries: ["SE"], every_country: false, worldwide: true, always_free: false },
  ]);
  const wrong = capture();
  assert.equal(await run(["types", "--family", "tech,space"], { fetch: server.fetch, env: {}, ...wrong }), 2);
  assert.deepEqual(wrong.lines.err, ["No family space. The families: company, tech."]);
});

const FIELDS = {
  type: "procurement.tender_published",
  fields: [
    { path: "data.tender.main_procurement_category", label: "Tender › Main procurement category", kind: "enum", values: ["goods", "services", "works"] },
    { path: "data.tender.value.eur", label: "Tender › Value › in EUR at today's rate", kind: "number" },
    { path: "data.cpv", label: "CPV", kind: "text", list: true },
  ],
};

test("fields lists a type's fields for conditions: path, kind and an enum's values; an unknown type is said", async () => {
  const server = answering(200, FIELDS);
  const io = capture();
  assert.equal(await run(["fields", "procurement.tender_published"], { fetch: server.fetch, env: { WS_API: "https://ws.test" }, ...io }), 0);
  assert.equal(server.calls[0].url, "https://ws.test/api/fields?type=procurement.tender_published");
  assert.equal(server.calls[0].init.headers.authorization, undefined);
  assert.deepEqual(io.lines.out, [
    "procurement.tender_published: 3 fields, for --where and --match conditions.",
    "  data.tender.main_procurement_category  enum         Tender › Main procurement category: goods|services|works",
    "  data.tender.value.eur                  number       Tender › Value › in EUR at today's rate",
    "  data.cpv                               text (list)  CPV",
    "Operators: = != > >= < <=, text *= !*= ^= $= ~= !~=, | between values. E.g. --where 'data.tender.main_procurement_category=goods'",
    "  or ws stream set --match 'procurement.tender_published:data.tender.main_procurement_category=goods'",
  ]);
  const json = capture();
  assert.equal(await run(["fields", "procurement.tender_published", "--json"], { fetch: server.fetch, env: {}, ...json }), 0);
  assert.deepEqual(JSON.parse(json.lines.out[0]), FIELDS);
  const unknown = capture();
  assert.equal(await run(["fields", "nope.type"], { ...answering(404, { error: "No such event type with a schema. See /api/catalogue." }), env: {}, ...unknown }), 2);
  assert.deepEqual(unknown.lines.err, ["ws fields: No such event type with a schema. See /api/catalogue. (ws types lists them.)"]);
  assert.equal(await run(["fields"], { fetch: () => assert.fail("no request"), env: {}, ...capture() }), 2);
});

const ESTIMATE = {
  since: "2026-10-20T12:00:00.000Z",
  count: 1234,
  capped: false,
  exact: true,
  always_free: 234,
  counts_toward_usage: 1000,
  locked: 0,
  allowance: { used: 1500, limit: 50000, left: 48500 },
  plan: "developer",
  window_days: 7,
  earliest: "2026-10-20T12:00:00.000Z",
  allowed: true,
};

test("estimate asks with the filters and since, signed, and prints the count, what counts, the allowance left", async () => {
  const { sinceTime } = await import("../bin/ws.mjs");
  const now = Date.parse("2026-10-27T12:00:00Z");
  assert.equal(sinceTime("7d", now), "2026-10-20T12:00:00.000Z");
  assert.equal(sinceTime("24h", now), "2026-10-26T12:00:00.000Z");
  assert.equal(sinceTime("30m", now), "2026-10-27T11:30:00.000Z");
  assert.equal(sinceTime("2026-10-01", now), "2026-10-01T00:00:00.000Z");
  assert.equal(sinceTime("last week", now), null);

  const { env, server } = await withAgent({ "GET /api/events/estimate": () => [200, { ...ESTIMATE, since: new Date(Date.now() - 7 * 86_400_000).toISOString() }] });
  const io = capture();
  const args = ["estimate", "--type", "company.registered", "--country", "pt,eu", "--since", "7d", "--where", "subject.name*=bakery", "--match", "procurement.tender_published:data.cpv^=72"];
  assert.equal(await run(args, { fetch: server.fetch, env, ...io }), 0);
  const call = server.calls[0];
  assert.deepEqual([call.method, call.path, call.agentId, call.signed], ["GET", "/api/events/estimate", "agt_1", true]);
  const q = new URL(call.url).searchParams;
  assert.ok(Math.abs(Date.parse(q.get("since")) - (Date.now() - 7 * 86_400_000)) < 60_000);
  assert.equal(q.get("types"), "company.registered,procurement.tender_published");
  assert.equal(q.get("country"), "PT,EU", "groups pass through");
  assert.equal(q.get("where"), "subject.name*=bakery");
  assert.deepEqual(JSON.parse(q.get("matches")), [{ type: "procurement.tender_published", where: ["data.cpv^=72"] }]);
  assert.match(io.lines.out[0], /^1,234 events since \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\.$/);
  assert.deepEqual(io.lines.out.slice(1), [
    "  1,000 count toward this month's events",
    "  234 always free (vulnerabilities and WorldSignals' notices)",
    "This month: 1,500 of 50,000 events used, 48,500 left (Developer plan).",
    "At this pace: about 5,289 a month, 4,286 of them counting toward usage.",
    "Estimating uses none of the monthly events.",
  ]);
  // --json is the answer as is; the free plan says what would arrive locked, and what it can't read back.
  const json = capture();
  assert.equal(await run(["estimate", "--json"], { ...answering(200, ESTIMATE), env: { WS_KEY: "k" }, ...json }), 0);
  assert.deepEqual(JSON.parse(json.lines.out[0]), ESTIMATE);
  const free = capture();
  const freeAnswer = { ...ESTIMATE, exact: false, plan: "free", locked: 200, allowance: { used: 1700, limit: 2500, left: 800 }, allowed: false, error: "The free plan reads the last 24 hours." };
  assert.equal(await run(["estimate", "--where", "title*=x"], { ...answering(200, freeAnswer), env: { WS_KEY: "k" }, ...free }), 0);
  assert.match(free.lines.out[0], /^Up to 1,234 events since/);
  assert.ok(free.lines.out.includes("  200 would arrive locked, past the free plan's events this month"));
  assert.ok(free.lines.out.includes("This month: 1,700 of 2,500 events used, 800 left (Free plan)."));
  assert.deepEqual(free.lines.err, ["Note: The free plan reads the last 24 hours."]);
  const unlimited = capture();
  assert.equal(await run(["estimate"], { ...answering(200, { ...ESTIMATE, plan: "business", allowance: { used: 9, limit: null, left: null } }), env: { WS_KEY: "k" }, ...unlimited }), 0);
  assert.ok(unlimited.lines.out.includes("This month: 9 events used; the Business plan has no monthly limit."));
  // Checked before anything is sent: --since, a malformed match, and a key.
  const none = () => assert.fail("no request");
  assert.equal(await run(["estimate", "--since", "yesterday"], { fetch: none, env: { WS_KEY: "k" }, ...capture() }), 2);
  assert.equal(await run(["estimate", "--match", "x"], { fetch: none, env: { WS_KEY: "k" }, ...capture() }), 2);
  const nokey = capture();
  assert.equal(await run(["estimate"], { fetch: none, env: { XDG_CONFIG_HOME: CONFIG }, ...nokey }), 2);
  assert.match(nokey.lines.err[0], /^ws estimate needs an agent key/);
});

test("api sends any call under /api/, signed with the agent key, and prints the answer's JSON", async () => {
  const { writeFileSync } = await import("node:fs");
  const { env, server } = await withAgent({
    "GET /api/me": () => [200, { eventTypes: ["company.registered"] }],
    "PATCH /api/me/stream": ({ body }) => [200, { ...body, saved: true }],
    "POST /api/me/stream/preview": () => [402, { error: "This agent isn't paid for yet." }],
  });
  const io = capture();
  assert.equal(await run(["api", "get", "/api/me"], { fetch: server.fetch, env, ...io }), 0);
  assert.deepEqual(io.lines.out, ['{\n  "eventTypes": [\n    "company.registered"\n  ]\n}']);
  // The body as text, from a file, or from stdin; --raw prints one line.
  const file = join(mkdtempSync(join(tmpdir(), "ws-body-")), "b.json");
  writeFileSync(file, '{ "speed": "hourly" }\n');
  const raw = capture();
  assert.equal(await run(["api", "PATCH", "/api/me/stream", '{"speed": "daily"}', "--raw"], { fetch: server.fetch, env, ...raw }), 0);
  assert.equal(await run(["api", "PATCH", "api/me/stream", `@${file}`, "--raw"], { fetch: server.fetch, env, ...raw }), 0);
  assert.equal(await run(["api", "PATCH", "https://ws.test/api/me/stream", "-", "--raw"], { fetch: server.fetch, env, readStdin: async () => '{"speed":"realtime"}', ...raw }), 0);
  assert.deepEqual(raw.lines.out, ['{"speed":"daily","saved":true}', '{"speed":"hourly","saved":true}', '{"speed":"realtime","saved":true}']);
  assert.deepEqual(server.calls.map((c) => [c.method, c.path, c.agentId, c.signed, c.headers["content-type"]]), [
    ["GET", "/api/me", "agt_1", true, undefined],
    ["PATCH", "/api/me/stream", "agt_1", true, "application/json"],
    ["PATCH", "/api/me/stream", "agt_1", true, "application/json"],
    ["PATCH", "/api/me/stream", "agt_1", true, "application/json"],
  ]);
  // An answer of 400 or more: its JSON on stdout, the status and the error on stderr, exit 1.
  const refusedIo = capture();
  assert.equal(await run(["api", "POST", "/api/me/stream/preview", "{}"], { fetch: server.fetch, env, ...refusedIo }), 1);
  assert.deepEqual(JSON.parse(refusedIo.lines.out[0]), { error: "This agent isn't paid for yet." });
  assert.deepEqual(refusedIo.lines.err, ["ws api: POST /api/me/stream/preview answered 402: This agent isn't paid for yet."]);
  const busy = capture();
  assert.equal(await run(["api", "GET", "/api/events?limit=1"], { ...answering(429, { error: "Too many requests." }, { "retry-after": "20" }), env: { WS_KEY: "wsk_1.a" }, ...busy }), 1);
  assert.deepEqual(busy.lines.err, ["ws api: GET /api/events answered 429: Too many requests. Try again in 20 seconds."]);
  // An access key goes as a bearer token, the query kept.
  const keyed = answering(200, { events: [] });
  assert.equal(await run(["api", "GET", "/api/events?types=company.registered&limit=5", "--key", "wsk_2.b"], { fetch: keyed.fetch, env: { WS_API: "https://ws.test" }, ...capture() }), 0);
  assert.equal(keyed.calls[0].url, "https://ws.test/api/events?types=company.registered&limit=5");
  assert.equal(keyed.calls[0].init.headers.authorization, "Bearer wsk_2.b");
});

test("api refuses other hosts, paths outside /api/, a body on GET, and a body that isn't JSON, before sending", async () => {
  const { apiTarget } = await import("../bin/ws.mjs");
  assert.equal(apiTarget("https://ws.test", "/api/me"), "https://ws.test/api/me");
  assert.equal(apiTarget("https://ws.test", "https://ws.test/api/x?y=1"), "https://ws.test/api/x?y=1");
  const none = () => assert.fail("no request");
  const env = { WS_API: "https://ws.test", WS_KEY: "k" };
  const cases = [
    [["api", "GET", "https://evil.example/api/me"], /^ws api only sends to ws\.test: give a path such as \/api\/me, not a link to evil\.example\.$/],
    [["api", "GET", "//evil.example/api/me"], /not a link to evil\.example/],
    [["api", "GET", "http://ws.test/api/me"], /only sends to ws\.test/],
    [["api", "POST", "/mcp", "{}"], /under \/api\/ only.*the MCP server at \/mcp has its own clients/],
    [["api", "GET", "/api/../mcp"], /under \/api\/ only/],
    [["api", "GET", "/signin"], /under \/api\/ only/],
    [["api", "GET", "/api/me", "{}"], /^ws api GET sends no body/],
    [["api", "POST", "/api/feedback", "{nope"], /^The body is JSON/],
    [["api", "POST", "/api/feedback", "@/no/such.json"], /^Couldn't read @\/no\/such\.json/],
    [["api", "FETCH", "/api/me"], /^ws api is ws api <METHOD> <path>/],
    [["api", "GET"], /^ws api is ws api <METHOD> <path>/],
  ];
  for (const [args, message] of cases) {
    const io = capture();
    assert.equal(await run(args, { fetch: none, env, ...io }), 2, args.join(" "));
    assert.match(io.lines.err[0], message, args.join(" "));
  }
  // With no key at all, it still sends (public routes need none) and says how to get one on a 401.
  const io = capture();
  assert.equal(await run(["api", "GET", "/api/me"], { ...answering(401, { error: "Not signed in." }), env: { WS_API: "https://ws.test", XDG_CONFIG_HOME: CONFIG }, ...io }), 1);
  assert.equal(io.lines.err[0], "ws api: GET /api/me answered 401: Not signed in.");
  assert.match(io.lines.err[1], /^ws api needs an agent key/);
});

/** A fake events API: answers newest-first pages from `pages` in turn, recording each before and limit asked. */
function pagingServer(pages) {
  const asked = [];
  const fetch = async (url) => {
    const q = new URL(url).searchParams;
    asked.push({ before: q.get("before"), limit: q.get("limit") });
    const page = pages[Math.min(asked.length - 1, pages.length - 1)];
    return new Response(JSON.stringify({ cursor: 900, ...page }), { status: 200 });
  };
  return { fetch, asked };
}
const ev = (title) => ({ time: "2026-10-20T00:00:00Z", type: "company.registered", country: "GB", title });

test("events pages back while the answer says older events may match, and says how far it looked", async () => {
  // Two empty windows, then a match, then nothing older.
  const server = pagingServer([
    { events: [], before: 800, older: true },
    { events: [], before: 700, older: true },
    { events: [ev("Bakery Ltd")], before: 600, older: true },
    { events: [ev("Pastry Ltd")], before: null, older: false },
  ]);
  const io = capture();
  assert.equal(await run(["events", "--where", "subject.name*=bakery|pastry", "--limit", "5"], { fetch: server.fetch, env: { WS_KEY: "k" }, ...io }), 0);
  assert.deepEqual(server.asked, [
    { before: null, limit: "5" },
    { before: "800", limit: "5" },
    { before: "700", limit: "5" },
    { before: "600", limit: "4" },
  ]);
  assert.deepEqual(io.lines.out, ["2026-10-20  company.registered              GB  Bakery Ltd", "2026-10-20  company.registered              GB  Pastry Ltd", "Next: ws events --after 900"]);
  // Nothing anywhere: said only once the server has nothing older.
  const empty = capture();
  const nothing = pagingServer([{ events: [], before: 800, older: true }, { events: [], before: null, older: false }]);
  assert.equal(await run(["events", "--where", "title*=zzz"], { fetch: nothing.fetch, env: { WS_KEY: "k" }, ...empty }), 0);
  assert.equal(empty.lines.out[0], "No events match: searched back to the oldest events kept (the last 30 days).");
  // At --pages, it stops and says where to carry on.
  const capped = capture();
  const endless = pagingServer([{ events: [], before: 500, older: true }]);
  assert.equal(await run(["events", "--where", "title*=zzz", "--pages", "3"], { fetch: endless.fetch, env: { WS_KEY: "k" }, ...capped }), 0);
  assert.equal(endless.asked.length, 3);
  assert.deepEqual(capped.lines.out.slice(0, 2), [
    "No events match in the 3 windows of the newest events searched (about 15,000 events back).",
    "Older ones may: add --before 500 to look further back, or --pages <n> (up to 100) to read more at once.",
  ]);
  const json = capture();
  assert.equal(await run(["events", "--where", "title*=zzz", "--pages", "2", "--json", "--before", "1000"], { fetch: endless.fetch, env: { WS_KEY: "k" }, ...json }), 0);
  assert.equal(endless.asked[3].before, "1000");
  assert.deepEqual(json.lines.out, []);
  assert.deepEqual(json.lines.err, ["Note: older events may match too: add --before 500 to look further back."]);
  // A later page refused: what was found is still printed. Polling (--after <number>) reads one answer.
  const halfway = capture();
  let n = 0;
  const flaky = async () => (++n === 1 ? new Response(JSON.stringify({ events: [ev("A")], before: 800, older: true }), { status: 200 }) : new Response(JSON.stringify({ error: "Too many requests." }), { status: 429 }));
  assert.equal(await run(["events", "--where", "title*=a", "--limit", "2"], { fetch: flaky, env: { WS_KEY: "k" }, ...halfway }), 0);
  assert.equal(halfway.lines.out[0], "2026-10-20  company.registered              GB  A");
  assert.deepEqual(halfway.lines.err, ["Note: stopped looking further back (429: Too many requests.)."]);
  const poll = pagingServer([{ events: [], older: false, cursor: 950 }]);
  assert.equal(await run(["events", "--after", "900", "--where", "title*=a"], { fetch: poll.fetch, env: { WS_KEY: "k" }, ...capture() }), 0);
  assert.equal(poll.asked.length, 1);
  assert.equal(await run(["events", "--pages", "0"], { fetch: () => assert.fail("no request"), env: { WS_KEY: "k" }, ...capture() }), 2);
});

test("newerVersion compares semver: numbers first, then a release over its prereleases", () => {
  assert.equal(newerVersion("0.5.2", "0.5.1"), true);
  assert.equal(newerVersion("0.10.0", "0.9.9"), true);
  assert.equal(newerVersion("0.5.1", "0.5.1"), false);
  assert.equal(newerVersion("0.5.1", "0.5.1-rc.1"), true);
  assert.equal(newerVersion("0.5.1-rc.1", "0.5.1"), false);
  assert.equal(newerVersion("nonsense", "0.5.1"), false);
  assert.deepEqual(parseNoticeHeader('evt_N2; title="Deprecated %E2%80%94 after"; url="https://worldsignals.dev/docs"'), { id: "evt_N2", title: "Deprecated — after", data: { url: "https://worldsignals.dev/docs" } });
  assert.equal(parseNoticeHeader("nothing here"), null);
  // A notice's title can't move the terminal's cursor.
  assert.equal(noticeLine({ title: "Hi\u001b[2J", data: { url: "https://x.test/a" } }), "WorldSignals: Hi [2J — https://x.test/a");
});

test("watch prints WorldSignals notices on stderr only: never on stdout, never to --exec, never moving the cursor", async () => {
  const { readFileSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "ws-cli-"));
  const state = join(dir, "watch.json");
  const notice = { id: "evt_N1", type: "worldsignals.maintenance_scheduled", title: "Maintenance on Monday\u001b[2J", data: { url: "https://worldsignals.dev/status" } };
  const body = `event: ready\ndata: {"after":4,"head":5,"cli_latest":"99.0.0"}\n\nevent: notice\ndata: ${JSON.stringify(notice)}\n\nid: 5\ndata: {"id":"evt_5","type":"company.registered"}\n\n: hb\n\n`;
  const fetch = async () => new Response(body, { headers: { "content-type": "text/event-stream" } });
  const env = { WS_KEY: "wsk_test", XDG_CONFIG_HOME: dir };
  const io = capture();
  assert.equal(await run(["watch", "--once", "--state", state], { fetch, env, ...io }), 0);
  assert.deepEqual(io.lines.out, ['{"id":"evt_5","type":"company.registered"}']);
  assert.ok(io.lines.err.includes("WorldSignals: Maintenance on Monday [2J — https://worldsignals.dev/status"));
  assert.ok(io.lines.err.includes(`worldsignals 99.0.0 is out (you have ${VERSION}): npx worldsignals@latest, or npm i -g worldsignals`));
  assert.equal(JSON.parse(readFileSync(state, "utf8")).after, 5);

  // The next run (or a reconnect that sends the notice again): neither line is repeated, at most once a day.
  const again = capture();
  assert.equal(await run(["watch", "--once", "--state", state], { fetch, env, ...again }), 0);
  assert.deepEqual(again.lines.out, ['{"id":"evt_5","type":"company.registered"}']);
  assert.equal(again.lines.err.filter((l) => l.startsWith("WorldSignals:") || l.startsWith("worldsignals 99")).length, 0);

  // --exec never gets a notice: only the event.
  const spawned = [];
  const spawn = () => ({ stdin: { end: (input) => spawned.push(input), on: () => {} }, on: (ev, cb) => ev === "close" && setTimeout(() => cb(0), 0), kill: () => {} });
  assert.equal(await run(["watch", "--once", "--from", "4", "--state", join(dir, "w2.json"), "--exec", "./handle"], { fetch, env: { ...env, XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "ws-cli-")) }, spawn, ...capture() }), 0);
  assert.deepEqual(spawned, ['{"id":"evt_5","type":"company.registered"}\n']);
});

test("events says a newer CLI version once a day on stderr, from the server's header, and stays quiet under --json", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-cli-"));
  const events = [{ time: "2026-10-23T00:00:00Z", type: "company.registered", country: "ES", title: "X SL" }];
  const fetch = async () =>
    new Response(JSON.stringify({ events, cursor: 9 }), {
      headers: { "content-type": "application/json", "x-ws-cli-latest": "99.0.0", "x-ws-notice": 'evt_N2; title="Deprecated %E2%80%94 after=<time>"; url="https://worldsignals.dev/docs#api"' },
    });
  const env = { WS_KEY: "wsk_test", XDG_CONFIG_HOME: dir };
  const quiet = capture();
  assert.equal(await run(["events", "--json"], { fetch, env, ...quiet }), 0);
  assert.deepEqual(quiet.lines.err, []);

  const io = capture();
  assert.equal(await run(["events"], { fetch, env, ...io }), 0);
  assert.deepEqual(io.lines.err, [`worldsignals 99.0.0 is out (you have ${VERSION}): npx worldsignals@latest, or npm i -g worldsignals`, "WorldSignals: Deprecated — after=<time> — https://worldsignals.dev/docs#api"]);
  const later = capture();
  assert.equal(await run(["events"], { fetch, env, ...later }), 0);
  assert.deepEqual(later.lines.err, []);
  // The same version as this one: nothing to say.
  const current = async () => new Response(JSON.stringify({ events: [], cursor: 9 }), { headers: { "x-ws-cli-latest": VERSION } });
  const none = capture();
  assert.equal(await run(["events"], { fetch: current, env: { ...env, XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "ws-cli-")) }, ...none }), 0);
  assert.deepEqual(none.lines.err.filter((l) => l.startsWith("worldsignals ")), []);
});

test("a release notice for this version or an older one isn't shown; a newer one is", async () => {
  const tag = (v) => `https://github.com/Yumankind/worldsignals-js/releases/tag/v${v}`;
  assert.equal(releasedVersion({ type: "worldsignals.cli_released", data: { version: "0.6.0" } }), "0.6.0");
  assert.equal(releasedVersion(parseNoticeHeader(`evt_R; title="worldsignals 0.6.0 is out"; url="${tag("0.6.0")}"; version="0.6.0"`)), "0.6.0");
  // From a server that doesn't send version yet: the release link's tag.
  assert.equal(releasedVersion(parseNoticeHeader(`evt_R; title="worldsignals 0.6.0 is out"; url="${tag("0.6.0")}"`)), "0.6.0");
  assert.equal(releasedVersion({ type: "worldsignals.maintenance_scheduled", data: { url: "https://worldsignals.dev/status" } }), null);
  const said = async (header) => {
    const fetch = async () => new Response(JSON.stringify({ events: [], cursor: 9 }), { headers: { "content-type": "application/json", "x-ws-notice": header } });
    const io = capture();
    assert.equal(await run(["events"], { fetch, env: { WS_KEY: "k", XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "ws-cli-")) }, ...io }), 0);
    return io.lines.err;
  };
  assert.deepEqual(await said(`evt_A; title="worldsignals ${VERSION} is out: npx worldsignals@latest"; url="${tag(VERSION)}"; version="${VERSION}"`), []);
  assert.deepEqual(await said(`evt_B; title="worldsignals 0.0.1 is out"; url="${tag("0.0.1")}"`), []);
  assert.deepEqual(await said(`evt_C; title="worldsignals 99.0.0 is out"; url="${tag("99.0.0")}"; version="99.0.0"`), [`WorldSignals: worldsignals 99.0.0 is out — ${tag("99.0.0")}`]);
});
