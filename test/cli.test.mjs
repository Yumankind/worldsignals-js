// The ws command line tool, run by Node's own test runner (pnpm test:cli): it is a Node program,
// not Worker code. The server is a fake that records what the tool sent.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentHeaders, agentPath, commandName, help, newKeyPair, readAgent, run as runCli, signedString, signingTime } from "../bin/ws.mjs";

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
  for (const c of ["signup", "upgrade", "connect", "status", "billing", "keys rotate", "recover", "events", "watch"]) assert.match(text, new RegExp(`^ {2}npx worldsignals ${c}`, "m"));
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
  assert.deepEqual(JSON.parse(all.lines.out[0]), { eventTypes: ["company.registered"], countries: ["WW"], delivery: [], speed: null });
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
  assert.deepEqual(io.lines.err, ["This agent isn't paid for yet. Run ws upgrade for a payment link, or ws connect to use the account of the person you work for."]);
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
