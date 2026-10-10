import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp } from "../src/server.js";
import { loadDefaults, State } from "../src/state.js";

let server: Server;
let base: string;
const KEY = "test-key-123";

before(async () => {
  const { rules, blocklist } = loadDefaults();
  server = createApp(new State(rules, blocklist), KEY).listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => server.close());

const failLines = Array.from({ length: 12 }, (_, i) => `Oct 10 02:15:${String(10 + i).padStart(2, "0")} web01 sshd[1]: Failed password for root from 203.0.113.66 port 22 ssh2`).join("\n");

test("security headers are set and x-powered-by is hidden", async () => {
  const r = await fetch(`${base}/api/stats`);
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  assert.match(r.headers.get("content-security-policy") ?? "", /default-src 'none'/);
  assert.equal(r.headers.get("x-powered-by"), null);
  assert.equal(r.headers.get("cache-control"), "no-store");
});

test("ingest requires the API key", async () => {
  const none = await fetch(`${base}/api/ingest?source=ssh`, { method: "POST", body: failLines });
  assert.equal(none.status, 401);
  const wrong = await fetch(`${base}/api/ingest?source=ssh`, { method: "POST", body: failLines, headers: { "x-api-key": "nope" } });
  assert.equal(wrong.status, 401);
});

test("ingest validates its inputs", async () => {
  const h = { "x-api-key": KEY };
  assert.equal((await fetch(`${base}/api/ingest?source=evil`, { method: "POST", body: "x", headers: h })).status, 400);
  assert.equal((await fetch(`${base}/api/ingest?source=ssh&year=abc`, { method: "POST", body: "x", headers: h })).status, 400);
  assert.equal((await fetch(`${base}/api/ingest?source=ssh`, { method: "POST", body: "   ", headers: h })).status, 400);
});

test("oversized ingest is rejected with a generic error", async () => {
  const r = await fetch(`${base}/api/ingest?source=ssh`, { method: "POST", body: "a".repeat(2_000_000), headers: { "x-api-key": KEY } });
  assert.equal(r.status, 413);
  assert.deepEqual(await r.json(), { error: "payload too large" });
});

test("authorized ingest produces alerts visible through the API", async () => {
  const r = await fetch(`${base}/api/ingest?source=ssh&year=2026`, { method: "POST", body: failLines, headers: { "x-api-key": KEY } });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).ingested, 12);
  const alerts = await (await fetch(`${base}/api/alerts?severity=high`)).json();
  assert.ok(alerts.some((a: any) => a.ruleId === "ssh-bruteforce"));
  const one = await fetch(`${base}/api/alerts/${alerts[0].id}`);
  assert.equal(one.status, 200);
  assert.equal((await fetch(`${base}/api/alerts/doesnotexist`)).status, 404);
  assert.equal((await fetch(`${base}/api/alerts?severity=bogus`)).status, 400);
  const md = await (await fetch(`${base}/api/report`)).text();
  assert.match(md, /# Security Incident Report/);
});

test("ingest is disabled when no API key is configured", async () => {
  const { rules, blocklist } = loadDefaults();
  const s = createApp(new State(rules, blocklist), undefined).listen(0, "127.0.0.1");
  await new Promise((r) => s.once("listening", r));
  const r = await fetch(`http://127.0.0.1:${(s.address() as AddressInfo).port}/api/ingest?source=ssh`, { method: "POST", body: failLines, headers: { "x-api-key": "anything" } });
  assert.equal(r.status, 503);
  s.close();
});
