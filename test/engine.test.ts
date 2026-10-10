import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compileRule, loadRules, validateRule } from "../src/engine/rules.js";
import { runRules, decodeAll } from "../src/engine/engine.js";
import { enrich, isBlocked, parseBlocklist } from "../src/engine/enrich.js";
import type { LogEvent, Rule } from "../src/types.js";

const T0 = Date.UTC(2026, 9, 10, 0, 0, 0);
const fail = (sec: number, ip = "1.1.1.1", user = "root"): LogEvent =>
  ({ ts: T0 + sec * 1000, source: "ssh", ip, user, action: "failed_login", raw: `fail ${sec} ${ip} ${user}` });
const ok = (sec: number, ip = "1.1.1.1", user = "root"): LogEvent =>
  ({ ts: T0 + sec * 1000, source: "ssh", ip, user, action: "login_success", raw: `ok ${sec}` });
const web = (sec: number, path: string, status = 200, ip = "2.2.2.2", ua = "x"): LogEvent =>
  ({ ts: T0 + sec * 1000, source: "nginx", ip, action: "http_request", method: "GET", path, status, ua, raw: `GET ${path}` });

const meta = { title: "t", description: "d", response: "r", severity: "high" as const, mitre: { id: "T1110", name: "n" } };
const threshold: Rule = { ...meta, id: "th", type: "threshold", filter: { source: "ssh", action: "failed_login" }, groupBy: "ip", count: 5, windowSec: 60 };

test("threshold fires exactly at the count, not below", () => {
  const c = [compileRule(threshold)];
  assert.equal(runRules([1, 2, 3, 4].map((s) => fail(s)), c).length, 0);
  assert.equal(runRules([1, 2, 3, 4, 5].map((s) => fail(s)), c).length, 1);
});

test("threshold respects the time window", () => {
  const c = [compileRule(threshold)];
  assert.equal(runRules([0, 20, 40, 70, 100].map((s) => fail(s)), c).length, 0); // never 5 inside 60s
});

test("threshold groups by source and merges continued activity into one alert", () => {
  const c = [compileRule(threshold)];
  const events = [...Array.from({ length: 12 }, (_, i) => fail(i, "1.1.1.1")), ...Array.from({ length: 3 }, (_, i) => fail(i, "9.9.9.9"))];
  const alerts = runRules(events, c);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].ip, "1.1.1.1");
  assert.equal(alerts[0].count, 12);
});

test("threshold with distinct counts unique users (spray)", () => {
  const spray = compileRule({ ...threshold, id: "spray", distinct: "user", count: 4 } as Rule);
  assert.equal(runRules([1, 2, 3, 4].map((s) => fail(s, "1.1.1.1", "same")), [spray]).length, 0);
  assert.equal(runRules(["a", "b", "c", "d"].map((u, i) => fail(i, "1.1.1.1", u)), [spray]).length, 1);
});

test("sequence fires when success follows enough failures, and not otherwise", () => {
  const seq = compileRule({
    ...meta, id: "seq", type: "sequence", groupBy: "ip", count: 3, windowSec: 120,
    first: { source: "ssh", action: "failed_login" }, then: { source: "ssh", action: "login_success" },
  });
  assert.equal(runRules([fail(1), fail(2), ok(3)], [seq]).length, 0);
  assert.equal(runRules([fail(1), fail(2), fail(3), ok(4)], [seq]).length, 1);
  assert.equal(runRules([fail(1), fail(2), fail(3), ok(500)], [seq]).length, 0); // too late
  assert.equal(runRules([fail(1, "a"), fail(2, "b"), fail(3, "c"), ok(4, "a")], [seq]).length, 0); // different IPs
});

test("match rule catches encoded and double-encoded payloads", () => {
  const trav = compileRule({ ...meta, id: "trav", type: "match", filter: { source: "nginx" }, field: "path", patterns: ["\\.\\./"] });
  for (const p of ["/f?x=../etc", "/f?x=%2e%2e%2fetc", "/f?x=%252e%252e%252fetc"]) {
    assert.equal(runRules([web(1, p)], [trav]).length, 1, p);
  }
  assert.equal(runRules([web(1, "/f?x=safe")], [trav]).length, 0);
});

test("decodeAll tolerates malformed percent-encoding", () => {
  assert.equal(decodeAll("%E0%A4%A"), "%E0%A4%A");
  assert.equal(decodeAll("%2527"), "'");
});

test("filter on status and path regex", () => {
  const stuff = compileRule({ ...meta, id: "stuff", type: "threshold", filter: { source: "nginx", status: [401], path: "^/login" }, groupBy: "ip", count: 3, windowSec: 60 });
  const hit = [1, 2, 3].map((s) => web(s, "/login", 401));
  const miss = [1, 2, 3].map((s) => web(s, "/login", 200));
  assert.equal(runRules(hit, [stuff]).length, 1);
  assert.equal(runRules(miss, [stuff]).length, 0);
});

test("blocklist supports exact IPs and CIDR; scoring reflects it", () => {
  const bl = parseBlocklist("# c\n1.2.3.4\n10.0.0.0/8\nbad-line\n203.0.113.96/27\n");
  assert.ok(isBlocked("1.2.3.4", bl));
  assert.ok(isBlocked("10.200.1.1", bl));
  assert.ok(isBlocked("203.0.113.127", bl));
  assert.ok(!isBlocked("203.0.113.128", bl));
  assert.ok(!isBlocked("1.2.3.5", bl));
  const c = [compileRule(threshold)];
  const clean = enrich(runRules([1, 2, 3, 4, 5].map((s) => fail(s, "8.8.8.8")), c), bl)[0];
  const dirty = enrich(runRules([1, 2, 3, 4, 5].map((s) => fail(s, "1.2.3.4")), c), bl)[0];
  assert.equal(dirty.score, clean.score + 10);
  assert.ok(dirty.tags.includes("known-bad-ip"));
});

test("rule validation rejects bad definitions with clear errors", () => {
  assert.throws(() => validateRule({ ...threshold, severity: "urgent" }, "f.yml"), /severity/);
  assert.throws(() => validateRule({ ...threshold, mitre: { id: "1110", name: "x" } }, "f.yml"), /mitre/);
  assert.throws(() => validateRule({ ...threshold, count: 1 }, "f.yml"), /count/);
  assert.throws(() => compileRule({ ...meta, id: "bad", type: "match", field: "path", patterns: ["("] }), /invalid regex/);
});

test("loadRules rejects duplicate ids", () => {
  const dir = mkdtempSync(join(tmpdir(), "rules-"));
  const body = "id: dup\ntitle: t\ndescription: d\nresponse: r\nseverity: low\nmitre: { id: T1110, name: n }\ntype: match\nfield: path\npatterns: ['x']\n";
  writeFileSync(join(dir, "a.yml"), body);
  writeFileSync(join(dir, "b.yml"), body);
  assert.throws(() => loadRules(dir), /duplicate rule id/);
});
