import test from "node:test";
import assert from "node:assert/strict";
import { parseSshLine } from "../src/parsers/ssh.js";
import { parseNginxLine } from "../src/parsers/nginx.js";
import { detectSource, parseText } from "../src/parsers/index.js";

test("ssh: failed login for invalid user", () => {
  const e = parseSshLine("Oct 10 02:15:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2", 2026)!;
  assert.equal(e.action, "failed_login");
  assert.equal(e.user, "admin");
  assert.equal(e.ip, "203.0.113.5");
  assert.equal(e.ts, Date.UTC(2026, 9, 10, 2, 15, 1));
});

test("ssh: accepted login and space-padded day", () => {
  const e = parseSshLine("Oct  1 08:00:00 web01 sshd[9]: Accepted publickey for alice from 198.51.100.5 port 22 ssh2", 2026)!;
  assert.equal(e.action, "login_success");
  assert.equal(e.user, "alice");
  assert.equal(e.ts, Date.UTC(2026, 9, 1, 8, 0, 0));
});

test("ssh: ignores unrelated and malformed lines", () => {
  assert.equal(parseSshLine("Oct 10 02:15:01 web01 cron[1]: job done", 2026), null);
  assert.equal(parseSshLine("garbage", 2026), null);
  assert.equal(parseSshLine("Foo 10 02:15:01 web01 sshd[1]: Failed password for x from 1.1.1.1 port 1", 2026), null);
});

test("nginx: parses fields and timezone offset", () => {
  const e = parseNginxLine('203.0.113.5 - - [10/Oct/2026:02:15:01 +0530] "GET /a?b=1 HTTP/1.1" 404 12 "-" "curl/8.0"')!;
  assert.equal(e.method, "GET");
  assert.equal(e.path, "/a?b=1");
  assert.equal(e.status, 404);
  assert.equal(e.ua, "curl/8.0");
  assert.equal(e.ts, Date.UTC(2026, 9, 10, 2, 15, 1) - 5.5 * 3600_000);
});

test("nginx: malformed lines return null", () => {
  assert.equal(parseNginxLine("nope"), null);
  assert.equal(parseNginxLine('1.1.1.1 - - [99/Foo/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'), null);
});

test("detectSource and parseText count skipped lines", () => {
  assert.equal(detectSource('1.1.1.1 - - [10/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"', 2026), "nginx");
  assert.equal(detectSource("Oct 10 00:00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2", 2026), "ssh");
  const r = parseText("bad line\n\nOct 10 00:00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2\n", "ssh", 2026);
  assert.equal(r.events.length, 1);
  assert.equal(r.skipped, 1);
});
