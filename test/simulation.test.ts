// End-to-end detection regression test: every simulated attack must be detected,
// and benign traffic must produce zero alerts (no false positives).
import test from "node:test";
import assert from "node:assert/strict";
import { simulate, SIM_YEAR } from "../src/simulate.js";
import { parseText } from "../src/parsers/index.js";
import { loadDefaults, State } from "../src/state.js";

function run(seed?: number) {
  const sim = simulate(seed);
  const { rules, blocklist } = loadDefaults();
  const state = new State(rules, blocklist);
  const ssh = parseText(sim.ssh.join("\n"), "ssh", SIM_YEAR);
  const web = parseText(sim.nginx.join("\n"), "nginx", SIM_YEAR);
  assert.equal(ssh.skipped + web.skipped, 0, "parsers must understand every simulated line");
  state.ingest([...ssh.events, ...web.events]);
  return state;
}

const EXPECTED: [string, string][] = [
  ["ssh-bruteforce", "203.0.113.66"],
  ["ssh-password-spray", "203.0.113.77"],
  ["ssh-compromise", "203.0.113.99"],
  ["ssh-root-login", "203.0.113.99"],
  ["web-scanner-ua", "198.51.100.200"],
  ["web-404-burst", "198.51.100.200"],
  ["web-sensitive-files", "198.51.100.200"],
  ["web-sqli", "203.0.113.66"],
  ["web-scanner-ua", "203.0.113.66"],
  ["web-xss", "198.51.100.150"],
  ["web-path-traversal", "203.0.113.120"],
  ["web-credential-stuffing", "198.51.100.77"],
];

test("every simulated attack is detected", () => {
  const state = run();
  for (const [rule, ip] of EXPECTED) {
    assert.ok(state.alerts.some((a) => a.ruleId === rule && a.ip === ip), `missing ${rule} for ${ip}`);
  }
});

test("no false positives on benign traffic", () => {
  const state = run();
  const benign = (ip: string) => ip.startsWith("192.0.2.") || ip === "198.51.100.5" || ip === "198.51.100.6";
  const fp = state.alerts.filter((a) => benign(a.ip));
  assert.deepEqual(fp.map((a) => `${a.ruleId}@${a.ip}`), []);
});

test("brute force from a blocklisted IP outranks the same pattern from a clean one", () => {
  const state = run();
  const bf = state.alerts.find((a) => a.ruleId === "ssh-bruteforce")!;
  assert.ok(bf.tags.includes("known-bad-ip"));
  assert.equal(state.alerts[0].severity, "critical"); // highest score first
});

test("detections are stable across different seeds and simulation is deterministic", () => {
  assert.deepEqual(simulate(7), simulate(7));
  assert.notDeepEqual(simulate(7), simulate(8));
  for (const seed of [1, 2, 3]) {
    const state = run(seed);
    for (const [rule, ip] of EXPECTED) assert.ok(state.alerts.some((a) => a.ruleId === rule && a.ip === ip), `seed ${seed}: ${rule}/${ip}`);
  }
});

test("all alerts carry ATT&CK technique ids and evidence", () => {
  for (const a of run().alerts) {
    assert.match(a.mitre.id, /^T\d{4}(\.\d{3})?$/);
    assert.ok(a.evidence.length > 0 && a.evidence.length <= 5);
  }
});
