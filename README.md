# SentinelLite: a mini SIEM with ATT&CK-mapped detections

SentinelLite ingests SSH and web server logs, normalizes them, runs a YAML-defined **detection rule engine** mapped to **MITRE ATT&CK**, scores and de-duplicates alerts, and exposes them through a CLI, a hardened REST API, a dashboard and Markdown incident reports.

It is a defensive project. It includes a **log simulator** that writes synthetic attack traffic (as text only; nothing is sent over a network), so the detections can be demonstrated and **regression-tested** end to end.

```
 auth.log / access.log ──► parsers ──► normalized events ──► rule engine ──► enrich + score ──► alerts
   (or POST /api/ingest)   ssh, nginx    (LogEvent)         match/threshold/   blocklist, CIDR     │
                                                            sequence rules                         ├─► CLI table / JSON / Markdown report
                                                            (rules/*.yml)                          ├─► REST API + dashboard
                                                                                                   └─► CI gate (--fail-on)
```

## Quick start (Node 20.11+)

```bash
npm install
npm run simulate        # writes logs/auth.log and logs/access.log (synthetic)
npm run analyze         # detections in your terminal
npm run serve           # dashboard at http://127.0.0.1:8080
npm test                # 28 tests incl. detection regression
```

More: `npx tsx src/cli.ts analyze logs/*.log --format md > report.md`, `--min-severity high`, `--fail-on critical` (exit code 2, for CI), `rules` (list the ATT&CK mapping).

Sample output on the simulated day (1,226 events):

```
SCORE SEVERITY  RULE                      SOURCE IP        COUNT  FIRST SEEN (UTC)
96    CRITICAL  ssh-compromise            203.0.113.99     8      2026-10-10 04:05:00
80    HIGH      ssh-bruteforce            203.0.113.66     80     2026-10-10 02:15:00
72    HIGH      web-sqli                  203.0.113.66     10     2026-10-10 09:41:00
...
1226 events analyzed, 13 alerts: 1 critical, 7 high, 5 medium, 0 low
```

## Detection coverage

| Rule | Type | Severity | ATT&CK |
|---|---|---|---|
| `ssh-bruteforce` | threshold (10 fails / 60 s / IP) | high | T1110.001 Password Guessing |
| `ssh-password-spray` | threshold, distinct users (5 / 120 s) | high | T1110.003 Password Spraying |
| `ssh-compromise` | sequence (5 fails then success / 300 s) | critical | T1078 Valid Accounts |
| `ssh-root-login` | match | medium | T1078.003 Local Accounts |
| `web-sqli` | match (decoded path) | high | T1190 Exploit Public-Facing App |
| `web-xss` | match | medium | T1190 |
| `web-path-traversal` | match (double-decoded) | high | T1190 |
| `web-sensitive-files` | match | high | T1552.001 Credentials In Files |
| `web-scanner-ua` | match on user-agent | medium | T1595.002 Vulnerability Scanning |
| `web-404-burst` | threshold (20 x 404 / 60 s) | medium | T1595.003 Wordlist Scanning |
| `web-credential-stuffing` | threshold (15 x 401 on /login / 60 s) | high | T1110.004 Credential Stuffing |

### Writing a rule

Drop a YAML file in `rules/`. Rules are validated on load (types, regexes, ATT&CK id format, duplicate ids), so mistakes fail fast with a clear message.

```yaml
- id: ssh-bruteforce
  title: SSH brute-force attempt
  severity: high
  mitre: { id: T1110.001, name: Password Guessing }
  type: threshold                       # match | threshold | sequence
  filter: { source: ssh, action: failed_login }
  groupBy: ip
  count: 10
  windowSec: 60
  response: Block the source IP, enforce key-only SSH, deploy fail2ban.
```

## Engineering decisions

- **Normalized event schema:** rules never see raw log formats, so adding a new source (Windows events, CloudTrail) means writing one parser.
- **Incidents, not noise:** repeated hits from one source merge into a single alert with a count, a time window and up to 5 evidence lines.
- **Evasion resistance:** web payloads are URL-decoded up to twice before matching, so `%2e%2e%2f` and `%252e%252e%252f` are caught.
- **Scoring (0-100):** severity baseline, +10 for known-bad infrastructure (exact IP or CIDR blocklist), up to +10 for volume.
- **Sliding-window state per key** keeps threshold rules O(events) and independent per source.
- **Detection regression suite:** `test/simulation.test.ts` asserts every simulated attack is detected, benign traffic produces **zero** false positives, and results hold across multiple random seeds.

## Securing the tool itself

A security tool is also an attack surface, and its inputs (log lines) are attacker-controlled.

| Threat | Mitigation |
|---|---|
| Stored XSS via crafted log lines shown in the dashboard | Dashboard uses `textContent` only (no `innerHTML`); strict CSP (`default-src 'none'; script-src 'self'`) |
| Markdown/code-fence breakout in generated reports | Evidence is sanitized before being placed in code fences |
| Unauthenticated log injection (alert forging/flooding) | Ingest needs `x-api-key` (constant-time compare); **disabled by default** until `SENTINEL_API_KEY` is set |
| Resource exhaustion | 1 MB body limit, 30 req/min limiter on ingest, 200k event cap |
| Information leakage | Generic JSON errors, `x-powered-by` removed, `Cache-Control: no-store` on API |
| Exposure | Binds to `127.0.0.1` by default; Docker image runs as non-root user |
| Malformed rules / ReDoS-prone input | Rules validated on load; ingest size-bounded |
| Supply chain | `npm audit` in CI, CodeQL workflow, minimal dependencies (express, yaml, tsx) |

## Known limitations (honest scope)

- Batch re-analysis on each ingest is fine for demos; real SIEMs stream and index.
- State is in memory and per-process; there is no persistence or multi-node support.
- Threshold windows use event time and assume mostly ordered logs.
- Regex rules are signatures: a determined attacker can obfuscate beyond double-decoding. Pair with a WAF and anomaly detection.
- Behind NAT or proxies, IP-based grouping can mis-attribute traffic (use `X-Forwarded-For` parsing carefully).
- The dashboard and API have no user accounts; do not expose them publicly without a reverse proxy providing authentication and TLS.

## Ideas for extension

Syslog/auth.log for `sudo` and `su` events, Windows Event Log parser, Sigma rule import, GeoIP and impossible-travel detection, persistence in PostgreSQL, webhooks to Slack, a baseline/anomaly detector (z-score on request rate), and alert suppression with allowlists.

## Layout

```
rules/*.yml          detection rules (data, not code)
src/parsers/         ssh + nginx parsers -> LogEvent
src/engine/          rule loader/validator, evaluator, enrichment + scoring
src/simulate.ts      synthetic benign + attack log generator
src/server.ts        hardened REST API + static dashboard
src/cli.ts           simulate | analyze | serve | rules
public/              dashboard (vanilla JS, CSP-safe)
test/                parsers, engine, server and end-to-end detection tests
```
