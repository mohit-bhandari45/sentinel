import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { loadDefaults, State } from "./state.js";
import { detectSource, parseText } from "./parsers/index.js";
import { simulate, SIM_YEAR } from "./simulate.js";
import { markdownReport, summarize } from "./report.js";
import { createApp } from "./server.js";
import { SEVERITIES, type Alert, type LogEvent, type Severity, type Source } from "./types.js";

process.stdout.on("error", (e: NodeJS.ErrnoException) => { if (e.code === "EPIPE") process.exit(0); throw e; });
const color = process.stdout.isTTY;
const paint = (s: string, c: number) => (color ? `\x1b[${c}m${s}\x1b[0m` : s);
const SEV_COLOR: Record<Severity, number> = { critical: 41, high: 31, medium: 33, low: 36 };
const iso = (ms: number) => new Date(ms).toISOString().slice(0, 19).replace("T", " ");

const USAGE = `SentinelLite: mini SIEM

Usage:
  sentinel simulate [--out DIR] [--seed N]         Generate synthetic logs (benign + attacks)
  sentinel analyze FILE... [options]               Run detections over log files
      --source ssh|nginx   force parser (default: auto-detect per file)
      --year N             year for syslog timestamps (default: current)
      --format table|json|md
      --min-severity low|medium|high|critical
      --fail-on SEVERITY   exit 2 if any alert at or above this severity (CI gate)
  sentinel serve [FILE...] [--port N] [--host H]   Dashboard + API (set SENTINEL_API_KEY to enable ingest)
  sentinel rules                                   List detection rules and ATT&CK mapping
`;

function loadFiles(files: string[], forced: string | undefined, year: number): LogEvent[] {
  const all: LogEvent[] = [];
  for (const f of files) {
    const text = readFileSync(f, "utf8");
    let source = forced as Source | undefined;
    if (!source) {
      const first = text.split(/\r?\n/).find((l) => l.trim());
      source = (first && detectSource(first, year)) || undefined;
    }
    if (!source) { console.error(`! ${f}: could not detect log type (use --source)`); continue; }
    const { events, skipped } = parseText(text, source, year);
    console.error(`# ${f}: ${events.length} ${source} events${skipped ? `, ${skipped} lines skipped` : ""}`);
    all.push(...events);
  }
  return all;
}

function printTable(alerts: Alert[]): void {
  if (!alerts.length) { console.log("No alerts."); return; }
  console.log(`${"SCORE".padEnd(6)}${"SEVERITY".padEnd(10)}${"RULE".padEnd(26)}${"SOURCE IP".padEnd(17)}${"COUNT".padEnd(7)}FIRST SEEN (UTC)`);
  for (const a of alerts) {
    console.log(`${String(a.score).padEnd(6)}${paint(a.severity.toUpperCase().padEnd(9), SEV_COLOR[a.severity])} ${a.ruleId.padEnd(26)}${a.ip.padEnd(17)}${String(a.count).padEnd(7)}${iso(a.firstSeen)}`);
  }
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  const { values, positionals } = parseArgs({
    args: rest, allowPositionals: true,
    options: {
      out: { type: "string" }, seed: { type: "string" }, source: { type: "string" }, year: { type: "string" },
      format: { type: "string" }, "min-severity": { type: "string" }, "fail-on": { type: "string" },
      port: { type: "string" }, host: { type: "string" },
    },
  });
  const year = values.year ? Number(values.year) : new Date().getUTCFullYear();

  switch (cmd) {
    case "simulate": {
      const dir = values.out ?? "logs";
      mkdirSync(dir, { recursive: true });
      const sim = simulate(values.seed ? Number(values.seed) : undefined);
      writeFileSync(join(dir, "auth.log"), sim.ssh.join("\n") + "\n");
      writeFileSync(join(dir, "access.log"), sim.nginx.join("\n") + "\n");
      console.log(`Wrote ${sim.ssh.length} SSH lines and ${sim.nginx.length} web lines to ${dir}/ (use --year ${SIM_YEAR} when analyzing)`);
      return;
    }
    case "analyze": {
      if (!positionals.length) { console.error(USAGE); process.exit(1); }
      const { rules, blocklist } = loadDefaults();
      const state = new State(rules, blocklist);
      state.ingest(loadFiles(positionals, values.source, values.year ? year : SIM_YEAR));
      const min = values["min-severity"] as Severity | undefined;
      if (min && !SEVERITIES.includes(min)) { console.error("invalid --min-severity"); process.exit(1); }
      const shown = min ? state.alerts.filter((a) => SEVERITIES.indexOf(a.severity) >= SEVERITIES.indexOf(min)) : state.alerts;
      const stats = summarize(shown, state.events.length);
      if (values.format === "json") console.log(JSON.stringify({ stats, alerts: shown }, null, 2));
      else if (values.format === "md") console.log(markdownReport(shown, stats));
      else {
        printTable(shown);
        console.log(`\n${state.events.length} events analyzed, ${shown.length} alerts: ` + [...SEVERITIES].reverse().map((s) => `${stats.bySeverity[s]} ${s}`).join(", "));
      }
      const gate = values["fail-on"] as Severity | undefined;
      if (gate && shown.some((a) => SEVERITIES.indexOf(a.severity) >= SEVERITIES.indexOf(gate))) process.exit(2);
      return;
    }
    case "serve": {
      const { rules, blocklist } = loadDefaults();
      const state = new State(rules, blocklist);
      if (positionals.length) state.ingest(loadFiles(positionals, values.source, values.year ? year : SIM_YEAR));
      const key = process.env.SENTINEL_API_KEY;
      const port = Number(values.port ?? 8080);
      const host = values.host ?? "127.0.0.1";
      createApp(state, key).listen(port, host, () => {
        console.log(`Dashboard: http://${host}:${port}  (${state.events.length} events, ${state.alerts.length} alerts)`);
        console.log(key ? "Ingest API enabled (x-api-key required)." : "Ingest API disabled. Set SENTINEL_API_KEY to enable POST /api/ingest.");
      });
      return;
    }
    case "rules": {
      const { rules } = loadDefaults();
      console.log(`${"RULE".padEnd(26)}${"SEV".padEnd(10)}${"ATT&CK".padEnd(11)}NAME`);
      for (const { rule: r } of rules) console.log(`${r.id.padEnd(26)}${r.severity.padEnd(10)}${r.mitre.id.padEnd(11)}${r.mitre.name}`);
      return;
    }
    default:
      console.log(USAGE);
      process.exit(cmd ? 1 : 0);
  }
}

main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exit(1); });
