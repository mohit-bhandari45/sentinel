import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./paths.js";
import type { Alert, LogEvent } from "./types.js";
import { loadRules, type Compiled } from "./engine/rules.js";
import { runRules } from "./engine/engine.js";
import { enrich, parseBlocklist, type Blocklist } from "./engine/enrich.js";

export function loadDefaults(): { rules: Compiled[]; blocklist: Blocklist } {
  return {
    rules: loadRules(join(ROOT, "rules")),
    blocklist: parseBlocklist(readFileSync(join(ROOT, "data", "blocklist.txt"), "utf8")),
  };
}

export class State {
  events: LogEvent[] = [];
  alerts: Alert[] = [];
  constructor(private rules: Compiled[], private blocklist: Blocklist, private maxEvents = 200_000) {}

  ingest(events: LogEvent[]): void {
    for (const e of events) this.events.push(e);
    if (this.events.length > this.maxEvents) this.events.splice(0, this.events.length - this.maxEvents);
    this.recompute();
  }

  recompute(): void {
    this.alerts = enrich(runRules(this.events, this.rules), this.blocklist).sort((a, b) => b.score - a.score || a.firstSeen - b.firstSeen);
  }
}
