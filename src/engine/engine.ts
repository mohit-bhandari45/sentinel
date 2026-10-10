import { createHash } from "node:crypto";
import type { Alert, LogEvent, MatchRule, SequenceRule, ThresholdRule } from "../types.js";
import type { CFilter, Compiled } from "./rules.js";

const DEDUPE_MS = 300_000;

export function matchesFilter(e: LogEvent, f: CFilter): boolean {
  if (f.source && e.source !== f.source) return false;
  if (f.action && e.action !== f.action) return false;
  if (f.status && (e.status === undefined || !f.status.includes(e.status))) return false;
  if (f.path && !(e.path !== undefined && f.path.test(e.path))) return false;
  return true;
}

/** Decodes up to twice so double-encoded payloads (%252e%252e) can't dodge rules. */
export function decodeAll(v: string): string {
  let out = v;
  for (let i = 0; i < 2; i++) {
    try {
      const d = decodeURIComponent(out);
      if (d === out) break;
      out = d;
    } catch { break; }
  }
  return out;
}

function fieldValue(e: LogEvent, f: MatchRule["field"]): string {
  return f === "path" ? e.path ?? "" : f === "ua" ? e.ua ?? "" : f === "user" ? e.user ?? "" : e.raw;
}

/** Merges repeated hits of the same rule+source into one alert so analysts see incidents, not noise. */
class Aggregator {
  alerts: Alert[] = [];
  private open = new Map<string, Alert>();

  add(c: Compiled, groupKey: string, e: LogEvent, windowMs: number, startTs: number, count: number, evidence: string[]): void {
    const key = `${c.rule.id}|${groupKey}`;
    const cur = this.open.get(key);
    if (cur && e.ts - cur.lastSeen <= windowMs) {
      cur.lastSeen = e.ts;
      cur.count += 1;
      if (cur.evidence.length < 5) cur.evidence.push(e.raw);
      return;
    }
    const a: Alert = {
      id: createHash("sha1").update(`${key}|${startTs}`).digest("hex").slice(0, 10),
      ruleId: c.rule.id, title: c.rule.title, severity: c.rule.severity, mitre: c.rule.mitre,
      ip: e.ip, user: e.user, firstSeen: startTs, lastSeen: e.ts, count,
      evidence: evidence.slice(0, 5), score: 0, tags: [], response: c.rule.response,
    };
    this.open.set(key, a);
    this.alerts.push(a);
  }
}

function evalMatch(c: Compiled, r: MatchRule, events: LogEvent[], agg: Aggregator): void {
  for (const e of events) {
    if (!matchesFilter(e, c.filter)) continue;
    const v = fieldValue(e, r.field);
    const candidates = [v, decodeAll(v)];
    if (c.patterns.some((re) => candidates.some((s) => re.test(s)))) {
      agg.add(c, e.ip, e, DEDUPE_MS, e.ts, 1, [e.raw]);
    }
  }
}

function evalThreshold(c: Compiled, r: ThresholdRule, events: LogEvent[], agg: Aggregator): void {
  const windowMs = r.windowSec * 1000;
  const groups = new Map<string, LogEvent[]>();
  for (const e of events) {
    if (!matchesFilter(e, c.filter)) continue;
    const key = r.groupBy === "ip" ? e.ip : e.user ?? "";
    if (!key) continue;
    const arr = groups.get(key) ?? [];
    groups.set(key, arr);
    arr.push(e);
    while (arr.length && arr[0].ts < e.ts - windowMs) arr.shift();
    const measure = r.distinct
      ? new Set(arr.map((x) => (r.distinct === "user" ? x.user : x.path))).size
      : arr.length;
    if (measure >= r.count) agg.add(c, key, e, windowMs, arr[0].ts, arr.length, arr.map((x) => x.raw));
  }
}

function evalSequence(c: Compiled, r: SequenceRule, events: LogEvent[], agg: Aggregator): void {
  const windowMs = r.windowSec * 1000;
  const firsts = new Map<string, LogEvent[]>();
  for (const e of events) {
    const arr = firsts.get(e.ip) ?? [];
    firsts.set(e.ip, arr);
    if (c.first && matchesFilter(e, c.first)) {
      arr.push(e);
      while (arr.length && arr[0].ts < e.ts - windowMs) arr.shift();
    } else if (c.then && matchesFilter(e, c.then)) {
      while (arr.length && arr[0].ts < e.ts - windowMs) arr.shift();
      if (arr.length >= r.count) {
        agg.add(c, e.ip, e, windowMs, arr[0].ts, arr.length + 1, [...arr.slice(-4), e].map((x) => x.raw));
        arr.length = 0;
      }
    }
  }
}

export function runRules(events: LogEvent[], compiled: Compiled[]): Alert[] {
  const sorted = [...events].sort((a, b) => a.ts - b.ts);
  const agg = new Aggregator();
  for (const c of compiled) {
    const r = c.rule;
    if (r.type === "match") evalMatch(c, r, sorted, agg);
    else if (r.type === "threshold") evalThreshold(c, r, sorted, agg);
    else evalSequence(c, r, sorted, agg);
  }
  return agg.alerts;
}
