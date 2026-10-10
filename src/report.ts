import type { Alert, Severity } from "./types.js";
import { SEVERITIES } from "./types.js";

export interface Stats {
  events: number;
  alerts: number;
  bySeverity: Record<Severity, number>;
  byTechnique: { id: string; name: string; count: number }[];
  byRule: { ruleId: string; title: string; count: number }[];
  topIps: { ip: string; alerts: number; maxScore: number }[];
}

export function summarize(alerts: Alert[], events: number): Stats {
  const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const tech = new Map<string, { id: string; name: string; count: number }>();
  const rule = new Map<string, { ruleId: string; title: string; count: number }>();
  const ips = new Map<string, { ip: string; alerts: number; maxScore: number }>();
  for (const a of alerts) {
    bySeverity[a.severity]++;
    const t = tech.get(a.mitre.id) ?? { id: a.mitre.id, name: a.mitre.name, count: 0 };
    t.count++; tech.set(a.mitre.id, t);
    const r = rule.get(a.ruleId) ?? { ruleId: a.ruleId, title: a.title, count: 0 };
    r.count++; rule.set(a.ruleId, r);
    const i = ips.get(a.ip) ?? { ip: a.ip, alerts: 0, maxScore: 0 };
    i.alerts++; i.maxScore = Math.max(i.maxScore, a.score); ips.set(a.ip, i);
  }
  return {
    events, alerts: alerts.length, bySeverity,
    byTechnique: [...tech.values()].sort((a, b) => b.count - a.count),
    byRule: [...rule.values()].sort((a, b) => b.count - a.count),
    topIps: [...ips.values()].sort((a, b) => b.maxScore - a.maxScore || b.alerts - a.alerts).slice(0, 10),
  };
}

const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z");
// Log content is attacker-controlled: keep it from breaking out of the markdown code fence.
const safe = (s: string) => s.replaceAll("```", "'''");

export function markdownReport(alerts: Alert[], stats: Stats, generatedAt = new Date()): string {
  const L: string[] = [];
  L.push("# Security Incident Report", "", `Generated: ${generatedAt.toISOString()}`, "");
  L.push("## Executive summary", "");
  L.push(`Analyzed **${stats.events}** events and raised **${stats.alerts}** alerts.`, "");
  L.push("| Severity | Alerts |", "|---|---|");
  for (const s of [...SEVERITIES].reverse()) L.push(`| ${s} | ${stats.bySeverity[s]} |`);
  L.push("", "## Top sources", "", "| IP | Alerts | Max score |", "|---|---|---|");
  for (const i of stats.topIps) L.push(`| ${i.ip} | ${i.alerts} | ${i.maxScore} |`);
  L.push("", "## MITRE ATT&CK coverage observed", "", "| Technique | Name | Alerts |", "|---|---|---|");
  for (const t of stats.byTechnique) L.push(`| ${t.id} | ${t.name} | ${t.count} |`);
  L.push("", "## Findings", "");
  for (const a of alerts) {
    L.push(`### [${a.severity.toUpperCase()}] ${a.title} (score ${a.score})`, "");
    L.push(`- **Source:** ${a.ip}${a.user ? ` (user: ${a.user})` : ""}`);
    L.push(`- **Window:** ${iso(a.firstSeen)} to ${iso(a.lastSeen)}`);
    L.push(`- **Events:** ${a.count}`);
    L.push(`- **ATT&CK:** ${a.mitre.id} ${a.mitre.name}`);
    L.push(`- **Tags:** ${a.tags.join(", ")}`);
    L.push(`- **Recommended response:** ${a.response}`, "", "```");
    for (const e of a.evidence) L.push(safe(e));
    L.push("```", "");
  }
  return L.join("\n");
}
