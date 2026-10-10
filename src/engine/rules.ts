import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { SEVERITIES, type EventFilter, type Rule, type Source } from "../types.js";

export interface CFilter { source?: Source; action?: string; status?: number[]; path?: RegExp }
export interface Compiled { rule: Rule; filter: CFilter; patterns: RegExp[]; first?: CFilter; then?: CFilter }

function need(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

function compileRegex(src: string, ctx: string): RegExp {
  try { return new RegExp(src, "i"); }
  catch (e) { throw new Error(`${ctx}: invalid regex /${src}/ (${(e as Error).message})`); }
}

function compileFilter(f: EventFilter | undefined, ctx: string): CFilter {
  if (!f) return {};
  need(typeof f === "object", `${ctx}: filter must be an object`);
  if (f.source !== undefined) need(f.source === "ssh" || f.source === "nginx", `${ctx}: filter.source must be ssh|nginx`);
  if (f.status !== undefined) need(Array.isArray(f.status) && f.status.every(Number.isInteger), `${ctx}: filter.status must be integers`);
  return { source: f.source, action: f.action, status: f.status, path: f.path ? compileRegex(f.path, ctx) : undefined };
}

export function validateRule(r: any, file: string): Rule {
  const ctx = `${file}${r?.id ? ` (${r.id})` : ""}`;
  need(r && typeof r === "object", `${ctx}: rule must be an object`);
  for (const k of ["id", "title", "description", "response"]) need(typeof r[k] === "string" && r[k], `${ctx}: missing "${k}"`);
  need(/^[a-z0-9-]+$/.test(r.id), `${ctx}: id must be lowercase kebab-case`);
  need(SEVERITIES.includes(r.severity), `${ctx}: severity must be one of ${SEVERITIES.join(", ")}`);
  need(r.mitre && /^T\d{4}(\.\d{3})?$/.test(r.mitre.id) && r.mitre.name, `${ctx}: mitre needs a valid technique id (e.g. T1110.001) and name`);
  switch (r.type) {
    case "match":
      need(["path", "ua", "user", "raw"].includes(r.field), `${ctx}: match.field must be path|ua|user|raw`);
      need(Array.isArray(r.patterns) && r.patterns.length > 0, `${ctx}: match.patterns must be a non-empty list`);
      break;
    case "threshold":
      need(["ip", "user"].includes(r.groupBy), `${ctx}: groupBy must be ip|user`);
      need(Number.isInteger(r.count) && r.count > 1, `${ctx}: count must be an integer > 1`);
      need(Number.isInteger(r.windowSec) && r.windowSec > 0, `${ctx}: windowSec must be a positive integer`);
      if (r.distinct !== undefined) need(["user", "path"].includes(r.distinct), `${ctx}: distinct must be user|path`);
      break;
    case "sequence":
      need(r.groupBy === "ip", `${ctx}: sequence rules support groupBy: ip`);
      need(r.first && r.then, `${ctx}: sequence needs "first" and "then" filters`);
      need(Number.isInteger(r.count) && r.count > 0, `${ctx}: count must be a positive integer`);
      need(Number.isInteger(r.windowSec) && r.windowSec > 0, `${ctx}: windowSec must be a positive integer`);
      break;
    default:
      throw new Error(`${ctx}: unknown rule type "${r.type}"`);
  }
  return r as Rule;
}

export function compileRule(rule: Rule): Compiled {
  const ctx = rule.id;
  const c: Compiled = { rule, filter: compileFilter(rule.filter, ctx), patterns: [] };
  if (rule.type === "match") c.patterns = rule.patterns.map((p) => compileRegex(p, ctx));
  if (rule.type === "sequence") { c.first = compileFilter(rule.first, ctx); c.then = compileFilter(rule.then, ctx); }
  return c;
}

export function loadRules(dir: string): Compiled[] {
  const files = readdirSync(dir).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml")).sort();
  const seen = new Set<string>();
  const out: Compiled[] = [];
  for (const f of files) {
    const doc = parse(readFileSync(join(dir, f), "utf8"));
    for (const raw of Array.isArray(doc) ? doc : [doc]) {
      const rule = validateRule(raw, f);
      need(!seen.has(rule.id), `${f}: duplicate rule id "${rule.id}"`);
      seen.add(rule.id);
      out.push(compileRule(rule));
    }
  }
  return out;
}
