export type Source = "ssh" | "nginx";
export type Severity = "low" | "medium" | "high" | "critical";
export const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

/** Normalized event: every parser outputs this shape so rules are source-agnostic. */
export interface LogEvent {
  ts: number; // epoch ms (UTC)
  source: Source;
  ip: string;
  action: string; // failed_login | login_success | http_request
  user?: string;
  status?: number;
  method?: string;
  path?: string;
  ua?: string;
  raw: string;
}

export interface EventFilter {
  source?: Source;
  action?: string;
  status?: number[];
  path?: string; // regex source
}

interface RuleBase {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  mitre: { id: string; name: string };
  response: string;
  filter?: EventFilter;
}
export interface MatchRule extends RuleBase {
  type: "match";
  field: "path" | "ua" | "user" | "raw";
  patterns: string[];
}
export interface ThresholdRule extends RuleBase {
  type: "threshold";
  groupBy: "ip" | "user";
  count: number;
  windowSec: number;
  distinct?: "user" | "path";
}
export interface SequenceRule extends RuleBase {
  type: "sequence";
  groupBy: "ip";
  first: EventFilter;
  then: EventFilter;
  count: number;
  windowSec: number;
}
export type Rule = MatchRule | ThresholdRule | SequenceRule;

export interface Alert {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  mitre: { id: string; name: string };
  ip: string;
  user?: string;
  firstSeen: number;
  lastSeen: number;
  count: number;
  evidence: string[];
  score: number;
  tags: string[];
  response: string;
}
