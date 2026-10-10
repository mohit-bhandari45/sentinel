import type { LogEvent } from "../types.js";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const LINE = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) (?:\d+|-) "[^"]*" "([^"]*)"/;
const STAMP = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/;

function parseStamp(s: string): number | null {
  const m = STAMP.exec(s);
  if (!m) return null;
  const mon = MONTHS.indexOf(m[2]);
  if (mon < 0) return null;
  const offsetMs = (m[7] === "-" ? -1 : 1) * (Number(m[8]) * 60 + Number(m[9])) * 60_000;
  return Date.UTC(Number(m[3]), mon, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6])) - offsetMs;
}

/** Parses nginx/Apache "combined" access log lines. */
export function parseNginxLine(line: string): LogEvent | null {
  const m = LINE.exec(line);
  if (!m) return null;
  const ts = parseStamp(m[2]);
  if (ts === null) return null;
  return {
    ts, source: "nginx", ip: m[1], action: "http_request",
    method: m[3], path: m[4], status: Number(m[5]), ua: m[6], raw: line,
  };
}
