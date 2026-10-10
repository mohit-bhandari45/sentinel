import type { LogEvent } from "../types.js";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const LINE = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+(.*)$/;
const FAILED = /^Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port \d+/;
const ACCEPTED = /^Accepted (\S+) for (\S+) from (\S+) port \d+/;

/** Parses OpenSSH syslog lines. Syslog has no year, so the caller supplies one. */
export function parseSshLine(line: string, year: number): LogEvent | null {
  const m = LINE.exec(line);
  if (!m) return null;
  const mon = MONTHS.indexOf(m[1]);
  if (mon < 0) return null;
  const ts = Date.UTC(year, mon, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
  const msg = m[6];
  const f = FAILED.exec(msg);
  if (f) return { ts, source: "ssh", ip: f[2], user: f[1], action: "failed_login", raw: line };
  const a = ACCEPTED.exec(msg);
  if (a) return { ts, source: "ssh", ip: a[3], user: a[2], action: "login_success", raw: line };
  return null;
}
