import type { Alert, Severity } from "../types.js";

export interface Blocklist { exact: Set<string>; cidrs: { net: number; mask: number }[] }

export function ipToInt(ip: string): number | null {
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    if (!/^\d{1,3}$/.test(part) || Number(part) > 255) return null;
    n = n * 256 + Number(part);
  }
  return n;
}

export function parseBlocklist(text: string): Blocklist {
  const bl: Blocklist = { exact: new Set(), cidrs: [] };
  for (const line of text.split(/\r?\n/)) {
    const entry = line.replace(/#.*/, "").trim();
    if (!entry) continue;
    const [addr, bits] = entry.split("/");
    const base = ipToInt(addr);
    if (base === null) continue;
    if (bits === undefined) { bl.exact.add(addr); continue; }
    const b = Number(bits);
    if (!Number.isInteger(b) || b < 0 || b > 32) continue;
    const mask = b === 0 ? 0 : (0xffffffff << (32 - b)) >>> 0;
    bl.cidrs.push({ net: (base & mask) >>> 0, mask });
  }
  return bl;
}

export function isBlocked(ip: string, bl: Blocklist): boolean {
  if (bl.exact.has(ip)) return true;
  const n = ipToInt(ip);
  return n !== null && bl.cidrs.some((c) => ((n & c.mask) >>> 0) === c.net);
}

export function isPrivateIp(ip: string): boolean {
  const n = ipToInt(ip);
  if (n === null) return false;
  const in_ = (base: string, bits: number) => {
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    return ((n & mask) >>> 0) === ((ipToInt(base)! & mask) >>> 0);
  };
  return in_("10.0.0.0", 8) || in_("172.16.0.0", 12) || in_("192.168.0.0", 16) || in_("127.0.0.0", 8);
}

const BASE: Record<Severity, number> = { low: 10, medium: 30, high: 60, critical: 85 };

/** Score 0-100: severity baseline, +10 for known-bad infrastructure, up to +10 for volume. */
export function enrich(alerts: Alert[], bl: Blocklist): Alert[] {
  for (const a of alerts) {
    const bad = isBlocked(a.ip, bl);
    a.tags = [];
    if (bad) a.tags.push("known-bad-ip");
    if (isPrivateIp(a.ip)) a.tags.push("internal-source");
    a.tags.push(a.mitre.id);
    a.score = Math.min(100, BASE[a.severity] + (bad ? 10 : 0) + Math.min(10, Math.floor(a.count / 5)));
  }
  return alerts;
}
