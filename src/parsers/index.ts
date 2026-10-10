import type { LogEvent, Source } from "../types.js";
import { parseSshLine } from "./ssh.js";
import { parseNginxLine } from "./nginx.js";

export function parseLine(line: string, source: Source, year: number): LogEvent | null {
  return source === "ssh" ? parseSshLine(line, year) : parseNginxLine(line);
}

export function detectSource(line: string, year: number): Source | null {
  if (parseSshLine(line, year)) return "ssh";
  if (parseNginxLine(line)) return "nginx";
  return null;
}

export function parseText(text: string, source: Source, year: number): { events: LogEvent[]; skipped: number } {
  const events: LogEvent[] = [];
  let skipped = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const e = parseLine(line, source, year);
    if (e) events.push(e);
    else skipped++;
  }
  return { events, skipped };
}
