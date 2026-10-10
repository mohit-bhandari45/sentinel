import express, { type NextFunction, type Request, type Response } from "express";
import { createHash, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { ROOT } from "./paths.js";
import { SEVERITIES, type Severity, type Source } from "./types.js";
import type { State } from "./state.js";
import { parseText } from "./parsers/index.js";
import { markdownReport, summarize } from "./report.js";

const sha = (s: string) => createHash("sha256").update(s).digest();
const keyOk = (given: string, expected: string) => timingSafeEqual(sha(given), sha(expected)); // constant time

export function createApp(state: State, apiKey?: string) {
  const app = express();
  app.disable("x-powered-by");

  app.use((_req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    next();
  });
  app.use("/api", (_req, res, next) => { res.setHeader("Cache-Control", "no-store"); next(); });
  app.use(express.static(join(ROOT, "public")));

  app.get("/api/stats", (_req, res) => res.json(summarize(state.alerts, state.events.length)));

  app.get("/api/alerts", (req, res) => {
    const { severity, ip } = req.query;
    if (severity !== undefined && !SEVERITIES.includes(severity as Severity)) return res.status(400).json({ error: "invalid severity" });
    if (ip !== undefined && typeof ip !== "string") return res.status(400).json({ error: "invalid ip" });
    const limit = Math.min(1000, Math.max(1, Number.parseInt(String(req.query.limit ?? "200"), 10) || 200));
    res.json(state.alerts.filter((a) => (!severity || a.severity === severity) && (!ip || a.ip === ip)).slice(0, limit));
  });

  app.get("/api/alerts/:id", (req, res) => {
    const a = state.alerts.find((x) => x.id === req.params.id);
    return a ? res.json(a) : res.status(404).json({ error: "not found" });
  });

  app.get("/api/report", (_req, res) => {
    res.type("text/markdown").send(markdownReport(state.alerts, summarize(state.alerts, state.events.length)));
  });

  // ---- Ingest: authenticated, size-limited and rate-limited ----
  const hits = new Map<string, { n: number; reset: number }>();
  const limiter = (req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    const k = req.ip ?? "unknown";
    const h = hits.get(k);
    if (!h || h.reset < now) hits.set(k, { n: 1, reset: now + 60_000 });
    else if (++h.n > 30) return res.status(429).json({ error: "rate limit exceeded" });
    next();
  };
  const requireKey = (req: Request, res: Response, next: NextFunction) => {
    if (!apiKey) return res.status(503).json({ error: "ingest disabled: set SENTINEL_API_KEY" });
    const given = req.header("x-api-key");
    if (!given || !keyOk(given, apiKey)) return res.status(401).json({ error: "unauthorized" });
    next();
  };

  app.post("/api/ingest", limiter, requireKey, express.text({ type: "*/*", limit: "1mb" }), (req, res) => {
    const source = req.query.source;
    if (source !== "ssh" && source !== "nginx") return res.status(400).json({ error: "source must be ssh or nginx" });
    const year = req.query.year === undefined ? new Date().getUTCFullYear() : Number.parseInt(String(req.query.year), 10);
    if (!Number.isInteger(year) || year < 2000 || year > 2100) return res.status(400).json({ error: "invalid year" });
    if (typeof req.body !== "string" || !req.body.trim()) return res.status(400).json({ error: "empty body" });
    const { events, skipped } = parseText(req.body, source as Source, year);
    state.ingest(events);
    res.json({ ingested: events.length, skipped, totalEvents: state.events.length, alerts: state.alerts.length });
  });

  // Generic error handler: never leak stack traces.
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err?.status && err.status >= 400 && err.status < 600 ? err.status : 500;
    res.status(status).json({ error: status === 413 ? "payload too large" : "request failed" });
  });
  return app;
}
