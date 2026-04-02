// src/reporter/watch.reporter.ts — Compact output for watch mode scan cycles
import chalk from "chalk";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import type { NetworkChange } from "../analyser/diff.js";
import { TEAL, AMBER } from "./render-helpers.js";

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDuration(ms: number): string {
  const secs = Math.round(ms / 1000);
  return `${secs}s`;
}

export function renderWatchBaseline(result: NetworkScanResult, score: number): string {
  const time = formatTime(result.meta.timestamp);
  const duration = formatDuration(result.meta.duration);
  const hosts = result.network.hosts.length;
  const ssid = result.wifi.ssid ?? "(hidden)";

  const lines: string[] = [];
  lines.push(chalk.dim("─".repeat(60)));
  lines.push(
    TEAL(`[${time}]`) +
    ` Baseline scan — ${ssid} — score: ${score.toFixed(1)}/10 — ${hosts} hosts — ${duration}`,
  );
  lines.push(chalk.dim("Watching for changes... Press Ctrl+C to stop."));
  return lines.join("\n");
}

export function renderWatchCycle(
  cycle: number,
  result: NetworkScanResult,
  score: number,
  changes: NetworkChange[],
): string {
  const time = formatTime(result.meta.timestamp);
  const duration = formatDuration(result.meta.duration);
  const hosts = result.network.hosts.length;

  const lines: string[] = [];
  lines.push(chalk.dim("─".repeat(60)));

  const summaryColour = changes.length > 0 ? AMBER : TEAL;
  lines.push(
    summaryColour(`[${time}]`) +
    ` Scan #${cycle} — score: ${score.toFixed(1)}/10 — ${hosts} hosts — ${duration}`,
  );

  for (const change of changes) {
    lines.push(renderAlert(change));
  }

  return lines.join("\n");
}

function renderAlert(change: NetworkChange): string {
  const prefix = AMBER("  \u25B2 ALERT:");

  switch (change.type) {
    case "host:joined": {
      const vendor = change.vendor ? ` (${change.vendor})` : "";
      return `${prefix} New host joined: ${change.ip}${vendor}`;
    }
    case "host:left": {
      const vendor = change.vendor ? ` (${change.vendor})` : "";
      return `${prefix} Host left: ${change.ip}${vendor}`;
    }
    case "port:opened":
      return `${prefix} Port ${change.port}/${change.service} opened on ${change.ip}`;
    case "port:closed":
      return `${prefix} Port ${change.port}/${change.service} closed on ${change.ip}`;
    case "security:changed":
      return `${prefix} Security change — ${change.field}: ${change.from} -> ${change.to}`;
    case "wifi:changed":
      return `${prefix} WiFi change — ${change.field}: ${change.from} -> ${change.to}`;
  }
}
