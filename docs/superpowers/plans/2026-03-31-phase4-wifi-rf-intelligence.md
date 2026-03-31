# Phase 4: WiFi RF Intelligence — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add channel occupancy mapping, saturation scoring, optimal channel recommendations, rogue AP detection, WiFi environment change detection, and signal trend tracking to WiFi Sentinel.

**Architecture:** A new `src/analyser/rf/` module with three focused sub-modules (channel-map, rogue-ap, environment) producing an `RFAnalysis` object. A dedicated `wifisentinel rf` command for detailed RF output, plus a condensed summary integrated into the existing scan reports.

**Tech Stack:** TypeScript (ES2022, Node16 modules), Zod, chalk, commander — no new dependencies.

---

### Task 1: RF analysis types

**Files:**
- Create: `src/analyser/rf/types.ts`

- [ ] **Step 1: Create the RF types file**

```ts
// src/analyser/rf/types.ts
import { z } from "zod";

export const ChannelInfo = z.object({
  channel: z.number(),
  band: z.enum(["2.4GHz", "5GHz"]),
  networkCount: z.number(),
  overlapCount: z.number(),
  saturationScore: z.number(),
  networks: z.array(z.object({
    ssid: z.string().nullable(),
    signal: z.number(),
    security: z.string(),
  })),
});
export type ChannelInfo = z.infer<typeof ChannelInfo>;

export const ChannelMap = z.object({
  channels: z.array(ChannelInfo),
  currentChannel: z.number(),
  currentBand: z.string(),
  currentSaturation: z.number(),
  recommendedChannel: z.number(),
  recommendationReason: z.string(),
});
export type ChannelMap = z.infer<typeof ChannelMap>;

export const RogueAPFinding = z.object({
  ssid: z.string(),
  bssid: z.string().optional(),
  channel: z.number(),
  signal: z.number(),
  security: z.string(),
  indicators: z.array(z.string()),
  severity: z.enum(["high", "medium", "low"]),
  description: z.string(),
});
export type RogueAPFinding = z.infer<typeof RogueAPFinding>;

export const RogueAPAnalysis = z.object({
  findings: z.array(RogueAPFinding),
  riskLevel: z.enum(["clear", "suspicious", "danger"]),
});
export type RogueAPAnalysis = z.infer<typeof RogueAPAnalysis>;

export const EnvironmentChange = z.object({
  type: z.enum(["new_ap", "disappeared_ap", "security_change", "signal_anomaly", "channel_change"]),
  ssid: z.string().nullable(),
  bssid: z.string().optional(),
  detail: z.string(),
  severity: z.enum(["high", "medium", "low"]),
});
export type EnvironmentChange = z.infer<typeof EnvironmentChange>;

export const EnvironmentAnalysis = z.object({
  baselineScanId: z.string(),
  baselineTimestamp: z.string(),
  changes: z.array(EnvironmentChange),
  summary: z.string(),
});
export type EnvironmentAnalysis = z.infer<typeof EnvironmentAnalysis>;

export const RFAnalysis = z.object({
  channelMap: ChannelMap,
  rogueAPs: RogueAPAnalysis,
  environment: EnvironmentAnalysis.optional(),
});
export type RFAnalysis = z.infer<typeof RFAnalysis>;
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/analyser/rf/types.ts
git commit -m "add RF analysis types and Zod schemas"
```

---

### Task 2: Channel map and saturation scoring

**Files:**
- Create: `src/analyser/rf/channel-map.ts`

- [ ] **Step 1: Create the channel map module**

```ts
// src/analyser/rf/channel-map.ts
import type { NetworkScanResult, NearbyNetwork } from "../../collector/schema/scan-result.js";
import type { ChannelInfo, ChannelMap } from "./types.js";

/** 2.4 GHz channels 1-14. A 20 MHz signal on channel N overlaps N-2 to N+2. */
const CHANNELS_2_4 = Array.from({ length: 14 }, (_, i) => i + 1);

/** Common 5 GHz channels (UNII-1 through UNII-3). */
const CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];

/** Non-overlapping 2.4 GHz channels for recommendations. */
const NON_OVERLAPPING_2_4 = [1, 6, 11];

/**
 * Convert signal dBm to a linear weight (0-1).
 * -30 dBm (strongest typical) -> 1.0, -100 dBm (noise floor) -> 0.0
 */
function signalWeight(signal: number): number {
  const clamped = Math.max(-100, Math.min(-30, signal));
  return (clamped + 100) / 70;
}

/**
 * Compute saturation score (0-100) for a channel given direct and overlapping networks.
 * Factors: network count, cumulative signal weight, overlap penalty.
 */
function computeSaturation(directNetworks: number, directSignalSum: number, overlapNetworks: number, overlapSignalSum: number): number {
  // Direct networks contribute fully, overlapping networks contribute at 50%
  const effectiveLoad = directSignalSum + overlapSignalSum * 0.5;
  const effectiveCount = directNetworks + overlapNetworks * 0.5;

  // Saturation: each strong network (~1.0 weight) contributes ~25 points,
  // capped at 100. Empty channel = 0.
  const score = Math.min(100, Math.round(effectiveLoad * 25 + effectiveCount * 5));
  return score;
}

function channelBand(channel: number): "2.4GHz" | "5GHz" {
  return channel <= 14 ? "2.4GHz" : "5GHz";
}

interface NetworkEntry {
  ssid: string | null;
  signal: number;
  security: string;
  channel: number;
}

export function buildChannelMap(wifi: NetworkScanResult["wifi"]): ChannelMap {
  // Combine current network + nearby networks into a single list
  const allNetworks: NetworkEntry[] = [
    { ssid: wifi.ssid, signal: wifi.signal, security: wifi.security, channel: wifi.channel },
    ...wifi.nearbyNetworks.map(n => ({
      ssid: n.ssid,
      signal: n.signal,
      security: n.security,
      channel: n.channel,
    })),
  ];

  const currentBand = channelBand(wifi.channel);
  const channelList = currentBand === "2.4GHz" ? CHANNELS_2_4 : CHANNELS_5;

  const channels: ChannelInfo[] = channelList.map(ch => {
    const band = channelBand(ch);
    const directNets = allNetworks.filter(n => n.channel === ch && channelBand(n.channel) === band);
    const directSignalSum = directNets.reduce((sum, n) => sum + signalWeight(n.signal), 0);

    // Overlap: 2.4 GHz only, channels within +/- 2
    let overlapNets: NetworkEntry[] = [];
    let overlapSignalSum = 0;
    if (band === "2.4GHz") {
      overlapNets = allNetworks.filter(n =>
        channelBand(n.channel) === "2.4GHz" &&
        n.channel !== ch &&
        Math.abs(n.channel - ch) <= 2
      );
      overlapSignalSum = overlapNets.reduce((sum, n) => sum + signalWeight(n.signal), 0);
    }

    const saturationScore = computeSaturation(
      directNets.length, directSignalSum,
      overlapNets.length, overlapSignalSum,
    );

    return {
      channel: ch,
      band,
      networkCount: directNets.length,
      overlapCount: overlapNets.length,
      saturationScore,
      networks: directNets.map(n => ({ ssid: n.ssid, signal: n.signal, security: n.security })),
    };
  });

  // Find current channel saturation
  const currentInfo = channels.find(c => c.channel === wifi.channel);
  const currentSaturation = currentInfo?.saturationScore ?? 0;

  // Recommend: least-saturated non-overlapping channel in same band
  const candidates = currentBand === "2.4GHz"
    ? channels.filter(c => NON_OVERLAPPING_2_4.includes(c.channel))
    : channels;

  const best = candidates.reduce((a, b) => a.saturationScore <= b.saturationScore ? a : b);

  let recommendedChannel = best.channel;
  let recommendationReason: string;

  if (best.channel === wifi.channel) {
    recommendedChannel = wifi.channel;
    recommendationReason = `Current channel ${wifi.channel} is already optimal (saturation ${currentSaturation}%)`;
  } else {
    recommendationReason = `Channel ${best.channel} has saturation ${best.saturationScore}% vs current ${currentSaturation}%`;
  }

  return {
    channels,
    currentChannel: wifi.channel,
    currentBand,
    currentSaturation,
    recommendedChannel,
    recommendationReason,
  };
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/analyser/rf/channel-map.ts
git commit -m "add channel map with saturation scoring and recommendations"
```

---

### Task 3: Rogue AP detection

**Files:**
- Create: `src/analyser/rf/rogue-ap.ts`

- [ ] **Step 1: Create the rogue AP detection module**

```ts
// src/analyser/rf/rogue-ap.ts
import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { RogueAPFinding, RogueAPAnalysis } from "./types.js";

/** Security strength ordering (lower index = weaker). */
const SECURITY_STRENGTH = [
  "None",
  "WEP",
  "WPA Personal",
  "WPA2 Personal",
  "WPA2/WPA3 Personal",
  "WPA3 Personal",
  "WPA Enterprise",
  "WPA2 Enterprise",
  "WPA3 Enterprise",
];

function securityIndex(security: string): number {
  const normalised = security.trim();
  const idx = SECURITY_STRENGTH.findIndex(s =>
    normalised.toLowerCase().includes(s.toLowerCase())
  );
  return idx >= 0 ? idx : -1;
}

function isWeakerSecurity(suspect: string, current: string): boolean {
  const si = securityIndex(suspect);
  const ci = securityIndex(current);
  if (si < 0 || ci < 0) return false;
  return si < ci;
}

export function detectRogueAPs(wifi: NetworkScanResult["wifi"]): RogueAPAnalysis {
  const findings: RogueAPFinding[] = [];
  const currentSsid = wifi.ssid;

  if (!currentSsid) {
    return { findings: [], riskLevel: "clear" };
  }

  for (const nearby of wifi.nearbyNetworks) {
    if (nearby.ssid !== currentSsid) continue;

    const indicators: string[] = [];
    let severity: RogueAPFinding["severity"] = "low";
    const descParts: string[] = [];

    // Rule 1: Same SSID, different BSSID
    if (nearby.bssid && nearby.bssid !== wifi.bssid) {
      indicators.push("different_bssid");
      descParts.push(`BSSID ${nearby.bssid} differs from current ${wifi.bssid}`);
      severity = "medium";
    }

    // Rule 2: Same SSID, weaker security
    if (isWeakerSecurity(nearby.security, wifi.security)) {
      indicators.push("weaker_security");
      descParts.push(`Security downgraded: ${nearby.security} vs current ${wifi.security}`);
      severity = "high";
    }

    // Rule 3: Same SSID, different channel
    if (nearby.channel !== wifi.channel) {
      indicators.push("different_channel");
      descParts.push(`On channel ${nearby.channel} vs current ${wifi.channel}`);
      if (severity === "low") severity = "low";
    }

    if (indicators.length === 0) continue;

    // Escalate: multiple indicators together are more suspicious
    if (indicators.length >= 2 && severity === "low") severity = "medium";
    if (indicators.includes("weaker_security") && indicators.includes("different_bssid")) severity = "high";

    findings.push({
      ssid: currentSsid,
      bssid: nearby.bssid,
      channel: nearby.channel,
      signal: nearby.signal,
      security: nearby.security,
      indicators,
      severity,
      description: descParts.join(". "),
    });
  }

  let riskLevel: RogueAPAnalysis["riskLevel"] = "clear";
  if (findings.some(f => f.severity === "high")) riskLevel = "danger";
  else if (findings.some(f => f.severity === "medium")) riskLevel = "suspicious";

  return { findings, riskLevel };
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/analyser/rf/rogue-ap.ts
git commit -m "add rogue AP and evil twin detection"
```

---

### Task 4: WiFi environment change detection

**Files:**
- Create: `src/analyser/rf/environment.ts`

- [ ] **Step 1: Create the environment change detection module**

```ts
// src/analyser/rf/environment.ts
import type { NetworkScanResult, NearbyNetwork } from "../../collector/schema/scan-result.js";
import type { EnvironmentChange, EnvironmentAnalysis } from "./types.js";

/** Key for matching APs across scans. Uses BSSID if available, else SSID+channel. */
function apKey(n: NearbyNetwork): string {
  if (n.bssid) return `bssid:${n.bssid}`;
  return `ssid:${n.ssid ?? "(hidden)"}:ch${n.channel}`;
}

const SIGNAL_ANOMALY_THRESHOLD = 15; // dB

export function detectEnvironmentChanges(
  current: NetworkScanResult["wifi"],
  baseline: NetworkScanResult["wifi"],
  baselineMeta: { scanId: string; timestamp: string },
): EnvironmentAnalysis {
  const changes: EnvironmentChange[] = [];

  const currentMap = new Map(current.nearbyNetworks.map(n => [apKey(n), n]));
  const baselineMap = new Map(baseline.nearbyNetworks.map(n => [apKey(n), n]));

  // New APs
  for (const [key, net] of currentMap) {
    if (!baselineMap.has(key)) {
      changes.push({
        type: "new_ap",
        ssid: net.ssid,
        bssid: net.bssid,
        detail: `New AP detected on channel ${net.channel} (${net.security}, ${net.signal} dBm)`,
        severity: "medium",
      });
    }
  }

  // Disappeared APs
  for (const [key, net] of baselineMap) {
    if (!currentMap.has(key)) {
      changes.push({
        type: "disappeared_ap",
        ssid: net.ssid,
        bssid: net.bssid,
        detail: `AP no longer visible (was on channel ${net.channel}, ${net.signal} dBm)`,
        severity: "low",
      });
    }
  }

  // Changes on matched APs
  for (const [key, current_net] of currentMap) {
    const baseline_net = baselineMap.get(key);
    if (!baseline_net) continue;

    // Security change
    if (current_net.security !== baseline_net.security) {
      const isDowngrade = current_net.security.length < baseline_net.security.length;
      changes.push({
        type: "security_change",
        ssid: current_net.ssid,
        bssid: current_net.bssid,
        detail: `Security changed: ${baseline_net.security} -> ${current_net.security}`,
        severity: isDowngrade ? "high" : "medium",
      });
    }

    // Signal anomaly
    const signalDelta = Math.abs(current_net.signal - baseline_net.signal);
    if (signalDelta >= SIGNAL_ANOMALY_THRESHOLD) {
      changes.push({
        type: "signal_anomaly",
        ssid: current_net.ssid,
        bssid: current_net.bssid,
        detail: `Signal changed by ${signalDelta} dB (${baseline_net.signal} -> ${current_net.signal} dBm)`,
        severity: signalDelta >= 25 ? "high" : "medium",
      });
    }

    // Channel change (only for BSSID-matched APs to avoid false positives)
    if (current_net.bssid && current_net.channel !== baseline_net.channel) {
      changes.push({
        type: "channel_change",
        ssid: current_net.ssid,
        bssid: current_net.bssid,
        detail: `Channel changed: ${baseline_net.channel} -> ${current_net.channel}`,
        severity: "low",
      });
    }
  }

  // Build summary
  const counts = new Map<string, number>();
  for (const c of changes) {
    counts.set(c.type, (counts.get(c.type) ?? 0) + 1);
  }
  const parts: string[] = [];
  if (counts.get("new_ap")) parts.push(`${counts.get("new_ap")} new AP(s)`);
  if (counts.get("disappeared_ap")) parts.push(`${counts.get("disappeared_ap")} disappeared`);
  if (counts.get("security_change")) parts.push(`${counts.get("security_change")} security change(s)`);
  if (counts.get("signal_anomaly")) parts.push(`${counts.get("signal_anomaly")} signal anomaly(s)`);
  if (counts.get("channel_change")) parts.push(`${counts.get("channel_change")} channel change(s)`);
  const summary = changes.length === 0
    ? "No environment changes detected"
    : `${changes.length} change(s): ${parts.join(", ")}`;

  return {
    baselineScanId: baselineMeta.scanId,
    baselineTimestamp: baselineMeta.timestamp,
    changes,
    summary,
  };
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/analyser/rf/environment.ts
git commit -m "add WiFi environment change detection"
```

---

### Task 5: RF analysis entry point

**Files:**
- Create: `src/analyser/rf/index.ts`

- [ ] **Step 1: Create the RF analysis entry point**

```ts
// src/analyser/rf/index.ts
import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { RFAnalysis } from "./types.js";
import { buildChannelMap } from "./channel-map.js";
import { detectRogueAPs } from "./rogue-ap.js";
import { detectEnvironmentChanges } from "./environment.js";

export { buildChannelMap } from "./channel-map.js";
export { detectRogueAPs } from "./rogue-ap.js";
export { detectEnvironmentChanges } from "./environment.js";
export type {
  RFAnalysis,
  ChannelMap,
  ChannelInfo,
  RogueAPAnalysis,
  RogueAPFinding,
  EnvironmentAnalysis,
  EnvironmentChange,
} from "./types.js";

export function analyseRF(
  result: NetworkScanResult,
  baseline?: { wifi: NetworkScanResult["wifi"]; meta: { scanId: string; timestamp: string } },
): RFAnalysis {
  const channelMap = buildChannelMap(result.wifi);
  const rogueAPs = detectRogueAPs(result.wifi);
  const environment = baseline
    ? detectEnvironmentChanges(result.wifi, baseline.wifi, baseline.meta)
    : undefined;

  return { channelMap, rogueAPs, environment };
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/analyser/rf/index.ts
git commit -m "add RF analysis entry point"
```

---

### Task 6: RF terminal reporter

**Files:**
- Create: `src/reporter/rf.reporter.ts`

- [ ] **Step 1: Create the RF reporter**

```ts
// src/reporter/rf.reporter.ts
import chalk from "chalk";
import type { RFAnalysis, ChannelInfo, RogueAPFinding, EnvironmentChange } from "../analyser/rf/index.js";
import { pad } from "./render-helpers.js";

function saturationBar(score: number): string {
  const filled = Math.round(score / 10);
  const empty = 10 - filled;
  const color = score <= 30 ? chalk.green : score <= 60 ? chalk.yellow : chalk.red;
  return color("█".repeat(filled)) + chalk.gray("░".repeat(empty));
}

function severityColor(severity: "high" | "medium" | "low"): (s: string) => string {
  if (severity === "high") return chalk.red;
  if (severity === "medium") return chalk.yellow;
  return chalk.dim;
}

function renderChannelMap(analysis: RFAnalysis): string {
  const { channelMap } = analysis;
  const lines: string[] = [];

  lines.push(chalk.bold(`  ${channelMap.currentBand} Channel Occupancy`));
  lines.push("");

  for (const ch of channelMap.channels) {
    if (ch.saturationScore === 0 && ch.networkCount === 0 && ch.overlapCount === 0) continue;

    const bar = saturationBar(ch.saturationScore);
    const pct = pad(String(ch.saturationScore) + "%", 5);
    const marker = ch.channel === channelMap.currentChannel ? chalk.cyan("  <- YOU ARE HERE") : "";

    let detail = "";
    if (ch.networkCount > 0 && ch.overlapCount > 0) {
      detail = `(${ch.networkCount} network${ch.networkCount > 1 ? "s" : ""}, +${ch.overlapCount} overlap)`;
    } else if (ch.networkCount > 0) {
      detail = `(${ch.networkCount} network${ch.networkCount > 1 ? "s" : ""})`;
    } else if (ch.overlapCount > 0) {
      detail = `(overlap only)`;
    }

    lines.push(`  ${pad("Ch " + ch.channel, 7)} ${bar}  ${pct}  ${chalk.dim(detail)}${marker}`);
  }

  lines.push("");

  if (channelMap.recommendedChannel === channelMap.currentChannel) {
    lines.push(chalk.green(`  ${channelMap.recommendationReason}`));
  } else {
    lines.push(chalk.yellow(`  Recommendation: Switch to channel ${channelMap.recommendedChannel}`));
    lines.push(chalk.dim(`  ${channelMap.recommendationReason}`));
  }

  return lines.join("\n");
}

function renderRogueAPs(analysis: RFAnalysis): string {
  const { rogueAPs } = analysis;
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.bold("  Rogue AP Detection"));
  lines.push("");

  if (rogueAPs.findings.length === 0) {
    lines.push(chalk.green("  No rogue APs detected."));
    return lines.join("\n");
  }

  const riskColor = rogueAPs.riskLevel === "danger" ? chalk.red : chalk.yellow;
  lines.push(riskColor(`  Risk: ${rogueAPs.riskLevel.toUpperCase()}`));
  lines.push("");

  for (const f of rogueAPs.findings) {
    const sc = severityColor(f.severity);
    const bssidStr = f.bssid ? chalk.dim(` [${f.bssid}]`) : "";
    lines.push(`  ${sc("[" + f.severity.toUpperCase() + "]")} ${f.ssid}${bssidStr}  ch${f.channel}  ${f.signal} dBm`);
    lines.push(`    ${f.description}`);
    lines.push(`    ${chalk.dim("Indicators: " + f.indicators.join(", "))}`);
  }

  return lines.join("\n");
}

function renderEnvironment(analysis: RFAnalysis): string {
  const { environment } = analysis;
  if (!environment) return "";

  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.bold("  WiFi Environment Changes"));
  const baseDate = new Date(environment.baselineTimestamp).toLocaleString();
  lines.push(chalk.dim(`  Compared to scan ${environment.baselineScanId.slice(0, 8)} (${baseDate})`));
  lines.push("");

  if (environment.changes.length === 0) {
    lines.push(chalk.green("  No environment changes detected."));
    return lines.join("\n");
  }

  lines.push(chalk.dim(`  ${environment.summary}`));
  lines.push("");

  for (const c of environment.changes) {
    const sc = severityColor(c.severity);
    const icon = c.type === "new_ap" ? "+" : c.type === "disappeared_ap" ? "-" : "~";
    const iconColor = c.type === "new_ap" ? chalk.green : c.type === "disappeared_ap" ? chalk.red : chalk.yellow;
    const ssid = c.ssid ?? "(hidden)";
    lines.push(`  ${iconColor(icon)} ${sc("[" + c.severity.toUpperCase() + "]")} ${ssid}: ${c.detail}`);
  }

  return lines.join("\n");
}

export function renderRFReport(analysis: RFAnalysis): string {
  const sections = [
    renderChannelMap(analysis),
    renderRogueAPs(analysis),
    renderEnvironment(analysis),
  ].filter(Boolean);

  return sections.join("\n");
}

/** Condensed one-line summary for embedding in main scan output. */
export function renderRFSummary(analysis: RFAnalysis): string {
  const { channelMap, rogueAPs } = analysis;
  const lines: string[] = [];

  const satColor = channelMap.currentSaturation <= 30 ? chalk.green
    : channelMap.currentSaturation <= 60 ? chalk.yellow : chalk.red;

  let channelLine = `Channel ${channelMap.currentChannel} saturation: ${satColor(channelMap.currentSaturation + "%")}`;
  if (channelMap.recommendedChannel !== channelMap.currentChannel) {
    channelLine += chalk.yellow(` — consider channel ${channelMap.recommendedChannel}`);
  }
  lines.push(channelLine);

  if (rogueAPs.findings.length === 0) {
    lines.push(`Rogue APs: ${chalk.green("clear")}`);
  } else {
    const riskColor = rogueAPs.riskLevel === "danger" ? chalk.red : chalk.yellow;
    lines.push(`Rogue APs: ${riskColor(rogueAPs.riskLevel.toUpperCase())} (${rogueAPs.findings.length} finding${rogueAPs.findings.length > 1 ? "s" : ""})`);
  }

  return lines.join("\n");
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/reporter/rf.reporter.ts
git commit -m "add RF terminal reporter with channel map and rogue AP rendering"
```

---

### Task 7: RF CLI command

**Files:**
- Create: `src/commands/rf.ts`
- Modify: `src/cli.ts`

- [ ] **Step 1: Create the RF command handler**

```ts
// src/commands/rf.ts
import chalk from "chalk";
import type { Command } from "commander";
import { scanWifi } from "../collector/scanners/wifi.scanner.js";
import { analyseRF } from "../analyser/rf/index.js";
import { renderRFReport } from "../reporter/rf.reporter.js";
import { loadScan, listScans, type IndexEntry } from "../store/index.js";
import { pad } from "../reporter/render-helpers.js";

function renderSignalTrend(entries: IndexEntry[], scans: Array<{ wifi: { signal: number; snr: number; txRate: number; channel: number; nearbyNetworks: { length: number } } }>): string {
  const lines: string[] = [];

  lines.push(chalk.bold("  WiFi Signal Trends"));
  lines.push("");

  const header =
    pad(chalk.bold("DATE"), 16) +
    pad(chalk.bold("SIGNAL"), 9) +
    pad(chalk.bold("SNR"), 6) +
    pad(chalk.bold("TX RATE"), 10) +
    pad(chalk.bold("CH"), 5) +
    chalk.bold("NEARBY");
  lines.push("  " + header);
  lines.push("  " + chalk.dim("─".repeat(55)));

  // Render oldest first
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i];
    const w = scans[i].wifi;
    const date = new Date(e.timestamp).toLocaleDateString("en-GB", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
    lines.push("  " +
      pad(chalk.dim(date), 16) +
      pad(String(w.signal), 9) +
      pad(String(w.snr), 6) +
      pad(w.txRate + " Mbps", 10) +
      pad(String(w.channel), 5) +
      String(w.nearbyNetworks.length),
    );
  }

  // Summary line
  if (scans.length >= 2) {
    const first = scans[scans.length - 1].wifi;
    const last = scans[0].wifi;
    const signalDir = last.signal > first.signal ? chalk.green("improving") : last.signal < first.signal ? chalk.red("declining") : chalk.yellow("stable");
    const snrDir = last.snr > first.snr ? chalk.green("improving") : last.snr < first.snr ? chalk.red("declining") : chalk.yellow("stable");
    const nearbyFirst = scans[scans.length - 1].wifi.nearbyNetworks.length;
    const nearbyLast = scans[0].wifi.nearbyNetworks.length;
    const nearbyDir = nearbyLast > nearbyFirst ? chalk.yellow("growing") : nearbyLast < nearbyFirst ? chalk.green("shrinking") : chalk.dim("stable");

    lines.push("  " + chalk.dim("─".repeat(55)));
    lines.push(`  Signal: ${signalDir}  SNR: ${snrDir}  Nearby APs: ${nearbyDir}`);
  }

  return lines.join("\n");
}

export function registerRFCommand(program: Command): void {
  program
    .command("rf")
    .description("Analyse WiFi RF environment (channel map, rogue APs)")
    .option("--json", "Output as JSON")
    .option("--compare <scanId>", "Compare against a stored scan")
    .option("--trend", "Show WiFi signal trends over time")
    .option("-n, --limit <count>", "Number of scans for --trend", "10")
    .action(async (opts) => {
      try {
        // Trend mode: read from store, no live scan
        if (opts.trend) {
          const entries = listScans({ limit: parseInt(opts.limit, 10) });
          if (entries.length === 0) {
            console.log(chalk.dim("No scans in history. Run 'wifisentinel scan' first."));
            return;
          }
          const scans = entries.map(e => {
            const stored = loadScan(e.scanId);
            return stored.scan;
          });

          if (opts.json) {
            const data = entries.map((e, i) => ({
              scanId: e.scanId,
              timestamp: e.timestamp,
              signal: scans[i].wifi.signal,
              snr: scans[i].wifi.snr,
              txRate: scans[i].wifi.txRate,
              channel: scans[i].wifi.channel,
              nearbyNetworks: scans[i].wifi.nearbyNetworks.length,
            }));
            console.log(JSON.stringify(data, null, 2));
            return;
          }

          console.log(renderSignalTrend(entries, scans));
          return;
        }

        // Live RF scan
        const wifi = await scanWifi();
        // Build a minimal result object for analyseRF
        const minimalResult = { wifi } as any;

        let baseline: { wifi: typeof wifi; meta: { scanId: string; timestamp: string } } | undefined;
        if (opts.compare) {
          const stored = loadScan(opts.compare);
          baseline = {
            wifi: stored.scan.wifi,
            meta: { scanId: stored.scan.meta.scanId, timestamp: stored.scan.meta.timestamp },
          };
        }

        const analysis = analyseRF(minimalResult, baseline);

        if (opts.json) {
          console.log(JSON.stringify(analysis, null, 2));
          return;
        }

        console.log("");
        console.log(chalk.bold.cyan("  RF INTELLIGENCE"));
        console.log("");
        console.log(renderRFReport(analysis));
        console.log("");
      } catch (err: any) {
        console.error(chalk.red(err.message));
        process.exit(1);
      }
    });
}
```

- [ ] **Step 2: Register the command in cli.ts**

At the top of `src/cli.ts`, add:

```ts
import { registerRFCommand } from "./commands/rf.js";
```

Before `program.parse()`, add:

```ts
registerRFCommand(program);
```

- [ ] **Step 3: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Test the rf command**

Run: `npx tsx src/cli.ts rf`
Expected: Channel map with saturation bars, recommendation, and rogue AP section.

- [ ] **Step 5: Commit**

```bash
git add src/commands/rf.ts src/cli.ts
git commit -m "add rf command for WiFi RF intelligence"
```

---

### Task 8: Integrate RF summary into main scan reports

**Files:**
- Modify: `src/reporter/terminal.reporter.ts`
- Modify: `src/reporter/analysis.reporter.ts`

- [ ] **Step 1: Add RF summary to terminal reporter**

Read `src/reporter/terminal.reporter.ts`. Add the import at the top:

```ts
import { analyseRF } from "../analyser/rf/index.js";
import { renderRFSummary } from "./rf.reporter.js";
```

Add a new section renderer function:

```ts
function renderRFIntelligence(result: NetworkScanResult): string {
  const analysis = analyseRF(result);
  const summary = renderRFSummary(analysis);
  const lines: string[] = [
    sectionHeader("RF INTELLIGENCE"),
    row(""),
  ];
  for (const line of summary.split("\n")) {
    lines.push(row("  " + line));
  }
  lines.push(row(""));
  return lines.join("\n");
}
```

In the `renderTerminalReport` function, add `renderRFIntelligence(result)` to the sections array, after `renderWifiDetails(result)`:

```ts
export function renderTerminalReport(result: NetworkScanResult): string {
  const sections: string[] = [
    renderHeader(result),
    renderNetworkMap(result),
    renderWifiDetails(result),
    renderRFIntelligence(result),    // <-- add this line
    renderSecurityPosture(result),
    renderDnsAudit(result),
    renderHiddenDeviceAlerts(result),
    renderIntrusionIndicators(result),
    renderExposedServices(result),
    renderConnectionsSummary(result),
    renderSpeedTest(result),
    renderScorecard(result),
  ].filter(Boolean);

  return sections.join("\n");
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Test the integration**

Run: `npx tsx src/cli.ts scan --skip-ports --skip-speed --skip-traffic 2>/dev/null | grep -A5 "RF INTELLIGENCE"`
Expected: The RF Intelligence section should appear with channel saturation and rogue AP status.

- [ ] **Step 4: Commit**

```bash
git add src/reporter/terminal.reporter.ts
git commit -m "add RF intelligence summary to terminal scan report"
```

Note: the analysis reporter calls `renderTerminalReport(result)` internally, so the RF summary automatically appears in the `analyse` output too. No separate modification needed for `analysis.reporter.ts`.

---

### Task 9: Add rfAnalysis to StoredScan and save it

**Files:**
- Modify: `src/store/types.ts`
- Modify: `src/store/index.ts`
- Modify: `src/cli.ts`

- [ ] **Step 1: Add rfAnalysis to StoredScan**

In `src/store/types.ts`, add the import and update the interface:

```ts
// Add at top:
import type { RFAnalysis } from "../analyser/rf/types.js";

// Change StoredScan to:
export interface StoredScan {
  scan: NetworkScanResult;
  compliance: ComplianceReport;
  analysis: FullAnalysis;
  rfAnalysis?: RFAnalysis;
}
```

- [ ] **Step 2: Update saveScan to accept rfAnalysis**

In `src/store/index.ts`, update the `saveScan` function signature and body.

Add import at top:

```ts
import type { RFAnalysis } from "../analyser/rf/types.js";
```

Change the function signature:

```ts
export function saveScan(
  result: NetworkScanResult,
  compliance: ComplianceReport,
  analysis: FullAnalysis,
  rfAnalysis?: RFAnalysis,
): void {
```

Update the stored object:

```ts
  const stored: StoredScan = { scan: result, compliance, analysis, rfAnalysis };
```

- [ ] **Step 3: Update cli.ts to compute and pass rfAnalysis when saving**

In `src/cli.ts`, add import:

```ts
import { analyseRF } from "./analyser/rf/index.js";
```

In both the `scan` and `analyse` command save blocks, change:

```ts
      if (opts.save) {
        const compliance = scoreAllStandards(result);
        const analysis = analyseAllPersonas(result);
        const rfAnalysis = analyseRF(result);
        saveScan(result, compliance, analysis, rfAnalysis);
```

(Add the `rfAnalysis` line and pass it to `saveScan` in both command handlers.)

- [ ] **Step 4: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add src/store/types.ts src/store/index.ts src/cli.ts
git commit -m "persist RF analysis in stored scans"
```

---

### Task 10: Update ROADMAP.md

**Files:**
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update Phase 4 status**

Change the Phase 4 section to:

```markdown
## Phase 4: WiFi RF Intelligence (COMPLETE)

- [x] Channel utilisation map: 2.4 GHz and 5 GHz channel occupancy from nearby networks
- [x] Channel saturation scoring: overlap calculation, co-channel interference count, signal-weighted penalty
- [x] Optimal channel recommendation engine based on local RF environment
- [x] Signal strength trends over time (rf --trend, reads from scan history)
- [x] Rogue AP / evil twin detection: nearby APs matching SSID with different BSSID or weaker security
- [ ] Deauth flood detection via frame counters (deferred — requires monitor mode)
- [x] WiFi environment change detection: new APs, signal anomalies, security downgrades between scans
```

- [ ] **Step 2: Commit**

```bash
git add ROADMAP.md
git commit -m "mark Phase 4 WiFi RF intelligence as complete"
```

---

### Task 11: End-to-end integration test

- [ ] **Step 1: Typecheck**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 2: Build**

Run: `npm run build`
Expected: Clean compilation.

- [ ] **Step 3: Test rf command**

Run: `npx tsx src/cli.ts rf`
Expected: Channel map with saturation bars, recommendation line, rogue AP section.

- [ ] **Step 4: Test rf --json**

Run: `npx tsx src/cli.ts rf --json 2>/dev/null | head -30`
Expected: JSON with channelMap, rogueAPs fields.

- [ ] **Step 5: Test rf --trend**

Run: `npx tsx src/cli.ts rf --trend`
Expected: Signal trend table from stored scans, or "No scans in history" message.

- [ ] **Step 6: Test rf --compare**

Get latest scan ID: `npx tsx src/cli.ts history --json 2>/dev/null | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));if(d.length)process.stdout.write(d[0].scanId.slice(0,8))"`

Run: `npx tsx src/cli.ts rf --compare <id>`
Expected: RF report with "WiFi Environment Changes" section.

- [ ] **Step 7: Test RF section in main scan**

Run: `npx tsx src/cli.ts scan --skip-ports --skip-speed --skip-traffic 2>/dev/null | grep -A5 "RF INTELLIGENCE"`
Expected: RF Intelligence section with channel saturation and rogue AP status.

- [ ] **Step 8: Verify rfAnalysis is persisted**

Run: `npx tsx src/cli.ts scan --skip-ports --skip-speed --skip-traffic 2>/dev/null > /dev/null && cat ~/.wifisentinel/scans/*.json | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log('rfAnalysis present:',!!d.rfAnalysis)"`
Expected: `rfAnalysis present: true` (from the most recent scan file).

- [ ] **Step 9: Test help**

Run: `npx tsx src/cli.ts --help`
Expected: `rf` command appears in command list.
