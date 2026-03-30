# Phase 2: Observability Pipeline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add scan persistence, history browsing, diff comparison, trend tracking, and OS-level scheduled scanning to WiFi Sentinel.

**Architecture:** JSON files in `~/.wifisentinel/scans/` with an `index.json` manifest for fast listing. Four new CLI commands (`history`, `diff`, `trend`, `schedule`) registered via commander. The existing `scan`/`analyse` commands auto-save results after rendering.

**Tech Stack:** Node.js (fs, path, os, child_process), Zod, chalk, commander — no new dependencies.

---

### Task 1: Store types and Zod schemas

**Files:**
- Create: `src/store/types.ts`

- [ ] **Step 1: Create the store types file**

```ts
// src/store/types.ts
import { z } from "zod";
import { NetworkScanResult } from "../collector/schema/scan-result.js";
import { ComplianceReport } from "../analyser/standards/types.js";
import { FullAnalysis } from "../analyser/personas/types.js";

export const IndexEntry = z.object({
  scanId: z.string(),
  timestamp: z.string(),
  ssid: z.string().nullable(),
  securityScore: z.number(),
  complianceGrade: z.string(),
  consensusRisk: z.string(),
  hostCount: z.number(),
  filename: z.string(),
});
export type IndexEntry = z.infer<typeof IndexEntry>;

export const ScanIndex = z.array(IndexEntry);
export type ScanIndex = z.infer<typeof ScanIndex>;

export interface StoredScan {
  scan: NetworkScanResult;
  compliance: ComplianceReport;
  analysis: FullAnalysis;
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/store/types.ts
git commit -m "add store types and Zod schemas for scan persistence"
```

---

### Task 2: Extract computeScore to a shared location

The `computeScore` function currently lives in `src/reporter/terminal.reporter.ts` as a private function. The store needs it to populate `IndexEntry.securityScore`. Move it to a shared location.

**Files:**
- Create: `src/analyser/score.ts`
- Modify: `src/reporter/terminal.reporter.ts`

- [ ] **Step 1: Create the shared score module**

```ts
// src/analyser/score.ts
import type { NetworkScanResult } from "../collector/schema/scan-result.js";

/** Compute an overall security score from 0 to 10. */
export function computeSecurityScore(result: NetworkScanResult): number {
  let score = 10;

  // Firewall
  if (!result.security.firewall.enabled) score -= 2;
  else if (!result.security.firewall.stealthMode) score -= 0.5;

  // VPN
  if (!result.security.vpn.active) score -= 1;

  // DNS
  if (result.network.dns.hijackTestResult === "intercepted") score -= 2;
  if (!result.network.dns.dnssecSupported) score -= 0.5;
  if (result.network.dns.anomalies.length > 0) score -= 0.5;

  // Intrusion indicators
  const ii = result.intrusionIndicators;
  if (ii) {
    const highArp = ii.arpAnomalies.filter(a => a.severity === "high").length;
    const highHost = ii.suspiciousHosts.filter(h => h.severity === "high").length;
    score -= highArp * 0.5;
    score -= highHost * 0.5;
    score -= ii.scanDetection.length * 0.3;
  }

  // Cameras
  if (result.hiddenDevices && result.hiddenDevices.suspectedCameras.length > 0) score -= 1;

  // Exposed services
  const exposed = result.localServices.filter(s => s.exposedToNetwork).length;
  score -= Math.min(exposed * 0.3, 1.5);

  // Kernel params
  if (result.security.kernelParams.ipForwarding) score -= 0.5;
  if (result.security.kernelParams.icmpRedirects) score -= 0.3;

  // Proxy
  if (result.security.proxy.enabled) score -= 0.5;

  // Traffic
  if (result.traffic) {
    score -= Math.min(result.traffic.unencrypted.length * 0.2, 1);
  }

  return Math.max(0, Math.min(10, Math.round(score * 10) / 10));
}
```

- [ ] **Step 2: Update terminal.reporter.ts to use the shared function**

Replace the private `computeScore` function in `src/reporter/terminal.reporter.ts` (lines 393-437) with an import:

```ts
// At the top of terminal.reporter.ts, add:
import { computeSecurityScore } from "../analyser/score.js";

// Replace the entire `function computeScore(result: NetworkScanResult): number { ... }` block with:
// (delete lines 393-437)

// In renderScorecard, change:
//   const score = computeScore(result);
// to:
//   const score = computeSecurityScore(result);
```

- [ ] **Step 3: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Run a quick scan to verify output is unchanged**

Run: `npx tsx src/cli.ts scan --skip-ports --skip-speed --skip-traffic 2>/dev/null | tail -20`
Expected: The scorecard section renders with the same score format as before.

- [ ] **Step 5: Commit**

```bash
git add src/analyser/score.ts src/reporter/terminal.reporter.ts
git commit -m "extract computeSecurityScore to shared analyser module"
```

---

### Task 3: Core store module — saveScan, listScans, loadScan, rebuildIndex

**Files:**
- Create: `src/store/index.ts`

- [ ] **Step 1: Create the store module**

```ts
// src/store/index.ts
import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import type { ComplianceReport } from "../analyser/standards/types.js";
import type { FullAnalysis } from "../analyser/personas/types.js";
import { ScanIndex, type IndexEntry, type StoredScan } from "./types.js";
import { computeSecurityScore } from "../analyser/score.js";

export type { IndexEntry, StoredScan } from "./types.js";

export function getStorePath(): string {
  if (process.platform === "linux" && process.env.XDG_DATA_HOME) {
    return join(process.env.XDG_DATA_HOME, "wifisentinel");
  }
  return join(homedir(), ".wifisentinel");
}

function getScansDir(): string {
  return join(getStorePath(), "scans");
}

function getIndexPath(): string {
  return join(getStorePath(), "index.json");
}

function ensureDirs(): void {
  const scansDir = getScansDir();
  mkdirSync(scansDir, { recursive: true });
}

function readIndex(): IndexEntry[] {
  const indexPath = getIndexPath();
  if (!existsSync(indexPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(indexPath, "utf-8"));
    return ScanIndex.parse(raw);
  } catch {
    return [];
  }
}

function writeIndex(entries: IndexEntry[]): void {
  writeFileSync(getIndexPath(), JSON.stringify(entries, null, 2), "utf-8");
}

function makeFilename(timestamp: string, scanId: string): string {
  const datePart = timestamp.replace(/:/g, "-").replace(/\.\d+Z$/, "");
  const idPrefix = scanId.slice(0, 8);
  return `${datePart}_${idPrefix}.json`;
}

export function saveScan(
  result: NetworkScanResult,
  compliance: ComplianceReport,
  analysis: FullAnalysis,
): void {
  ensureDirs();

  const filename = makeFilename(result.meta.timestamp, result.meta.scanId);
  const stored: StoredScan = { scan: result, compliance, analysis };
  writeFileSync(join(getScansDir(), filename), JSON.stringify(stored, null, 2), "utf-8");

  const entry: IndexEntry = {
    scanId: result.meta.scanId,
    timestamp: result.meta.timestamp,
    ssid: result.wifi.ssid,
    securityScore: computeSecurityScore(result),
    complianceGrade: compliance.overallGrade,
    consensusRisk: analysis.consensusRating,
    hostCount: result.network.hosts.length,
    filename,
  };

  const index = readIndex();
  index.push(entry);
  index.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  writeIndex(index);
}

export interface ListOptions {
  limit?: number;
  ssid?: string;
}

export function listScans(options: ListOptions = {}): IndexEntry[] {
  let entries = readIndex();
  if (entries.length === 0) {
    entries = rebuildIndex();
  }
  if (options.ssid) {
    entries = entries.filter(e => e.ssid === options.ssid);
  }
  if (options.limit) {
    entries = entries.slice(0, options.limit);
  }
  return entries;
}

export function loadScan(scanId: string): StoredScan {
  const entries = readIndex();
  const entry = entries.find(
    e => e.scanId === scanId || e.scanId.startsWith(scanId),
  );
  if (!entry) {
    throw new Error(
      `Scan "${scanId}" not found. Run "wifisentinel history" to list available scans.`,
    );
  }
  const filePath = join(getScansDir(), entry.filename);
  if (!existsSync(filePath)) {
    throw new Error(
      `Scan file missing: ${entry.filename}. Run "wifisentinel rebuild-index" to repair.`,
    );
  }
  return JSON.parse(readFileSync(filePath, "utf-8")) as StoredScan;
}

export function rebuildIndex(): IndexEntry[] {
  ensureDirs();
  const scansDir = getScansDir();
  const files = readdirSync(scansDir).filter(f => f.endsWith(".json"));
  const entries: IndexEntry[] = [];

  for (const filename of files) {
    try {
      const raw = JSON.parse(readFileSync(join(scansDir, filename), "utf-8")) as StoredScan;
      entries.push({
        scanId: raw.scan.meta.scanId,
        timestamp: raw.scan.meta.timestamp,
        ssid: raw.scan.wifi.ssid,
        securityScore: computeSecurityScore(raw.scan),
        complianceGrade: raw.compliance.overallGrade,
        consensusRisk: raw.analysis.consensusRating,
        hostCount: raw.scan.network.hosts.length,
        filename,
      });
    } catch {
      // skip corrupt files
    }
  }

  entries.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  writeIndex(entries);
  return entries;
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/store/index.ts
git commit -m "add core store module for scan persistence"
```

---

### Task 4: Integrate auto-save into scan and analyse commands

**Files:**
- Modify: `src/cli.ts`

- [ ] **Step 1: Add --no-save flag and auto-save logic to the scan command**

At the top of `src/cli.ts`, add the import:

```ts
import { saveScan } from "./store/index.js";
import { scoreAllStandards } from "./analyser/standards/index.js";
import { analyseAllPersonas } from "./analyser/personas/index.js";
```

In the `scan` command definition, add the `--no-save` option:

```ts
  .option("--no-save", "Skip saving scan to history")
```

In the scan command's action handler, after the output block (after `console.log(output)` / file write) but before the `catch`, add:

```ts
      if (!opts.noSave) {
        const compliance = scoreAllStandards(result);
        const analysis = analyseAllPersonas(result);
        saveScan(result, compliance, analysis);
        if (opts.verbose) {
          console.error("[wifisentinel] Scan saved to history.");
        }
      }
```

Note: when `--analyse` is used, compliance and analysis are already computed inside the reporter. But since those reporters don't return the objects (only strings), we recompute here. The computation is cheap (~1ms) so this is acceptable.

- [ ] **Step 2: Add --no-save flag and auto-save logic to the analyse command**

In the `analyse` command definition, add:

```ts
  .option("--no-save", "Skip saving scan to history")
```

In the analyse command's action handler, after the output block but before the `catch`, add the same save logic:

```ts
      if (!opts.noSave) {
        const compliance = scoreAllStandards(result);
        const analysis = analyseAllPersonas(result);
        saveScan(result, compliance, analysis);
        if (opts.verbose) {
          console.error("[wifisentinel] Scan saved to history.");
        }
      }
```

- [ ] **Step 3: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Test auto-save works**

Run: `npx tsx src/cli.ts scan --skip-ports --skip-speed --skip-traffic -v 2>&1 | grep -i "saved\|history"`
Expected: Should see `[wifisentinel] Scan saved to history.`

Then verify the file was created:
Run: `ls ~/.wifisentinel/scans/ && cat ~/.wifisentinel/index.json | head -20`
Expected: One JSON file in scans/, and index.json with one entry.

- [ ] **Step 5: Test --no-save skips persistence**

Run: `npx tsx src/cli.ts scan --skip-ports --skip-speed --skip-traffic --no-save -v 2>&1 | grep -i saved`
Expected: No "saved" message in output.

- [ ] **Step 6: Commit**

```bash
git add src/cli.ts
git commit -m "auto-save scan results to history store"
```

---

### Task 5: History command

**Files:**
- Create: `src/commands/history.ts`
- Modify: `src/cli.ts`

- [ ] **Step 1: Create the history command handler**

```ts
// src/commands/history.ts
import chalk from "chalk";
import type { Command } from "commander";
import { listScans } from "../store/index.js";
import { pad } from "../reporter/render-helpers.js";

function riskColor(risk: string): (s: string) => string {
  if (risk === "critical") return chalk.red.bold;
  if (risk === "high") return chalk.red;
  if (risk === "medium") return chalk.yellow;
  return chalk.green;
}

function gradeColor(grade: string): (s: string) => string {
  if (grade === "A" || grade === "B") return chalk.green;
  if (grade === "C" || grade === "D") return chalk.yellow;
  return chalk.red;
}

export function registerHistoryCommand(program: Command): void {
  program
    .command("history")
    .description("List past network scans")
    .option("-n, --limit <count>", "Number of scans to show", "20")
    .option("--ssid <name>", "Filter by SSID")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const entries = listScans({
        limit: parseInt(opts.limit, 10),
        ssid: opts.ssid,
      });

      if (entries.length === 0) {
        console.log(chalk.dim("No scans found. Run 'wifisentinel scan' to record one."));
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }

      // Header
      const header =
        pad(chalk.bold("DATE"), 22) +
        pad(chalk.bold("SSID"), 20) +
        pad(chalk.bold("SCORE"), 8) +
        pad(chalk.bold("GRADE"), 8) +
        pad(chalk.bold("RISK"), 12) +
        chalk.bold("HOSTS");
      console.log(header);
      console.log(chalk.dim("─".repeat(76)));

      for (const e of entries) {
        const date = new Date(e.timestamp).toLocaleString("en-GB", {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
        });
        const ssid = e.ssid ?? chalk.dim("(hidden)");
        const gc = gradeColor(e.complianceGrade);
        const rc = riskColor(e.consensusRisk);

        console.log(
          pad(chalk.dim(date), 22) +
          pad(ssid, 20) +
          pad(e.securityScore.toFixed(1), 8) +
          pad(gc(e.complianceGrade), 8) +
          pad(rc(e.consensusRisk.toUpperCase()), 12) +
          String(e.hostCount),
        );
      }

      console.log(chalk.dim(`\n${entries.length} scan(s) shown.`));
    });
}
```

- [ ] **Step 2: Register the command in cli.ts**

At the top of `src/cli.ts`, add:

```ts
import { registerHistoryCommand } from "./commands/history.js";
```

Before `program.parse()`, add:

```ts
registerHistoryCommand(program);
```

- [ ] **Step 3: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Test the history command**

Run: `npx tsx src/cli.ts history`
Expected: A table showing the scan(s) saved from Task 4 testing.

Run: `npx tsx src/cli.ts history --json`
Expected: JSON array output.

- [ ] **Step 5: Commit**

```bash
git add src/commands/history.ts src/cli.ts
git commit -m "add history command to list past scans"
```

---

### Task 6: Diff engine

**Files:**
- Create: `src/store/diff.ts`

- [ ] **Step 1: Create the diff module**

```ts
// src/store/diff.ts
import type { StoredScan } from "./types.js";
import type { Host } from "../collector/schema/scan-result.js";

export interface FieldChange {
  field: string;
  from: string | number | boolean;
  to: string | number | boolean;
  direction: "improved" | "regressed" | "changed";
}

export interface HostChange {
  type: "added" | "removed" | "changed";
  ip: string;
  mac: string;
  vendor?: string;
  changes?: FieldChange[];
}

export interface ScoreDelta {
  name: string;
  from: number;
  to: number;
  delta: number;
}

export interface PersonaDelta {
  persona: string;
  fromRisk: string;
  toRisk: string;
  direction: "improved" | "regressed" | "unchanged";
}

export interface ScanDiff {
  fromScanId: string;
  toScanId: string;
  fromTimestamp: string;
  toTimestamp: string;
  wifi: FieldChange[];
  security: FieldChange[];
  hosts: HostChange[];
  compliance: {
    overall: ScoreDelta;
    standards: ScoreDelta[];
  };
  personas: PersonaDelta[];
}

const RISK_ORDER = ["minimal", "low", "medium", "high", "critical"];

function riskDirection(from: string, to: string): "improved" | "regressed" | "unchanged" {
  const fi = RISK_ORDER.indexOf(from);
  const ti = RISK_ORDER.indexOf(to);
  if (ti < fi) return "improved";
  if (ti > fi) return "regressed";
  return "unchanged";
}

function fieldChange(
  field: string,
  from: string | number | boolean,
  to: string | number | boolean,
  higherIsBetter = true,
): FieldChange | null {
  if (from === to) return null;
  let direction: FieldChange["direction"] = "changed";
  if (typeof from === "number" && typeof to === "number") {
    direction = (to > from) === higherIsBetter ? "improved" : "regressed";
  }
  return { field, from, to, direction };
}

export function diffScans(a: StoredScan, b: StoredScan): ScanDiff {
  const wifi: FieldChange[] = [];
  const aw = a.scan.wifi;
  const bw = b.scan.wifi;

  const wifiFields: Array<{ field: string; from: any; to: any; higherIsBetter?: boolean }> = [
    { field: "ssid", from: aw.ssid, to: bw.ssid },
    { field: "security", from: aw.security, to: bw.security },
    { field: "channel", from: aw.channel, to: bw.channel },
    { field: "band", from: aw.band, to: bw.band },
    { field: "signal", from: aw.signal, to: bw.signal, higherIsBetter: true },
    { field: "snr", from: aw.snr, to: bw.snr, higherIsBetter: true },
    { field: "txRate", from: aw.txRate, to: bw.txRate, higherIsBetter: true },
  ];
  for (const f of wifiFields) {
    const change = fieldChange(f.field, f.from, f.to, f.higherIsBetter);
    if (change) wifi.push(change);
  }

  // Security posture
  const security: FieldChange[] = [];
  const as = a.scan.security;
  const bs = b.scan.security;

  const secFields: Array<{ field: string; from: any; to: any; higherIsBetter?: boolean }> = [
    { field: "firewall.enabled", from: as.firewall.enabled, to: bs.firewall.enabled },
    { field: "firewall.stealthMode", from: as.firewall.stealthMode, to: bs.firewall.stealthMode },
    { field: "vpn.active", from: as.vpn.active, to: bs.vpn.active },
    { field: "proxy.enabled", from: as.proxy.enabled, to: bs.proxy.enabled },
    { field: "kernelParams.ipForwarding", from: as.kernelParams.ipForwarding, to: bs.kernelParams.ipForwarding, higherIsBetter: false },
    { field: "kernelParams.icmpRedirects", from: as.kernelParams.icmpRedirects, to: bs.kernelParams.icmpRedirects, higherIsBetter: false },
    { field: "clientIsolation", from: a.scan.security.clientIsolation, to: b.scan.security.clientIsolation },
  ];
  for (const f of secFields) {
    const change = fieldChange(f.field, f.from, f.to, f.higherIsBetter);
    if (change) security.push(change);
  }

  // Hosts
  const hosts: HostChange[] = [];
  const aHosts = new Map(a.scan.network.hosts.map(h => [h.ip, h]));
  const bHosts = new Map(b.scan.network.hosts.map(h => [h.ip, h]));

  for (const [ip, host] of bHosts) {
    if (!aHosts.has(ip)) {
      hosts.push({ type: "added", ip, mac: host.mac, vendor: host.vendor });
    }
  }
  for (const [ip, host] of aHosts) {
    if (!bHosts.has(ip)) {
      hosts.push({ type: "removed", ip, mac: host.mac, vendor: host.vendor });
    }
  }
  for (const [ip, bHost] of bHosts) {
    const aHost = aHosts.get(ip);
    if (!aHost) continue;
    const changes: FieldChange[] = [];
    if (aHost.vendor !== bHost.vendor) {
      changes.push({ field: "vendor", from: aHost.vendor ?? "", to: bHost.vendor ?? "", direction: "changed" });
    }
    const aPorts = (aHost.ports ?? []).map(p => p.port).sort().join(",");
    const bPorts = (bHost.ports ?? []).map(p => p.port).sort().join(",");
    if (aPorts !== bPorts) {
      changes.push({ field: "ports", from: aPorts || "none", to: bPorts || "none", direction: "changed" });
    }
    if (changes.length > 0) {
      hosts.push({ type: "changed", ip, mac: bHost.mac, vendor: bHost.vendor, changes });
    }
  }

  // Compliance
  const overallDelta: ScoreDelta = {
    name: "Overall",
    from: a.compliance.overallScore,
    to: b.compliance.overallScore,
    delta: b.compliance.overallScore - a.compliance.overallScore,
  };
  const standardDeltas: ScoreDelta[] = [];
  for (const bStd of b.compliance.standards) {
    const aStd = a.compliance.standards.find(s => s.standard === bStd.standard);
    if (aStd) {
      standardDeltas.push({
        name: bStd.name,
        from: aStd.score,
        to: bStd.score,
        delta: bStd.score - aStd.score,
      });
    }
  }

  // Personas
  const personas: PersonaDelta[] = [];
  for (const bPersona of b.analysis.analyses) {
    const aPersona = a.analysis.analyses.find(p => p.persona === bPersona.persona);
    if (aPersona) {
      personas.push({
        persona: bPersona.displayName,
        fromRisk: aPersona.riskRating,
        toRisk: bPersona.riskRating,
        direction: riskDirection(aPersona.riskRating, bPersona.riskRating),
      });
    }
  }

  return {
    fromScanId: a.scan.meta.scanId,
    toScanId: b.scan.meta.scanId,
    fromTimestamp: a.scan.meta.timestamp,
    toTimestamp: b.scan.meta.timestamp,
    wifi,
    security,
    hosts,
    compliance: { overall: overallDelta, standards: standardDeltas },
    personas,
  };
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/store/diff.ts
git commit -m "add diff engine for comparing scan results"
```

---

### Task 7: Diff command

**Files:**
- Create: `src/commands/diff.ts`
- Modify: `src/cli.ts`

- [ ] **Step 1: Create the diff command handler**

```ts
// src/commands/diff.ts
import chalk from "chalk";
import type { Command } from "commander";
import { loadScan } from "../store/index.js";
import { diffScans, type ScanDiff, type FieldChange, type HostChange } from "../store/diff.js";
import { pad } from "../reporter/render-helpers.js";

function directionMarker(dir: string): string {
  if (dir === "improved") return chalk.green("+");
  if (dir === "regressed") return chalk.red("-");
  return chalk.yellow("~");
}

function renderFieldChanges(label: string, changes: FieldChange[]): void {
  if (changes.length === 0) return;
  console.log(chalk.bold(`\n  ${label}`));
  for (const c of changes) {
    console.log(`  ${directionMarker(c.direction)} ${c.field}: ${chalk.dim(String(c.from))} -> ${String(c.to)}`);
  }
}

function renderHostChanges(changes: HostChange[]): void {
  if (changes.length === 0) return;
  console.log(chalk.bold("\n  Hosts"));
  for (const h of changes) {
    const vendor = h.vendor ? ` (${h.vendor})` : "";
    if (h.type === "added") {
      console.log(`  ${chalk.green("+")} ${h.ip}  ${chalk.dim(h.mac)}${vendor}`);
    } else if (h.type === "removed") {
      console.log(`  ${chalk.red("-")} ${h.ip}  ${chalk.dim(h.mac)}${vendor}`);
    } else {
      console.log(`  ${chalk.yellow("~")} ${h.ip}  ${chalk.dim(h.mac)}${vendor}`);
      for (const c of h.changes ?? []) {
        console.log(`      ${directionMarker(c.direction)} ${c.field}: ${chalk.dim(String(c.from))} -> ${String(c.to)}`);
      }
    }
  }
}

export function registerDiffCommand(program: Command): void {
  program
    .command("diff <scan1> <scan2>")
    .description("Compare two scan results")
    .option("--json", "Output as JSON")
    .action((scan1: string, scan2: string, opts) => {
      try {
        const a = loadScan(scan1);
        const b = loadScan(scan2);
        const diff = diffScans(a, b);

        if (opts.json) {
          console.log(JSON.stringify(diff, null, 2));
          return;
        }

        const dateA = new Date(diff.fromTimestamp).toLocaleString();
        const dateB = new Date(diff.toTimestamp).toLocaleString();
        console.log(chalk.bold("Scan Comparison"));
        console.log(chalk.dim(`  From: ${diff.fromScanId.slice(0, 8)}  ${dateA}`));
        console.log(chalk.dim(`  To:   ${diff.toScanId.slice(0, 8)}  ${dateB}`));

        const hasChanges = diff.wifi.length > 0 ||
          diff.security.length > 0 ||
          diff.hosts.length > 0 ||
          diff.compliance.overall.delta !== 0 ||
          diff.personas.some(p => p.direction !== "unchanged");

        if (!hasChanges) {
          console.log(chalk.green("\n  No significant changes between scans."));
          return;
        }

        renderFieldChanges("WiFi", diff.wifi);
        renderFieldChanges("Security Posture", diff.security);
        renderHostChanges(diff.hosts);

        // Compliance
        const cd = diff.compliance;
        if (cd.overall.delta !== 0 || cd.standards.some(s => s.delta !== 0)) {
          console.log(chalk.bold("\n  Compliance"));
          const sign = cd.overall.delta > 0 ? "+" : "";
          const color = cd.overall.delta > 0 ? chalk.green : cd.overall.delta < 0 ? chalk.red : chalk.dim;
          console.log(`  ${color(sign + cd.overall.delta)} Overall: ${cd.overall.from}% -> ${cd.overall.to}%`);
          for (const s of cd.standards) {
            if (s.delta === 0) continue;
            const ss = s.delta > 0 ? "+" : "";
            const sc = s.delta > 0 ? chalk.green : chalk.red;
            console.log(`  ${sc(ss + s.delta)} ${s.name}: ${s.from}% -> ${s.to}%`);
          }
        }

        // Personas
        const personaChanges = diff.personas.filter(p => p.direction !== "unchanged");
        if (personaChanges.length > 0) {
          console.log(chalk.bold("\n  Persona Risk Ratings"));
          for (const p of personaChanges) {
            console.log(`  ${directionMarker(p.direction)} ${p.persona}: ${p.fromRisk} -> ${p.toRisk}`);
          }
        }

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
import { registerDiffCommand } from "./commands/diff.js";
```

Before `program.parse()`, add:

```ts
registerDiffCommand(program);
```

- [ ] **Step 3: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Test the diff command**

First, run two scans to have two entries:
Run: `npx tsx src/cli.ts scan --skip-ports --skip-speed --skip-traffic 2>/dev/null > /dev/null`
Run: `npx tsx src/cli.ts history --json | jq '.[].scanId'`

Then diff them (use the two scan IDs from history, or their 8-char prefixes):
Run: `npx tsx src/cli.ts diff <id1-prefix> <id2-prefix>`
Expected: Either "No significant changes" (if same network state) or a list of changes.

- [ ] **Step 5: Commit**

```bash
git add src/commands/diff.ts src/cli.ts
git commit -m "add diff command to compare scan results"
```

---

### Task 8: Trend command

**Files:**
- Create: `src/commands/trend.ts`
- Modify: `src/cli.ts`

- [ ] **Step 1: Create the trend command handler**

```ts
// src/commands/trend.ts
import chalk from "chalk";
import type { Command } from "commander";
import { listScans, type IndexEntry } from "../store/index.js";
import { pad } from "../reporter/render-helpers.js";

function riskColor(risk: string): (s: string) => string {
  if (risk === "critical") return chalk.red.bold;
  if (risk === "high") return chalk.red;
  if (risk === "medium") return chalk.yellow;
  return chalk.green;
}

function gradeColor(grade: string): (s: string) => string {
  if (grade === "A" || grade === "B") return chalk.green;
  if (grade === "C" || grade === "D") return chalk.yellow;
  return chalk.red;
}

function computeTrendDirection(entries: IndexEntry[]): string {
  if (entries.length < 2) return "insufficient data";
  const mid = Math.floor(entries.length / 2);
  // entries are newest-first, so reverse for chronological
  const chronological = [...entries].reverse();
  const firstHalf = chronological.slice(0, mid);
  const secondHalf = chronological.slice(mid);
  const avgFirst = firstHalf.reduce((s, e) => s + e.securityScore, 0) / firstHalf.length;
  const avgSecond = secondHalf.reduce((s, e) => s + e.securityScore, 0) / secondHalf.length;
  const delta = avgSecond - avgFirst;
  if (delta > 0.3) return chalk.green("improving");
  if (delta < -0.3) return chalk.red("declining");
  return chalk.yellow("stable");
}

export function registerTrendCommand(program: Command): void {
  program
    .command("trend")
    .description("Show security score trends over time")
    .option("-n, --limit <count>", "Number of scans to show", "10")
    .option("--ssid <name>", "Filter by SSID")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const entries = listScans({
        limit: parseInt(opts.limit, 10),
        ssid: opts.ssid,
      });

      if (entries.length === 0) {
        console.log(chalk.dim("No scans found. Run 'wifisentinel scan' to record one."));
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }

      // Header
      const header =
        pad(chalk.bold("DATE"), 14) +
        pad(chalk.bold("SCORE"), 8) +
        pad(chalk.bold("GRADE"), 8) +
        pad(chalk.bold("RISK"), 12) +
        chalk.bold("HOSTS");
      console.log(header);
      console.log(chalk.dim("─".repeat(50)));

      // Render newest-first (already sorted that way)
      const chronological = [...entries].reverse();
      for (const e of chronological) {
        const date = new Date(e.timestamp).toLocaleDateString("en-GB", {
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        });
        const gc = gradeColor(e.complianceGrade);
        const rc = riskColor(e.consensusRisk);

        console.log(
          pad(chalk.dim(date), 14) +
          pad(e.securityScore.toFixed(1), 8) +
          pad(gc(e.complianceGrade), 8) +
          pad(rc(e.consensusRisk.toUpperCase()), 12) +
          String(e.hostCount),
        );
      }

      // Summary line
      const scores = entries.map(e => e.securityScore);
      const avg = (scores.reduce((s, v) => s + v, 0) / scores.length).toFixed(1);
      const best = Math.max(...scores).toFixed(1);
      const worst = Math.min(...scores).toFixed(1);
      const trend = computeTrendDirection(entries);

      console.log(chalk.dim("─".repeat(50)));
      console.log(`Avg: ${chalk.bold(avg)}  Best: ${chalk.green(best)}  Worst: ${chalk.red(worst)}  Trend: ${trend}`);
    });
}
```

- [ ] **Step 2: Register the command in cli.ts**

At the top of `src/cli.ts`, add:

```ts
import { registerTrendCommand } from "./commands/trend.js";
```

Before `program.parse()`, add:

```ts
registerTrendCommand(program);
```

- [ ] **Step 3: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Test the trend command**

Run: `npx tsx src/cli.ts trend`
Expected: A table showing chronological scan scores with summary line.

- [ ] **Step 5: Commit**

```bash
git add src/commands/trend.ts src/cli.ts
git commit -m "add trend command for security score progression"
```

---

### Task 9: Schedule command

**Files:**
- Create: `src/commands/schedule.ts`
- Modify: `src/cli.ts`

- [ ] **Step 1: Create the schedule command handler**

```ts
// src/commands/schedule.ts
import { execFileSync } from "node:child_process";
import { writeFileSync, unlinkSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";
import type { Command } from "commander";
import { listScans } from "../store/index.js";

const PLIST_LABEL = "com.wifisentinel.scan";

function getPlistPath(): string {
  return join(homedir(), "Library", "LaunchAgents", `${PLIST_LABEL}.plist`);
}

function getBinaryPath(): string {
  // Resolve from package.json bin entry
  const distCli = join(process.cwd(), "dist", "cli.js");
  if (existsSync(distCli)) return distCli;
  // Fallback: try global install
  try {
    return execFileSync("command", ["-v", "wifisentinel"], {
      encoding: "utf-8",
      shell: true,
    }).trim();
  } catch {
    return distCli; // best guess
  }
}

function getNodePath(): string {
  try {
    return execFileSync("command", ["-v", "node"], {
      encoding: "utf-8",
      shell: true,
    }).trim();
  } catch {
    return "/usr/local/bin/node";
  }
}

function enableMacOS(intervalHours: number): void {
  const nodePath = getNodePath();
  const binaryPath = getBinaryPath();
  const intervalSeconds = intervalHours * 3600;

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${nodePath}</string>
    <string>${binaryPath}</string>
    <string>scan</string>
    <string>--analyse</string>
  </array>
  <key>StartInterval</key>
  <integer>${intervalSeconds}</integer>
  <key>StandardErrorPath</key>
  <string>${join(homedir(), ".wifisentinel", "schedule.log")}</string>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>`;

  const plistPath = getPlistPath();
  writeFileSync(plistPath, plist, "utf-8");

  try {
    execFileSync("launchctl", ["unload", plistPath], { stdio: "pipe" });
  } catch {
    // Ignore if not loaded
  }
  execFileSync("launchctl", ["load", plistPath]);

  console.log(chalk.green(`Scheduled scanning enabled (every ${intervalHours}h).`));
  console.log(chalk.dim(`Plist: ${plistPath}`));
  console.log(chalk.dim(`Log:   ~/.wifisentinel/schedule.log`));
}

function enableLinux(intervalHours: number): void {
  const binaryPath = getBinaryPath();
  const nodePath = getNodePath();
  const cronExpr = `0 */${intervalHours} * * *`;
  const cronLine = `${cronExpr} ${nodePath} ${binaryPath} scan --analyse > /dev/null 2>> ${join(homedir(), ".wifisentinel", "schedule.log")}`;
  const marker = "# wifisentinel-scheduled-scan";

  let existing = "";
  try {
    existing = execFileSync("crontab", ["-l"], { encoding: "utf-8" });
  } catch {
    // No crontab
  }

  // Remove old entry if present
  const lines = existing.split("\n").filter(l => !l.includes(marker));
  lines.push(`${cronLine} ${marker}`);

  execFileSync("crontab", ["-"], {
    input: lines.join("\n") + "\n",
    encoding: "utf-8",
  });

  console.log(chalk.green(`Scheduled scanning enabled (every ${intervalHours}h).`));
  console.log(chalk.dim(`Cron: ${cronLine}`));
}

function disableMacOS(): void {
  const plistPath = getPlistPath();
  if (!existsSync(plistPath)) {
    console.log(chalk.dim("No scheduled scan found."));
    return;
  }
  try {
    execFileSync("launchctl", ["unload", plistPath], { stdio: "pipe" });
  } catch {
    // Ignore
  }
  unlinkSync(plistPath);
  console.log(chalk.green("Scheduled scanning disabled."));
}

function disableLinux(): void {
  const marker = "# wifisentinel-scheduled-scan";
  let existing = "";
  try {
    existing = execFileSync("crontab", ["-l"], { encoding: "utf-8" });
  } catch {
    console.log(chalk.dim("No scheduled scan found."));
    return;
  }
  const lines = existing.split("\n").filter(l => !l.includes(marker));
  execFileSync("crontab", ["-"], {
    input: lines.join("\n") + "\n",
    encoding: "utf-8",
  });
  console.log(chalk.green("Scheduled scanning disabled."));
}

function showStatus(): void {
  const isMac = process.platform === "darwin";

  if (isMac) {
    const plistPath = getPlistPath();
    if (!existsSync(plistPath)) {
      console.log(chalk.dim("Scheduled scanning is not enabled."));
      return;
    }
    const content = readFileSync(plistPath, "utf-8");
    const intervalMatch = content.match(/<key>StartInterval<\/key>\s*<integer>(\d+)<\/integer>/);
    const intervalHours = intervalMatch ? parseInt(intervalMatch[1], 10) / 3600 : "unknown";
    console.log(chalk.green(`Scheduled scanning is enabled (every ${intervalHours}h).`));
  } else {
    try {
      const crontab = execFileSync("crontab", ["-l"], { encoding: "utf-8" });
      const marker = "# wifisentinel-scheduled-scan";
      const line = crontab.split("\n").find(l => l.includes(marker));
      if (line) {
        console.log(chalk.green(`Scheduled scanning is enabled.`));
        console.log(chalk.dim(`Cron: ${line.replace(marker, "").trim()}`));
      } else {
        console.log(chalk.dim("Scheduled scanning is not enabled."));
        return;
      }
    } catch {
      console.log(chalk.dim("Scheduled scanning is not enabled."));
      return;
    }
  }

  // Show last scan time from history
  const scans = listScans({ limit: 1 });
  if (scans.length > 0) {
    const last = new Date(scans[0].timestamp).toLocaleString();
    console.log(chalk.dim(`Last scan: ${last}`));
  }
}

export function registerScheduleCommand(program: Command): void {
  const schedule = program
    .command("schedule")
    .description("Manage scheduled network scanning");

  schedule
    .command("enable")
    .description("Enable periodic scanning")
    .option("-i, --interval <hours>", "Scan interval in hours", "6")
    .action((opts) => {
      const interval = parseInt(opts.interval, 10);
      if (isNaN(interval) || interval < 1) {
        console.error(chalk.red("Interval must be a positive integer (hours)."));
        process.exit(1);
      }
      if (process.platform === "darwin") {
        enableMacOS(interval);
      } else {
        enableLinux(interval);
      }
    });

  schedule
    .command("disable")
    .description("Disable periodic scanning")
    .action(() => {
      if (process.platform === "darwin") {
        disableMacOS();
      } else {
        disableLinux();
      }
    });

  schedule
    .command("status")
    .description("Show scheduling status")
    .action(() => {
      showStatus();
    });
}
```

- [ ] **Step 2: Register the command in cli.ts**

At the top of `src/cli.ts`, add:

```ts
import { registerScheduleCommand } from "./commands/schedule.js";
```

Before `program.parse()`, add:

```ts
registerScheduleCommand(program);
```

- [ ] **Step 3: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 4: Test schedule status (safe — read-only)**

Run: `npx tsx src/cli.ts schedule status`
Expected: "Scheduled scanning is not enabled."

- [ ] **Step 5: Commit**

```bash
git add src/commands/schedule.ts src/cli.ts
git commit -m "add schedule command for periodic scanning via launchd/cron"
```

---

### Task 10: Update ROADMAP.md

**Files:**
- Modify: `ROADMAP.md`

- [ ] **Step 1: Mark Phase 2 items as complete**

Update the Phase 2 section in `ROADMAP.md`:

```markdown
## Phase 2: Observability Pipeline (COMPLETE)

- [x] Persistent scan export (JSON files in ~/.wifisentinel/scans/)
- [x] Scan history and trend comparison (history, trend commands)
- [x] Scheduled scanning via launchd/cron (schedule command)
- [x] Diff reports between scans (diff command)
```

- [ ] **Step 2: Commit**

```bash
git add ROADMAP.md
git commit -m "mark Phase 2 observability pipeline as complete"
```

---

### Task 11: End-to-end integration test

This task verifies all Phase 2 features work together.

- [ ] **Step 1: Run a full scan and verify it saves**

```bash
npx tsx src/cli.ts scan --skip-speed -v 2>&1 | tail -5
ls ~/.wifisentinel/scans/
cat ~/.wifisentinel/index.json | head -20
```

Expected: Scan output renders, "Scan saved to history" message appears, one file in scans/, index has one entry.

- [ ] **Step 2: Run a second scan**

```bash
npx tsx src/cli.ts scan --skip-speed 2>/dev/null > /dev/null
```

- [ ] **Step 3: Test history**

```bash
npx tsx src/cli.ts history
```

Expected: Table with two scan entries.

- [ ] **Step 4: Test diff**

```bash
SCAN1=$(npx tsx src/cli.ts history --json | node -e "process.stdout.write(JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'))[1].scanId.slice(0,8))")
SCAN2=$(npx tsx src/cli.ts history --json | node -e "process.stdout.write(JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'))[0].scanId.slice(0,8))")
npx tsx src/cli.ts diff "$SCAN1" "$SCAN2"
```

Expected: Diff output showing changes (or "No significant changes").

- [ ] **Step 5: Test trend**

```bash
npx tsx src/cli.ts trend
```

Expected: Trend table with two entries and summary line.

- [ ] **Step 6: Test schedule status**

```bash
npx tsx src/cli.ts schedule status
```

Expected: "Scheduled scanning is not enabled."

- [ ] **Step 7: Verify build works**

```bash
npm run build
```

Expected: Clean compilation to dist/.

- [ ] **Step 8: Test --no-save**

```bash
COUNT_BEFORE=$(npx tsx src/cli.ts history --json | node -e "console.log(JSON.parse(require('fs').readFileSync('/dev/stdin','utf8')).length)")
npx tsx src/cli.ts scan --skip-ports --skip-speed --skip-traffic --no-save 2>/dev/null > /dev/null
COUNT_AFTER=$(npx tsx src/cli.ts history --json | node -e "console.log(JSON.parse(require('fs').readFileSync('/dev/stdin','utf8')).length)")
echo "Before: $COUNT_BEFORE, After: $COUNT_AFTER"
```

Expected: Both counts should be the same (no new entry added).
