# Terminal Revamp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Progressive enhancement of WiFi Sentinel's terminal output with accessible colours, live scan progress, responsive tables, sparkline visualisations, and dashboard scan triggering — designed so the collector's internal event model extends naturally into Phase 6.

**Architecture:** The collector gains an EventEmitter mixin that wraps scanner calls. The terminal UI subscribes to these events via listr2 (progress) and log-update (network tree). The dashboard spawns the CLI with `--events` and reads NDJSON via SSE. Scanners themselves are unchanged.

**Tech Stack:** listr2, cli-table3, figures, log-update, sparkly, terminal-link, d3-force (dashboard)

**Spec:** `docs/superpowers/specs/2026-04-01-terminal-revamp-design.md`

---

### Task 1: Install CLI dependencies

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Install the six new CLI dependencies**

```bash
npm install listr2 cli-table3 figures log-update sparkly terminal-link
```

- [ ] **Step 2: Install type declarations for cli-table3**

cli-table3 ships its own types. figures, log-update, sparkly, and terminal-link are pure ESM with bundled types. listr2 has bundled types. Verify all resolve:

```bash
npx tsc --noEmit
```

Expected: no new type errors.

- [ ] **Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "feat: add terminal revamp dependencies (listr2, cli-table3, figures, log-update, sparkly, terminal-link)"
```

---

### Task 2: Accessible colour palette in render-helpers

**Files:**
- Modify: `src/reporter/render-helpers.ts`
- Create: `tests/reporter/render-helpers.test.ts`

- [ ] **Step 1: Write failing tests for the new palette functions**

```typescript
// tests/reporter/render-helpers.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  statusIcon,
  statusLabel,
  severityColor,
  scoreBar,
  boolStatus,
  signalBar,
  snrLabel,
} from "../../src/reporter/render-helpers.js";

describe("statusIcon", () => {
  it("returns checkmark for pass", () => {
    const icon = statusIcon("pass");
    // Strip ANSI to check the symbol and label
    const plain = icon.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("PASS"));
    assert.ok(plain.length > 4); // icon + space + label
  });

  it("returns cross for fail", () => {
    const icon = statusIcon("fail");
    const plain = icon.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("FAIL"));
  });

  it("returns warning for warn", () => {
    const icon = statusIcon("warn");
    const plain = icon.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("WARN"));
  });

  it("returns info for info", () => {
    const icon = statusIcon("info");
    const plain = icon.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("INFO"));
  });

  it("returns dash for n/a", () => {
    const icon = statusIcon("n/a");
    const plain = icon.replace(/\x1B\[[0-9;]*m/g, "");
    assert.equal(plain, "— N/A");
  });
});

describe("boolStatus accessible", () => {
  it("uses teal checkmark for good-when-true", () => {
    const result = boolStatus(true, true);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("✔"));
  });

  it("uses red cross for bad-when-true", () => {
    const result = boolStatus(false, true);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("✘"));
  });
});

describe("scoreBar accessible", () => {
  it("produces 10-char bar for score of 10", () => {
    const bar = scoreBar(10);
    const plain = bar.replace(/\x1B\[[0-9;]*m/g, "");
    assert.equal(plain, "■■■■■■■■■■");
  });

  it("produces mixed bar for score of 5", () => {
    const bar = scoreBar(5);
    const plain = bar.replace(/\x1B\[[0-9;]*m/g, "");
    assert.equal(plain, "■■■■■□□□□□");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
node --import tsx --test tests/reporter/render-helpers.test.ts
```

Expected: FAIL — `statusIcon` does not exist yet (current code has `statusIcon` in analysis.reporter.ts as a local function, not exported from render-helpers).

- [ ] **Step 3: Update render-helpers.ts with the accessible palette**

Replace the colour functions in `src/reporter/render-helpers.ts`. The key changes: `boolStatus` switches from green/red to teal/red, `scoreBar` uses teal for high scores, `signalBar` uses teal, a new exported `statusIcon` function combines icon + colour + label, and `severityColor` adds a "critical" level.

```typescript
// src/reporter/render-helpers.ts
import chalk, { type ChalkInstance } from "chalk";

// ─── Accessible colour constants ─────────────────────────────────────────
// Teal/cyan for pass (distinguishable from red in all CVD types)
const TEAL = chalk.hex("#4ec9b0");
const RED = chalk.hex("#f44747");
const AMBER = chalk.hex("#cca700");
const BLUE = chalk.hex("#569cd6");

export function getTerminalWidth(): number {
  const cols = process.stdout.columns ?? 80;
  // Inner content width: subtract 4 for borders + padding, clamp 60–120
  return Math.max(60, Math.min(120, cols - 4));
}

export let W = getTerminalWidth();

/** Call once at report start to lock the width for the duration */
export function refreshWidth(): void {
  W = getTerminalWidth();
}

export function hRule(left: string, fill: string, right: string, width = W + 2): string {
  return left + fill.repeat(width) + right;
}

export function boxLine(content: string): string {
  return "║" + " " + content.padEnd(W) + " " + "║";
}

export function sectionHeader(title: string): string {
  const bar = chalk.cyan(hRule("├", "─", "┤"));
  const label = chalk.cyan("│") + " " + chalk.cyan.bold(` ${title} `).padEnd(W + 10) + chalk.cyan("│");
  return bar + "\n" + label;
}

export function pad(s: string, width: number): string {
  // strip ANSI before measuring
  // eslint-disable-next-line no-control-regex
  const plain = s.replace(/\x1B\[[0-9;]*m/g, "");
  const diff = width - plain.length;
  return s + (diff > 0 ? " ".repeat(diff) : "");
}

export function row(content: string): string {
  return chalk.cyan("│") + " " + pad(content, W) + " " + chalk.cyan("│");
}

import figures from "figures";

export type Status = "pass" | "fail" | "warn" | "info" | "n/a";

/** Triple-redundant status: colour + icon + label. Uses figures for ASCII fallback. */
export function statusIcon(status: Status): string {
  switch (status) {
    case "pass": return TEAL(`${figures.tick} PASS`);
    case "fail": return RED(`${figures.cross} FAIL`);
    case "warn": return AMBER(`${figures.warning} WARN`);
    case "info": return BLUE(`${figures.info} INFO`);
    case "n/a":  return chalk.dim("— N/A");
  }
}

export function scoreBar(score: number): string {
  const filled = Math.round(score);
  const empty = 10 - filled;
  const color = score >= 7 ? TEAL : score >= 4 ? AMBER : RED;
  return color("■".repeat(filled)) + chalk.gray("□".repeat(empty));
}

export function boolStatus(value: boolean, goodWhenTrue: boolean): string {
  const good = goodWhenTrue ? value : !value;
  return good ? TEAL("✔") : RED("✘");
}

export function severityColor(severity: "critical" | "high" | "medium" | "low"): ChalkInstance {
  if (severity === "critical") return RED.bold as unknown as ChalkInstance;
  if (severity === "high") return RED as unknown as ChalkInstance;
  if (severity === "medium") return AMBER as unknown as ChalkInstance;
  return chalk.dim;
}

export function signalBar(signal: number): string {
  const pct = Math.max(0, Math.min(100, ((signal + 100) / 70) * 100));
  const bars = Math.round(pct / 10);
  const filled = "█".repeat(bars);
  const empty = "░".repeat(10 - bars);
  const color = pct > 70 ? TEAL : pct > 40 ? AMBER : RED;
  return color(filled) + chalk.gray(empty) + chalk.dim(` ${signal} dBm`);
}

export function snrLabel(snr: number): string {
  if (snr >= 25) return TEAL("Excellent");
  if (snr >= 15) return TEAL("Good");
  if (snr >= 10) return AMBER("Fair");
  return RED("Poor");
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
node --import tsx --test tests/reporter/render-helpers.test.ts
```

Expected: PASS

- [ ] **Step 5: Run existing tests to check nothing broke**

```bash
npm test
```

Expected: all tests pass.

- [ ] **Step 6: Run typecheck**

```bash
npm run typecheck
```

Expected: no errors. The exported `severityColor` signature changed to accept `"critical"` — callers in `terminal.reporter.ts` and `analysis.reporter.ts` pass `"high" | "medium" | "low"` which still matches.

- [ ] **Step 7: Commit**

```bash
git add src/reporter/render-helpers.ts tests/reporter/render-helpers.test.ts
git commit -m "feat: accessible-by-default colour palette in render-helpers"
```

---

### Task 3: Update terminal.reporter.ts for accessible colours and dynamic width

**Files:**
- Modify: `src/reporter/terminal.reporter.ts`

- [ ] **Step 1: Update imports to use refreshWidth**

At the top of `renderTerminalReport`, call `refreshWidth()` so the report adapts to the current terminal size. The existing imports from render-helpers already bring in `W`, which is now a `let` that `refreshWidth` updates.

In `src/reporter/terminal.reporter.ts`, add `refreshWidth` to the import:

```typescript
import {
  W,
  refreshWidth,
  hRule,
  boxLine,
  sectionHeader,
  pad,
  row,
  signalBar,
  snrLabel,
  scoreBar,
  severityColor,
  boolStatus,
} from "./render-helpers.js";
```

- [ ] **Step 2: Call refreshWidth at the start of renderTerminalReport**

```typescript
export function renderTerminalReport(result: NetworkScanResult): string {
  refreshWidth();
  const sections: string[] = [
```

- [ ] **Step 3: Update colour usage in renderSecurityPosture, renderDnsAudit, renderSpeedTest**

The existing code uses `chalk.green`, `chalk.red`, `chalk.yellow` directly for status indicators. These now come through `boolStatus` and `severityColor` which already use the accessible palette. Scan through each section renderer and replace any remaining direct `chalk.green("✔")` / `chalk.red("✘")` with `boolStatus()` calls, and `chalk.green("supported")` / `chalk.yellow("not supported")` with the teal/amber equivalents.

In `renderDnsAudit`, replace:
```typescript
row(`  DNSSEC       ${dns.dnssecSupported ? chalk.green("supported") : chalk.yellow("not supported")}`),
```
with:
```typescript
row(`  DNSSEC       ${dns.dnssecSupported ? boolStatus(true, true) + " supported" : boolStatus(false, true) + " not supported"}`),
```

In `renderSpeedTest`, replace the rating colour map:
```typescript
const ratingColors: Record<string, (s: string) => string> = {
  excellent: chalk.green,
  good: chalk.green,
  fair: chalk.yellow,
  poor: chalk.red,
  unusable: chalk.red,
};
```
with:
```typescript
const TEAL = chalk.hex("#4ec9b0");
const AMBER = chalk.hex("#cca700");
const RED = chalk.hex("#f44747");
const ratingColors: Record<string, (s: string) => string> = {
  excellent: TEAL,
  good: TEAL,
  fair: AMBER,
  poor: RED,
  unusable: RED,
};
```

Apply the same pattern to `renderScorecard` where it uses `chalk.green("SECURE")`, `chalk.yellow("MODERATE RISK")`, etc.

- [ ] **Step 4: Run typecheck and tests**

```bash
npm run typecheck && npm test
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/reporter/terminal.reporter.ts
git commit -m "feat: accessible colours and dynamic width in terminal reporter"
```

---

### Task 4: Update analysis.reporter.ts for accessible colours

**Files:**
- Modify: `src/reporter/analysis.reporter.ts`

- [ ] **Step 1: Replace local colour functions with accessible palette**

The analysis reporter defines its own `gradeColor`, `findingSeverityColor`, `riskColor`, and `statusIcon` locally. Update these to use the accessible teal/red/amber/blue palette. Replace the local `statusIcon` to use the shared one from render-helpers (or keep it local but with accessible colours since it has different status values — `pass | fail | partial | not-applicable`).

Replace the local colour helpers at the top of `analysis.reporter.ts`:

```typescript
const TEAL = chalk.hex("#4ec9b0");
const RED = chalk.hex("#f44747");
const AMBER = chalk.hex("#cca700");
const BLUE = chalk.hex("#569cd6");

function gradeColor(grade: string): (s: string) => string {
  if (grade === "A" || grade === "B") return TEAL;
  if (grade === "C" || grade === "D") return AMBER;
  return RED;
}

function findingSeverityColor(severity: string): (s: string) => string {
  if (severity === "critical") return RED.bold as (s: string) => string;
  if (severity === "high") return RED;
  if (severity === "medium") return AMBER;
  if (severity === "low") return chalk.dim;
  return chalk.dim;
}

function riskColor(rating: string): (s: string) => string {
  if (rating === "critical") return RED.bold as (s: string) => string;
  if (rating === "high") return RED;
  if (rating === "medium") return AMBER;
  if (rating === "low") return TEAL;
  return chalk.dim;
}

function statusIcon(status: FindingStatus): string {
  if (status === "pass") return TEAL("✔");
  if (status === "fail") return RED("✘");
  if (status === "partial") return AMBER("◐");
  return chalk.dim("—");
}
```

- [ ] **Step 2: Run typecheck and tests**

```bash
npm run typecheck && npm test
```

Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add src/reporter/analysis.reporter.ts
git commit -m "feat: accessible colours in analysis reporter"
```

---

### Task 5: Collector event emitter

**Files:**
- Create: `src/collector/scan-events.ts`
- Create: `tests/collector/scan-events.test.ts`
- Modify: `src/collector/index.ts`

- [ ] **Step 1: Write failing test for ScanEventEmitter**

```typescript
// tests/collector/scan-events.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ScanEventEmitter } from "../../src/collector/scan-events.js";
import type { ScanEvent } from "../../src/collector/scan-events.js";

describe("ScanEventEmitter", () => {
  it("emits scan:start event", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));

    emitter.scanStart("test-id");

    assert.equal(events.length, 1);
    assert.equal(events[0].type, "scan:start");
    assert.equal((events[0] as any).scanId, "test-id");
  });

  it("emits scanner lifecycle events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));

    emitter.scannerStart("wifi");
    emitter.scannerComplete("wifi", "802.11ax, 5GHz");

    assert.equal(events.length, 2);
    assert.equal(events[0].type, "scanner:start");
    assert.equal(events[1].type, "scanner:complete");
    assert.equal((events[1] as any).summary, "802.11ax, 5GHz");
  });

  it("emits host:found events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));

    emitter.hostFound("192.168.1.100", "aa:bb:cc:dd:ee:ff");

    assert.equal(events.length, 1);
    assert.equal(events[0].type, "host:found");
    assert.equal((events[0] as any).ip, "192.168.1.100");
  });

  it("emits host:enriched events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));

    emitter.hostEnriched("192.168.1.100", "Apple Inc");

    assert.equal(events.length, 1);
    assert.equal(events[0].type, "host:enriched");
    assert.equal((events[0] as any).vendor, "Apple Inc");
  });

  it("emits port:found events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));

    emitter.portFound("192.168.1.100", 22, "ssh");

    assert.equal(events.length, 1);
    assert.equal(events[0].type, "port:found");
  });

  it("serialises events as NDJSON", () => {
    const emitter = new ScanEventEmitter();
    const lines: string[] = [];
    emitter.on("event", (e) => lines.push(emitter.toJSON(e)));

    emitter.scanStart("test-id");

    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.type, "scan:start");
    assert.equal(parsed.scanId, "test-id");
    assert.ok(parsed.timestamp);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
node --import tsx --test tests/collector/scan-events.test.ts
```

Expected: FAIL — module `../../src/collector/scan-events.js` does not exist.

- [ ] **Step 3: Implement ScanEventEmitter**

```typescript
// src/collector/scan-events.ts
import { EventEmitter } from "node:events";

export type ScanEvent =
  | { type: "scan:start"; scanId: string; timestamp: string }
  | { type: "scanner:start"; scanner: string; timestamp: string }
  | { type: "scanner:complete"; scanner: string; summary: string; timestamp: string }
  | { type: "scanner:error"; scanner: string; error: string; timestamp: string }
  | { type: "host:found"; ip: string; mac: string; timestamp: string }
  | { type: "host:enriched"; ip: string; vendor: string; timestamp: string }
  | { type: "port:found"; ip: string; port: number; service: string; timestamp: string }
  | { type: "scan:complete"; scanId: string; hostCount: number; timestamp: string }
  | { type: "scan:score"; score: number; timestamp: string };

export class ScanEventEmitter extends EventEmitter {
  private ts(): string {
    return new Date().toISOString();
  }

  scanStart(scanId: string): void {
    this.emit("event", { type: "scan:start", scanId, timestamp: this.ts() } satisfies ScanEvent);
  }

  scannerStart(scanner: string): void {
    this.emit("event", { type: "scanner:start", scanner, timestamp: this.ts() } satisfies ScanEvent);
  }

  scannerComplete(scanner: string, summary: string): void {
    this.emit("event", { type: "scanner:complete", scanner, summary, timestamp: this.ts() } satisfies ScanEvent);
  }

  scannerError(scanner: string, error: string): void {
    this.emit("event", { type: "scanner:error", scanner, error, timestamp: this.ts() } satisfies ScanEvent);
  }

  hostFound(ip: string, mac: string): void {
    this.emit("event", { type: "host:found", ip, mac, timestamp: this.ts() } satisfies ScanEvent);
  }

  hostEnriched(ip: string, vendor: string): void {
    this.emit("event", { type: "host:enriched", ip, vendor, timestamp: this.ts() } satisfies ScanEvent);
  }

  portFound(ip: string, port: number, service: string): void {
    this.emit("event", { type: "port:found", ip, port, service, timestamp: this.ts() } satisfies ScanEvent);
  }

  scanComplete(scanId: string, hostCount: number): void {
    this.emit("event", { type: "scan:complete", scanId, hostCount, timestamp: this.ts() } satisfies ScanEvent);
  }

  scanScore(score: number): void {
    this.emit("event", { type: "scan:score", score, timestamp: this.ts() } satisfies ScanEvent);
  }

  toJSON(event: ScanEvent): string {
    return JSON.stringify(event);
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
node --import tsx --test tests/collector/scan-events.test.ts
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/collector/scan-events.ts tests/collector/scan-events.test.ts
git commit -m "feat: ScanEventEmitter for collector event model"
```

---

### Task 6: Wire events into collector

**Files:**
- Modify: `src/collector/index.ts`

- [ ] **Step 1: Add ScanEventEmitter to ScanOptions and wire into collector**

Update `ScanOptions` to accept an optional emitter, and add event emissions at each scan stage in `collectNetworkScan`. The key insertion points are: `scan:start` at the beginning, `scanner:start`/`scanner:complete` around each scanner call, `host:found` after host discovery, and `scan:complete` at the end.

Add to imports in `src/collector/index.ts`:

```typescript
import { ScanEventEmitter } from "./scan-events.js";
```

Add to `ScanOptions`:

```typescript
export interface ScanOptions {
  timeout?: number;
  skipTraffic?: boolean;
  skipPortScan?: boolean;
  skipSpeed?: boolean;
  skipVendorLookup?: boolean;
  verbose?: boolean;
  emitter?: ScanEventEmitter;
}
```

Then wrap each scanner call with emitter calls. For example, around the parallel scans section:

```typescript
const emitter = options.emitter;
emitter?.scanStart(scanId);

// Step 3: Parallel scans
emitter?.scannerStart("wifi");
emitter?.scannerStart("dns");
emitter?.scannerStart("security");
emitter?.scannerStart("connections");
const [wifi, dns, security, connections] = await withSpan(
  "parallel-scans",
  {},
  async () => {
    return Promise.all([
      withSpan("wifi-scan", { "tool.resolved": tools.get("wifiAnalysis")?.name ?? "none" }, () => scanWifi())
        .then(r => { emitter?.scannerComplete("wifi", `${r.protocol}, ${r.band}, ch${r.channel}, ${r.security}`); return r; }),
      withSpan("dns-audit", { "tool.resolved": tools.get("dnsAudit")?.name ?? "none" }, () => scanDns(bootstrap.gateway.ip))
        .then(r => { emitter?.scannerComplete("dns", `${r.servers.length} servers, DNSSEC ${r.dnssecSupported ? "on" : "off"}`); return r; }),
      withSpan("security-posture", {}, () => scanSecurityPosture())
        .then(r => { emitter?.scannerComplete("security", `firewall ${r.firewall.enabled ? "on" : "off"}, VPN ${r.vpn.active ? "active" : "inactive"}`); return r; }),
      withSpan("connections", { "tool.resolved": "netstat" }, () => scanConnections())
        .then(r => { emitter?.scannerComplete("connections", `${r.established} established, ${r.listening} listening`); return r; }),
    ]);
  }
);
```

For host discovery, emit `host:found` for each discovered host:

```typescript
emitter?.scannerStart("host-discovery");
const { hosts, topology } = await withSpan(
  "host-discovery",
  { "tool.resolved": tools.get("hostDiscovery")?.name ?? "none" },
  () => scanHosts(bootstrap.interface, bootstrap.subnet, bootstrap.broadcastAddr)
);
for (const host of hosts) {
  emitter?.hostFound(host.ip, host.mac);
  if (host.vendor) emitter?.hostEnriched(host.ip, host.vendor);
}
emitter?.scannerComplete("host-discovery", `${hosts.length} hosts`);
```

For port scanning, emit `port:found` after merging port data:

```typescript
emitter?.scannerStart("ports");
// ... existing port scan code ...
for (const host of hosts) {
  const ports = portResult.hostPorts.get(host.ip);
  if (ports) {
    host.ports = ports;
    for (const p of ports.filter(p => p.state === "open")) {
      emitter?.portFound(host.ip, p.port, p.service);
    }
  }
}
emitter?.scannerComplete("ports", `${portResult.hostPorts.size} hosts scanned`);
```

For hidden devices, intrusion, and speed — wrap similarly with `scannerStart`/`scannerComplete`.

At the end, before returning:

```typescript
emitter?.scanComplete(scanId, hosts.length);
```

- [ ] **Step 2: Run typecheck and tests**

```bash
npm run typecheck && npm test
```

Expected: all pass. The emitter is optional so all existing call sites are unaffected.

- [ ] **Step 3: Commit**

```bash
git add src/collector/index.ts
git commit -m "feat: wire ScanEventEmitter into collector pipeline"
```

---

### Task 7: listr2 scan progress renderer

**Files:**
- Create: `src/reporter/progress.renderer.ts`
- Create: `tests/reporter/progress.renderer.test.ts`

- [ ] **Step 1: Write failing test for createScanTasks**

```typescript
// tests/reporter/progress.renderer.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createScanTasks } from "../../src/reporter/progress.renderer.js";

describe("createScanTasks", () => {
  it("returns a task list with expected scanner names", () => {
    const tasks = createScanTasks({});
    const titles = tasks.map(t => t.title);
    assert.ok(titles.includes("WiFi environment"));
    assert.ok(titles.includes("DNS audit"));
    assert.ok(titles.includes("Security posture"));
    assert.ok(titles.includes("Active connections"));
    assert.ok(titles.includes("Host discovery"));
  });

  it("excludes port scanning when skipPorts is true", () => {
    const tasks = createScanTasks({ skipPorts: true });
    const titles = tasks.map(t => t.title);
    assert.ok(!titles.includes("Port scanning"));
  });

  it("excludes speed test when skipSpeed is true", () => {
    const tasks = createScanTasks({ skipSpeed: true });
    const titles = tasks.map(t => t.title);
    assert.ok(!titles.includes("Speed test"));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
node --import tsx --test tests/reporter/progress.renderer.test.ts
```

Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement progress.renderer.ts**

This module creates the listr2 task definitions that map to scanner stages. It subscribes to the ScanEventEmitter and updates task output as events arrive.

```typescript
// src/reporter/progress.renderer.ts
import { Listr } from "listr2";
import type { ScanEvent } from "../collector/scan-events.js";
import { ScanEventEmitter } from "../collector/scan-events.js";
import { collectNetworkScan, type ScanOptions } from "../collector/index.js";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";

interface TaskDef {
  title: string;
  scanner: string;
}

export function createScanTasks(opts: { skipPorts?: boolean; skipSpeed?: boolean; skipTraffic?: boolean }): TaskDef[] {
  const tasks: TaskDef[] = [
    { title: "WiFi environment", scanner: "wifi" },
    { title: "DNS audit", scanner: "dns" },
    { title: "Security posture", scanner: "security" },
    { title: "Active connections", scanner: "connections" },
    { title: "Host discovery", scanner: "host-discovery" },
  ];

  if (!opts.skipPorts) {
    tasks.push({ title: "Port scanning", scanner: "ports" });
  }

  tasks.push({ title: "Deep analysis", scanner: "deep-analysis" });

  if (!opts.skipSpeed) {
    tasks.push({ title: "Speed test", scanner: "speed" });
  }

  return tasks;
}

export async function runScanWithProgress(
  scanOptions: ScanOptions,
): Promise<NetworkScanResult> {
  const emitter = new ScanEventEmitter();
  const taskDefs = createScanTasks(scanOptions);

  // Track which scanners have completed and their summaries
  const completed = new Map<string, string>();
  const started = new Set<string>();

  let result: NetworkScanResult | undefined;

  emitter.on("event", (event: ScanEvent) => {
    if (event.type === "scanner:start") {
      started.add(event.scanner);
    } else if (event.type === "scanner:complete") {
      completed.set(event.scanner, event.summary);
    }
  });

  const listrTasks = new Listr(
    [
      {
        title: "Network Scan",
        task: (_ctx, task) => {
          return task.newListr(
            taskDefs.map((def) => ({
              title: def.title,
              task: async (_ctx2, subtask) => {
                // Wait for this scanner to complete
                await new Promise<void>((resolve) => {
                  if (completed.has(def.scanner)) {
                    subtask.title = `${def.title} — ${completed.get(def.scanner)}`;
                    resolve();
                    return;
                  }
                  const handler = (event: ScanEvent) => {
                    if (event.type === "scanner:complete" && event.scanner === def.scanner) {
                      subtask.title = `${def.title} — ${event.summary}`;
                      emitter.off("event", handler);
                      resolve();
                    }
                  };
                  emitter.on("event", handler);
                });
              },
            })),
            { concurrent: false, rendererOptions: { collapseSubtasks: false } }
          );
        },
      },
    ],
    {
      concurrent: true,
      rendererOptions: { collapseSubtasks: false },
    }
  );

  // Run scan and listr in parallel
  const [scanResult] = await Promise.all([
    collectNetworkScan({ ...scanOptions, emitter }),
    listrTasks.run(),
  ]);

  return scanResult;
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
node --import tsx --test tests/reporter/progress.renderer.test.ts
```

Expected: PASS (the `createScanTasks` function is pure and testable independently of listr2).

- [ ] **Step 5: Commit**

```bash
git add src/reporter/progress.renderer.ts tests/reporter/progress.renderer.test.ts
git commit -m "feat: listr2 scan progress renderer"
```

---

### Task 8: Wire progress into CLI

**Files:**
- Modify: `src/cli.ts`

- [ ] **Step 1: Add --progress flag and wire into scan command**

Update the `scan` command to use `runScanWithProgress` when output is terminal (not JSON) and stdout is a TTY. Import the new module and replace the direct `collectNetworkScan` call.

Add import:

```typescript
import { runScanWithProgress } from "./reporter/progress.renderer.js";
```

In the scan command action, replace:

```typescript
const result = await collectNetworkScan({
  skipPortScan: opts.skipPorts,
  skipTraffic: opts.skipTraffic,
  skipSpeed: opts.skipSpeed,
  skipVendorLookup: !opts.vendorLookup,
  verbose: opts.verbose,
});
```

with:

```typescript
const scanOpts: ScanOptions = {
  skipPortScan: opts.skipPorts,
  skipTraffic: opts.skipTraffic,
  skipSpeed: opts.skipSpeed,
  skipVendorLookup: !opts.vendorLookup,
  verbose: opts.verbose,
};

const useProgress = opts.output !== "json" && process.stdout.isTTY;
const result = useProgress
  ? await runScanWithProgress(scanOpts)
  : await collectNetworkScan(scanOpts);
```

Add the same change to the `analyse` command action.

- [ ] **Step 2: Add --events flag for NDJSON output**

Add a new `--events` option to the scan command that outputs NDJSON events to stdout:

```typescript
.option("--events", "Output scan events as NDJSON instead of report")
```

In the action, when `opts.events` is set:

```typescript
if (opts.events) {
  const { ScanEventEmitter } = await import("./collector/scan-events.js");
  const emitter = new ScanEventEmitter();
  emitter.on("event", (e) => {
    process.stdout.write(emitter.toJSON(e) + "\n");
  });
  const result = await collectNetworkScan({ ...scanOpts, emitter });

  if (opts.save) {
    const compliance = scoreAllStandards(result);
    const analysis = analyseAllPersonas(result);
    const rfAnalysis = analyseRF(result);
    saveScan(result, compliance, analysis, rfAnalysis);
  }
  await shutdownTelemetry();
  return;
}
```

- [ ] **Step 3: Run typecheck**

```bash
npm run typecheck
```

Expected: no errors.

- [ ] **Step 4: Smoke test — run a real scan with progress**

```bash
npm run dev -- scan --skip-ports --skip-speed --skip-traffic
```

Expected: listr2 task tree appears with spinners, then report renders below.

- [ ] **Step 5: Smoke test — NDJSON events output**

```bash
npm run dev -- scan --skip-ports --skip-speed --skip-traffic --events | head -20
```

Expected: NDJSON lines with `scanner:start`, `scanner:complete`, `host:found`, etc.

- [ ] **Step 6: Commit**

```bash
git add src/cli.ts
git commit -m "feat: listr2 progress and --events NDJSON output in CLI"
```

---

### Task 9: Progressive network tree

**Files:**
- Create: `src/reporter/network-tree.ts`
- Create: `tests/reporter/network-tree.test.ts`

- [ ] **Step 1: Write failing test for renderNetworkTree**

```typescript
// tests/reporter/network-tree.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NetworkTreeRenderer } from "../../src/reporter/network-tree.js";

describe("NetworkTreeRenderer", () => {
  it("renders gateway as root node", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    const output = tree.render();
    assert.ok(output.includes("192.168.1.1"));
    assert.ok(output.includes("gateway"));
  });

  it("adds hosts progressively", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    tree.addHost("192.168.1.100", "aa:bb:cc:dd:ee:ff");

    const output = tree.render();
    assert.ok(output.includes("192.168.1.100"));
    assert.ok(output.includes("├─") || output.includes("└─"));
  });

  it("enriches hosts with vendor info", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    tree.addHost("192.168.1.100", "aa:bb:cc:dd:ee:ff");
    tree.enrichHost("192.168.1.100", "Apple Inc");

    const output = tree.render();
    assert.ok(output.includes("Apple Inc"));
  });

  it("adds ports to hosts", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    tree.addHost("192.168.1.100", "aa:bb:cc:dd:ee:ff");
    tree.addPort("192.168.1.100", 22, "ssh");

    const output = tree.render();
    assert.ok(output.includes("22/ssh"));
  });

  it("shows host count in header", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    tree.addHost("192.168.1.100", "aa:bb:cc:dd:ee:ff");
    tree.addHost("192.168.1.105", "bb:cc:dd:ee:ff:00");

    const output = tree.render();
    assert.ok(output.includes("2 hosts"));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
node --import tsx --test tests/reporter/network-tree.test.ts
```

Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement NetworkTreeRenderer**

```typescript
// src/reporter/network-tree.ts
import chalk from "chalk";

const TEAL = chalk.hex("#4ec9b0");
const RED = chalk.hex("#f44747");
const AMBER = chalk.hex("#cca700");

interface HostNode {
  ip: string;
  mac: string;
  vendor?: string;
  ports: Array<{ port: number; service: string }>;
  isCamera?: boolean;
}

export class NetworkTreeRenderer {
  private gateway = "";
  private hosts: Map<string, HostNode> = new Map();

  setGateway(ip: string): void {
    this.gateway = ip;
  }

  addHost(ip: string, mac: string): void {
    if (!this.hosts.has(ip)) {
      this.hosts.set(ip, { ip, mac, ports: [] });
    }
  }

  enrichHost(ip: string, vendor: string, isCamera?: boolean): void {
    const host = this.hosts.get(ip);
    if (host) {
      host.vendor = vendor;
      if (isCamera !== undefined) host.isCamera = isCamera;
    }
  }

  addPort(ip: string, port: number, service: string): void {
    const host = this.hosts.get(ip);
    if (host) {
      host.ports.push({ port, service });
    }
  }

  render(): string {
    const serviceCount = Array.from(this.hosts.values()).reduce((sum, h) => sum + h.ports.length, 0);
    const hostCount = this.hosts.size;
    const header = chalk.dim(`NETWORK MAP (${hostCount} hosts${serviceCount > 0 ? ` · ${serviceCount} services` : ""})`);

    const lines: string[] = [header];

    // Gateway
    lines.push(`${chalk.dim("┌─")} ${AMBER(this.gateway)} ${chalk.dim("gateway")}`);

    // Hosts
    const hostList = Array.from(this.hosts.values());
    hostList.forEach((host, idx) => {
      const isLast = idx === hostList.length - 1;
      const connector = isLast ? "└─" : "├─";
      const vendorStr = host.vendor ? chalk.dim(` ${host.vendor}`) : "";
      const cameraFlag = host.isCamera ? RED(" ✘ CAM") : "";
      const ipColor = host.isCamera ? RED : (s: string) => s;
      lines.push(`${chalk.dim(connector)} ${ipColor(host.ip)}${vendorStr}${cameraFlag}`);

      if (host.ports.length > 0) {
        const prefix = isLast ? " " : "│";
        const portStr = host.ports.map(p => `${p.port}/${p.service}`).join(" ");
        lines.push(`${chalk.dim(prefix)}  ${chalk.dim(portStr)}`);
      }
    });

    return lines.join("\n");
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
node --import tsx --test tests/reporter/network-tree.test.ts
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/reporter/network-tree.ts tests/reporter/network-tree.test.ts
git commit -m "feat: progressive NetworkTreeRenderer"
```

---

### Task 10: Wire network tree into progress renderer

**Files:**
- Modify: `src/reporter/progress.renderer.ts`

- [ ] **Step 1: Subscribe NetworkTreeRenderer to emitter events**

In `runScanWithProgress`, create a `NetworkTreeRenderer`, subscribe it to the emitter's `host:found`, `host:enriched`, and `port:found` events, and print the tree using `log-update` after each event. Set the gateway IP from the bootstrap (exposed via a new `bootstrap:complete` event or by reading the scan result).

Add to `runScanWithProgress`:

```typescript
import logUpdate from "log-update";
import { NetworkTreeRenderer } from "./network-tree.js";

// Inside runScanWithProgress, after creating the emitter:
const tree = new NetworkTreeRenderer();

emitter.on("event", (event: ScanEvent) => {
  if (event.type === "scanner:start") {
    started.add(event.scanner);
  } else if (event.type === "scanner:complete") {
    completed.set(event.scanner, event.summary);
  } else if (event.type === "host:found") {
    if (!tree["gateway"]) {
      // First event — we don't know gateway yet, set it from scan result later
    }
    tree.addHost(event.ip, event.mac);
    logUpdate(tree.render());
  } else if (event.type === "host:enriched") {
    tree.enrichHost(event.ip, event.vendor);
    logUpdate(tree.render());
  } else if (event.type === "port:found") {
    tree.addPort(event.ip, event.port, event.service);
    logUpdate(tree.render());
  }
});
```

After the scan completes, call `logUpdate.done()` to persist the tree output, then render the full report below:

```typescript
const scanResult = await collectNetworkScan({ ...scanOptions, emitter });
logUpdate.done(); // Persist tree output

return scanResult;
```

- [ ] **Step 2: Add gateway event to emitter**

In `src/collector/scan-events.ts`, add a `bootstrap:complete` event type:

```typescript
| { type: "bootstrap:complete"; gateway: string; ip: string; subnet: string; timestamp: string }
```

Add the method:

```typescript
bootstrapComplete(gateway: string, ip: string, subnet: string): void {
  this.emit("event", { type: "bootstrap:complete", gateway, ip, subnet, timestamp: this.ts() } satisfies ScanEvent);
}
```

In `src/collector/index.ts`, emit it after the bootstrap step:

```typescript
emitter?.bootstrapComplete(bootstrap.gateway.ip, bootstrap.ip, bootstrap.subnet);
```

In `progress.renderer.ts`, handle it:

```typescript
} else if (event.type === "bootstrap:complete") {
  tree.setGateway(event.gateway);
}
```

- [ ] **Step 3: Run typecheck and tests**

```bash
npm run typecheck && npm test
```

Expected: all pass.

- [ ] **Step 4: Smoke test — run a real scan**

```bash
npm run dev -- scan --skip-speed --skip-traffic
```

Expected: listr2 progress appears, then the network tree grows below as hosts are discovered, enriched with vendors, and populated with ports. When done, the full report renders below.

- [ ] **Step 5: Commit**

```bash
git add src/reporter/progress.renderer.ts src/collector/scan-events.ts src/collector/index.ts
git commit -m "feat: live network tree during scan progress"
```

---

### Task 11: Sparkline visualisations

**Files:**
- Create: `src/reporter/sparklines.ts`
- Create: `tests/reporter/sparklines.test.ts`
- Modify: `src/reporter/terminal.reporter.ts`

- [ ] **Step 1: Write failing test for sparkline helpers**

```typescript
// tests/reporter/sparklines.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { renderSparkline, renderScoreTrend } from "../../src/reporter/sparklines.js";

describe("renderSparkline", () => {
  it("renders sparkline characters for data points", () => {
    const result = renderSparkline([1, 3, 5, 7, 9]);
    // Strip ANSI
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    // Should contain block characters
    assert.ok(plain.length >= 5);
    assert.ok(/[▁▂▃▄▅▆▇█]/.test(plain));
  });

  it("returns empty string for empty data", () => {
    const result = renderSparkline([]);
    assert.equal(result, "");
  });
});

describe("renderScoreTrend", () => {
  it("shows improving trend", () => {
    const result = renderScoreTrend([6.0, 6.5, 7.0, 7.5, 8.0]);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("improving"));
  });

  it("shows degrading trend", () => {
    const result = renderScoreTrend([8.0, 7.5, 7.0, 6.5, 6.0]);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("degrading"));
  });

  it("shows stable trend", () => {
    const result = renderScoreTrend([7.0, 7.0, 7.0]);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("stable"));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
node --import tsx --test tests/reporter/sparklines.test.ts
```

Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement sparkline helpers**

```typescript
// src/reporter/sparklines.ts
import sparkly from "sparkly";
import chalk from "chalk";

const TEAL = chalk.hex("#4ec9b0");
const AMBER = chalk.hex("#cca700");
const RED = chalk.hex("#f44747");

export function renderSparkline(values: number[]): string {
  if (values.length === 0) return "";
  return sparkly(values);
}

export function renderScoreTrend(scores: number[]): string {
  if (scores.length < 2) return "";

  const spark = renderSparkline(scores);
  const first = scores[0];
  const last = scores[scores.length - 1];
  const diff = last - first;

  let direction: string;
  let color: (s: string) => string;
  if (diff > 0.3) {
    direction = "improving";
    color = TEAL;
  } else if (diff < -0.3) {
    direction = "degrading";
    color = RED;
  } else {
    direction = "stable";
    color = AMBER;
  }

  return `${spark} ${color(`${last.toFixed(1)} (${direction})`)}`;
}

export function renderSignalTrend(signals: number[]): string {
  if (signals.length < 2) return "";

  const spark = renderSparkline(signals.map(s => s + 100)); // Normalise to positive range
  const avg = signals.reduce((a, b) => a + b, 0) / signals.length;

  return `${spark} ${chalk.dim(`${avg.toFixed(0)} dBm avg`)}`;
}

export function renderChannelSaturation(channels: Array<{ channel: number; saturation: number }>): string {
  if (channels.length === 0) return "";

  return channels.map(ch => {
    const color = ch.saturation > 70 ? RED : ch.saturation > 40 ? AMBER : TEAL;
    const bar = renderSparkline([ch.saturation]);
    return `${chalk.dim(`Ch ${String(ch.channel).padStart(2)}`)} ${color(bar)} ${chalk.dim(`${ch.saturation}%`)}`;
  }).join("  ");
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
node --import tsx --test tests/reporter/sparklines.test.ts
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/reporter/sparklines.ts tests/reporter/sparklines.test.ts
git commit -m "feat: sparkline visualisation helpers"
```

---

### Task 12: Clickable links with terminal-link

**Files:**
- Modify: `src/reporter/render-helpers.ts`

- [ ] **Step 1: Add a link helper to render-helpers**

```typescript
import terminalLink from "terminal-link";

export function link(text: string, url: string): string {
  return terminalLink(text, url, { fallback: (text, url) => `${text} (${url})` });
}
```

This automatically renders as a clickable hyperlink in supported terminals and falls back to `text (url)` in others.

- [ ] **Step 2: Run typecheck**

```bash
npm run typecheck
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/reporter/render-helpers.ts
git commit -m "feat: terminal-link helper for clickable URLs"
```

---

### Task 13: Dashboard — install d3-force and add scan API route

**Files:**
- Modify: `dashboard/package.json`
- Create: `dashboard/app/api/scans/run/route.ts`

- [ ] **Step 1: Install d3-force in the dashboard**

```bash
cd dashboard && npm install d3-force @types/d3-force
```

- [ ] **Step 2: Create POST /api/scans/run SSE route**

```typescript
// dashboard/app/api/scans/run/route.ts
import { NextRequest } from "next/server";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const args = ["src/cli.ts", "scan", "--events", "--no-save"];

  if (body.skipPorts) args.push("--skip-ports");
  if (body.skipSpeed) args.push("--skip-speed");
  if (body.skipTraffic) args.push("--skip-traffic");

  const cliDir = resolve(process.cwd(), "..");

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const child = spawn("npx", ["tsx", ...args], {
        cwd: cliDir,
        stdio: ["ignore", "pipe", "pipe"],
      });

      child.stdout.on("data", (chunk: Buffer) => {
        const lines = chunk.toString().split("\n").filter(Boolean);
        for (const line of lines) {
          controller.enqueue(encoder.encode(`data: ${line}\n\n`));
        }
      });

      child.stderr.on("data", (chunk: Buffer) => {
        // Log but don't send to client
        console.error(`[scan-runner] ${chunk.toString().trim()}`);
      });

      child.on("close", (code) => {
        controller.enqueue(encoder.encode(`data: {"type":"stream:end","exitCode":${code ?? 0}}\n\n`));
        controller.close();
      });

      child.on("error", (err) => {
        controller.enqueue(encoder.encode(`data: {"type":"stream:error","error":"${err.message}"}\n\n`));
        controller.close();
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
```

- [ ] **Step 3: Run typecheck**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add dashboard/package.json dashboard/package-lock.json dashboard/app/api/scans/run/route.ts
git commit -m "feat: dashboard POST /api/scans/run SSE endpoint"
```

---

### Task 14: Dashboard — Run Scan button and live progress component

**Files:**
- Create: `dashboard/components/scan-runner.tsx`
- Modify: `dashboard/app/scans/page.tsx`

- [ ] **Step 1: Create ScanRunner component**

```tsx
// dashboard/components/scan-runner.tsx
"use client";

import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useRouter } from "next/navigation";

type ScanEvent = {
  type: string;
  scanner?: string;
  summary?: string;
  ip?: string;
  mac?: string;
  vendor?: string;
  port?: number;
  service?: string;
  scanId?: string;
  hostCount?: number;
  exitCode?: number;
  error?: string;
};

interface ScanOptions {
  skipPorts: boolean;
  skipSpeed: boolean;
  skipTraffic: boolean;
}

export function ScanRunner() {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [options, setOptions] = useState<ScanOptions>({
    skipPorts: false,
    skipSpeed: false,
    skipTraffic: true,
  });
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  const toggle = (key: keyof ScanOptions) =>
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));

  const startScan = useCallback(async () => {
    setRunning(true);
    setEvents([]);
    setError(null);

    try {
      const response = await fetch("/api/scans/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(options),
      });

      if (!response.ok || !response.body) {
        setError(`Scan failed: ${response.statusText}`);
        setRunning(false);
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          const dataMatch = line.match(/^data: (.+)$/m);
          if (dataMatch) {
            try {
              const event = JSON.parse(dataMatch[1]) as ScanEvent;
              setEvents((prev) => [...prev, event]);

              if (event.type === "stream:end") {
                setRunning(false);
                // Refresh the scan list after a short delay
                setTimeout(() => router.refresh(), 500);
              }
              if (event.type === "stream:error") {
                setError(event.error ?? "Unknown error");
                setRunning(false);
              }
            } catch {
              // Ignore malformed JSON lines
            }
          }
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Connection failed");
      setRunning(false);
    }
  }, [options, router]);

  const completedScanners = events
    .filter((e) => e.type === "scanner:complete")
    .map((e) => ({ scanner: e.scanner!, summary: e.summary! }));

  const activeScanners = events
    .filter((e) => e.type === "scanner:start")
    .map((e) => e.scanner!)
    .filter((s) => !completedScanners.some((c) => c.scanner === s));

  const hosts = events.filter((e) => e.type === "host:found");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Run Scan</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-4">
          <button
            onClick={startScan}
            disabled={running}
            className="px-4 py-2 bg-[#4ec9b0] text-black rounded font-semibold text-sm disabled:opacity-50"
          >
            {running ? "Scanning..." : "Start Scan"}
          </button>
          <label className="text-sm text-muted-foreground flex items-center gap-1">
            <input
              type="checkbox"
              checked={!options.skipPorts}
              onChange={() => toggle("skipPorts")}
              disabled={running}
            />
            Ports
          </label>
          <label className="text-sm text-muted-foreground flex items-center gap-1">
            <input
              type="checkbox"
              checked={!options.skipSpeed}
              onChange={() => toggle("skipSpeed")}
              disabled={running}
            />
            Speed
          </label>
          <label className="text-sm text-muted-foreground flex items-center gap-1">
            <input
              type="checkbox"
              checked={!options.skipTraffic}
              onChange={() => toggle("skipTraffic")}
              disabled={running}
            />
            Traffic
          </label>
        </div>

        {error && (
          <p className="text-sm text-red-400">{error}</p>
        )}

        {events.length > 0 && (
          <div className="text-sm space-y-1 font-mono">
            {completedScanners.map((s) => (
              <div key={s.scanner} className="text-[#4ec9b0]">
                ✔ {s.scanner} — {s.summary}
              </div>
            ))}
            {activeScanners.map((s) => (
              <div key={s} className="text-[#569cd6] animate-pulse">
                ◐ {s}...
              </div>
            ))}
            {hosts.length > 0 && (
              <div className="mt-2 text-muted-foreground">
                {hosts.length} host{hosts.length !== 1 ? "s" : ""} discovered
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 2: Add ScanRunner to the scans list page**

In `dashboard/app/scans/page.tsx`, import and render the `ScanRunner` component above the scan table:

```tsx
import { ScanRunner } from "@/components/scan-runner";
```

Add it at the top of the page content, before the scan table.

- [ ] **Step 3: Run typecheck**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add dashboard/components/scan-runner.tsx dashboard/app/scans/page.tsx
git commit -m "feat: dashboard Run Scan button with live SSE progress"
```

---

### Task 15: Dashboard — network topology component

**Files:**
- Create: `dashboard/components/network-topology.tsx`
- Modify: `dashboard/components/scan-runner.tsx`

- [ ] **Step 1: Create NetworkTopology component using D3 force**

```tsx
// dashboard/components/network-topology.tsx
"use client";

import { useEffect, useRef } from "react";
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from "d3-force";

interface TopologyNode extends SimulationNodeDatum {
  id: string;
  label: string;
  vendor?: string;
  isGateway?: boolean;
  isCamera?: boolean;
  ports: Array<{ port: number; service: string }>;
}

interface TopologyLink extends SimulationLinkDatum<TopologyNode> {
  source: string;
  target: string;
}

interface Props {
  gateway: string;
  hosts: Array<{
    ip: string;
    mac: string;
    vendor?: string;
    isCamera?: boolean;
    ports: Array<{ port: number; service: string }>;
  }>;
  width?: number;
  height?: number;
}

function nodeColor(node: TopologyNode): string {
  if (node.isGateway) return "#cca700";
  if (node.isCamera) return "#f44747";
  if (node.ports.length > 0) return "#cca700";
  return "#4ec9b0";
}

export function NetworkTopology({ gateway, hosts, width = 500, height = 350 }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const simulationRef = useRef<ReturnType<typeof forceSimulation<TopologyNode>> | null>(null);

  useEffect(() => {
    if (!svgRef.current) return;

    const nodes: TopologyNode[] = [
      { id: gateway, label: gateway, isGateway: true, ports: [] },
      ...hosts.map((h) => ({
        id: h.ip,
        label: h.ip.split(".").pop() ?? h.ip,
        vendor: h.vendor,
        isCamera: h.isCamera,
        ports: h.ports,
      })),
    ];

    const links: TopologyLink[] = hosts.map((h) => ({
      source: gateway,
      target: h.ip,
    }));

    simulationRef.current?.stop();

    const simulation = forceSimulation<TopologyNode>(nodes)
      .force("link", forceLink<TopologyNode, TopologyLink>(links).id((d) => d.id).distance(100))
      .force("charge", forceManyBody().strength(-200))
      .force("center", forceCenter(width / 2, height / 2))
      .force("collide", forceCollide(30));

    simulationRef.current = simulation;

    const svg = svgRef.current;

    simulation.on("tick", () => {
      // Clear and redraw
      while (svg.firstChild) svg.removeChild(svg.firstChild);

      // Links
      for (const link of links) {
        const source = link.source as unknown as TopologyNode;
        const target = link.target as unknown as TopologyNode;
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", String(source.x ?? 0));
        line.setAttribute("y1", String(source.y ?? 0));
        line.setAttribute("x2", String(target.x ?? 0));
        line.setAttribute("y2", String(target.y ?? 0));
        line.setAttribute("stroke", "#333");
        line.setAttribute("stroke-width", "1");
        svg.appendChild(line);
      }

      // Nodes
      for (const node of nodes) {
        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");

        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", String(node.x ?? 0));
        circle.setAttribute("cy", String(node.y ?? 0));
        circle.setAttribute("r", node.isGateway ? "20" : "14");
        circle.setAttribute("fill", "#1a1a2a");
        circle.setAttribute("stroke", nodeColor(node));
        circle.setAttribute("stroke-width", node.isGateway ? "2.5" : "1.5");
        g.appendChild(circle);

        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", String(node.x ?? 0));
        text.setAttribute("y", String((node.y ?? 0) + 4));
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("fill", node.isGateway ? "#cca700" : "#ccc");
        text.setAttribute("font-size", "9");
        text.setAttribute("font-family", "monospace");
        text.textContent = node.isGateway ? node.id : `.${node.label}`;
        g.appendChild(text);

        if (node.vendor) {
          const vendor = document.createElementNS("http://www.w3.org/2000/svg", "text");
          vendor.setAttribute("x", String(node.x ?? 0));
          vendor.setAttribute("y", String((node.y ?? 0) + 28));
          vendor.setAttribute("text-anchor", "middle");
          vendor.setAttribute("fill", "#555");
          vendor.setAttribute("font-size", "8");
          vendor.setAttribute("font-family", "monospace");
          vendor.textContent = node.vendor;
          g.appendChild(vendor);
        }

        svg.appendChild(g);
      }
    });

    return () => {
      simulation.stop();
    };
  }, [gateway, hosts, width, height]);

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${width} ${height}`}
      className="w-full h-auto"
      style={{ maxHeight: height }}
    />
  );
}
```

- [ ] **Step 2: Integrate NetworkTopology into ScanRunner**

In `dashboard/components/scan-runner.tsx`, import and render the topology below the progress list when hosts have been discovered. Build the host list from accumulated events:

```tsx
import { NetworkTopology } from "./network-topology";

// Inside the ScanRunner component, derive enriched hosts from events:
const enrichedHosts = hosts.map((h) => {
  const enrichment = events.find(
    (e) => e.type === "host:enriched" && e.ip === h.ip
  );
  const hostPorts = events
    .filter((e) => e.type === "port:found" && e.ip === h.ip)
    .map((e) => ({ port: e.port!, service: e.service! }));
  return {
    ip: h.ip!,
    mac: h.mac!,
    vendor: enrichment?.vendor,
    isCamera: false,
    ports: hostPorts,
  };
});

const gatewayEvent = events.find((e) => e.type === "bootstrap:complete");

// In the JSX, after the progress list:
{gatewayEvent && enrichedHosts.length > 0 && (
  <Card className="mt-4">
    <CardHeader>
      <CardTitle className="text-base">Network Topology</CardTitle>
    </CardHeader>
    <CardContent>
      <NetworkTopology
        gateway={(gatewayEvent as any).gateway}
        hosts={enrichedHosts}
      />
    </CardContent>
  </Card>
)}
```

- [ ] **Step 3: Run typecheck**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add dashboard/components/network-topology.tsx dashboard/components/scan-runner.tsx
git commit -m "feat: D3 force-directed network topology in dashboard"
```

---

### Task 16: Migrate host table to cli-table3

**Files:**
- Modify: `src/reporter/terminal.reporter.ts`

- [ ] **Step 1: Replace renderNetworkMap host list with cli-table3 table**

In `renderNetworkMap` in `src/reporter/terminal.reporter.ts`, replace the manual host iteration (lines that use `pad()` and string concatenation for IP, MAC, vendor alignment) with a `cli-table3` table.

Add import:

```typescript
import Table from "cli-table3";
```

Replace the host-rendering loop with a table:

```typescript
if (network.hosts.length > 0) {
  const table = new Table({
    head: ["IP", "MAC", "Vendor", "Services"],
    chars: {
      top: "─", "top-mid": "┬", "top-left": "┌", "top-right": "┐",
      bottom: "─", "bottom-mid": "┴", "bottom-left": "└", "bottom-right": "┘",
      left: "│", "left-mid": "├", mid: "─", "mid-mid": "┼",
      right: "│", "right-mid": "┤", middle: "│",
    },
    style: { head: ["cyan"], border: ["dim"] },
    colWidths: [18, 20, 20, null],
    wordWrap: true,
  });

  for (const host of network.hosts) {
    const cameraFlag = host.isCamera ? RED(" ✘ CAM") : "";
    const vendor = (host.vendor ?? "") + cameraFlag;
    const openPorts = (host.ports ?? []).filter(p => p.state === "open");
    const portStr = openPorts.slice(0, 5).map(p => `${p.port}/${p.service}`).join(", ");
    const more = openPorts.length > 5 ? ` +${openPorts.length - 5}` : "";
    table.push([host.ip, chalk.dim(host.mac), vendor, chalk.dim(portStr + more)]);
  }

  lines.push(row(""));
  for (const line of table.toString().split("\n")) {
    lines.push(row("  " + line));
  }
}
```

Apply the same pattern to the nearby networks list in `renderWifiDetails` and the connections destinations in `renderConnectionsSummary`.

- [ ] **Step 2: Run typecheck and tests**

```bash
npm run typecheck && npm test
```

Expected: all pass.

- [ ] **Step 3: Smoke test — verify table rendering**

```bash
npm run dev -- scan --skip-speed --skip-traffic
```

Expected: host table renders with proper borders and alignment, adapting to terminal width.

- [ ] **Step 4: Commit**

```bash
git add src/reporter/terminal.reporter.ts
git commit -m "feat: cli-table3 for host and connection tables"
```

---

### Task 17: Integrate sparklines into terminal reporter

**Files:**
- Modify: `src/reporter/terminal.reporter.ts`

- [ ] **Step 1: Add sparkline imports and integrate into RF and scorecard sections**

Import the sparkline helpers:

```typescript
import { renderScoreTrend, renderSignalTrend } from "./sparklines.js";
```

In `renderScorecard`, after the score bar, check for scan history and render a trend sparkline if available. Since the terminal reporter currently receives only the current scan result, add an optional `history` parameter to `renderTerminalReport`:

```typescript
export function renderTerminalReport(
  result: NetworkScanResult,
  options?: { scoreHistory?: number[]; signalHistory?: number[] },
): string {
  refreshWidth();
  // ...
}
```

In `renderScorecard`, add after the score bar:

```typescript
if (options?.scoreHistory && options.scoreHistory.length >= 2) {
  lines.push(row(`  Trend  ${renderScoreTrend(options.scoreHistory)}`));
}
```

In `renderWifiDetails`, add after the signal bar:

```typescript
if (options?.signalHistory && options.signalHistory.length >= 2) {
  lines.push(row(`  Trend      ${renderSignalTrend(options.signalHistory)}`));
}
```

Pass the options through from `renderTerminalReport` to the section renderers by threading the options parameter.

- [ ] **Step 2: Run typecheck and tests**

```bash
npm run typecheck && npm test
```

Expected: all pass. The new parameter is optional so existing callers are unaffected.

- [ ] **Step 3: Commit**

```bash
git add src/reporter/terminal.reporter.ts
git commit -m "feat: sparkline trends in scorecard and wifi sections"
```

---

### Task 18: Integrate terminal-link into compliance findings

**Files:**
- Modify: `src/reporter/analysis.reporter.ts`

- [ ] **Step 1: Use link helper for recommendation URLs in compliance details**

Import the link helper:

```typescript
import { link } from "./render-helpers.js";
```

In `renderComplianceDetails`, when rendering a finding's recommendation, detect URLs and make them clickable:

```typescript
// Replace:
lines.push(row(chalk.dim(`     → ${finding.recommendation}`)));

// With:
const rec = finding.recommendation.replace(
  /(https?:\/\/\S+)/g,
  (url) => link(url, url),
);
lines.push(row(chalk.dim(`     → ${rec}`)));
```

- [ ] **Step 2: Run typecheck**

```bash
npm run typecheck
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/reporter/analysis.reporter.ts
git commit -m "feat: clickable URLs in compliance findings"
```

---

### Task 19: Update dashboard colours to accessible palette

**Files:**
- Modify: `dashboard/components/score-gauge.tsx`
- Modify: `dashboard/components/persona-card.tsx`
- Modify: `dashboard/components/risk-badge.tsx`
- Modify: `dashboard/components/grade-badge.tsx`
- Modify: `dashboard/app/scans/[id]/page.tsx`

- [ ] **Step 1: Update score-gauge.tsx colours**

Replace `text-green-500` with `text-teal-400`, `stroke-green-500` with `stroke-teal-400`. Tailwind's teal-400 (#2dd4bf) is close to #4ec9b0.

In `dashboard/components/score-gauge.tsx`:

```typescript
function scoreColor(score: number): string {
  if (score >= 8) return "text-teal-400";
  if (score >= 5) return "text-amber-400";
  return "text-red-400";
}

function scoreBgRing(score: number): string {
  if (score >= 8) return "stroke-teal-400/20";
  if (score >= 5) return "stroke-amber-400/20";
  return "stroke-red-400/20";
}

function scoreRing(score: number): string {
  if (score >= 8) return "stroke-teal-400";
  if (score >= 5) return "stroke-amber-400";
  return "stroke-red-400";
}
```

- [ ] **Step 2: Update persona-card.tsx and risk-badge.tsx severity colours**

In `dashboard/components/persona-card.tsx`, update `severityColor`:

```typescript
const severityColor: Record<string, string> = {
  critical: "text-red-500",
  high: "text-red-400",
  medium: "text-amber-400",
  low: "text-muted-foreground",
  info: "text-blue-400",
};
```

Apply the same teal/amber/red mapping in `risk-badge.tsx` and `grade-badge.tsx`.

- [ ] **Step 3: Update scan detail page status indicators**

In `dashboard/app/scans/[id]/page.tsx`, replace `text-green-400` with `text-teal-400` for positive status indicators (line 96 firewall enabled, line 98 VPN active, etc.), and ensure the rogue AP section uses `text-amber-400` for medium severity.

- [ ] **Step 4: Run typecheck**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add dashboard/components/score-gauge.tsx dashboard/components/persona-card.tsx dashboard/components/risk-badge.tsx dashboard/components/grade-badge.tsx dashboard/app/scans/\[id\]/page.tsx
git commit -m "feat: accessible teal/amber colour palette in dashboard"
```

---

### Task 20: Smoke test end-to-end

**Files:** None — this is a verification task.

- [ ] **Step 1: Run full test suite**

```bash
npm test
```

Expected: all tests pass.

- [ ] **Step 2: Run typecheck across both projects**

```bash
npm run typecheck && cd dashboard && npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 3: Run lint**

```bash
npm run lint
```

Expected: no new warnings or errors.

- [ ] **Step 4: Terminal smoke test — scan with progress**

```bash
npm run dev -- scan --skip-speed --skip-traffic
```

Expected: listr2 progress tree with teal checkmarks, network tree growing as hosts appear, full report with accessible colours, responsive width, cli-table3 host table, sparkline trends (if history exists).

- [ ] **Step 5: Terminal smoke test — NDJSON events**

```bash
npm run dev -- scan --skip-speed --skip-traffic --events 2>/dev/null | head -15
```

Expected: clean NDJSON lines with `scan:start`, `scanner:start`, `scanner:complete`, `host:found`, etc.

- [ ] **Step 6: Dashboard smoke test — run scan from browser**

```bash
npm run dashboard
```

Open http://localhost:3000/scans, click "Start Scan", verify progress events stream in with teal/amber colours, topology graph appears with nodes, scan completes and list refreshes. Score gauge and persona cards should use the accessible colour palette.

- [ ] **Step 7: Commit all outstanding changes**

```bash
git add -A
git commit -m "chore: end-to-end smoke test verification"
```
