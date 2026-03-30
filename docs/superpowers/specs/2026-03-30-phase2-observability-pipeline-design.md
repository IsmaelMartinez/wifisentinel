# Phase 2: Observability Pipeline — Design Spec

## Overview

Phase 2 adds scan persistence, history browsing, diff comparison, trend tracking, and OS-level scheduled scanning to WiFi Sentinel. The goal is to turn one-shot scans into a longitudinal record that reveals how a network's security posture changes over time.

All four roadmap items are covered: persistent export (JSON files), scan history with trends, scheduled scanning (launchd/cron), and diff reports.

## Storage Layer

### Location and format

Scan results are stored as JSON files under `~/.wifisentinel/scans/`. Each file is named `<ISO-date>_<scanId>.json` (e.g. `2026-03-30T22-53-56_4fe506c0.json`). The content is the same combined shape that `renderJsonReport()` already produces: `{ scan: NetworkScanResult, compliance: ComplianceReport, analysis: FullAnalysis }`.

An index manifest at `~/.wifisentinel/index.json` holds lightweight metadata for fast listing without reading every scan file:

```ts
interface IndexEntry {
  scanId: string;
  timestamp: string;        // ISO 8601
  ssid: string | null;
  securityScore: number;    // 0-10
  complianceGrade: string;  // A-F
  consensusRisk: string;    // critical | high | medium | low | minimal
  hostCount: number;
  filename: string;         // relative to scans/
}
```

### Module: `src/store/`

The store module provides these functions:

`saveScan(result, compliance, analysis)` — writes the scan JSON file and appends an entry to the index. Creates `~/.wifisentinel/` and `scans/` directories on first use.

`listScans(options?)` — reads the index and returns entries in reverse chronological order. Supports `limit` and `ssid` filter options.

`loadScan(scanId)` — reads a full scan file by ID (looks up filename from the index).

`rebuildIndex()` — regenerates `index.json` by reading all scan files in the directory. Used as a recovery mechanism if the index gets out of sync.

`getStorePath()` — returns `~/.wifisentinel/`. On Linux, uses `$XDG_DATA_HOME/wifisentinel/` if `XDG_DATA_HOME` is set.

### Integration with existing scan command

The `scan` and `analyse` commands auto-save results to the store after rendering output. A `--no-save` flag skips persistence (useful for one-off checks or piping). No changes to the existing output behaviour — the save happens silently after output is written.

## CLI Commands

### `wifisentinel history`

Lists past scans from the index in a compact terminal table:

```
  DATE                 SSID            SCORE  GRADE  RISK     HOSTS
  2026-03-30 22:53     MyNetwork       7.6    D      HIGH     4
  2026-03-29 08:12     MyNetwork       7.8    C      MEDIUM   3
  2026-03-28 14:30     CoffeeShop      5.2    F      HIGH     12
```

Options: `--limit N` (default 20), `--json` for machine-readable output.

### `wifisentinel diff <id1> <id2>`

Loads two scan results and produces a structural comparison. The diff covers these categories:

**Hosts**: new hosts (appeared in scan 2), removed hosts (gone from scan 2), hosts with changed ports or vendor info.

**WiFi**: changes in SSID, security protocol, channel, band, signal strength, SNR.

**Security posture**: firewall settings, VPN status, kernel parameters, client isolation changes.

**Compliance**: per-standard score deltas (e.g. "CIS Wireless: 75 -> 82 (+7)") and overall grade change.

**Personas**: risk rating changes per persona, new/resolved findings.

Terminal output uses coloured markers: green `+` for improvements, red `-` for regressions, yellow `~` for neutral changes. JSON output via `--json`.

IDs can be full scan UUIDs or unique prefixes (first 8 chars).

### `wifisentinel trend`

Reads the last N scans from the index and renders a summary table showing how key metrics have evolved:

```
  DATE          SCORE  GRADE  RISK     HOSTS  DOWNLOAD
  Mar 28        5.2    F      HIGH     12     23.4 Mbps
  Mar 29        7.8    C      MEDIUM   3      58.2 Mbps
  Mar 30        7.6    D      HIGH     4      61.9 Mbps
  ────────────────────────────────────────────────────
  Avg: 6.9  Best: 7.8  Worst: 5.2  Trend: improving
```

Options: `--limit N` (default 10), `--ssid <name>` to filter by network, `--json`.

The trend line at the bottom compares the first half of scans to the second half to determine whether the overall direction is improving, stable, or declining.

### `wifisentinel schedule`

Subcommands:

`enable [--interval <hours>]` — installs an OS-level scheduled task to run `wifisentinel scan --analyse` periodically. Default interval is 6 hours. On macOS, writes a launchd plist to `~/Library/LaunchAgents/com.wifisentinel.scan.plist`. On Linux, adds a crontab entry via `crontab -l | ... | crontab -`.

`disable` — removes the scheduled task (deletes the plist / removes the crontab entry).

`status` — shows whether scheduling is active, the configured interval, and when the last scan ran (from the index).

The scheduled scan uses the built binary (`wifisentinel scan --analyse`) so it requires `npm run build` to have been run and the binary to be accessible on PATH (or the plist uses an absolute path to `dist/cli.js`).

## OTEL Persistence

No custom OTEL file exporter is needed. The auto-saved JSON files already capture timing data through `meta.duration` and the structured scan phases. The existing `--otel otlp` flag continues to work for real-time export to OTEL collectors (Jaeger, Grafana, etc.). The store becomes the persistent historical record that was previously missing.

## File Structure

New files and directories:

```
src/
  store/
    index.ts          — saveScan, listScans, loadScan, rebuildIndex, getStorePath
    types.ts          — IndexEntry type, StoredScan type
    diff.ts           — diffScans(a, b) -> ScanDiff
  commands/
    history.ts        — history command handler
    diff.ts           — diff command handler
    trend.ts          — trend command handler
    schedule.ts       — schedule enable/disable/status handlers
```

The existing `cli.ts` gains four new command registrations pointing at the handlers in `commands/`. The `scan` action in `cli.ts` is modified to call `saveScan()` after producing output.

## Dependencies

No new npm dependencies. The store uses `node:fs`, `node:path`, and `node:os` for file operations. The schedule command uses `node:child_process` for launchd/crontab interaction. All existing patterns (Zod schemas, chalk formatting, commander) are reused.

## Error Handling

If `~/.wifisentinel/` does not exist, `saveScan` creates it. If the index is missing or corrupt, `listScans` falls back to `rebuildIndex()`. If a referenced scan file is missing, `loadScan` returns a clear error suggesting `rebuildIndex`. The `diff` and `trend` commands fail gracefully with a message if fewer than the required number of scans exist.

## Out of Scope

SQLite storage, web dashboard, PDF export, and remote/cloud sync are all deferred to later phases. The diff engine compares structured data — it does not produce unified diff format or line-level text diffs.
