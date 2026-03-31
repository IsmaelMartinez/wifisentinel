# Phase 4: WiFi RF Intelligence — Design Spec

## Overview

Phase 4 adds RF-layer analysis to WiFi Sentinel: channel occupancy mapping with saturation scoring, optimal channel recommendations, rogue AP / evil twin detection, WiFi environment change detection between scans, and signal trend tracking over time. All features work without monitor mode — they use the `nearbyNetworks` data already collected by `system_profiler SPAirPortDataType`.

Deauth flood detection and frame-counter-based analysis are deferred to a future phase since they require monitor mode, which is increasingly restricted on modern macOS.

## RF Analyser Module

### Location: `src/analyser/rf/`

The module is a pure computation layer. It takes a `NetworkScanResult` (or its `wifi` section) and produces an `RFAnalysis` object. Three focused sub-modules:

### `channel-map.ts` — Channel occupancy and saturation

Builds a per-channel model for 2.4 GHz (channels 1-14) and 5 GHz. For each channel:

- Count of networks whose primary channel matches.
- Overlap count (2.4 GHz only): a 20 MHz signal on channel N affects channels N-2 through N+2. A network on channel 6 contributes interference to channels 4, 5, 7, and 8. The overlap penalty is weighted by signal strength — a strong overlapping AP is worse than a weak one.
- Saturation score (0-100): computed from network count and cumulative weighted signal strength on that channel. 0 = empty, 100 = severely congested.

Output type:

```ts
interface ChannelInfo {
  channel: number;
  band: "2.4GHz" | "5GHz";
  networkCount: number;
  overlapCount: number;         // networks on overlapping channels (2.4 GHz)
  saturationScore: number;       // 0-100
  networks: Array<{ ssid: string | null; signal: number; security: string }>;
}

interface ChannelMap {
  channels: ChannelInfo[];
  currentChannel: number;
  currentBand: string;
  currentSaturation: number;
  recommendedChannel: number;    // least-saturated non-overlapping channel in same band
  recommendationReason: string;  // e.g. "Channel 1 has saturation 12 vs current 67"
}
```

For optimal channel recommendation on 2.4 GHz, only non-overlapping channels (1, 6, 11) are considered. On 5 GHz, all available channels are candidates. The recommendation is the channel with the lowest saturation score in the same band as the current connection.

### `rogue-ap.ts` — Evil twin and rogue AP detection

Scans the `nearbyNetworks` array for indicators of rogue access points. Three detection rules:

1. Same SSID, different BSSID: another AP advertising the same network name but from a different MAC address. Could be a legitimate multi-AP setup or an evil twin. Severity depends on whether security matches.
2. Same SSID, weaker security: an AP with the current network's SSID but downgraded security (e.g. WPA2 Personal when the current network is WPA2/WPA3). High severity — classic evil twin pattern.
3. Same SSID, different channel: an AP with matching SSID on a different channel. Lower severity on its own but contributes to evil twin suspicion when combined with other indicators.

Output type:

```ts
interface RogueAPFinding {
  ssid: string;
  bssid: string | undefined;
  channel: number;
  signal: number;
  security: string;
  indicators: string[];          // which rules triggered
  severity: "high" | "medium" | "low";
  description: string;
}

interface RogueAPAnalysis {
  findings: RogueAPFinding[];
  riskLevel: "clear" | "suspicious" | "danger";
}
```

The `riskLevel` is "danger" if any finding has high severity, "suspicious" if any medium, "clear" otherwise.

### `environment.ts` — WiFi environment change detection

Compares two scans' `nearbyNetworks` arrays to detect RF environment changes. Uses the Phase 2 store to load a previous scan for comparison. Detections:

- New APs: networks in the current scan not present in the baseline (matched by BSSID if available, else by SSID + channel).
- Disappeared APs: networks in the baseline that are gone.
- Security changes: an AP that was seen before but with different security (especially downgrades).
- Signal anomalies: a known AP whose signal strength changed by more than 15 dB — could indicate the AP moved, was replaced, or is being spoofed.
- Channel changes: a known AP that switched channels.

Output type:

```ts
interface EnvironmentChange {
  type: "new_ap" | "disappeared_ap" | "security_change" | "signal_anomaly" | "channel_change";
  ssid: string | null;
  bssid?: string;
  detail: string;
  severity: "high" | "medium" | "low";
}

interface EnvironmentAnalysis {
  baselineScanId: string;
  baselineTimestamp: string;
  changes: EnvironmentChange[];
  summary: string;               // e.g. "3 changes: 1 new AP, 1 security downgrade, 1 signal anomaly"
}
```

### `index.ts` — Combined RF analysis

Top-level `analyseRF(result, baselineScan?)` runs all three sub-modules and returns:

```ts
interface RFAnalysis {
  channelMap: ChannelMap;
  rogueAPs: RogueAPAnalysis;
  environment?: EnvironmentAnalysis;  // only present when baseline provided
}
```

## CLI Command: `wifisentinel rf`

A lightweight command that runs only the WiFi scan (calls `scanWifi()` directly, no host discovery, port scan, speed test, etc.) and renders the RF analysis. Much faster than a full scan — only needs `system_profiler SPAirPortDataType`.

### Output

The terminal output includes:

**Channel Map**: an ASCII bar chart showing saturation per channel, with the current channel highlighted. Example:

```
  2.4 GHz Channel Occupancy
  Ch 1  ████░░░░░░  35%  (2 networks)
  Ch 2  ██░░░░░░░░  15%  (1 network, overlap)
  Ch 3  ██░░░░░░░░  12%  (overlap only)
  Ch 4  ████████░░  67%  (3 networks)  <- YOU ARE HERE
  Ch 5  ██████░░░░  52%  (2 networks, overlap)
  Ch 6  ████░░░░░░  38%  (2 networks)
  ...
  Ch 11 █░░░░░░░░░   8%  (1 network)

  Recommendation: Switch to channel 11 (saturation 8% vs current 67%)
```

**Rogue AP Detection**: lists any suspicious findings, or "No rogue APs detected."

**Environment Changes** (only with `--compare <scanId>`): lists changes since the baseline scan.

### Options

- `--json`: machine-readable JSON output.
- `--compare <scanId>`: compare against a stored scan for environment change detection. Accepts full UUID or 8-char prefix.
- `--trend`: show WiFi-specific metrics (signal, SNR, txRate, channel) from the last N stored scans.
- `-n, --limit <count>`: number of scans for `--trend` (default 10).

## Integration with Main Scan

The existing `scan` and `analyse` commands gain a new "RF Intelligence" section in their terminal output, positioned after the WiFi details section. This is a condensed summary showing:

- Current channel saturation score and recommended channel (one line).
- Rogue AP alert count, or "clear" (one line).

The full detailed channel map is only available via the dedicated `rf` command.

When the scan is saved to the store, the `RFAnalysis` is included in the stored JSON alongside the existing scan/compliance/analysis data. The `StoredScan` interface gains an optional `rfAnalysis` field.

## Signal Trends (`rf --trend`)

Reads the last N scans from the Phase 2 store and extracts WiFi metrics to show how the RF environment has evolved. Renders as a compact table:

```
  DATE          SIGNAL  SNR   TX RATE  CHANNEL  NEARBY
  Mar 28 14:30  -65     30    144      6        8
  Mar 29 08:12  -71     25    77       4        10
  Mar 30 22:53  -62     33    144      4        10
  ─────────────────────────────────────────────────
  Signal: improving  SNR: stable  Nearby APs: growing
```

## File Structure

New files:

```
src/
  analyser/rf/
    types.ts          — ChannelInfo, ChannelMap, RogueAPFinding, etc.
    channel-map.ts    — buildChannelMap(wifi) -> ChannelMap
    rogue-ap.ts       — detectRogueAPs(wifi) -> RogueAPAnalysis
    environment.ts    — detectEnvironmentChanges(current, baseline) -> EnvironmentAnalysis
    index.ts          — analyseRF(result, baseline?) -> RFAnalysis
  commands/
    rf.ts             — rf command handler with --json, --compare, --trend
  reporter/
    rf.reporter.ts    — terminal rendering for RF analysis (channel map, rogue APs, etc.)
```

Modified files:

```
src/store/types.ts    — add optional rfAnalysis to StoredScan
src/cli.ts            — register rf command
src/reporter/terminal.reporter.ts  — add condensed RF summary section
src/reporter/analysis.reporter.ts  — add condensed RF summary section
```

## Dependencies

No new npm dependencies. Uses existing chalk for rendering, Zod for types, and the Phase 2 store for historical comparisons.

## Out of Scope

- Monitor mode / frame-level analysis (requires elevated privileges, deferred).
- Deauth flood detection (requires monitor mode).
- 6 GHz band analysis (no 6 GHz hardware to test with; can be added later by extending the channel map).
- Live/continuous RF monitoring (Phase 6).
