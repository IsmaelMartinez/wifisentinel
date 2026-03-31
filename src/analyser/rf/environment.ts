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
