// src/analyser/rf/rogue-ap.ts
import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import { isWeakerSecurity } from "../../collector/schema/security.js";
import type { RogueAPFinding, RogueAPAnalysis } from "./types.js";

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
