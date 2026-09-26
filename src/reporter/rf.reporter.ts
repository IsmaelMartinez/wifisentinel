// src/reporter/rf.reporter.ts
import chalk from "chalk";
import type { RFAnalysis } from "../analyser/rf/index.js";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import { pad, TEAL, AMBER, RED, severityColor } from "./render-helpers.js";

function saturationBar(score: number): string {
  const filled = Math.round(score / 10);
  const empty = 10 - filled;
  const color = score <= 30 ? TEAL : score <= 60 ? AMBER : RED;
  return color("█".repeat(filled)) + chalk.gray("░".repeat(empty));
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
    lines.push(TEAL(`  ${channelMap.recommendationReason}`));
  } else {
    lines.push(AMBER(`  Recommendation: Switch to channel ${channelMap.recommendedChannel}`));
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
    lines.push(TEAL("  No rogue APs detected."));
    return lines.join("\n");
  }

  const riskColor = rogueAPs.riskLevel === "danger" ? RED : AMBER;
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
    lines.push(TEAL("  No environment changes detected."));
    return lines.join("\n");
  }

  lines.push(chalk.dim(`  ${environment.summary}`));
  lines.push("");

  for (const c of environment.changes) {
    const sc = severityColor(c.severity);
    const icon = c.type === "new_ap" ? "+" : c.type === "disappeared_ap" ? "-" : "~";
    const iconColor = c.type === "new_ap" ? TEAL : c.type === "disappeared_ap" ? RED : AMBER;
    const ssid = c.ssid ?? "(hidden)";
    lines.push(`  ${iconColor(icon)} ${sc("[" + c.severity.toUpperCase() + "]")} ${ssid}: ${c.detail}`);
  }

  return lines.join("\n");
}

function renderDeauthDetection(deauth: NonNullable<NetworkScanResult["deauthDetection"]>): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.bold("  Deauth Flood Detection"));
  lines.push(chalk.dim(`  Method: ${deauth.method}`));
  lines.push("");

  if (!deauth.detected) {
    lines.push(TEAL("  No deauthentication events detected."));
    return lines.join("\n");
  }

  lines.push(AMBER(`  ${deauth.frameCount} deauth/disassoc event(s) detected`));
  lines.push("");

  if (deauth.sources.length > 0) {
    lines.push(chalk.dim("  Sources:"));
    for (const src of deauth.sources.slice(0, 10)) {
      lines.push(`    ${chalk.cyan(src.mac.padEnd(18))} ${AMBER(String(src.count))} event(s)`);
    }
  }

  return lines.join("\n");
}

export function renderRFReport(analysis: RFAnalysis, deauth?: NetworkScanResult["deauthDetection"]): string {
  const sections = [
    renderChannelMap(analysis),
    renderRogueAPs(analysis),
    renderEnvironment(analysis),
    deauth ? renderDeauthDetection(deauth) : "",
  ].filter(Boolean);

  return sections.join("\n");
}

/** Condensed one-line summary for embedding in main scan output. */
export function renderRFSummary(analysis: RFAnalysis, deauth?: NetworkScanResult["deauthDetection"]): string {
  const { channelMap, rogueAPs } = analysis;
  const lines: string[] = [];

  const satColor = channelMap.currentSaturation <= 30 ? TEAL
    : channelMap.currentSaturation <= 60 ? AMBER : RED;

  let channelLine = `Channel ${channelMap.currentChannel} saturation: ${satColor(channelMap.currentSaturation + "%")}`;
  if (channelMap.recommendedChannel !== channelMap.currentChannel) {
    channelLine += AMBER(` — consider channel ${channelMap.recommendedChannel}`);
  }
  lines.push(channelLine);

  if (rogueAPs.findings.length === 0) {
    lines.push(`Rogue APs: ${TEAL("clear")}`);
  } else {
    const riskColor = rogueAPs.riskLevel === "danger" ? RED : AMBER;
    lines.push(`Rogue APs: ${riskColor(rogueAPs.riskLevel.toUpperCase())} (${rogueAPs.findings.length} finding${rogueAPs.findings.length > 1 ? "s" : ""})`);
  }

  if (deauth) {
    if (deauth.detected) {
      lines.push(`Deauth events: ${AMBER(String(deauth.frameCount) + " detected")} via ${chalk.dim(deauth.method)}`);
    } else {
      lines.push(`Deauth events: ${TEAL("none")} via ${chalk.dim(deauth.method)}`);
    }
  }

  return lines.join("\n");
}
