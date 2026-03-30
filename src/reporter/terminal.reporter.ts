import chalk from "chalk";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import { computeSecurityScore } from "../analyser/score.js";
import {
  W,
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

// ─── Section renderers ─────────────────────────────────────────────────────

function renderHeader(result: NetworkScanResult): string {
  const { meta, wifi, network } = result;
  const ts = new Date(meta.timestamp).toLocaleString();
  const title = "NETWORK SECURITY ANALYSIS";
  const titlePad = Math.floor((W - title.length) / 2);

  const lines: string[] = [
    chalk.cyan(hRule("╔", "═", "╗")),
    chalk.cyan("║") + " ".repeat(W + 2) + chalk.cyan("║"),
    chalk.cyan("║") + " ".repeat(titlePad) + chalk.cyan.bold(title) + " ".repeat(W + 2 - titlePad - title.length) + chalk.cyan("║"),
    chalk.cyan("║") + " ".repeat(W + 2) + chalk.cyan("║"),
    boxLine(chalk.dim(`Scan ID  : ${meta.scanId}`)),
    boxLine(chalk.dim(`Time     : ${ts}  (${meta.duration}ms)`)),
    boxLine(chalk.dim(`Host     : ${meta.hostname}  [${meta.platform}]`)),
    boxLine(chalk.dim(`Network  : ${network.ip}  on  ${network.interface}  (${network.subnet})`)),
    boxLine(chalk.dim(`SSID     : ${wifi.ssid ?? "(hidden)"}  [${wifi.bssid}]`)),
    chalk.cyan("║") + " ".repeat(W + 2) + chalk.cyan("║"),
    chalk.cyan(hRule("╚", "═", "╝")),
  ];

  return lines.join("\n");
}

function renderNetworkMap(result: NetworkScanResult): string {
  const { network } = result;
  const gw = network.gateway;
  const lines: string[] = [
    sectionHeader("NETWORK MAP"),
    row(""),
    row(chalk.bold("  GATEWAY")),
    row(`  ┌─ ${chalk.yellow(gw.ip)}  ${chalk.dim(gw.mac)}  ${chalk.cyan(gw.vendor ?? "unknown vendor")}`),
    row("  │"),
  ];

  if (network.hosts.length === 0) {
    lines.push(row("  └─ (no hosts discovered)"));
  } else {
    network.hosts.forEach((host, idx) => {
      const isLast = idx === network.hosts.length - 1;
      const connector = isLast ? "└─" : "├─";
      const cameraFlag = host.isCamera ? chalk.red(" ⚠ CAMERA") : "";
      const deviceType = host.deviceType ? chalk.dim(` [${host.deviceType}]`) : "";
      const vendor = host.vendor ? chalk.cyan(` ${host.vendor}`) : "";
      const hostname = host.hostname ? chalk.dim(` (${host.hostname})`) : "";
      lines.push(row(`  ${connector} ${chalk.green(host.ip)}  ${chalk.dim(host.mac)}${vendor}${deviceType}${hostname}${cameraFlag}`));
      const openPorts = (host.ports ?? []).filter(p => p.state === "open");
      if (openPorts.length > 0) {
        const portList = openPorts
          .slice(0, 5)
          .map(p => `${p.port}/${p.service}`)
          .join("  ");
        const more = openPorts.length > 5 ? chalk.dim(` +${openPorts.length - 5} more`) : "";
        lines.push(row(`  ${isLast ? " " : "│"}     ${chalk.dim("ports:")} ${chalk.dim(portList)}${more}`));
      }
    });
  }

  lines.push(row(""));

  if (network.topology.doubleNat) {
    lines.push(row(chalk.yellow("  ⚠  Double NAT detected — you are behind multiple routers")));
  }

  if (network.topology.hops.length > 0) {
    lines.push(row(chalk.dim("  Traceroute hops:")));
    network.topology.hops.slice(0, 6).forEach((hop, i) => {
      const label = hop.hostname ? ` (${hop.hostname})` : "";
      lines.push(row(chalk.dim(`    ${i + 1}. ${hop.ip}${label}  ${hop.latencyMs}ms`)));
    });
  }

  lines.push(row(""));
  return lines.join("\n");
}

function renderWifiDetails(result: NetworkScanResult): string {
  const w = result.wifi;
  const lines: string[] = [
    sectionHeader("WI-FI DETAILS"),
    row(""),
    row(`  SSID         ${chalk.bold(w.ssid ?? chalk.dim("(hidden)"))}  ${chalk.dim(`[${w.bssid}]`)}`),
    row(`  Protocol     ${chalk.cyan(w.protocol)}   Band: ${chalk.cyan(w.band)}   Channel: ${chalk.cyan(String(w.channel))}   Width: ${chalk.cyan(w.width)}`),
    row(`  Security     ${chalk.bold(w.security)}`),
    row(`  Signal       ${signalBar(w.signal)}`),
    row(`  Noise        ${chalk.dim(`${w.noise} dBm`)}   SNR: ${chalk.bold(String(w.snr))} dB  →  ${snrLabel(w.snr)}`),
    row(`  TX Rate      ${chalk.dim(`${w.txRate} Mbps`)}`),
    row(`  MAC Random   ${w.macRandomised ? chalk.green("enabled") : chalk.yellow("disabled")}`),
    row(`  Country      ${chalk.dim(w.countryCode)}`),
    row(""),
  ];

  if (w.nearbyNetworks.length > 0) {
    lines.push(row(chalk.dim("  Nearby networks:")));
    w.nearbyNetworks.slice(0, 8).forEach(n => {
      const ssid = n.ssid ?? chalk.dim("(hidden)");
      const sig = `${n.signal} dBm`.padStart(8);
      lines.push(row(chalk.dim(`    ${ssid.padEnd(32)} ${n.protocol.padEnd(10)} ch${String(n.channel).padEnd(4)} ${sig}  ${n.security}`)));
    });
    if (w.nearbyNetworks.length > 8) {
      lines.push(row(chalk.dim(`    … and ${w.nearbyNetworks.length - 8} more`)));
    }
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderSecurityPosture(result: NetworkScanResult): string {
  const sec = result.security;
  const fw = sec.firewall;
  const vpn = sec.vpn;
  const lines: string[] = [
    sectionHeader("SECURITY POSTURE"),
    row(""),
    row(chalk.bold("  Firewall")),
    row(`    ${boolStatus(fw.enabled, true)}  Enabled           ${boolStatus(fw.stealthMode, true)}  Stealth mode`),
    row(`    ${boolStatus(!fw.autoAllowSigned, true)}  Auto-allow signed  ${boolStatus(!fw.autoAllowDownloaded, true)}  Auto-allow downloaded apps`),
    row(""),
    row(chalk.bold("  VPN")),
    row(`    ${boolStatus(vpn.installed, true)}  Installed    ${boolStatus(vpn.active, true)}  Active${vpn.provider ? chalk.dim(`   (${vpn.provider})`) : ""}`),
    row(""),
    row(chalk.bold("  Proxy")),
    row(`    ${boolStatus(!sec.proxy.enabled, true)}  Proxy ${sec.proxy.enabled ? chalk.yellow("ENABLED") + chalk.dim(` → ${sec.proxy.server ?? ""}:${sec.proxy.port ?? ""}`) : chalk.green("disabled")}`),
    row(""),
    row(chalk.bold("  Kernel Parameters")),
    row(`    ${boolStatus(!sec.kernelParams.ipForwarding, true)}  IP forwarding    ${boolStatus(!sec.kernelParams.icmpRedirects, true)}  ICMP redirects`),
    row(""),
  ];

  if (sec.clientIsolation !== null) {
    const label = sec.clientIsolation ? chalk.green("enabled") : chalk.red("disabled — hosts can reach each other");
    lines.push(row(`  ${boolStatus(sec.clientIsolation ?? false, true)}  Client isolation: ${label}`));
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderDnsAudit(result: NetworkScanResult): string {
  const dns = result.network.dns;
  const hijackColor =
    dns.hijackTestResult === "clean"
      ? chalk.green
      : dns.hijackTestResult === "intercepted"
      ? chalk.red
      : chalk.yellow;

  const lines: string[] = [
    sectionHeader("DNS AUDIT"),
    row(""),
    row(`  Servers      ${dns.servers.join("  ")}`),
    row(`  DNSSEC       ${dns.dnssecSupported ? chalk.green("supported") : chalk.yellow("not supported")}`),
    row(`  DoH / DoT    ${dns.dohDotEnabled ? chalk.green("enabled") : chalk.dim("not detected")}`),
    row(`  Hijack test  ${hijackColor(dns.hijackTestResult.toUpperCase())}`),
    row(""),
  ];

  if (dns.anomalies.length > 0) {
    lines.push(row(chalk.yellow("  Anomalies detected:")));
    dns.anomalies.forEach(a => lines.push(row(chalk.yellow(`    ⚠  ${a}`))));
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderHiddenDeviceAlerts(result: NetworkScanResult): string {
  const hd = result.hiddenDevices;
  if (!hd || (hd.suspectedCameras.length === 0 && hd.unknownDevices.length === 0)) {
    return "";
  }

  const lines: string[] = [sectionHeader("HIDDEN DEVICE ALERTS"), row("")];

  if (hd.suspectedCameras.length > 0) {
    lines.push(row(chalk.red.bold("  ██  SUSPECTED SURVEILLANCE CAMERAS DETECTED  ██")));
    lines.push(row(""));
    hd.suspectedCameras.forEach(cam => {
      const indicators = cam.cameraIndicators ?? [];
      const confidence =
        indicators.length >= 3
          ? chalk.red("HIGH")
          : indicators.length === 2
          ? chalk.yellow("MEDIUM")
          : chalk.dim("LOW");
      lines.push(row(chalk.red(`  ⚠  ${cam.ip}  ${chalk.dim(cam.mac)}  ${chalk.cyan(cam.vendor ?? "unknown vendor")}  — confidence: ${confidence}`)));
      indicators.forEach(ind => lines.push(row(chalk.dim(`       • ${ind}`))));
    });
    lines.push(row(""));
  }

  if (hd.unknownDevices.length > 0) {
    lines.push(row(chalk.yellow(`  Unknown devices (${hd.unknownDevices.length}):`)));
    hd.unknownDevices.forEach(d => {
      lines.push(row(chalk.yellow(`    ?  ${d.ip}  ${chalk.dim(d.mac)}  ${chalk.dim(d.vendor ?? "unknown vendor")}${d.hostname ? chalk.dim(` (${d.hostname})`) : ""}`)));
    });
    lines.push(row(""));
  }

  if (hd.indicators.length > 0) {
    lines.push(row(chalk.dim("  Detection indicators used:")));
    hd.indicators.forEach(ind => lines.push(row(chalk.dim(`    • ${ind}`))));
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderIntrusionIndicators(result: NetworkScanResult): string {
  const ii = result.intrusionIndicators;
  if (!ii) return "";
  if (ii.arpAnomalies.length === 0 && ii.suspiciousHosts.length === 0 && ii.scanDetection.length === 0) {
    return [
      sectionHeader("INTRUSION INDICATORS"),
      row(""),
      row(chalk.green("  No intrusion indicators detected.")),
      row(""),
    ].join("\n");
  }

  const lines: string[] = [sectionHeader("INTRUSION INDICATORS"), row("")];

  if (ii.arpAnomalies.length > 0) {
    lines.push(row(chalk.bold("  ARP Anomalies:")));
    ii.arpAnomalies.forEach(a => {
      const c = severityColor(a.severity);
      lines.push(row(c(`    [${a.severity.toUpperCase()}] ${a.type} — ${a.detail}`)));
    });
    lines.push(row(""));
  }

  if (ii.suspiciousHosts.length > 0) {
    lines.push(row(chalk.bold("  Suspicious Hosts:")));
    ii.suspiciousHosts.forEach(h => {
      const c = severityColor(h.severity);
      lines.push(row(c(`    [${h.severity.toUpperCase()}] ${h.ip}  ${chalk.dim(h.mac)}  — ${h.reason}`)));
    });
    lines.push(row(""));
  }

  if (ii.scanDetection.length > 0) {
    lines.push(row(chalk.bold("  Scan Detection:")));
    ii.scanDetection.forEach(s => {
      lines.push(row(chalk.red(`    ${s.type.toUpperCase()} from ${s.source} — ${s.detail}`)));
    });
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderExposedServices(result: NetworkScanResult): string {
  const exposed = result.localServices.filter(s => s.exposedToNetwork);
  const lines: string[] = [sectionHeader("EXPOSED SERVICES"), row("")];

  if (exposed.length === 0) {
    lines.push(row(chalk.green("  No services exposed to the network (0.0.0.0).")));
  } else {
    lines.push(row(chalk.yellow(`  ${exposed.length} service(s) bound to 0.0.0.0 — visible to all network hosts:`)));
    lines.push(row(""));
    exposed.forEach(svc => {
      lines.push(row(chalk.yellow(`    ⚠  port ${String(svc.port).padEnd(6)} ${svc.process.padEnd(28)} ${chalk.dim(svc.bindAddress)}`)));
    });
  }

  const bound = result.localServices.filter(s => !s.exposedToNetwork);
  if (bound.length > 0) {
    lines.push(row(""));
    lines.push(row(chalk.dim(`  ${bound.length} service(s) bound to loopback only (safe).`)));
  }

  lines.push(row(""));
  return lines.join("\n");
}

function renderConnectionsSummary(result: NetworkScanResult): string {
  const conn = result.connections;
  const lines: string[] = [
    sectionHeader("CONNECTIONS SUMMARY"),
    row(""),
    row(`  Established: ${chalk.bold(String(conn.established))}   Listening: ${chalk.dim(String(conn.listening))}   TIME_WAIT: ${chalk.dim(String(conn.timeWait))}`),
    row(""),
  ];

  if (conn.topDestinations.length > 0) {
    lines.push(row(chalk.dim("  Top destinations:")));
    conn.topDestinations.slice(0, 10).forEach(d => {
      const label = d.reverseDns ? chalk.dim(` → ${d.reverseDns}`) : "";
      const cnt = chalk.cyan(String(d.count).padStart(4));
      lines.push(row(`    ${cnt} conns   ${d.ip.padEnd(18)}${label}`));
    });
  }

  lines.push(row(""));

  if (result.traffic) {
    const t = result.traffic;
    lines.push(row(chalk.dim(`  Traffic capture: ${t.capturedPackets} packets over ${t.durationSeconds}s`)));
    const protoEntries = Object.entries(t.protocols)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([proto, count]) => `${proto}:${count}`)
      .join("  ");
    if (protoEntries) {
      lines.push(row(chalk.dim(`  Protocols: ${protoEntries}`)));
    }
    if (t.unencrypted.length > 0) {
      lines.push(row(chalk.red(`  ⚠  ${t.unencrypted.length} unencrypted flow(s) detected`)));
      t.unencrypted.slice(0, 3).forEach(u =>
        lines.push(row(chalk.red(`       ${u.protocol.toUpperCase()}  →  ${u.dest}:${u.port}`)))
      );
    }
    if (t.mdnsLeaks.length > 0) {
      lines.push(row(chalk.yellow(`  ⚠  ${t.mdnsLeaks.length} mDNS leak(s): ${t.mdnsLeaks.slice(0, 3).map(m => m.service).join(", ")}`)));
    }
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderSpeedTest(result: NetworkScanResult): string {
  const s = result.speed;
  if (!s) return "";

  const lines: string[] = [sectionHeader("SPEED TEST"), row("")];

  // Rating badge
  const ratingColors: Record<string, (s: string) => string> = {
    excellent: chalk.green,
    good: chalk.green,
    fair: chalk.yellow,
    poor: chalk.red,
    unusable: chalk.red,
  };
  const colorFn = ratingColors[s.rating] ?? chalk.white;
  lines.push(row(`  Rating:  ${colorFn(s.rating.toUpperCase())}`));
  lines.push(row(""));

  // Download/Upload bars
  const maxBar = 40;
  const dlBar = Math.min(maxBar, Math.round(s.download.speedMbps / 5));
  const ulBar = Math.min(maxBar, Math.round(s.upload.speedMbps / 5));
  const dlColor = s.download.speedMbps >= 50 ? chalk.green : s.download.speedMbps >= 10 ? chalk.yellow : chalk.red;
  const ulColor = s.upload.speedMbps >= 20 ? chalk.green : s.upload.speedMbps >= 5 ? chalk.yellow : chalk.red;

  lines.push(row(`  Download  ${dlColor("█".repeat(dlBar) + "░".repeat(Math.max(0, 10 - dlBar)))}  ${chalk.bold(s.download.speedMbps.toFixed(1) + " Mbps")}`));
  lines.push(row(`  Upload    ${ulColor("█".repeat(ulBar) + "░".repeat(Math.max(0, 10 - ulBar)))}  ${chalk.bold(s.upload.speedMbps.toFixed(1) + " Mbps")}`));
  lines.push(row(""));

  // Latency
  const latColor = (ms: number) => ms < 20 ? chalk.green : ms < 50 ? chalk.yellow : chalk.red;
  lines.push(row(`  Latency`));
  lines.push(row(`    Gateway:     ${latColor(s.latency.gatewayMs)(s.latency.gatewayMs.toFixed(1) + " ms")}   jitter: ${s.jitter.gatewayMs.toFixed(1)} ms`));
  lines.push(row(`    Internet:    ${latColor(s.latency.internetMs)(s.latency.internetMs.toFixed(1) + " ms")}   jitter: ${s.jitter.internetMs.toFixed(1)} ms`));
  lines.push(row(`    DNS resolve: ${s.latency.dnsResolutionMs} ms`));
  lines.push(row(""));

  // Packet loss
  const plColor = (pct: number) => pct === 0 ? chalk.green : pct < 5 ? chalk.yellow : chalk.red;
  lines.push(row(`  Packet Loss`));
  lines.push(row(`    Gateway:   ${plColor(s.packetLoss.gatewayPercent)(s.packetLoss.gatewayPercent.toFixed(0) + "%")}    Internet: ${plColor(s.packetLoss.internetPercent)(s.packetLoss.internetPercent.toFixed(0) + "%")}`));
  lines.push(row(""));

  // WiFi utilisation
  if (s.wifiLinkRate > 0) {
    const utilColor = s.effectiveUtilisation > 50 ? chalk.green : s.effectiveUtilisation > 20 ? chalk.yellow : chalk.red;
    lines.push(row(`  WiFi Link Rate: ${s.wifiLinkRate} Mbps → actual throughput: ${s.download.speedMbps.toFixed(1)} Mbps (${utilColor(s.effectiveUtilisation.toFixed(1) + "% utilisation")})`));
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderScorecard(result: NetworkScanResult): string {
  const score = computeSecurityScore(result);
  const label =
    score >= 8
      ? chalk.green("SECURE")
      : score >= 6
      ? chalk.yellow("MODERATE RISK")
      : score >= 4
      ? chalk.yellow("ELEVATED RISK")
      : chalk.red("HIGH RISK");

  const bar = scoreBar(Math.round(score));
  const scoreStr = `${score.toFixed(1)} / 10`;

  const lines: string[] = [
    sectionHeader("SECURITY SCORECARD"),
    row(""),
    row(`  Overall posture:  ${label}`),
    row(""),
    row(`  Score  ${bar}  ${chalk.bold(scoreStr)}`),
    row(""),
    chalk.cyan(hRule("╚", "═", "╝")),
  ];

  return lines.join("\n");
}

// ─── Main export ──────────────────────────────────────────────────────────

export function renderTerminalReport(result: NetworkScanResult): string {
  const sections: string[] = [
    renderHeader(result),
    renderNetworkMap(result),
    renderWifiDetails(result),
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
