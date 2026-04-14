import { run } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";

type IntrusionResult = NonNullable<NetworkScanResult["intrusionIndicators"]>;
type ArpAnomaly = IntrusionResult["arpAnomalies"][number];
type SuspiciousHost = IntrusionResult["suspiciousHosts"][number];
type ScanDetection = IntrusionResult["scanDetection"][number];

// Parse `arp -a` output into a map of ip -> mac
function parseArpTable(output: string): Map<string, string> {
  const table = new Map<string, string>();
  // Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
  const lineRe = /\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)/;
  for (const line of output.split("\n")) {
    const match = line.match(lineRe);
    if (!match) continue;
    const [, ip, mac] = match;
    if (mac === "ff:ff:ff:ff:ff:ff" || line.includes("(incomplete)")) continue;
    table.set(ip, mac.toLowerCase());
  }
  return table;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function detectArpAnomalies(
  snapshot1: Map<string, string>,
  snapshot2: Map<string, string>,
  gatewayIp: string,
  gatewayMac: string
): ArpAnomaly[] {
  const anomalies: ArpAnomaly[] = [];
  const normalizedGatewayMac = gatewayMac.toLowerCase();

  // Check for MAC changes and new entries in snapshot2
  for (const [ip, mac2] of snapshot2) {
    const mac1 = snapshot1.get(ip);

    if (!mac1) {
      // New device appeared between snapshots
      anomalies.push({
        type: "new_device",
        detail: `New device appeared at ${ip} with MAC ${mac2} (could be ARP spoofing or legitimate join)`,
        severity: "low",
      });
      continue;
    }

    if (mac1 !== mac2) {
      if (ip === gatewayIp) {
        anomalies.push({
          type: "gateway_mac_changed",
          detail: `Gateway ${ip} MAC changed from ${mac1} to ${mac2} — possible man-in-the-middle attack`,
          severity: "high",
        });
      } else {
        anomalies.push({
          type: "mac_changed",
          detail: `MAC address for ${ip} changed from ${mac1} to ${mac2} — possible ARP spoofing`,
          severity: "high",
        });
      }
    }
  }

  // Check for duplicate IPs with different MACs across both snapshots combined
  const combined = new Map<string, Set<string>>();
  for (const [ip, mac] of snapshot1) {
    if (!combined.has(ip)) combined.set(ip, new Set());
    combined.get(ip)!.add(mac);
  }
  for (const [ip, mac] of snapshot2) {
    if (!combined.has(ip)) combined.set(ip, new Set());
    combined.get(ip)!.add(mac);
  }

  for (const [ip, macs] of combined) {
    if (macs.size > 1) {
      const macList = Array.from(macs).join(", ");
      anomalies.push({
        type: "duplicate_ip",
        detail: `IP ${ip} is associated with multiple MACs: ${macList} — ARP spoofing indicator`,
        severity: "high",
      });
    }
  }

  // Verify gateway MAC against known value in both snapshots
  const gw1 = snapshot1.get(gatewayIp);
  const gw2 = snapshot2.get(gatewayIp);
  if (gw1 && gw1 !== normalizedGatewayMac) {
    anomalies.push({
      type: "gateway_mac_mismatch",
      detail: `Gateway ${gatewayIp} MAC in ARP table (${gw1}) does not match expected MAC (${normalizedGatewayMac}) — MITM risk`,
      severity: "high",
    });
  }
  if (gw2 && gw2 !== normalizedGatewayMac && (!gw1 || gw2 !== gw1)) {
    anomalies.push({
      type: "gateway_mac_mismatch",
      detail: `Gateway ${gatewayIp} MAC after snapshot (${gw2}) does not match expected MAC (${normalizedGatewayMac}) — MITM risk`,
      severity: "high",
    });
  }

  return anomalies;
}

interface NetstatEntry {
  proto: string;
  localAddr: string;
  localPort: string;
  remoteAddr: string;
  remotePort: string;
  state: string;
}

// Parse `netstat -an` output
function parseNetstat(output: string): NetstatEntry[] {
  const entries: NetstatEntry[] = [];
  // Format: tcp4  0  0  192.168.1.5.54321  93.184.216.34.80  ESTABLISHED
  // Or:     tcp   0  0  0.0.0.0.22         0.0.0.0.*         LISTEN
  const lineRe = /^(tcp[46]?|udp[46]?)\s+\d+\s+\d+\s+(\S+)\.(\d+|\*)\s+(\S+)\.(\d+|\*)\s*(\S+)?/;
  for (const line of output.split("\n")) {
    const match = line.trim().match(lineRe);
    if (!match) continue;
    const [, proto, localAddr, localPort, remoteAddr, remotePort, state = ""] = match;
    entries.push({ proto, localAddr, localPort, remoteAddr, remotePort, state });
  }
  return entries;
}

function detectScanPatterns(netstatEntries: NetstatEntry[]): ScanDetection[] {
  const detections: ScanDetection[] = [];

  // Count SYN_SENT/SYN_RECV by remote source to detect outbound/inbound scans
  const synSentByRemote = new Map<string, number>();
  const synRecvByRemote = new Map<string, number>();
  const timeWaitByRemote = new Map<string, Set<string>>();

  for (const entry of netstatEntries) {
    if (entry.state === "SYN_SENT") {
      synSentByRemote.set(entry.remoteAddr, (synSentByRemote.get(entry.remoteAddr) ?? 0) + 1);
    }
    if (entry.state === "SYN_RECV") {
      synRecvByRemote.set(entry.remoteAddr, (synRecvByRemote.get(entry.remoteAddr) ?? 0) + 1);
    }
    if (entry.state === "TIME_WAIT") {
      if (!timeWaitByRemote.has(entry.remoteAddr)) {
        timeWaitByRemote.set(entry.remoteAddr, new Set());
      }
      timeWaitByRemote.get(entry.remoteAddr)!.add(entry.remotePort);
    }
  }

  // Many half-open connections to different destinations = outbound port scan
  for (const [remote, count] of synSentByRemote) {
    if (count >= 5) {
      detections.push({
        source: "localhost",
        type: "outbound_scan",
        detail: `${count} simultaneous SYN_SENT connections to ${remote} — possible outbound port scan`,
      });
    }
  }

  // Many incoming half-open connections from same source = inbound scan
  for (const [remote, count] of synRecvByRemote) {
    if (count >= 5) {
      detections.push({
        source: remote,
        type: "inbound_scan",
        detail: `${count} half-open SYN_RECV connections from ${remote} — possible inbound port scan`,
      });
    }
  }

  // Many TIME_WAIT to different ports from same remote = port scan footprint
  for (const [remote, ports] of timeWaitByRemote) {
    if (ports.size >= 10) {
      detections.push({
        source: remote,
        type: "port_scan_footprint",
        detail: `${ports.size} TIME_WAIT connections to different ports from/to ${remote} — port scan footprint`,
      });
    }
  }

  return detections;
}

function detectSuspiciousHosts(
  snapshot1: Map<string, string>,
  snapshot2: Map<string, string>
): SuspiciousHost[] {
  const suspicious: SuspiciousHost[] = [];

  // Detect rapid sequential IP appearance (scan sweep indicator)
  const newIps = [...snapshot2.keys()].filter((ip) => !snapshot1.has(ip));
  if (newIps.length >= 3) {
    // Check if new IPs are sequential
    const ipNums = newIps.map((ip) => {
      const parts = ip.split(".").map(Number);
      return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    }).sort((a, b) => a - b);

    let sequentialCount = 1;
    let maxSequential = 1;
    for (let i = 1; i < ipNums.length; i++) {
      if (ipNums[i] - ipNums[i - 1] <= 2) {
        sequentialCount++;
        maxSequential = Math.max(maxSequential, sequentialCount);
      } else {
        sequentialCount = 1;
      }
    }

    if (maxSequential >= 3) {
      for (const ip of newIps) {
        const mac = snapshot2.get(ip)!;
        suspicious.push({
          ip,
          mac,
          reason: `Host appeared rapidly alongside ${newIps.length - 1} other new sequential hosts — possible network scan sweep`,
          severity: "medium",
        });
      }
    }
  }

  return suspicious;
}

export async function scanForIntrusions(
  gatewayIp: string,
  gatewayMac: string
): Promise<IntrusionResult> {
  // Take two ARP snapshots 3 seconds apart
  const arp1Result = run("/usr/sbin/arp", ["-a"]);
  const snapshot1 = parseArpTable(arp1Result.stdout);

  await sleep(3_000);

  const arp2Result = run("/usr/sbin/arp", ["-a"]);
  const snapshot2 = parseArpTable(arp2Result.stdout);

  const arpAnomalies = detectArpAnomalies(snapshot1, snapshot2, gatewayIp, gatewayMac);

  // Parse netstat for scan patterns
  const netstatResult = run("/usr/sbin/netstat", ["-an"]);
  const netstatEntries = parseNetstat(netstatResult.stdout);
  const scanDetection = detectScanPatterns(netstatEntries);

  const suspiciousHosts = detectSuspiciousHosts(snapshot1, snapshot2);

  return {
    arpAnomalies,
    suspiciousHosts,
    scanDetection,
  };
}
