import { run } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";

interface ArpEntry {
  ip: string;
  mac: string;
  iface: string;
}

function parseArpOutput(output: string): ArpEntry[] {
  const entries: ArpEntry[] = [];
  // Format: ? (192.168.68.1) at 48:22:54:b:d0:90 on en0 ifscope [ethernet]
  const lineRe = /\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+(\S+)/;

  for (const line of output.split("\n")) {
    const match = line.match(lineRe);
    if (!match) continue;
    const [, ip, mac, iface] = match;
    // Skip incomplete entries where mac is "ff:ff:ff:ff:ff:ff" or "(incomplete)"
    if (mac === "ff:ff:ff:ff:ff:ff" || line.includes("(incomplete)")) continue;
    entries.push({ ip, mac, iface });
  }

  return entries;
}

function deduplicateByIp(entries: ArpEntry[]): ArpEntry[] {
  const map = new Map<string, ArpEntry>();
  for (const entry of entries) {
    map.set(entry.ip, entry);
  }
  return Array.from(map.values());
}

async function lookupMacVendor(mac: string): Promise<string | undefined> {
  // Use only the first 3 octets (OUI prefix)
  const prefix = mac.split(":").slice(0, 3).join(":");
  try {
    const res = await fetch(`https://api.macvendors.com/${encodeURIComponent(prefix)}`, {
      signal: AbortSignal.timeout(3_000),
    });
    if (res.status === 200) {
      const text = await res.text();
      return text.trim() || undefined;
    }
  } catch {
    // Network error or timeout — skip silently
  }
  return undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface TopologyHop {
  ip: string;
  hostname?: string;
  latencyMs: number;
}

function isPrivateIp(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

function parseTraceroute(output: string): TopologyHop[] {
  const hops: TopologyHop[] = [];
  // Typical macOS traceroute line:
  //  1  192.168.68.1 (192.168.68.1)  3.210 ms  2.875 ms  3.011 ms
  //  2  * * *
  const lineRe = /^\s*(\d+)\s+(?:\*|(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+([\d.]+)\s+ms)/;

  for (const line of output.split("\n")) {
    const match = line.match(lineRe);
    if (!match) continue;
    const [, , hostname, ip, latency] = match;
    if (!ip) continue; // timeout hop
    hops.push({
      ip,
      hostname: hostname !== ip ? hostname : undefined,
      latencyMs: parseFloat(latency),
    });
  }

  return hops;
}

export async function scanHosts(
  iface: string,
  subnet: string,
  broadcastAddr: string
): Promise<{
  hosts: NetworkScanResult["network"]["hosts"];
  topology: NetworkScanResult["network"]["topology"];
}> {
  // 1. Initial ARP table read
  const initialArp = run("/usr/sbin/arp", ["-a"]);
  let arpEntries = parseArpOutput(initialArp.stdout);

  // 2. Broadcast ping to stimulate ARP responses
  run("/sbin/ping", ["-c", "2", "-t", "1", broadcastAddr], 10_000);

  // 3. Re-read ARP after broadcast ping
  const refreshedArp = run("/usr/sbin/arp", ["-a"]);
  arpEntries = deduplicateByIp([...arpEntries, ...parseArpOutput(refreshedArp.stdout)]);

  // 4. Vendor lookups with 1-per-second rate limiting
  const hosts: NetworkScanResult["network"]["hosts"] = [];
  for (const entry of arpEntries) {
    const vendor = await lookupMacVendor(entry.mac);
    hosts.push({
      ip: entry.ip,
      mac: entry.mac,
      vendor,
    });
    if (vendor) await sleep(500);
  }

  // 5. Topology: traceroute to 8.8.8.8 with max 5 hops
  const traceResult = run("/usr/sbin/traceroute", ["-m", "5", "-q", "1", "8.8.8.8"], 30_000);
  const hops = parseTraceroute(traceResult.stdout);

  // 6. Double NAT detection: hop 2 (index 1) is also a private IP
  const doubleNat = hops.length >= 2 && isPrivateIp(hops[1].ip);

  return {
    hosts,
    topology: {
      doubleNat,
      hops,
    },
  };
}
