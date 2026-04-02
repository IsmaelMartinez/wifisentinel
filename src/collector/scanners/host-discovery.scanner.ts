import { run } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";
import { lookupVendor } from "../oui-lookup.js";

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

function lookupMacVendor(mac: string): string | undefined {
  return lookupVendor(mac);
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

export interface HostScanOptions {
  stealth?: boolean;
}

export async function scanHosts(
  iface: string,
  subnet: string,
  broadcastAddr: string,
  options: HostScanOptions = {},
): Promise<{
  hosts: NetworkScanResult["network"]["hosts"];
  topology: NetworkScanResult["network"]["topology"];
}> {
  // 1. Initial ARP table read (passive — no network traffic)
  const initialArp = run("/usr/sbin/arp", ["-a"]);
  let arpEntries = parseArpOutput(initialArp.stdout);

  if (!options.stealth) {
    // 2. Broadcast ping to stimulate ARP responses (active — visible on network)
    run("/sbin/ping", ["-c", "2", "-t", "1", broadcastAddr], 10_000);

    // 3. Re-read ARP after broadcast ping
    const refreshedArp = run("/usr/sbin/arp", ["-a"]);
    arpEntries = deduplicateByIp([...arpEntries, ...parseArpOutput(refreshedArp.stdout)]);
  }

  // 4. Vendor lookups from local OUI database (no network traffic)
  const hosts: NetworkScanResult["network"]["hosts"] = [];
  for (const entry of arpEntries) {
    const vendor = lookupMacVendor(entry.mac);
    hosts.push({
      ip: entry.ip,
      mac: entry.mac,
      vendor,
    });
  }

  let hops: TopologyHop[] = [];
  let doubleNat = false;

  if (!options.stealth) {
    // 5. Topology: traceroute to 8.8.8.8 with max 5 hops (active — UDP probes)
    const traceResult = run("/usr/sbin/traceroute", ["-m", "5", "-q", "1", "8.8.8.8"], 30_000);
    hops = parseTraceroute(traceResult.stdout);

    // 6. Double NAT detection: hop 2 (index 1) is also a private IP
    doubleNat = hops.length >= 2 && isPrivateIp(hops[1].ip);
  } else {
    // Stealth: read routing table instead of traceroute (passive)
    const routeResult = run("/usr/sbin/netstat", ["-rn"]);
    const defaultRoute = routeResult.stdout.split("\n").find(l => l.startsWith("default"));
    if (defaultRoute) {
      const parts = defaultRoute.trim().split(/\s+/);
      if (parts[1]) {
        hops = [{ ip: parts[1], latencyMs: 0 }];
      }
    }
  }

  return {
    hosts,
    topology: {
      doubleNat,
      hops,
    },
  };
}
