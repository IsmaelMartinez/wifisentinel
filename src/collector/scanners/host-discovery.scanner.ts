import { run } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";
import { lookupVendor } from "../oui-lookup.js";
import { readArpTable, type ArpEntry } from "../platform/arp.js";
import { bin, broadcastPingArgs } from "../platform/commands.js";
import { isPrivateIp } from "../util.js";

interface TopologyHop {
  ip: string;
  hostname?: string;
  latencyMs: number;
}

export function parseTraceroute(output: string): TopologyHop[] {
  const hops: TopologyHop[] = [];
  // Typical traceroute line (macOS and Linux):
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

export interface ArpDiscoveryOptions {
  stealth?: boolean;
  broadcastAddr: string;
}

/**
 * Read the ARP table once for the whole scan. Outside stealth mode a
 * broadcast ping first stimulates replies (active — visible on the network).
 */
export function discoverArpTable(options: ArpDiscoveryOptions): ArpEntry[] {
  if (!options.stealth) {
    run(bin("ping"), broadcastPingArgs(options.broadcastAddr), 10_000);
  }
  return readArpTable();
}

export interface HostScanOptions {
  stealth?: boolean;
  gatewayIp?: string;
}

export async function scanHosts(
  arpEntries: ArpEntry[],
  options: HostScanOptions = {},
): Promise<{
  hosts: NetworkScanResult["network"]["hosts"];
  topology: NetworkScanResult["network"]["topology"];
}> {
  // Vendor lookups from local OUI database (no network traffic)
  const hosts: NetworkScanResult["network"]["hosts"] = arpEntries.map((entry) => ({
    ip: entry.ip,
    mac: entry.mac,
    vendor: lookupVendor(entry.mac),
  }));

  let hops: TopologyHop[] = [];
  let doubleNat = false;

  if (!options.stealth) {
    // Topology: traceroute to 8.8.8.8 with max 5 hops (active — UDP probes)
    const traceResult = run(bin("traceroute"), ["-m", "5", "-q", "1", "8.8.8.8"], 30_000);
    hops = parseTraceroute(traceResult.stdout);

    // Double NAT detection: hop 2 (index 1) is also a private IP
    doubleNat = hops.length >= 2 && isPrivateIp(hops[1].ip);
  } else if (options.gatewayIp) {
    // Stealth: use gateway IP from bootstrap (already known, no network traffic)
    hops = [{ ip: options.gatewayIp, latencyMs: 0 }];
  }

  return {
    hosts,
    topology: {
      doubleNat,
      hops,
    },
  };
}
