import { runAsync } from "../exec.js";
import { isMulticastMac, isValidMac, normaliseMac } from "../mac.js";
import { bin, type Platform } from "./commands.js";

export interface ArpEntry {
  ip: string;
  mac: string;
  iface: string;
}

// macOS: ? (192.168.1.1) at 48:22:54:b:d0:90 on en0 ifscope [ethernet]
// Linux: ? (192.168.1.1) at 48:22:54:0b:d0:90 [ether] on wlp2s0
const ARP_LINE = /\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)(?:\s+\[\w+\])?\s+on\s+(\S+)/;

/**
 * Parse `arp -a` output (macOS or Linux) into unicast entries with
 * normalised MACs, one per IP. Incomplete, broadcast and multicast entries
 * (e.g. 224.0.0.251 at 1:0:5e:0:0:fb) are dropped — they are not hosts.
 */
export function parseArp(output: string): ArpEntry[] {
  const byIp = new Map<string, ArpEntry>();
  for (const line of output.split("\n")) {
    const match = ARP_LINE.exec(line);
    if (!match) continue;
    const mac = normaliseMac(match[2]);
    if (!isValidMac(mac) || isMulticastMac(mac)) continue;
    byIp.set(match[1], { ip: match[1], mac, iface: match[3] });
  }
  return [...byIp.values()];
}

/** Read the ARP table once. */
export async function readArpTable(platform?: Platform): Promise<ArpEntry[]> {
  return parseArp((await runAsync(bin("arp", platform), ["-a"])).stdout);
}

/** ip -> mac map, the shape the intrusion detector compares. */
export function arpMap(entries: ArpEntry[]): Map<string, string> {
  return new Map(entries.map((e) => [e.ip, e.mac]));
}
