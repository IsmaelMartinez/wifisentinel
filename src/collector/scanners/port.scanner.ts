import { runAsync } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";
import { bin } from "../platform/commands.js";
import { mapLimit, sleep } from "../util.js";

const COMMON_PORTS: number[] = [
  22, 23, 53, 80, 443, 445, 548, 554, 3000, 5000, 7547, 8080, 8443, 8554, 9100,
];

/** Maximum nc probes in flight outside stealth mode. */
export const PORT_PROBE_CONCURRENCY = 16;

const PORT_SERVICE_MAP: Record<number, string> = {
  22: "SSH",
  23: "Telnet",
  53: "DNS",
  80: "HTTP",
  443: "HTTPS",
  445: "SMB",
  548: "AFP",
  554: "RTSP",
  3000: "HTTP-alt",
  5000: "UPnP",
  7547: "TR-069",
  8080: "HTTP-proxy",
  8443: "HTTPS-alt",
  8554: "RTSP-alt",
  9100: "JetDirect",
};

interface PortResult {
  port: number;
  service: string;
  state: string;
}

export function openPortsOnly(results: PortResult[]): PortResult[] {
  return results.filter((r) => r.state === "open");
}

async function scanHostPort(ip: string, port: number): Promise<PortResult> {
  const service = PORT_SERVICE_MAP[port] ?? `port-${port}`;
  // nc -z: zero-I/O mode (scan only), -w 2: 2-second timeout
  const result = await runAsync(bin("nc"), ["-z", "-w", "2", ip, String(port)], 5_000);
  const state = result.exitCode === 0 ? "open" : "closed";
  return { port, service, state };
}

interface LsofEntry {
  port: number;
  process: string;
  bindAddress: string;
}

export function parseLsofOutput(output: string): LsofEntry[] {
  const entries: LsofEntry[] = [];
  // Example line:
  // node    1234 user   22u  IPv4 0x...  0t0  TCP 127.0.0.1:3000 (LISTEN)
  // node    1234 user   22u  IPv6 0x...  0t0  TCP *:8080 (LISTEN)
  const lineRe = /^(\S+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+TCP\s+(\S+):(\d+)\s+\(LISTEN\)/;

  for (const line of output.split("\n")) {
    const match = line.match(lineRe);
    if (!match) continue;
    const [, processName, addr, portStr] = match;
    const port = parseInt(portStr, 10);
    if (isNaN(port)) continue;
    // addr can be "*", "0.0.0.0", "127.0.0.1", "::1", etc.
    entries.push({ port, process: processName, bindAddress: addr });
  }

  return entries;
}

function deduplicateLsof(entries: LsofEntry[]): LsofEntry[] {
  const seen = new Set<string>();
  const result: LsofEntry[] = [];
  for (const e of entries) {
    const key = `${e.port}:${e.process}:${e.bindAddress}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(e);
    }
  }
  return result;
}

function isExposedToNetwork(bindAddress: string): boolean {
  // Exposed if bound to wildcard or 0.0.0.0, not just loopback
  return bindAddress === "*" || bindAddress === "0.0.0.0" || bindAddress === "::";
}

export function shuffle<T>(arr: T[]): T[] {
  const shuffled = [...arr];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

export interface PortScanOptions {
  stealth?: boolean;
}

export async function scanPorts(
  hosts: Array<{ ip: string; mac: string }>,
  options: PortScanOptions = {},
): Promise<{
  hostPorts: Map<string, Array<PortResult>>;
  localServices: NetworkScanResult["localServices"];
}> {
  // 1. Probe every host × port pair. Normal mode runs a bounded pool of
  // probes; stealth mode stays sequential with shuffled order and jitter
  // between probes to avoid portscan detection.
  const hostOrder = options.stealth ? shuffle(hosts) : hosts;
  const probes = hostOrder.flatMap((host) =>
    (options.stealth ? shuffle([...COMMON_PORTS]) : COMMON_PORTS).map((port) => ({ ip: host.ip, port })),
  );

  const [results, lsofResult] = await Promise.all([
    mapLimit(probes, options.stealth ? 1 : PORT_PROBE_CONCURRENCY, async ({ ip, port }) => {
      if (options.stealth) await sleep(200 + Math.random() * 300);
      return { ip, result: await scanHostPort(ip, port) };
    }),
    // 2. Discover local listening services via lsof
    runAsync(bin("lsof"), ["-i", "-P", "-n"], 15_000),
  ]);

  // Only open ports are reported; closed probes are not findings.
  const hostPorts = new Map<string, Array<PortResult>>();
  for (const host of hostOrder) {
    hostPorts.set(host.ip, openPortsOnly(results.filter((r) => r.ip === host.ip).map((r) => r.result)));
  }

  const lsofEntries = deduplicateLsof(parseLsofOutput(lsofResult.stdout));

  const localServices: NetworkScanResult["localServices"] = lsofEntries
    .filter((e) => e.port > 0)
    .map((e) => ({
      port: e.port,
      process: e.process,
      bindAddress: e.bindAddress,
      exposedToNetwork: isExposedToNetwork(e.bindAddress),
    }));

  return { hostPorts, localServices };
}
