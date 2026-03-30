import { run, runAsync } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";

// ---------------------------------------------------------------------------
// netstat parsing
// ---------------------------------------------------------------------------

interface NetstatCounts {
  established: number;
  listening: number;
  timeWait: number;
  establishedDestinations: string[];
}

function parseNetstat(output: string): NetstatCounts {
  let established = 0;
  let listening = 0;
  let timeWait = 0;
  const establishedDestinations: string[] = [];

  for (const line of output.split("\n")) {
    const cols = line.trim().split(/\s+/);
    // netstat -an columns (TCP):  Proto  Recv-Q  Send-Q  Local  Foreign  State
    // We need at least 6 columns and the first must be tcp/tcp4/tcp6
    if (cols.length < 6 || !/^tcp/i.test(cols[0])) continue;

    const state = cols[5].toUpperCase();
    const foreign = cols[4]; // e.g. "1.2.3.4.443" or "*.*"

    if (state === "ESTABLISHED") {
      established++;
      // Extract IP from "a.b.c.d.port" — everything before the last dot segment
      const ip = extractIpFromNetstatAddr(foreign);
      if (ip) establishedDestinations.push(ip);
    } else if (state === "LISTEN") {
      listening++;
    } else if (state === "TIME_WAIT") {
      timeWait++;
    }
  }

  return { established, listening, timeWait, establishedDestinations };
}

/**
 * netstat -an on macOS uses dot-separated notation: "1.2.3.4.443"
 * The last segment is the port; everything before is the IP.
 */
function extractIpFromNetstatAddr(addr: string): string | null {
  if (!addr || addr === "*.*" || addr.startsWith("*")) return null;

  // IPv6 addresses are wrapped in brackets: [::1].port — skip them
  if (addr.startsWith("[") || addr.includes("::")) return null;

  const parts = addr.split(".");
  if (parts.length < 5) return null; // need at least a.b.c.d.port

  // Last part is the port; first four are the IPv4 address
  const ip = parts.slice(0, 4).join(".");

  // Validate it looks like an IPv4 address
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;

  // Skip loopback / private link-local
  if (ip === "127.0.0.1" || ip.startsWith("169.254.")) return null;

  return ip;
}

// ---------------------------------------------------------------------------
// Top destinations + reverse DNS
// ---------------------------------------------------------------------------

function countDestinations(
  ips: string[]
): Array<{ ip: string; count: number }> {
  const counts = new Map<string, number>();
  for (const ip of ips) {
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count);
}

async function reverseDns(ip: string): Promise<string | undefined> {
  const result = await runAsync("/usr/bin/dig", [
    "-x",
    ip,
    "+short",
    "+time=2",
  ]);
  if (result.exitCode !== 0 || !result.stdout) return undefined;
  // dig may return multiple lines; take the first, strip trailing dot
  const first = result.stdout.split("\n")[0].trim().replace(/\.$/, "");
  return first || undefined;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function scanConnections(): Promise<
  NetworkScanResult["connections"]
> {
  const netstatOut = run("/usr/sbin/netstat", ["-an"]).stdout;
  const { established, listening, timeWait, establishedDestinations } =
    parseNetstat(netstatOut);

  const sorted = countDestinations(establishedDestinations);
  const top10 = sorted.slice(0, 10);

  // Resolve reverse DNS in parallel for all top destinations
  const topDestinations = await Promise.all(
    top10.map(async ({ ip, count }) => {
      const reverseDnsResult = await reverseDns(ip);
      return {
        ip,
        count,
        ...(reverseDnsResult ? { reverseDns: reverseDnsResult } : {}),
      };
    })
  );

  return { established, listening, timeWait, topDestinations };
}
