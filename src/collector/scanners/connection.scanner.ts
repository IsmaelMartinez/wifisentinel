import { run, runAsync } from "../exec.js";
import { bin } from "../platform/commands.js";
import { parseNetstat, type NetstatEntry } from "../platform/netstat.js";
import type { NetworkScanResult } from "../schema/scan-result.js";

// ---------------------------------------------------------------------------
// netstat counting
// ---------------------------------------------------------------------------

interface NetstatCounts {
  established: number;
  listening: number;
  timeWait: number;
  establishedDestinations: string[];
}

/** Public IPv4 destination worth reporting, or null for IPv6/loopback/link-local. */
function reportableIpv4(addr: string): string | null {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(addr)) return null;
  if (addr.startsWith("127.") || addr.startsWith("169.254.")) return null;
  return addr;
}

export function countNetstat(entries: NetstatEntry[]): NetstatCounts {
  let established = 0;
  let listening = 0;
  let timeWait = 0;
  const establishedDestinations: string[] = [];

  for (const entry of entries) {
    if (!entry.proto.startsWith("tcp")) continue;
    if (entry.state === "ESTABLISHED") {
      established++;
      const ip = reportableIpv4(entry.remoteAddr);
      if (ip) establishedDestinations.push(ip);
    } else if (entry.state === "LISTEN") {
      listening++;
    } else if (entry.state === "TIME_WAIT") {
      timeWait++;
    }
  }

  return { established, listening, timeWait, establishedDestinations };
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
  const result = await runAsync(bin("dig"), [
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
  const netstatOut = run(bin("netstat"), ["-an"]).stdout;
  const { established, listening, timeWait, establishedDestinations } =
    countNetstat(parseNetstat(netstatOut));

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
