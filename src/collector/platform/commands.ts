export type Platform = "darwin" | "linux";

export function currentPlatform(): Platform {
  return process.platform === "linux" ? "linux" : "darwin";
}

type BinName =
  | "arp"
  | "ping"
  | "netstat"
  | "lsof"
  | "traceroute"
  | "nc"
  | "dig"
  | "ifconfig"
  | "networksetup"
  | "scutil"
  | "sysctl"
  | "system_profiler"
  | "nslookup";

// macOS ships these at fixed paths; calling them by absolute path avoids a
// PATH-hijacked binary. Linux distributions vary, so resolve from PATH there.
const DARWIN_PATHS: Record<BinName, string> = {
  arp: "/usr/sbin/arp",
  ping: "/sbin/ping",
  netstat: "/usr/sbin/netstat",
  lsof: "/usr/sbin/lsof",
  traceroute: "/usr/sbin/traceroute",
  nc: "/usr/bin/nc",
  dig: "/usr/bin/dig",
  ifconfig: "/sbin/ifconfig",
  networksetup: "/usr/sbin/networksetup",
  scutil: "/usr/sbin/scutil",
  sysctl: "/usr/sbin/sysctl",
  system_profiler: "/usr/sbin/system_profiler",
  nslookup: "/usr/bin/nslookup",
};

export function bin(name: BinName, platform: Platform = currentPlatform()): string {
  return platform === "darwin" ? DARWIN_PATHS[name] : name;
}

/** The fixed absolute path `bin()` runs for this tool on this platform, if any. */
export function fixedPath(name: string, platform: Platform): string | undefined {
  return platform === "darwin" && Object.hasOwn(DARWIN_PATHS, name)
    ? DARWIN_PATHS[name as BinName]
    : undefined;
}

/**
 * Broadcast ping to stimulate ARP replies. macOS `-t` is a timeout in
 * seconds; on Linux `-t` is the TTL, so use `-w` and allow broadcast with `-b`.
 */
export function broadcastPingArgs(addr: string, platform: Platform = currentPlatform()): string[] {
  return platform === "darwin"
    ? ["-c", "2", "-t", "1", addr]
    : ["-b", "-c", "2", "-w", "1", addr];
}

/** Single ping with a 2 s reply wait (`-W` is milliseconds on macOS, seconds on Linux). */
export function singlePingArgs(target: string, platform: Platform = currentPlatform()): string[] {
  return ["-c", "1", "-W", platform === "darwin" ? "2000" : "2", target];
}
