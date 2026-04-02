import { run, runAsync } from "../exec.js";

export interface DeauthScanOptions {
  monitorMode?: boolean;
  interface?: string;
  duration?: number;
}

export interface DeauthSource {
  mac: string;
  count: number;
}

export interface DeauthResult {
  detected: boolean;
  frameCount: number;
  sources: DeauthSource[];
  method: "system-logs" | "monitor-mode";
  duration: number;
}

// Patterns that indicate deauth or disassociation events in macOS system logs
const MACOS_DEAUTH_PATTERNS = [
  /deauth(?:entication)?/i,
  /disassoc(?:iation)?/i,
  /reason\s+code[:\s]+(?:[2-9]|1[0-6])/i, // IEEE 802.11 deauth reason codes
];

// Patterns for Linux kernel/journal logs
const LINUX_DEAUTH_PATTERNS = [
  /deauthenticated/i,
  /disassociated/i,
  /deauth from/i,
  /reason:\s*\d+/i,
];

// MAC address regex
const MAC_RE = /([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})/gi;

function parseMacosLogs(output: string): Pick<DeauthResult, "detected" | "frameCount" | "sources"> {
  const lines = output.split("\n").filter((l) => {
    return MACOS_DEAUTH_PATTERNS.some((p) => p.test(l));
  });

  const macCounts = new Map<string, number>();
  for (const line of lines) {
    const matches = line.matchAll(MAC_RE);
    for (const m of matches) {
      const mac = m[1].toLowerCase();
      // Skip broadcast and multicast MACs
      if (mac === "ff:ff:ff:ff:ff:ff") continue;
      macCounts.set(mac, (macCounts.get(mac) ?? 0) + 1);
    }
  }

  const sources: DeauthSource[] = [...macCounts.entries()]
    .map(([mac, count]) => ({ mac, count }))
    .sort((a, b) => b.count - a.count);

  return {
    detected: lines.length > 0,
    frameCount: lines.length,
    sources,
  };
}

function parseLinuxLogs(output: string): Pick<DeauthResult, "detected" | "frameCount" | "sources"> {
  const lines = output.split("\n").filter((l) => {
    return LINUX_DEAUTH_PATTERNS.some((p) => p.test(l));
  });

  const macCounts = new Map<string, number>();
  for (const line of lines) {
    const matches = line.matchAll(MAC_RE);
    for (const m of matches) {
      const mac = m[1].toLowerCase();
      if (mac === "ff:ff:ff:ff:ff:ff") continue;
      macCounts.set(mac, (macCounts.get(mac) ?? 0) + 1);
    }
  }

  const sources: DeauthSource[] = [...macCounts.entries()]
    .map(([mac, count]) => ({ mac, count }))
    .sort((a, b) => b.count - a.count);

  return {
    detected: lines.length > 0,
    frameCount: lines.length,
    sources,
  };
}

function parseTcpdumpOutput(output: string): Pick<DeauthResult, "detected" | "frameCount" | "sources"> {
  // tcpdump lines for deauth/disassoc look like:
  // HH:MM:SS.ffffff SA > DA: ... Deauthentication (reason: 3)
  // HH:MM:SS.ffffff SA > DA: ... Disassociation (reason: 8)
  const lines = output.split("\n").filter((l) =>
    /deauth(?:entication)?|disassoc(?:iation)?/i.test(l)
  );

  const macCounts = new Map<string, number>();
  for (const line of lines) {
    // Capture the source MAC (before ">")
    const arrowIdx = line.indexOf(">");
    if (arrowIdx > 0) {
      const srcPart = line.slice(0, arrowIdx).trim();
      // MAC is typically the last token before ">"
      const tokens = srcPart.split(/\s+/);
      const possibleMac = tokens[tokens.length - 1];
      if (possibleMac && /^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$/i.test(possibleMac)) {
        const mac = possibleMac.toLowerCase();
        if (mac !== "ff:ff:ff:ff:ff:ff") {
          macCounts.set(mac, (macCounts.get(mac) ?? 0) + 1);
        }
      }
    }
  }

  const sources: DeauthSource[] = [...macCounts.entries()]
    .map(([mac, count]) => ({ mac, count }))
    .sort((a, b) => b.count - a.count);

  return {
    detected: lines.length > 0,
    frameCount: lines.length,
    sources,
  };
}

async function scanViaSystemLogs(startTime: number): Promise<DeauthResult> {
  if (process.platform === "darwin") {
    // macOS: use log show to query the last 5 minutes of Wi-Fi subsystem logs
    const result = run(
      "log",
      [
        "show",
        "--predicate",
        'subsystem == "com.apple.wifi"',
        "--last",
        "5m",
      ],
      60_000
    );

    const parsed = parseMacosLogs(result.stdout + "\n" + result.stderr);
    return {
      ...parsed,
      method: "system-logs",
      duration: Date.now() - startTime,
    };
  }

  // Linux: try journalctl first, fall back to dmesg
  const journalResult = run(
    "journalctl",
    ["-k", "--no-pager", "--since", "5 minutes ago", "-g", "deauth\\|disassoc"],
    30_000
  );

  let logOutput = journalResult.stdout;

  if (journalResult.exitCode !== 0 || !logOutput.trim()) {
    // Fallback: dmesg
    const dmesgResult = run("dmesg", [], 10_000);
    logOutput = dmesgResult.stdout;
  }

  const parsed = parseLinuxLogs(logOutput);
  return {
    ...parsed,
    method: "system-logs",
    duration: Date.now() - startTime,
  };
}

async function scanViaMonitorMode(
  iface: string,
  durationSec: number,
  startTime: number
): Promise<DeauthResult> {
  // Use tcpdump to capture deauth/disassoc frames from an interface already in monitor mode.
  // The tool does NOT put the interface into monitor mode itself.
  const packetCount = Math.max(10, durationSec * 20); // rough frame budget
  const result = await runAsync(
    "tcpdump",
    [
      "-c",
      String(packetCount),
      "-i",
      iface,
      "-e",          // print MAC addresses
      "-l",          // line-buffered
      "type mgt subtype deauth or type mgt subtype disassoc",
    ],
    (durationSec + 2) * 1000
  );

  const parsed = parseTcpdumpOutput(result.stdout + "\n" + result.stderr);
  return {
    ...parsed,
    method: "monitor-mode",
    duration: Date.now() - startTime,
  };
}

export async function scanDeauth(options: DeauthScanOptions = {}): Promise<DeauthResult> {
  const startTime = Date.now();
  const durationSec = options.duration ?? 10;

  if (options.monitorMode && options.interface) {
    return scanViaMonitorMode(options.interface, durationSec, startTime);
  }

  return scanViaSystemLogs(startTime);
}

// Export parse helpers for unit testing
export { parseMacosLogs, parseLinuxLogs, parseTcpdumpOutput };
