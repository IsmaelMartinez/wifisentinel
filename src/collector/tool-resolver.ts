import { accessSync, constants } from "node:fs";
import { join } from "node:path";
import type { ToolTier } from "./schema/scan-result.js";
import { currentPlatform, fixedPath, type Platform } from "./platform/commands.js";

export interface ToolChain {
  capability: string;
  candidates: Array<{ name: string; tier: ToolTier }>;
}

export interface ResolvedToolResult {
  capability: string;
  name: string;
  path: string;
  tier: ToolTier;
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve a tool the way the scanners will run it: the fixed platform path
 * from `bin()` when there is one (macOS system tools), otherwise a PATH
 * search — no shell spawned.
 */
function whichTool(name: string, platform: Platform, pathEnv: string): string | null {
  const fixed = fixedPath(name, platform);
  if (fixed) return isExecutable(fixed) ? fixed : null;
  for (const dir of pathEnv.split(":")) {
    if (!dir) continue;
    const candidate = join(dir, name);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

/**
 * The binaries each scanner actually runs, in the order it prefers them.
 * dnsAudit and packetAnalysis are consumed by the dns and traffic scanners;
 * the others are single-binary capabilities reported for the toolchain summary.
 */
export function toolChains(platform: Platform): ToolChain[] {
  return [
    {
      capability: "wifiAnalysis",
      candidates:
        platform === "darwin"
          ? [
              { name: "system_profiler", tier: "preferred" },
              { name: "networksetup", tier: "minimal" },
            ]
          : [
              // iw supplies SSID/BSSID/signal for the current link; nmcli alone
              // only yields nearby networks, so it is the minimal tier.
              { name: "iw", tier: "preferred" },
              { name: "nmcli", tier: "minimal" },
            ],
    },
    {
      capability: "dnsAudit",
      candidates: [
        { name: "dig", tier: "preferred" },
        { name: "nslookup", tier: "fallback" },
      ],
    },
    {
      capability: "packetAnalysis",
      candidates: [
        { name: "tshark", tier: "preferred" },
        { name: "tcpdump", tier: "fallback" },
      ],
    },
    { capability: "hostDiscovery", candidates: [{ name: "arp", tier: "minimal" }] },
    { capability: "portScanning", candidates: [{ name: "nc", tier: "minimal" }] },
    { capability: "traceroute", candidates: [{ name: "traceroute", tier: "minimal" }] },
  ];
}

function resolveChain(chain: ToolChain, platform: Platform, pathEnv: string): ResolvedToolResult {
  for (const candidate of chain.candidates) {
    const path = whichTool(candidate.name, platform, pathEnv);
    if (path) {
      return { capability: chain.capability, name: candidate.name, path, tier: candidate.tier };
    }
  }
  return { capability: chain.capability, name: "none", path: "", tier: "minimal" };
}

export function resolveAllTools(
  platform: Platform = currentPlatform(),
  pathEnv: string = process.env.PATH ?? "",
): Map<string, ResolvedToolResult> {
  const results = new Map<string, ResolvedToolResult>();
  for (const chain of toolChains(platform)) {
    results.set(chain.capability, resolveChain(chain, platform, pathEnv));
  }
  return results;
}

/** Resolve one capability, for scanners called outside a full scan. */
export function resolveCapability(
  capability: string,
  platform: Platform = currentPlatform(),
  pathEnv: string = process.env.PATH ?? "",
): ResolvedToolResult | undefined {
  const chain = toolChains(platform).find((c) => c.capability === capability);
  return chain ? resolveChain(chain, platform, pathEnv) : undefined;
}

export function toolchainSummary(
  tools: Map<string, ResolvedToolResult>
): Record<string, string | null> {
  const summary: Record<string, string | null> = {};
  for (const [capability, tool] of tools) {
    summary[capability] = tool.name === "none" ? null : tool.name;
  }
  return summary;
}
