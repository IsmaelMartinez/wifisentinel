import { accessSync, constants } from "node:fs";
import { join } from "node:path";
import type { ToolTier } from "./schema/scan-result.js";

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

/** Resolve a tool by searching PATH directories — no shell spawned. */
function whichTool(name: string): string | null {
  const dirs = (process.env.PATH ?? "").split(":");
  for (const dir of dirs) {
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // not found in this directory
    }
  }
  return null;
}

const TOOL_CHAINS: ToolChain[] = [
  {
    capability: "hostDiscovery",
    candidates: [
      { name: "nmap", tier: "preferred" },
      { name: "arp-scan", tier: "fallback" },
      { name: "arp", tier: "minimal" },
    ],
  },
  {
    capability: "portScanning",
    candidates: [
      { name: "nmap", tier: "preferred" },
      { name: "masscan", tier: "fallback" },
      { name: "nc", tier: "minimal" },
    ],
  },
  {
    capability: "wifiAnalysis",
    candidates: [
      { name: "system_profiler", tier: "preferred" },
      { name: "networksetup", tier: "minimal" },
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
  {
    capability: "tlsVerify",
    candidates: [
      { name: "testssl.sh", tier: "preferred" },
      { name: "openssl", tier: "fallback" },
      { name: "curl", tier: "minimal" },
    ],
  },
  {
    capability: "mitmDetection",
    candidates: [
      { name: "bettercap", tier: "preferred" },
      { name: "arp", tier: "minimal" },
    ],
  },
  {
    capability: "traceroute",
    candidates: [
      { name: "mtr", tier: "preferred" },
      { name: "traceroute", tier: "fallback" },
    ],
  },
  {
    capability: "serviceDiscovery",
    candidates: [
      { name: "avahi-browse", tier: "preferred" },
      { name: "dns-sd", tier: "fallback" },
    ],
  },
];

export function resolveAllTools(): Map<string, ResolvedToolResult> {
  const results = new Map<string, ResolvedToolResult>();

  for (const chain of TOOL_CHAINS) {
    let resolved = false;
    for (const candidate of chain.candidates) {
      const path = whichTool(candidate.name);
      if (path) {
        results.set(chain.capability, {
          capability: chain.capability,
          name: candidate.name,
          path,
          tier: candidate.tier,
        });
        resolved = true;
        break;
      }
    }
    if (!resolved) {
      results.set(chain.capability, {
        capability: chain.capability,
        name: "none",
        path: "",
        tier: "minimal",
      });
    }
  }

  return results;
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
