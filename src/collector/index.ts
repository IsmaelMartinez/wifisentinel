import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { run } from "./exec.js";
import {
  resolveAllTools,
  toolchainSummary,
  type ResolvedToolResult,
} from "./tool-resolver.js";
import type { NetworkScanResult } from "./schema/scan-result.js";
import { scanWifi } from "./scanners/wifi.scanner.js";
import { scanDns } from "./scanners/dns.scanner.js";
import { scanHosts } from "./scanners/host-discovery.scanner.js";
import { scanPorts } from "./scanners/port.scanner.js";
import { scanSecurityPosture } from "./scanners/security-posture.scanner.js";
import { scanConnections } from "./scanners/connection.scanner.js";
import { scanHiddenDevices } from "./scanners/hidden-device.scanner.js";
import { scanForIntrusions } from "./scanners/intrusion-detection.scanner.js";
import { scanSpeed } from "./scanners/speed.scanner.js";
import { withSpan } from "../telemetry/tracing.js";
import {
  recordScanDuration,
  recordToolResolution,
} from "../telemetry/metrics.js";

interface NetworkBootstrap {
  interface: string;
  ip: string;
  subnet: string;
  gateway: { ip: string; mac: string };
  broadcastAddr: string;
}

function detectNetwork(): NetworkBootstrap {
  const ifconfigResult = run("ifconfig", ["en0"]);
  const inetMatch = ifconfigResult.stdout.match(
    /inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+) broadcast (\d+\.\d+\.\d+\.\d+)/
  );
  const ip = inetMatch?.[1] ?? "unknown";
  const broadcastAddr = inetMatch?.[3] ?? "255.255.255.255";

  const maskHex = inetMatch?.[2] ?? "0xffffff00";
  const maskNum = parseInt(maskHex, 16);
  const cidrBits = maskNum.toString(2).split("1").length - 1;
  const subnet = `${ip.split(".").slice(0, 3).join(".")}.0/${cidrBits}`;

  // Use networksetup for reliable gateway detection (works even with VPN active)
  const nsInfoResult = run("networksetup", ["-getinfo", "Wi-Fi"]);
  let gatewayIp = "unknown";
  const routerMatch = nsInfoResult.stdout.match(/Router:\s+(\d+\.\d+\.\d+\.\d+)/);
  if (routerMatch) {
    gatewayIp = routerMatch[1];
  } else {
    // Fallback: parse netstat for en0 specifically
    const routeResult = run("netstat", ["-rn"]);
    const en0Default = routeResult.stdout
      .split("\n")
      .find((l) => l.startsWith("default") && l.includes("en0"));
    const gwMatch = en0Default?.match(/default\s+(\d+\.\d+\.\d+\.\d+)/);
    if (gwMatch) gatewayIp = gwMatch[1];
  }

  const arpResult = run("arp", ["-n", gatewayIp]);
  const macMatch = arpResult.stdout.match(
    /([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2})/i
  );
  const gatewayMac = macMatch?.[1] ?? "unknown";

  return {
    interface: "en0",
    ip,
    subnet,
    gateway: { ip: gatewayIp, mac: gatewayMac },
    broadcastAddr,
  };
}

export interface ScanOptions {
  timeout?: number;
  skipTraffic?: boolean;
  skipPortScan?: boolean;
  skipSpeed?: boolean;
  verbose?: boolean;
}

export async function collectNetworkScan(
  options: ScanOptions = {}
): Promise<NetworkScanResult> {
  const scanId = randomUUID();
  const startTime = Date.now();

  return withSpan("network-scan", { "scan.id": scanId }, async () => {
    // Step 1: Resolve tools
    const tools = await withSpan("tool-resolution", {}, async () => {
      const resolved = resolveAllTools();
      for (const [capability, tool] of resolved) {
        recordToolResolution(capability, tool.tier);
      }
      return resolved;
    });

    // Step 2: Network bootstrap
    const bootstrap = await withSpan("network-bootstrap", {}, async () => {
      return detectNetwork();
    });

    if (options.verbose) {
      console.error(
        `[bootstrap] IP: ${bootstrap.ip}, Gateway: ${bootstrap.gateway.ip}, Subnet: ${bootstrap.subnet}`
      );
    }

    // Step 3: Parallel scans (independent of each other)
    const [wifi, dns, security, connections] = await withSpan(
      "parallel-scans",
      {},
      async () => {
        return Promise.all([
          withSpan(
            "wifi-scan",
            { "tool.resolved": tools.get("wifiAnalysis")?.name ?? "none" },
            () => scanWifi()
          ),
          withSpan(
            "dns-audit",
            { "tool.resolved": tools.get("dnsAudit")?.name ?? "none" },
            () => scanDns(bootstrap.gateway.ip)
          ),
          withSpan("security-posture", {}, () => scanSecurityPosture()),
          withSpan(
            "connections",
            { "tool.resolved": "netstat" },
            () => scanConnections()
          ),
        ]);
      }
    );

    // Step 4: Host discovery (needs bootstrap)
    const { hosts, topology } = await withSpan(
      "host-discovery",
      { "tool.resolved": tools.get("hostDiscovery")?.name ?? "none" },
      () =>
        scanHosts(
          bootstrap.interface,
          bootstrap.subnet,
          bootstrap.broadcastAddr
        )
    );

    // Step 5: Port scan + hidden device + intrusion detection (needs hosts)
    const [portResults, hiddenDevices, intrusionIndicators] = await withSpan(
      "deep-analysis",
      {},
      async () => {
        const portResult = options.skipPortScan
          ? {
              hostPorts: new Map<
                string,
                Array<{ port: number; service: string; state: string }>
              >(),
              localServices: [] as NetworkScanResult["localServices"],
            }
          : await withSpan(
              "port-scan",
              { "tool.resolved": tools.get("portScanning")?.name ?? "none" },
              () => scanPorts(hosts)
            );

        // Merge port data into hosts
        for (const host of hosts) {
          const ports = portResult.hostPorts.get(host.ip);
          if (ports) {
            host.ports = ports;
          }
        }

        const [hidden, intrusion] = await Promise.all([
          withSpan("hidden-device-scan", {}, () => scanHiddenDevices(hosts)),
          withSpan("intrusion-detection", {}, () =>
            scanForIntrusions(bootstrap.gateway.ip, bootstrap.gateway.mac)
          ),
        ]);

        return [portResult, hidden, intrusion] as const;
      }
    );

    // Step 6: Speed test (runs after other scans to avoid skewing results)
    const speed = options.skipSpeed
      ? undefined
      : await withSpan("speed-test", {}, () =>
          scanSpeed(bootstrap.gateway.ip, wifi.txRate)
        );

    // Step 7: Look up gateway vendor
    let gatewayVendor: string | undefined;
    try {
      const prefix = bootstrap.gateway.mac.split(":").slice(0, 3).join(":");
      const vendorResult = run("curl", [
        "-s",
        "--max-time",
        "3",
        `https://api.macvendors.com/${prefix}`,
      ]);
      if (
        vendorResult.exitCode === 0 &&
        !vendorResult.stdout.includes("errors")
      ) {
        gatewayVendor = vendorResult.stdout;
      }
    } catch (_e) { /* vendor lookup is optional */ }

    const duration = Date.now() - startTime;
    recordScanDuration("total", duration);

    // Step 8: Assemble result
    const result: NetworkScanResult = {
      meta: {
        scanId,
        timestamp: new Date().toISOString(),
        duration,
        hostname: hostname(),
        platform: process.platform as "darwin" | "linux" | "win32",
        toolchain: toolchainSummary(tools),
      },
      wifi,
      network: {
        interface: bootstrap.interface,
        ip: bootstrap.ip,
        subnet: bootstrap.subnet,
        gateway: {
          ...bootstrap.gateway,
          vendor: gatewayVendor,
        },
        topology,
        dns,
        hosts,
      },
      localServices: portResults.localServices,
      security,
      connections,
      hiddenDevices,
      intrusionIndicators,
      speed,
    };

    return result;
  });
}
