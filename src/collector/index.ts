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
import { lookupVendor } from "./oui-lookup.js";
import { ScanEventEmitter } from "./scan-events.js";

interface NetworkBootstrap {
  interface: string;
  ip: string;
  subnet: string;
  gateway: { ip: string; mac: string };
  broadcastAddr: string;
}

function detectNetworkDarwin(): NetworkBootstrap {
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

function detectNetworkLinux(): NetworkBootstrap {
  // Find default interface and gateway from ip route
  const routeResult = run("ip", ["route", "show", "default"]);
  let iface = "wlan0";
  let gatewayIp = "unknown";

  const routeMatch = routeResult.stdout.match(
    /default via (\d+\.\d+\.\d+\.\d+) dev (\S+)/
  );
  if (routeMatch) {
    gatewayIp = routeMatch[1];
    iface = routeMatch[2];
  } else {
    // Fallback: find a wireless interface via iw dev
    const iwResult = run("iw", ["dev"]);
    const ifaceMatch = iwResult.stdout.match(/Interface\s+(\S+)/);
    if (ifaceMatch) iface = ifaceMatch[1];
  }

  // Get IP and CIDR from ip addr
  const addrResult = run("ip", ["-o", "-4", "addr", "show", iface]);
  let ip = "unknown";
  let cidrBits = 24;
  const addrMatch = addrResult.stdout.match(/inet (\d+\.\d+\.\d+\.\d+)\/(\d+)/);
  if (addrMatch) {
    ip = addrMatch[1];
    cidrBits = parseInt(addrMatch[2], 10);
  }

  const subnet = `${ip.split(".").slice(0, 3).join(".")}.0/${cidrBits}`;

  // Compute broadcast from IP and CIDR
  const ipParts = ip.split(".").map(Number);
  const hostBits = 32 - cidrBits;
  const ipNum =
    ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
  const broadcastNum = (ipNum | ((1 << hostBits) - 1)) >>> 0;
  const broadcastAddr = ip === "unknown"
    ? "255.255.255.255"
    : `${(broadcastNum >>> 24) & 0xff}.${(broadcastNum >>> 16) & 0xff}.${(broadcastNum >>> 8) & 0xff}.${broadcastNum & 0xff}`;

  // Gateway MAC via arp
  const arpResult = run("arp", ["-n", gatewayIp]);
  const macMatch = arpResult.stdout.match(
    /([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2})/i
  );
  const gatewayMac = macMatch?.[1] ?? "unknown";

  return {
    interface: iface,
    ip,
    subnet,
    gateway: { ip: gatewayIp, mac: gatewayMac },
    broadcastAddr,
  };
}

function detectNetwork(): NetworkBootstrap {
  if (process.platform === "linux") {
    return detectNetworkLinux();
  }
  return detectNetworkDarwin();
}

export interface ScanOptions {
  timeout?: number;
  skipTraffic?: boolean;
  skipPortScan?: boolean;
  skipSpeed?: boolean;
  skipVendorLookup?: boolean;
  verbose?: boolean;
  emitter?: ScanEventEmitter;
}

export async function collectNetworkScan(
  options: ScanOptions = {}
): Promise<NetworkScanResult> {
  const scanId = randomUUID();
  const startTime = Date.now();
  const emitter = options.emitter;

  return withSpan("network-scan", { "scan.id": scanId }, async () => {
    emitter?.scanStart(scanId);

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

    emitter?.bootstrapComplete(bootstrap.gateway.ip, bootstrap.ip, bootstrap.subnet);

    if (options.verbose) {
      console.error(
        `[bootstrap] IP: ${bootstrap.ip}, Gateway: ${bootstrap.gateway.ip}, Subnet: ${bootstrap.subnet}`
      );
    }

    // Step 3: Parallel scans (independent of each other)
    emitter?.scannerStart("wifi");
    emitter?.scannerStart("dns");
    emitter?.scannerStart("security");
    emitter?.scannerStart("connections");

    const [wifi, dns, security, connections] = await withSpan(
      "parallel-scans",
      {},
      async () => {
        return Promise.all([
          withSpan(
            "wifi-scan",
            { "tool.resolved": tools.get("wifiAnalysis")?.name ?? "none" },
            () => scanWifi()
          ).then((r) => {
            emitter?.scannerComplete("wifi", `${r.protocol}, ${r.band}, ch${r.channel}, ${r.security}`);
            return r;
          }),
          withSpan(
            "dns-audit",
            { "tool.resolved": tools.get("dnsAudit")?.name ?? "none" },
            () => scanDns(bootstrap.gateway.ip)
          ).then((r) => {
            emitter?.scannerComplete("dns", `${r.servers.length} servers, DNSSEC ${r.dnssecSupported ? "on" : "off"}`);
            return r;
          }),
          withSpan("security-posture", {}, () => scanSecurityPosture()).then((r) => {
            emitter?.scannerComplete("security", `firewall ${r.firewall.enabled ? "on" : "off"}, VPN ${r.vpn.active ? "active" : "inactive"}`);
            return r;
          }),
          withSpan(
            "connections",
            { "tool.resolved": "netstat" },
            () => scanConnections()
          ).then((r) => {
            emitter?.scannerComplete("connections", `${r.established} established, ${r.listening} listening`);
            return r;
          }),
        ]);
      }
    );

    // Step 4: Host discovery (needs bootstrap)
    emitter?.scannerStart("host-discovery");
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
    for (const host of hosts) {
      emitter?.hostFound(host.ip, host.mac);
      if (host.vendor) {
        emitter?.hostEnriched(host.ip, host.vendor);
      }
    }
    emitter?.scannerComplete("host-discovery", `${hosts.length} hosts discovered`);

    // Step 5: Port scan + hidden device + intrusion detection (needs hosts)
    const [portResults, hiddenDevices, intrusionIndicators] = await withSpan(
      "deep-analysis",
      {},
      async () => {
        emitter?.scannerStart("port-scan");
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

        // Emit port:found for each open port
        for (const host of hosts) {
          for (const port of host.ports ?? []) {
            emitter?.portFound(host.ip, port.port, port.service);
          }
        }
        emitter?.scannerComplete("port-scan", `${hosts.reduce((acc, h) => acc + (h.ports?.length ?? 0), 0)} open ports`);

        emitter?.scannerStart("hidden-device-scan");
        emitter?.scannerStart("intrusion-detection");
        const [hidden, intrusion] = await Promise.all([
          withSpan("hidden-device-scan", {}, () => scanHiddenDevices(hosts)).then((r) => {
            emitter?.scannerComplete("hidden-device-scan", `${(r?.unknownDevices?.length ?? 0) + (r?.suspectedCameras?.length ?? 0)} hidden devices`);
            return r;
          }),
          withSpan("intrusion-detection", {}, () =>
            scanForIntrusions(bootstrap.gateway.ip, bootstrap.gateway.mac)
          ).then((r) => {
            emitter?.scannerComplete("intrusion-detection", `${r?.arpAnomalies?.length ?? 0} ARP anomalies`);
            return r;
          }),
        ]);

        return [portResult, hidden, intrusion] as const;
      }
    );

    // Step 6: Speed test (runs after other scans to avoid skewing results)
    emitter?.scannerStart("speed-test");
    const speed = options.skipSpeed
      ? undefined
      : await withSpan("speed-test", {}, () =>
          scanSpeed(bootstrap.gateway.ip, wifi.txRate)
        );
    emitter?.scannerComplete("speed-test", speed ? `${speed.download.speedMbps} Mbps down, ${speed.upload.speedMbps} Mbps up` : "skipped");

    // Step 7: Look up gateway vendor
    const gatewayVendor = options.skipVendorLookup
      ? undefined
      : lookupVendor(bootstrap.gateway.mac);

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

    emitter?.scanComplete(scanId, hosts.length);

    return result;
  });
}
