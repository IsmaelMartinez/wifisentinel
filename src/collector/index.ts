import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import {
  resolveAllTools,
  toolchainSummary,
} from "./tool-resolver.js";
import type { NetworkScanResult } from "./schema/scan-result.js";
import { scanWifi } from "./scanners/wifi.scanner.js";
import { scanDns } from "./scanners/dns.scanner.js";
import { discoverArpTable, scanHosts } from "./scanners/host-discovery.scanner.js";
import { scanPorts } from "./scanners/port.scanner.js";
import { scanSecurityPosture } from "./scanners/security-posture.scanner.js";
import { scanConnections } from "./scanners/connection.scanner.js";
import { scanHiddenDevices } from "./scanners/hidden-device.scanner.js";
import { scanForIntrusions } from "./scanners/intrusion-detection.scanner.js";
import { scanDeauth } from "./scanners/deauth.scanner.js";
import { scanSpeed } from "./scanners/speed.scanner.js";
import { scanTraffic } from "./scanners/traffic.scanner.js";
import { withSpan } from "../telemetry/tracing.js";
import {
  recordScanDuration,
  recordToolResolution,
} from "../telemetry/metrics.js";
import { lookupVendor } from "./oui-lookup.js";
import { detectNetwork } from "./platform/bootstrap.js";
import { ScanEventEmitter } from "./scan-events.js";

export interface ScanOptions {
  timeout?: number;
  skipTraffic?: boolean;
  trafficDuration?: number;
  skipPortScan?: boolean;
  skipSpeed?: boolean;
  skipVendorLookup?: boolean;
  verbose?: boolean;
  stealth?: boolean;
  emitter?: ScanEventEmitter;
  monitorInterface?: string;
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

    // Step 2: Network bootstrap, including the single ARP table read shared
    // by host discovery, client isolation and intrusion detection.
    const { bootstrap, arpEntries } = await withSpan(
      "network-bootstrap",
      { "tool.resolved": tools.get("hostDiscovery")?.name ?? "none" },
      async () => {
        const net = detectNetwork();
        const arpEntries = discoverArpTable({
          stealth: options.stealth,
          broadcastAddr: net.broadcastAddr,
        });
        const gatewayMac = arpEntries.find((e) => e.ip === net.gatewayIp)?.mac ?? "unknown";
        return {
          bootstrap: { ...net, gateway: { ip: net.gatewayIp, mac: gatewayMac } },
          arpEntries,
        };
      },
    );

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
            () => scanWifi(bootstrap.interface)
          ).then((r) => {
            emitter?.scannerComplete("wifi", `${r.protocol}, ${r.band}, ch${r.channel}, ${r.security}`);
            return r;
          }),
          withSpan(
            "dns-audit",
            { "tool.resolved": tools.get("dnsAudit")?.name ?? "none" },
            () =>
              scanDns(bootstrap.gateway.ip, {
                stealth: options.stealth,
                tool: tools.get("dnsAudit")?.name,
              })
          ).then((r) => {
            emitter?.scannerComplete("dns", `${r.servers.length} servers, DNSSEC ${r.dnssecSupported ? "on" : "off"}`);
            return r;
          }),
          withSpan("security-posture", {}, () =>
            scanSecurityPosture({
              gatewayIp: bootstrap.gateway.ip,
              localIp: bootstrap.ip,
              arpEntries,
              service: bootstrap.service,
            })
          ).then((r) => {
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
      // ARP ran during bootstrap; this stage runs traceroute for topology.
      { "tool.resolved": options.stealth ? "none" : tools.get("traceroute")?.name ?? "none" },
      () =>
        scanHosts(arpEntries, { stealth: options.stealth, gatewayIp: bootstrap.gateway.ip })
    );
    for (const host of hosts) {
      emitter?.hostFound(host.ip, host.mac);
      if (host.vendor) {
        emitter?.hostEnriched(host.ip, host.vendor);
      }
    }
    emitter?.scannerComplete("host-discovery", `${hosts.length} hosts discovered`);

    // Step 5: Port scan + hidden device + intrusion detection + deauth detection + traffic capture (needs hosts)
    const [portResults, hiddenDevices, intrusionIndicators, deauthDetection, traffic] = await withSpan(
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
              () => scanPorts(hosts, { stealth: options.stealth })
            );

        // Merge port data into hosts
        for (const host of hosts) {
          const ports = portResult.hostPorts.get(host.ip);
          if (ports) {
            host.ports = ports;
          }
        }

        // Emit port:found for each open port (hostPorts only carries open ports)
        for (const host of hosts) {
          for (const port of host.ports ?? []) {
            emitter?.portFound(host.ip, port.port, port.service);
          }
        }
        emitter?.scannerComplete("port-scan", `${hosts.reduce((acc, h) => acc + (h.ports?.length ?? 0), 0)} open ports`);

        emitter?.scannerStart("hidden-device-scan");
        emitter?.scannerStart("intrusion-detection");
        emitter?.scannerStart("deauth-detection");
        if (!options.skipTraffic) {
          emitter?.scannerStart("traffic-capture");
        }
        const [hidden, intrusion, deauthDetection, traffic] = await Promise.all([
          withSpan("hidden-device-scan", {}, () => scanHiddenDevices(hosts)).then((r) => {
            emitter?.scannerComplete("hidden-device-scan", `${(r?.unknownDevices?.length ?? 0) + (r?.suspectedCameras?.length ?? 0)} hidden devices`);
            return r;
          }),
          withSpan("intrusion-detection", {}, () =>
            scanForIntrusions(bootstrap.gateway.ip, bootstrap.gateway.mac, arpEntries)
          ).then((r) => {
            emitter?.scannerComplete("intrusion-detection", `${r?.arpAnomalies?.length ?? 0} ARP anomalies`);
            return r;
          }),
          withSpan("deauth-detection", {}, () =>
            scanDeauth({
              monitorMode: !!options.monitorInterface,
              interface: options.monitorInterface,
            })
          ).then((r) => {
            emitter?.scannerComplete(
              "deauth-detection",
              r.detected
                ? `${r.frameCount} deauth frame(s) via ${r.method}`
                : `no deauth events via ${r.method}`
            );
            return r;
          }),
          options.skipTraffic
            ? Promise.resolve(undefined)
            : withSpan(
                "traffic-capture",
                { "tool.resolved": tools.get("packetAnalysis")?.name ?? "none" },
                () =>
                  scanTraffic({
                    interface: bootstrap.interface,
                    duration: options.trafficDuration,
                    tool: tools.get("packetAnalysis")?.name,
                  })
              ).then((r) => {
                emitter?.scannerComplete(
                  "traffic-capture",
                  r
                    ? `${r.capturedPackets} packets, ${r.unencrypted.length} unencrypted flow(s)`
                    : "unavailable (no tshark/tcpdump or permissions)"
                );
                return r;
              }),
        ]);

        if (hidden?.suspectedCameras) {
          for (const cam of hidden.suspectedCameras) {
            emitter?.hostCameraDetected(cam.ip, cam.cameraIndicators ?? []);
          }
        }

        return [portResult, hidden, intrusion, deauthDetection, traffic] as const;
      }
    );

    // Step 6: Speed test (runs after other scans to avoid skewing results)
    emitter?.scannerStart("speed-test");
    const speed = options.skipSpeed
      ? undefined
      : await withSpan("speed-test", {}, () =>
          scanSpeed(bootstrap.gateway.ip, wifi.txRate)
        );
    emitter?.scannerComplete("speed-test", speed?.download ? `${speed.download.speedMbps} Mbps down${speed.upload ? `, ${speed.upload.speedMbps} Mbps up` : ""}` : "skipped");

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
      traffic,
      connections,
      hiddenDevices,
      intrusionIndicators,
      deauthDetection,
      speed,
    };

    emitter?.scanComplete(scanId, hosts.length);

    return result;
  });
}
