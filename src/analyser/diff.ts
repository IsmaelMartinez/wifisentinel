// src/analyser/diff.ts — Lightweight change detection for watch mode
import type { NetworkScanResult } from "../collector/schema/scan-result.js";

export type NetworkChange =
  | { type: "host:joined"; ip: string; mac: string; vendor?: string }
  | { type: "host:left"; ip: string; mac: string; vendor?: string }
  | { type: "port:opened"; ip: string; port: number; service: string }
  | { type: "port:closed"; ip: string; port: number; service: string }
  | { type: "security:changed"; field: string; from: string; to: string }
  | { type: "wifi:changed"; field: string; from: string; to: string };

export function detectChanges(
  previous: NetworkScanResult,
  current: NetworkScanResult,
): NetworkChange[] {
  const changes: NetworkChange[] = [];

  const prevHosts = new Map(previous.network.hosts.map((h) => [h.ip, h]));
  const currHosts = new Map(current.network.hosts.map((h) => [h.ip, h]));

  // Hosts joined
  for (const [ip, host] of currHosts) {
    if (!prevHosts.has(ip)) {
      changes.push({ type: "host:joined", ip, mac: host.mac, vendor: host.vendor });
    }
  }

  // Hosts left
  for (const [ip, host] of prevHosts) {
    if (!currHosts.has(ip)) {
      changes.push({ type: "host:left", ip, mac: host.mac, vendor: host.vendor });
    }
  }

  // Port changes on hosts present in both scans
  for (const [ip, currHost] of currHosts) {
    const prevHost = prevHosts.get(ip);
    if (!prevHost) continue;

    const prevPorts = new Map((prevHost.ports ?? []).map((p) => [p.port, p]));
    const currPorts = new Map((currHost.ports ?? []).map((p) => [p.port, p]));

    for (const [port, info] of currPorts) {
      if (!prevPorts.has(port)) {
        changes.push({ type: "port:opened", ip, port, service: info.service });
      }
    }
    for (const [port, info] of prevPorts) {
      if (!currPorts.has(port)) {
        changes.push({ type: "port:closed", ip, port, service: info.service });
      }
    }
  }

  // Security posture changes
  const securityFields: Array<{ field: string; prev: string; curr: string }> = [
    {
      field: "firewall",
      prev: String(previous.security.firewall.enabled),
      curr: String(current.security.firewall.enabled),
    },
    {
      field: "vpn",
      prev: String(previous.security.vpn.active),
      curr: String(current.security.vpn.active),
    },
    {
      field: "clientIsolation",
      prev: String(previous.security.clientIsolation),
      curr: String(current.security.clientIsolation),
    },
    {
      field: "stealthMode",
      prev: String(previous.security.firewall.stealthMode),
      curr: String(current.security.firewall.stealthMode),
    },
    {
      field: "ipForwarding",
      prev: String(previous.security.kernelParams.ipForwarding),
      curr: String(current.security.kernelParams.ipForwarding),
    },
  ];
  for (const { field, prev, curr } of securityFields) {
    if (prev !== curr) {
      changes.push({ type: "security:changed", field, from: prev, to: curr });
    }
  }

  // WiFi changes
  const wifiFields: Array<{ field: string; prev: string; curr: string }> = [
    { field: "ssid", prev: previous.wifi.ssid ?? "", curr: current.wifi.ssid ?? "" },
    { field: "security", prev: previous.wifi.security, curr: current.wifi.security },
    { field: "channel", prev: String(previous.wifi.channel), curr: String(current.wifi.channel) },
    { field: "band", prev: previous.wifi.band, curr: current.wifi.band },
  ];
  for (const { field, prev, curr } of wifiFields) {
    if (prev !== curr) {
      changes.push({ type: "wifi:changed", field, from: prev, to: curr });
    }
  }

  return changes;
}
