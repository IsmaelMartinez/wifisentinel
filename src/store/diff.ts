// src/store/diff.ts
import type { StoredScan } from "./types.js";
import type { Host } from "../collector/schema/scan-result.js";

export interface FieldChange {
  field: string;
  from: string | number | boolean;
  to: string | number | boolean;
  direction: "improved" | "regressed" | "changed";
}

export interface HostChange {
  type: "added" | "removed" | "changed";
  ip: string;
  mac: string;
  vendor?: string;
  changes?: FieldChange[];
}

export interface ScoreDelta {
  name: string;
  from: number;
  to: number;
  delta: number;
}

export interface PersonaDelta {
  persona: string;
  fromRisk: string;
  toRisk: string;
  direction: "improved" | "regressed" | "unchanged";
}

export interface ScanDiff {
  fromScanId: string;
  toScanId: string;
  fromTimestamp: string;
  toTimestamp: string;
  wifi: FieldChange[];
  security: FieldChange[];
  hosts: HostChange[];
  compliance: {
    overall: ScoreDelta;
    standards: ScoreDelta[];
  };
  personas: PersonaDelta[];
}

const RISK_ORDER = ["minimal", "low", "medium", "high", "critical"];

function riskDirection(from: string, to: string): "improved" | "regressed" | "unchanged" {
  const fi = RISK_ORDER.indexOf(from);
  const ti = RISK_ORDER.indexOf(to);
  if (ti < fi) return "improved";
  if (ti > fi) return "regressed";
  return "unchanged";
}

function fieldChange(
  field: string,
  from: string | number | boolean,
  to: string | number | boolean,
  higherIsBetter = true,
): FieldChange | null {
  if (from === to) return null;
  let direction: FieldChange["direction"] = "changed";
  if (typeof from === "number" && typeof to === "number") {
    direction = (to > from) === higherIsBetter ? "improved" : "regressed";
  }
  return { field, from, to, direction };
}

export function diffScans(a: StoredScan, b: StoredScan): ScanDiff {
  const wifi: FieldChange[] = [];
  const aw = a.scan.wifi;
  const bw = b.scan.wifi;

  const wifiFields: Array<{ field: string; from: any; to: any; higherIsBetter?: boolean }> = [
    { field: "ssid", from: aw.ssid, to: bw.ssid },
    { field: "security", from: aw.security, to: bw.security },
    { field: "channel", from: aw.channel, to: bw.channel },
    { field: "band", from: aw.band, to: bw.band },
    { field: "signal", from: aw.signal, to: bw.signal, higherIsBetter: true },
    { field: "snr", from: aw.snr, to: bw.snr, higherIsBetter: true },
    { field: "txRate", from: aw.txRate, to: bw.txRate, higherIsBetter: true },
  ];
  for (const f of wifiFields) {
    const change = fieldChange(f.field, f.from, f.to, f.higherIsBetter);
    if (change) wifi.push(change);
  }

  // Security posture
  const security: FieldChange[] = [];
  const as = a.scan.security;
  const bs = b.scan.security;

  const secFields: Array<{ field: string; from: any; to: any; higherIsBetter?: boolean }> = [
    { field: "firewall.enabled", from: as.firewall.enabled, to: bs.firewall.enabled },
    { field: "firewall.stealthMode", from: as.firewall.stealthMode, to: bs.firewall.stealthMode },
    { field: "vpn.active", from: as.vpn.active, to: bs.vpn.active },
    { field: "proxy.enabled", from: as.proxy.enabled, to: bs.proxy.enabled },
    { field: "kernelParams.ipForwarding", from: as.kernelParams.ipForwarding, to: bs.kernelParams.ipForwarding, higherIsBetter: false },
    { field: "kernelParams.icmpRedirects", from: as.kernelParams.icmpRedirects, to: bs.kernelParams.icmpRedirects, higherIsBetter: false },
    { field: "clientIsolation", from: a.scan.security.clientIsolation, to: b.scan.security.clientIsolation },
  ];
  for (const f of secFields) {
    const change = fieldChange(f.field, f.from, f.to, f.higherIsBetter);
    if (change) security.push(change);
  }

  // Hosts
  const hosts: HostChange[] = [];
  const aHosts = new Map(a.scan.network.hosts.map(h => [h.ip, h]));
  const bHosts = new Map(b.scan.network.hosts.map(h => [h.ip, h]));

  for (const [ip, host] of bHosts) {
    if (!aHosts.has(ip)) {
      hosts.push({ type: "added", ip, mac: host.mac, vendor: host.vendor });
    }
  }
  for (const [ip, host] of aHosts) {
    if (!bHosts.has(ip)) {
      hosts.push({ type: "removed", ip, mac: host.mac, vendor: host.vendor });
    }
  }
  for (const [ip, bHost] of bHosts) {
    const aHost = aHosts.get(ip);
    if (!aHost) continue;
    const changes: FieldChange[] = [];
    if (aHost.vendor !== bHost.vendor) {
      changes.push({ field: "vendor", from: aHost.vendor ?? "", to: bHost.vendor ?? "", direction: "changed" });
    }
    const aPorts = (aHost.ports ?? []).map(p => p.port).sort().join(",");
    const bPorts = (bHost.ports ?? []).map(p => p.port).sort().join(",");
    if (aPorts !== bPorts) {
      changes.push({ field: "ports", from: aPorts || "none", to: bPorts || "none", direction: "changed" });
    }
    if (changes.length > 0) {
      hosts.push({ type: "changed", ip, mac: bHost.mac, vendor: bHost.vendor, changes });
    }
  }

  // Compliance
  const overallDelta: ScoreDelta = {
    name: "Overall",
    from: a.compliance.overallScore,
    to: b.compliance.overallScore,
    delta: b.compliance.overallScore - a.compliance.overallScore,
  };
  const standardDeltas: ScoreDelta[] = [];
  for (const bStd of b.compliance.standards) {
    const aStd = a.compliance.standards.find(s => s.standard === bStd.standard);
    if (aStd) {
      standardDeltas.push({
        name: bStd.name,
        from: aStd.score,
        to: bStd.score,
        delta: bStd.score - aStd.score,
      });
    }
  }

  // Personas
  const personas: PersonaDelta[] = [];
  for (const bPersona of b.analysis.analyses) {
    const aPersona = a.analysis.analyses.find(p => p.persona === bPersona.persona);
    if (aPersona) {
      personas.push({
        persona: bPersona.displayName,
        fromRisk: aPersona.riskRating,
        toRisk: bPersona.riskRating,
        direction: riskDirection(aPersona.riskRating, bPersona.riskRating),
      });
    }
  }

  return {
    fromScanId: a.scan.meta.scanId,
    toScanId: b.scan.meta.scanId,
    fromTimestamp: a.scan.meta.timestamp,
    toTimestamp: b.scan.meta.timestamp,
    wifi,
    security,
    hosts,
    compliance: { overall: overallDelta, standards: standardDeltas },
    personas,
  };
}
