import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { diffScans } from "../../src/store/diff.js";

function makeStoredScan(overrides: any = {}): any {
  const base = {
    scan: {
      meta: { scanId: "scan-1", timestamp: "2025-01-01T00:00:00Z" },
      wifi: {
        ssid: "TestNet",
        security: "WPA3 Personal",
        channel: 6,
        band: "2.4GHz",
        signal: -50,
        snr: 30,
        txRate: 144,
      },
      security: {
        firewall: { enabled: true, stealthMode: true },
        vpn: { active: true },
        proxy: { enabled: false },
        kernelParams: { ipForwarding: false, icmpRedirects: false },
        clientIsolation: null,
      },
      network: {
        hosts: [],
      },
    },
    compliance: {
      overallScore: 85,
      standards: [
        { standard: "cis-wireless", name: "CIS Wireless", score: 90 },
      ],
    },
    analysis: {
      analyses: [
        { persona: "red-team", displayName: "Red Team", riskRating: "medium" },
      ],
    },
  };

  // Deep merge overrides
  if (overrides.scan) {
    if (overrides.scan.meta) Object.assign(base.scan.meta, overrides.scan.meta);
    if (overrides.scan.wifi) Object.assign(base.scan.wifi, overrides.scan.wifi);
    if (overrides.scan.security) {
      if (overrides.scan.security.firewall) Object.assign(base.scan.security.firewall, overrides.scan.security.firewall);
      if (overrides.scan.security.vpn) Object.assign(base.scan.security.vpn, overrides.scan.security.vpn);
      if (overrides.scan.security.kernelParams) Object.assign(base.scan.security.kernelParams, overrides.scan.security.kernelParams);
      if ("clientIsolation" in overrides.scan.security) base.scan.security.clientIsolation = overrides.scan.security.clientIsolation;
    }
    if (overrides.scan.network) {
      if (overrides.scan.network.hosts) base.scan.network.hosts = overrides.scan.network.hosts;
    }
  }
  if (overrides.compliance) Object.assign(base.compliance, overrides.compliance);
  if (overrides.analysis) Object.assign(base.analysis, overrides.analysis);

  return base;
}

describe("diffScans", () => {
  it("reports no changes when scans are identical", () => {
    const a = makeStoredScan();
    const b = makeStoredScan();
    const diff = diffScans(a, b);
    assert.equal(diff.wifi.length, 0);
    assert.equal(diff.security.length, 0);
    assert.equal(diff.hosts.length, 0);
    assert.equal(diff.compliance.overall.delta, 0);
    assert.equal(diff.personas[0].direction, "unchanged");
  });

  it("detects new host", () => {
    const a = makeStoredScan();
    const b = makeStoredScan({
      scan: {
        meta: { scanId: "scan-2", timestamp: "2025-01-02T00:00:00Z" },
        network: {
          hosts: [{ ip: "192.168.1.100", mac: "AA:BB:CC:DD:EE:01", vendor: "Acme" }],
        },
      },
    });
    const diff = diffScans(a, b);
    const added = diff.hosts.find(h => h.type === "added");
    assert.ok(added);
    assert.equal(added.ip, "192.168.1.100");
    assert.equal(added.vendor, "Acme");
  });

  it("detects removed host", () => {
    const a = makeStoredScan({
      scan: {
        network: {
          hosts: [{ ip: "192.168.1.50", mac: "AA:BB:CC:DD:EE:02", vendor: "OldDevice" }],
        },
      },
    });
    const b = makeStoredScan({
      scan: { meta: { scanId: "scan-2", timestamp: "2025-01-02T00:00:00Z" } },
    });
    const diff = diffScans(a, b);
    const removed = diff.hosts.find(h => h.type === "removed");
    assert.ok(removed);
    assert.equal(removed.ip, "192.168.1.50");
  });

  it("detects WiFi signal change", () => {
    const a = makeStoredScan();
    const b = makeStoredScan({
      scan: {
        meta: { scanId: "scan-2", timestamp: "2025-01-02T00:00:00Z" },
        wifi: { signal: -65 },
      },
    });
    const diff = diffScans(a, b);
    const signalChange = diff.wifi.find(w => w.field === "signal");
    assert.ok(signalChange);
    assert.equal(signalChange.from, -50);
    assert.equal(signalChange.to, -65);
    assert.equal(signalChange.direction, "regressed");
  });

  it("computes compliance score delta correctly", () => {
    const a = makeStoredScan();
    const b = makeStoredScan({
      scan: { meta: { scanId: "scan-2", timestamp: "2025-01-02T00:00:00Z" } },
      compliance: {
        overallScore: 92,
        standards: [
          { standard: "cis-wireless", name: "CIS Wireless", score: 95 },
        ],
      },
    });
    const diff = diffScans(a, b);
    assert.equal(diff.compliance.overall.from, 85);
    assert.equal(diff.compliance.overall.to, 92);
    assert.equal(diff.compliance.overall.delta, 7);
    assert.equal(diff.compliance.standards[0].delta, 5);
  });

  it("computes persona risk direction: improved", () => {
    const a = makeStoredScan();
    const b = makeStoredScan({
      scan: { meta: { scanId: "scan-2", timestamp: "2025-01-02T00:00:00Z" } },
      analysis: {
        analyses: [
          { persona: "red-team", displayName: "Red Team", riskRating: "low" },
        ],
      },
    });
    const diff = diffScans(a, b);
    assert.equal(diff.personas[0].direction, "improved");
    assert.equal(diff.personas[0].fromRisk, "medium");
    assert.equal(diff.personas[0].toRisk, "low");
  });

  it("computes persona risk direction: regressed", () => {
    const a = makeStoredScan();
    const b = makeStoredScan({
      scan: { meta: { scanId: "scan-2", timestamp: "2025-01-02T00:00:00Z" } },
      analysis: {
        analyses: [
          { persona: "red-team", displayName: "Red Team", riskRating: "high" },
        ],
      },
    });
    const diff = diffScans(a, b);
    assert.equal(diff.personas[0].direction, "regressed");
  });
});
