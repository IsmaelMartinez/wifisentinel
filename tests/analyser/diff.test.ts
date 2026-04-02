import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { detectChanges } from "../../src/analyser/diff.js";
import type { NetworkScanResult } from "../../src/collector/schema/scan-result.js";

function makeScanResult(overrides: any = {}): NetworkScanResult {
  const base: any = {
    meta: {
      scanId: "test-scan-1",
      timestamp: "2025-06-01T12:00:00Z",
      duration: 30000,
      hostname: "testhost",
      platform: "darwin",
      toolchain: {},
    },
    wifi: {
      ssid: "TestNet",
      bssid: "AA:BB:CC:DD:EE:FF",
      protocol: "802.11ax",
      channel: 6,
      band: "2.4GHz",
      width: "20MHz",
      security: "WPA3 Personal",
      signal: -50,
      noise: -90,
      snr: 40,
      txRate: 144,
      macRandomised: true,
      countryCode: "GB",
      nearbyNetworks: [],
    },
    network: {
      interface: "en0",
      ip: "192.168.1.10",
      subnet: "192.168.1.0/24",
      gateway: { ip: "192.168.1.1", mac: "00:11:22:33:44:55" },
      topology: { doubleNat: false, hops: [] },
      dns: {
        servers: ["192.168.1.1"],
        anomalies: [],
        dnssecSupported: true,
        dohDotEnabled: false,
        hijackTestResult: "clean",
      },
      hosts: [],
    },
    localServices: [],
    security: {
      firewall: {
        enabled: true,
        stealthMode: true,
        autoAllowSigned: false,
        autoAllowDownloaded: false,
      },
      vpn: { installed: true, active: true },
      proxy: { enabled: false },
      kernelParams: { ipForwarding: false, icmpRedirects: false },
      clientIsolation: null,
    },
    connections: {
      established: 10,
      listening: 5,
      timeWait: 2,
      topDestinations: [],
    },
  };

  // Apply overrides
  if (overrides.wifi) Object.assign(base.wifi, overrides.wifi);
  if (overrides.network) {
    if (overrides.network.hosts) base.network.hosts = overrides.network.hosts;
    if (overrides.network.dns) Object.assign(base.network.dns, overrides.network.dns);
  }
  if (overrides.security) {
    if (overrides.security.firewall) Object.assign(base.security.firewall, overrides.security.firewall);
    if (overrides.security.vpn) Object.assign(base.security.vpn, overrides.security.vpn);
    if (overrides.security.kernelParams) Object.assign(base.security.kernelParams, overrides.security.kernelParams);
    if ("clientIsolation" in (overrides.security ?? {})) base.security.clientIsolation = overrides.security.clientIsolation;
  }

  return base as NetworkScanResult;
}

describe("detectChanges", () => {
  it("returns empty array when scans are identical", () => {
    const a = makeScanResult();
    const b = makeScanResult();
    const changes = detectChanges(a, b);
    assert.equal(changes.length, 0);
  });

  it("detects a new host joining", () => {
    const a = makeScanResult();
    const b = makeScanResult({
      network: {
        hosts: [
          { ip: "192.168.1.100", mac: "AA:BB:CC:DD:EE:01", vendor: "Samsung Electronics" },
        ],
      },
    });
    const changes = detectChanges(a, b);
    const joined = changes.find((c) => c.type === "host:joined");
    assert.ok(joined);
    assert.equal(joined.type, "host:joined");
    if (joined.type === "host:joined") {
      assert.equal(joined.ip, "192.168.1.100");
      assert.equal(joined.mac, "AA:BB:CC:DD:EE:01");
      assert.equal(joined.vendor, "Samsung Electronics");
    }
  });

  it("detects a host leaving", () => {
    const a = makeScanResult({
      network: {
        hosts: [
          { ip: "192.168.1.50", mac: "AA:BB:CC:DD:EE:02", vendor: "Apple" },
        ],
      },
    });
    const b = makeScanResult();
    const changes = detectChanges(a, b);
    const left = changes.find((c) => c.type === "host:left");
    assert.ok(left);
    if (left.type === "host:left") {
      assert.equal(left.ip, "192.168.1.50");
      assert.equal(left.vendor, "Apple");
    }
  });

  it("detects a port opening on an existing host", () => {
    const host = { ip: "192.168.1.100", mac: "AA:BB:CC:DD:EE:01" };
    const a = makeScanResult({ network: { hosts: [{ ...host, ports: [] }] } });
    const b = makeScanResult({
      network: {
        hosts: [
          { ...host, ports: [{ port: 22, service: "ssh", state: "open" }] },
        ],
      },
    });
    const changes = detectChanges(a, b);
    const opened = changes.find((c) => c.type === "port:opened");
    assert.ok(opened);
    if (opened.type === "port:opened") {
      assert.equal(opened.ip, "192.168.1.100");
      assert.equal(opened.port, 22);
      assert.equal(opened.service, "ssh");
    }
  });

  it("detects a port closing on an existing host", () => {
    const host = { ip: "192.168.1.100", mac: "AA:BB:CC:DD:EE:01" };
    const a = makeScanResult({
      network: {
        hosts: [
          { ...host, ports: [{ port: 80, service: "http", state: "open" }] },
        ],
      },
    });
    const b = makeScanResult({ network: { hosts: [{ ...host, ports: [] }] } });
    const changes = detectChanges(a, b);
    const closed = changes.find((c) => c.type === "port:closed");
    assert.ok(closed);
    if (closed.type === "port:closed") {
      assert.equal(closed.ip, "192.168.1.100");
      assert.equal(closed.port, 80);
      assert.equal(closed.service, "http");
    }
  });

  it("detects security posture changes", () => {
    const a = makeScanResult();
    const b = makeScanResult({
      security: { firewall: { enabled: false } },
    });
    const changes = detectChanges(a, b);
    const secChange = changes.find(
      (c) => c.type === "security:changed" && c.field === "firewall",
    );
    assert.ok(secChange);
    if (secChange.type === "security:changed") {
      assert.equal(secChange.from, "true");
      assert.equal(secChange.to, "false");
    }
  });

  it("detects VPN state change", () => {
    const a = makeScanResult();
    const b = makeScanResult({ security: { vpn: { active: false } } });
    const changes = detectChanges(a, b);
    const vpnChange = changes.find(
      (c) => c.type === "security:changed" && c.field === "vpn",
    );
    assert.ok(vpnChange);
    if (vpnChange.type === "security:changed") {
      assert.equal(vpnChange.from, "true");
      assert.equal(vpnChange.to, "false");
    }
  });

  it("detects WiFi SSID change", () => {
    const a = makeScanResult();
    const b = makeScanResult({ wifi: { ssid: "DifferentNet" } });
    const changes = detectChanges(a, b);
    const ssidChange = changes.find(
      (c) => c.type === "wifi:changed" && c.field === "ssid",
    );
    assert.ok(ssidChange);
    if (ssidChange.type === "wifi:changed") {
      assert.equal(ssidChange.from, "TestNet");
      assert.equal(ssidChange.to, "DifferentNet");
    }
  });

  it("detects WiFi channel change", () => {
    const a = makeScanResult();
    const b = makeScanResult({ wifi: { channel: 11 } });
    const changes = detectChanges(a, b);
    const chChange = changes.find(
      (c) => c.type === "wifi:changed" && c.field === "channel",
    );
    assert.ok(chChange);
    if (chChange.type === "wifi:changed") {
      assert.equal(chChange.from, "6");
      assert.equal(chChange.to, "11");
    }
  });

  it("detects WiFi security protocol downgrade", () => {
    const a = makeScanResult();
    const b = makeScanResult({ wifi: { security: "WPA2 Personal" } });
    const changes = detectChanges(a, b);
    const secChange = changes.find(
      (c) => c.type === "wifi:changed" && c.field === "security",
    );
    assert.ok(secChange);
    if (secChange.type === "wifi:changed") {
      assert.equal(secChange.from, "WPA3 Personal");
      assert.equal(secChange.to, "WPA2 Personal");
    }
  });

  it("detects multiple changes in a single comparison", () => {
    const a = makeScanResult({
      network: {
        hosts: [
          { ip: "192.168.1.50", mac: "AA:BB:CC:DD:EE:02" },
        ],
      },
    });
    const b = makeScanResult({
      network: {
        hosts: [
          { ip: "192.168.1.100", mac: "AA:BB:CC:DD:EE:03" },
        ],
      },
      security: { vpn: { active: false } },
    });
    const changes = detectChanges(a, b);
    const joined = changes.filter((c) => c.type === "host:joined");
    const left = changes.filter((c) => c.type === "host:left");
    const secChanges = changes.filter((c) => c.type === "security:changed");
    assert.equal(joined.length, 1);
    assert.equal(left.length, 1);
    assert.ok(secChanges.length >= 1);
  });
});
