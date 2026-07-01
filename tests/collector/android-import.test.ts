import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  AndroidScanImport,
  androidImportToScanResult,
} from "../../src/collector/android-import.js";
import { NetworkScanResult } from "../../src/collector/schema/scan-result.js";
import { scoreAllStandards } from "../../src/analyser/standards/index.js";
import { analyseAllPersonas } from "../../src/analyser/personas/index.js";

const fullExport = {
  meta: {
    scanId: "11111111-2222-3333-4444-555555555555",
    timestamp: "2026-07-01T10:00:00.000Z",
    platform: "android" as const,
    partial: true,
    appVersion: "1.0.0",
  },
  wifi: {
    ssid: "HomeNet",
    bssid: "aa:bb:cc:dd:ee:ff",
    security: "WPA2",
    channel: 36,
    band: "5 GHz",
    signal: -55,
    txRate: 866,
  },
  network: {
    ip: "192.168.1.42",
    gatewayIp: "192.168.1.1",
    dnsServers: ["192.168.1.1", "1.1.1.1"],
    vpnActive: false,
  },
  hosts: [
    { ip: "192.168.1.10", hostname: "printer.local", serviceType: "_ipp._tcp", openPorts: [631] },
    { ip: "192.168.1.20", openPorts: [] },
  ],
  latencyMs: 24,
};

describe("AndroidScanImport schema", () => {
  it("accepts a complete Android export", () => {
    assert.equal(AndroidScanImport.safeParse(fullExport).success, true);
  });

  it("accepts a minimal export with only required meta", () => {
    const minimal = {
      meta: {
        scanId: "abc",
        timestamp: "2026-07-01T10:00:00.000Z",
        platform: "android",
      },
    };
    assert.equal(AndroidScanImport.safeParse(minimal).success, true);
  });

  it("rejects a non-android platform", () => {
    const bad = { ...fullExport, meta: { ...fullExport.meta, platform: "darwin" } };
    assert.equal(AndroidScanImport.safeParse(bad).success, false);
  });

  it("rejects missing scanId", () => {
    const bad = { meta: { timestamp: "t", platform: "android" } };
    assert.equal(AndroidScanImport.safeParse(bad).success, false);
  });
});

describe("androidImportToScanResult", () => {
  it("expands a full export into a schema-valid NetworkScanResult", () => {
    const result = androidImportToScanResult(fullExport);
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
  });

  it("flags the record as a partial android scan", () => {
    const result = androidImportToScanResult(fullExport);
    assert.equal(result.meta.platform, "android");
    assert.equal(result.meta.partial, true);
    assert.match(result.meta.hostname, /android/);
  });

  it("preserves observed wifi and network fields", () => {
    const result = androidImportToScanResult(fullExport);
    assert.equal(result.wifi.ssid, "HomeNet");
    assert.equal(result.wifi.security, "WPA2");
    assert.equal(result.wifi.channel, 36);
    assert.equal(result.wifi.signal, -55);
    assert.equal(result.network.ip, "192.168.1.42");
    assert.equal(result.network.gateway.ip, "192.168.1.1");
    assert.deepEqual(result.network.dns.servers, ["192.168.1.1", "1.1.1.1"]);
  });

  it("maps hosts and open ports into the CLI host shape", () => {
    const result = androidImportToScanResult(fullExport);
    assert.equal(result.network.hosts.length, 2);
    const printer = result.network.hosts[0];
    assert.equal(printer.ip, "192.168.1.10");
    assert.equal(printer.hostname, "printer.local");
    assert.equal(printer.mac, "unknown");
    assert.deepEqual(printer.ports, [{ port: 631, service: "unknown", state: "open" }]);
    assert.deepEqual(result.network.hosts[1].ports, []);
  });

  it("reflects VPN state into the security section", () => {
    const vpnOn = androidImportToScanResult({
      ...fullExport,
      network: { ...fullExport.network, vpnActive: true },
    });
    assert.equal(vpnOn.security.vpn.active, true);
    assert.equal(vpnOn.security.vpn.installed, true);
  });

  it("fills honest sentinels when optional sections are absent", () => {
    const minimal = androidImportToScanResult({
      meta: {
        scanId: "abc",
        timestamp: "2026-07-01T10:00:00.000Z",
        platform: "android",
      },
    });
    assert.doesNotThrow(() => NetworkScanResult.parse(minimal));
    assert.equal(minimal.wifi.ssid, null);
    assert.equal(minimal.wifi.security, "unknown");
    assert.equal(minimal.network.ip, "unknown");
    assert.equal(minimal.network.hosts.length, 0);
    assert.equal(minimal.traffic, undefined);
    assert.equal(minimal.speed, undefined);
  });

  it("produces a result the analyser and standards scorers accept", () => {
    const result = androidImportToScanResult(fullExport);
    assert.doesNotThrow(() => scoreAllStandards(result));
    assert.doesNotThrow(() => analyseAllPersonas(result));
  });
});
