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
  speed: {
    download: {
      speedMbps: 87.5,
      bytesTransferred: 26214400,
      durationMs: 2396,
      testUrl: "https://speed.cloudflare.com/__down?bytes=26214400",
    },
  },
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

  it("carries the opt-in speed test across as a download-only speed section", () => {
    const result = androidImportToScanResult(fullExport);
    assert.deepEqual(result.speed?.download, fullExport.speed.download);
    // The sub-sections the phone doesn't measure stay absent, not zero-filled
    // (zeros would read as genuine "slow upload" persona findings).
    assert.equal(result.speed?.upload, undefined);
    assert.equal(result.speed?.rating, undefined);
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
  });

  it("degrades a malformed speed section to absent instead of rejecting the scan", () => {
    const trimmed = {
      ...fullExport,
      // Missing bytesTransferred/durationMs/testUrl — e.g. a hand-trimmed
      // export or a future app version after field drift.
      speed: { download: { speedMbps: 87.5 } },
    };
    const parsed = AndroidScanImport.safeParse(trimmed);
    assert.equal(parsed.success, true);
    if (parsed.success) {
      assert.equal(parsed.data.speed, undefined);
      const result = androidImportToScanResult(parsed.data);
      // The download section degrades to absent; the independently-measured
      // latency figure still comes across.
      assert.equal(result.speed?.download, undefined);
      assert.equal(result.speed?.latency?.internetMs, 24);
      assert.doesNotThrow(() => NetworkScanResult.parse(result));
    }
  });

  it("maps the phone's latency figure into speed.latency.internetMs", () => {
    const result = androidImportToScanResult(fullExport);
    assert.equal(result.speed?.latency?.internetMs, 24);
    // The latency sub-fields the phone can't measure stay absent — the same
    // degrade-to-absent convention as the download-only speed section.
    assert.equal(result.speed?.latency?.gatewayMs, undefined);
    assert.equal(result.speed?.latency?.dnsResolutionMs, undefined);
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
  });

  it("builds a latency-only speed section when the speed test was off", () => {
    const result = androidImportToScanResult({ ...fullExport, speed: undefined });
    assert.equal(result.speed?.latency?.internetMs, 24);
    assert.equal(result.speed?.download, undefined);
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
    // Latency-only records must still flow through the analysis layer.
    assert.doesNotThrow(() => scoreAllStandards(result));
    assert.doesNotThrow(() => analyseAllPersonas(result));
  });

  it("omits the speed section entirely when neither latency nor download exist", () => {
    const result = androidImportToScanResult({
      ...fullExport,
      speed: undefined,
      latencyMs: undefined,
    });
    assert.equal(result.speed, undefined);
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
  });

  it("treats a null latencyMs (failed probe) as absent", () => {
    const result = androidImportToScanResult({
      ...fullExport,
      speed: undefined,
      latencyMs: null,
    });
    assert.equal(result.speed, undefined);
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
