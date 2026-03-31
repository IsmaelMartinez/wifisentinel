import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { detectEnvironmentChanges } from "../../../src/analyser/rf/environment.js";

const META = { scanId: "baseline-1", timestamp: "2025-01-01T00:00:00Z" };

function makeWifi(nearbyNetworks: any[] = []): any {
  return { nearbyNetworks };
}

describe("detectEnvironmentChanges", () => {
  it("reports no changes when nearby networks are identical", () => {
    const nets = [
      { ssid: "NetA", bssid: "AA:BB:CC:DD:EE:01", security: "WPA3 Personal", channel: 6, signal: -50, noise: -90 },
    ];
    const result = detectEnvironmentChanges(makeWifi(nets), makeWifi(nets), META);
    assert.equal(result.changes.length, 0);
    assert.equal(result.summary, "No environment changes detected");
  });

  it("detects new AP", () => {
    const baseline = makeWifi([]);
    const current = makeWifi([
      { ssid: "NewAP", bssid: "11:22:33:44:55:66", security: "WPA2 Personal", channel: 1, signal: -60, noise: -90 },
    ]);
    const result = detectEnvironmentChanges(current, baseline, META);
    assert.equal(result.changes.length, 1);
    assert.equal(result.changes[0].type, "new_ap");
    assert.equal(result.changes[0].ssid, "NewAP");
    assert.equal(result.changes[0].severity, "medium");
    assert.ok(result.summary.includes("1 new AP(s)"));
  });

  it("detects disappeared AP", () => {
    const baseline = makeWifi([
      { ssid: "OldAP", bssid: "AA:BB:CC:DD:EE:99", security: "WPA2 Personal", channel: 11, signal: -70, noise: -90 },
    ]);
    const current = makeWifi([]);
    const result = detectEnvironmentChanges(current, baseline, META);
    assert.equal(result.changes.length, 1);
    assert.equal(result.changes[0].type, "disappeared_ap");
    assert.equal(result.changes[0].severity, "low");
    assert.ok(result.summary.includes("1 disappeared"));
  });

  it("flags security downgrade as high severity", () => {
    const baseline = makeWifi([
      { ssid: "Net", bssid: "AA:BB:CC:DD:EE:01", security: "WPA3 Personal", channel: 6, signal: -50, noise: -90 },
    ]);
    const current = makeWifi([
      { ssid: "Net", bssid: "AA:BB:CC:DD:EE:01", security: "WEP", channel: 6, signal: -50, noise: -90 },
    ]);
    const result = detectEnvironmentChanges(current, baseline, META);
    const secChange = result.changes.find(c => c.type === "security_change");
    assert.ok(secChange);
    // "WEP".length < "WPA3 Personal".length => downgrade => high
    assert.equal(secChange.severity, "high");
    assert.ok(result.summary.includes("security change(s)"));
  });

  it("detects signal anomaly >= 15 dB", () => {
    const baseline = makeWifi([
      { ssid: "Net", bssid: "AA:BB:CC:DD:EE:01", security: "WPA3 Personal", channel: 6, signal: -70, noise: -90 },
    ]);
    const current = makeWifi([
      { ssid: "Net", bssid: "AA:BB:CC:DD:EE:01", security: "WPA3 Personal", channel: 6, signal: -50, noise: -90 },
    ]);
    const result = detectEnvironmentChanges(current, baseline, META);
    const anomaly = result.changes.find(c => c.type === "signal_anomaly");
    assert.ok(anomaly);
    assert.equal(anomaly.severity, "medium");
    assert.ok(anomaly.detail.includes("20 dB"));
  });

  it("flags signal anomaly >= 25 dB as high severity", () => {
    const baseline = makeWifi([
      { ssid: "Net", bssid: "AA:BB:CC:DD:EE:01", security: "WPA3 Personal", channel: 6, signal: -80, noise: -90 },
    ]);
    const current = makeWifi([
      { ssid: "Net", bssid: "AA:BB:CC:DD:EE:01", security: "WPA3 Personal", channel: 6, signal: -50, noise: -90 },
    ]);
    const result = detectEnvironmentChanges(current, baseline, META);
    const anomaly = result.changes.find(c => c.type === "signal_anomaly");
    assert.ok(anomaly);
    assert.equal(anomaly.severity, "high");
  });

  it("does not flag signal change below 15 dB threshold", () => {
    const baseline = makeWifi([
      { ssid: "Net", bssid: "AA:BB:CC:DD:EE:01", security: "WPA3 Personal", channel: 6, signal: -50, noise: -90 },
    ]);
    const current = makeWifi([
      { ssid: "Net", bssid: "AA:BB:CC:DD:EE:01", security: "WPA3 Personal", channel: 6, signal: -55, noise: -90 },
    ]);
    const result = detectEnvironmentChanges(current, baseline, META);
    const anomaly = result.changes.find(c => c.type === "signal_anomaly");
    assert.equal(anomaly, undefined);
  });

  it("builds correct summary string with multiple change types", () => {
    const baseline = makeWifi([
      { ssid: "OldAP", bssid: "AA:BB:CC:DD:EE:99", security: "WPA2 Personal", channel: 11, signal: -70, noise: -90 },
    ]);
    const current = makeWifi([
      { ssid: "NewAP", bssid: "11:22:33:44:55:66", security: "WPA2 Personal", channel: 1, signal: -60, noise: -90 },
    ]);
    const result = detectEnvironmentChanges(current, baseline, META);
    // 1 new AP + 1 disappeared AP = 2 changes
    assert.equal(result.changes.length, 2);
    assert.ok(result.summary.startsWith("2 change(s):"));
    assert.ok(result.summary.includes("1 new AP(s)"));
    assert.ok(result.summary.includes("1 disappeared"));
  });

  it("includes baseline metadata in result", () => {
    const result = detectEnvironmentChanges(makeWifi(), makeWifi(), META);
    assert.equal(result.baselineScanId, "baseline-1");
    assert.equal(result.baselineTimestamp, "2025-01-01T00:00:00Z");
  });
});
