import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { detectRogueAPs } from "../../../src/analyser/rf/rogue-ap.js";

function baseWifi(overrides: any = {}): any {
  return {
    ssid: "HomeNetwork",
    bssid: "AA:BB:CC:DD:EE:FF",
    security: "WPA3 Personal",
    channel: 6,
    nearbyNetworks: [],
    ...overrides,
  };
}

describe("detectRogueAPs", () => {
  it("returns no findings when no nearby networks match current SSID", () => {
    const wifi = baseWifi({
      nearbyNetworks: [
        { ssid: "OtherNetwork", bssid: "11:22:33:44:55:66", security: "WPA2 Personal", channel: 1, signal: -60 },
      ],
    });
    const result = detectRogueAPs(wifi);
    assert.equal(result.findings.length, 0);
    assert.equal(result.riskLevel, "clear");
  });

  it("flags same SSID + different BSSID as medium severity", () => {
    const wifi = baseWifi({
      nearbyNetworks: [
        { ssid: "HomeNetwork", bssid: "11:22:33:44:55:66", security: "WPA3 Personal", channel: 6, signal: -55 },
      ],
    });
    const result = detectRogueAPs(wifi);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].severity, "medium");
    assert.ok(result.findings[0].indicators.includes("different_bssid"));
    assert.equal(result.riskLevel, "suspicious");
  });

  it("flags same SSID + weaker security as high severity", () => {
    const wifi = baseWifi({
      nearbyNetworks: [
        { ssid: "HomeNetwork", bssid: "AA:BB:CC:DD:EE:FF", security: "WEP", channel: 6, signal: -55 },
      ],
    });
    const result = detectRogueAPs(wifi);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].severity, "high");
    assert.ok(result.findings[0].indicators.includes("weaker_security"));
    assert.equal(result.riskLevel, "danger");
  });

  it("escalates severity when multiple indicators are present", () => {
    const wifi = baseWifi({
      nearbyNetworks: [
        {
          ssid: "HomeNetwork",
          bssid: "11:22:33:44:55:66",
          security: "WEP",
          channel: 11,
          signal: -70,
        },
      ],
    });
    const result = detectRogueAPs(wifi);
    assert.equal(result.findings.length, 1);
    // different_bssid + weaker_security + different_channel = high
    assert.equal(result.findings[0].severity, "high");
    assert.ok(result.findings[0].indicators.includes("different_bssid"));
    assert.ok(result.findings[0].indicators.includes("weaker_security"));
    assert.ok(result.findings[0].indicators.includes("different_channel"));
    assert.equal(result.riskLevel, "danger");
  });

  it("returns empty findings when SSID is null", () => {
    const wifi = baseWifi({ ssid: null });
    const result = detectRogueAPs(wifi);
    assert.equal(result.findings.length, 0);
    assert.equal(result.riskLevel, "clear");
  });

  it("sets riskLevel to danger when a high severity finding exists", () => {
    const wifi = baseWifi({
      nearbyNetworks: [
        { ssid: "HomeNetwork", bssid: "11:22:33:44:55:66", security: "None", channel: 6, signal: -60 },
      ],
    });
    const result = detectRogueAPs(wifi);
    assert.ok(result.findings.some(f => f.severity === "high"));
    assert.equal(result.riskLevel, "danger");
  });

  it("does not flag nearby network with same SSID, same BSSID, same security, same channel", () => {
    const wifi = baseWifi({
      nearbyNetworks: [
        { ssid: "HomeNetwork", bssid: "AA:BB:CC:DD:EE:FF", security: "WPA3 Personal", channel: 6, signal: -50 },
      ],
    });
    const result = detectRogueAPs(wifi);
    assert.equal(result.findings.length, 0);
    assert.equal(result.riskLevel, "clear");
  });
});
