import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { renderHtmlReport } from "../../src/reporter/html.reporter.js";
import { scoreAllStandards } from "../../src/analyser/standards/index.js";
import { analyseAllPersonas } from "../../src/analyser/personas/index.js";
import type { NetworkScanResult } from "../../src/collector/schema/scan-result.js";

// Any neighbour can broadcast an SSID, so it is attacker-controlled input.
const XSS = "<script>alert(1)</script>";
const ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;";

function scanWithSsid(ssid: string): NetworkScanResult {
  return {
    meta: {
      scanId: "html-escape-test",
      timestamp: "2026-09-01T12:00:00Z",
      duration: 1000,
      hostname: "testhost",
      platform: "darwin",
      toolchain: {},
    },
    wifi: {
      ssid,
      bssid: "aa:bb:cc:dd:ee:01",
      protocol: "802.11ax",
      channel: 36,
      band: "5GHz",
      width: "80MHz",
      security: "WPA2 Personal",
      signal: -50,
      noise: -90,
      snr: 40,
      txRate: 600,
      macRandomised: true,
      countryCode: "GB",
      nearbyNetworks: [
        // Same SSID on another BSSID with weaker security: also exercises the rogue-AP findings.
        { ssid, bssid: "aa:bb:cc:dd:ee:02", security: "Open", protocol: "802.11n", channel: 36, signal: -40, noise: -90 },
        { ssid: `${XSS}-2`, bssid: "aa:bb:cc:dd:ee:03", security: "WPA2 Personal", protocol: "802.11ac", channel: 44, signal: -70, noise: -90 },
      ],
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
        dnssecSupported: false,
        dohDotEnabled: false,
        hijackTestResult: "clean",
      },
      hosts: [],
    },
    localServices: [],
    security: {
      firewall: { enabled: true, stealthMode: false, autoAllowSigned: false, autoAllowDownloaded: false },
      vpn: { installed: false, active: false },
      proxy: { enabled: false },
      kernelParams: { ipForwarding: false, icmpRedirects: false },
      clientIsolation: null,
    },
    connections: { established: 0, listening: 0, timeWait: 0, topDestinations: [] },
  };
}

describe("renderHtmlReport", () => {
  it("escapes a hostile SSID everywhere it is rendered", () => {
    const scan = scanWithSsid(XSS);
    const html = renderHtmlReport({
      scan,
      compliance: scoreAllStandards(scan),
      analysis: analyseAllPersonas(scan),
    });

    assert.ok(!html.includes("<script"), "report must not contain a raw <script> tag");
    assert.ok(html.includes(`<title>WiFi Sentinel Report — ${ESCAPED}`), "title shows the escaped SSID");
    assert.ok(html.includes(`<td>${ESCAPED}</td>`), "nearby-network table shows the escaped SSID");
    assert.ok(html.includes(`<td>${ESCAPED}-2</td>`));
    assert.ok(html.includes(`SSID: ${ESCAPED}`), "rogue-AP finding shows the escaped SSID");
  });
});
