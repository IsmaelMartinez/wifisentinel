import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  AndroidScanImport,
  androidImportToScanResult,
} from "../../src/collector/android-import.js";
import { NetworkScanResult } from "../../src/collector/schema/scan-result.js";
import { scoreAllStandards } from "../../src/analyser/standards/index.js";
import { analyseAllPersonas } from "../../src/analyser/personas/index.js";
import { detectRogueAPs } from "../../src/analyser/rf/rogue-ap.js";

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
    nearbyNetworks: [
      {
        ssid: "NextDoor",
        bssid: "11:22:33:44:55:66",
        security: "WPA3",
        channel: 36,
        band: "5 GHz",
        signal: -70,
      },
      { ssid: null, bssid: "22:33:44:55:66:AA", security: "WPA2", channel: 149, band: "5 GHz", signal: -80 },
    ],
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

  it("carries the opt-in speed test across without zero-filling unmeasured sub-sections", () => {
    const result = androidImportToScanResult(fullExport);
    assert.deepEqual(result.speed?.download, fullExport.speed.download);
    // The sub-sections the phone doesn't measure stay absent, not zero-filled
    // (zeros would read as genuine "slow upload" persona findings).
    assert.equal(result.speed?.upload, undefined);
    assert.equal(result.speed?.rating, undefined);
    assert.equal(result.speed?.jitter, undefined);
    assert.equal(result.speed?.packetLoss, undefined);
    assert.equal(result.speed?.wifiLinkRate, undefined);
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

  it("stamps the latency method as https-rtt so consumers don't read ping thresholds", () => {
    // The phone's probe is an HTTPS HEAD round-trip (~100–400 ms healthy),
    // not an ICMP ping (~15 ms) — without the method stamp a healthy phone
    // import renders amber/red in the terminal/HTML latency sections.
    const result = androidImportToScanResult(fullExport);
    assert.equal(result.speed?.latency?.method, "https-rtt");
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
  });

  it("suppresses ping-semantics persona insights for https-rtt latency", () => {
    // A healthy-for-HTTPS 350 ms figure must not fire the net-engineer's
    // ICMP-calibrated latency insights, even when jitter/gateway fields are
    // (hypothetically) present alongside it.
    const result = androidImportToScanResult({ ...fullExport, latencyMs: 350 });
    result.speed = {
      ...result.speed,
      latency: { gatewayMs: 350, internetMs: 350, method: "https-rtt" },
      jitter: { gatewayMs: 5, internetMs: 5 },
    };
    const analysis = analyseAllPersonas(result);
    const netEngineer = analysis.analyses.find((a) => a.persona === "net-engineer");
    const ids = new Set(netEngineer?.insights.map((i) => i.id));
    assert.equal(ids.has("ne-high-gateway-latency"), false);
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

  it("rejects empty speed/latency husks at the schema level", () => {
    const base = androidImportToScanResult(fullExport);
    // Sections degrade to absent, never to empty objects — the schema
    // enforces at least one measurement per (sub-)section.
    assert.throws(() => NetworkScanResult.parse({ ...base, speed: {} }));
    assert.throws(() =>
      NetworkScanResult.parse({ ...base, speed: { latency: {} } })
    );
    // `method` is an annotation, not a measurement — it can't carry a
    // latency section on its own.
    assert.throws(() =>
      NetworkScanResult.parse({
        ...base,
        speed: { latency: { method: "https-rtt" } },
      })
    );
  });

  it("carries nearby networks into wifi.nearbyNetworks with honest sentinels", () => {
    const result = androidImportToScanResult(fullExport);
    assert.equal(result.wifi.nearbyNetworks.length, 2);
    const [first, hidden] = result.wifi.nearbyNetworks;
    assert.equal(first.ssid, "NextDoor");
    assert.equal(first.bssid, "11:22:33:44:55:66");
    assert.equal(first.security, "WPA3");
    assert.equal(first.channel, 36);
    assert.equal(first.signal, -70);
    // Not observable from the phone — sentinels, same as the connected AP.
    assert.equal(first.protocol, "unknown");
    assert.equal(first.noise, 0);
    // Hidden networks keep their null SSID; BSSIDs normalise to lowercase.
    assert.equal(hidden.ssid, null);
    assert.equal(hidden.bssid, "22:33:44:55:66:aa");
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
  });

  it("defaults nearby networks to empty when the export predates the field", () => {
    for (const legacy of [undefined, null]) {
      const result = androidImportToScanResult({
        ...fullExport,
        wifi: { ...fullExport.wifi, nearbyNetworks: legacy },
      });
      assert.deepEqual(result.wifi.nearbyNetworks, []);
      assert.doesNotThrow(() => NetworkScanResult.parse(result));
    }
  });

  it("drops nearby entries missing bssid/channel/signal instead of sentinel-filling", () => {
    // 0 dBm would read as the strongest possible signal and channel 0
    // aliases with the unknown-channel sentinel — dropping is the honest
    // degradation for hand-trimmed or drifted exports.
    const result = androidImportToScanResult({
      ...fullExport,
      wifi: {
        ...fullExport.wifi,
        nearbyNetworks: [
          { ssid: "NoBssid", channel: 6, signal: -60 },
          { ssid: "NoChannel", bssid: "33:44:55:66:77:88", signal: -60 },
          { ssid: "UnknownFreq", bssid: "44:55:66:77:88:99", channel: 0, signal: -60 },
          { ssid: "NoSignal", bssid: "55:66:77:88:99:aa", channel: 6 },
          { ssid: "Kept", bssid: "66:77:88:99:aa:bb", channel: 6, signal: -60 },
        ],
      },
    });
    assert.deepEqual(
      result.wifi.nearbyNetworks.map((n) => n.ssid),
      ["Kept"]
    );
  });

  it("never fires channel congestion on the unknown-channel sentinel", () => {
    // Connected channel unknown (absent → 0 sentinel) + nearby entries on
    // channel 0 must not read as "channel 0 is congested". The import layer
    // already drops channel-0 nearby entries, so build the sentinel state
    // directly to exercise the persona's own guard.
    const result = androidImportToScanResult({
      ...fullExport,
      wifi: { ...fullExport.wifi, channel: undefined },
    });
    result.wifi.nearbyNetworks = [1, 2, 3].map((i) => ({
      ssid: `Mystery${i}`,
      bssid: `00:00:00:00:01:0${i}`,
      security: "unknown",
      protocol: "unknown",
      channel: 0,
      signal: -60,
      noise: 0,
    }));
    assert.equal(result.wifi.channel, 0);
    const analysis = analyseAllPersonas(result);
    const netEngineer = analysis.analyses.find((a) => a.persona === "net-engineer");
    const ids = new Set(netEngineer?.insights.map((i) => i.id));
    assert.equal(ids.has("ne-channel-congestion"), false);
  });

  it("feeds nearby networks into the net-engineer channel-congestion insight", () => {
    const congested = androidImportToScanResult({
      ...fullExport,
      wifi: {
        ...fullExport.wifi,
        nearbyNetworks: [1, 2, 3].map((i) => ({
          ssid: `Neighbour${i}`,
          bssid: `00:00:00:00:00:0${i}`,
          security: "WPA2",
          channel: 36, // same channel as the connected AP in fullExport
          band: "5 GHz",
          signal: -60 - i,
        })),
      },
    });
    const analysis = analyseAllPersonas(congested);
    const netEngineer = analysis.analyses.find((a) => a.persona === "net-engineer");
    const congestion = netEngineer?.insights.find((i) => i.id === "ne-channel-congestion");
    assert.ok(congestion, "expected ne-channel-congestion to fire on the imported scan");
  });

  it("accepts and expands a top-level nearby list decoupled from wifi", () => {
    const survey = {
      ...fullExport,
      wifi: { ...fullExport.wifi, nearbyNetworks: undefined },
      nearbyNetworks: [
        { ssid: "Roof", bssid: "ab:cd:ef:00:11:22", security: "WPA2", channel: 40, band: "5 GHz", signal: -65 },
      ],
    };
    assert.equal(AndroidScanImport.safeParse(survey).success, true);
    const result = androidImportToScanResult(survey);
    assert.equal(result.wifi.nearbyNetworks.length, 1);
    assert.equal(result.wifi.nearbyNetworks[0].bssid, "ab:cd:ef:00:11:22");
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
  });

  it("round-trips a nearby-only survey with the connected AP absent", () => {
    // Scanned while disconnected (or with WifiInfo redacted): no `wifi`, but
    // the RF neighbourhood still exports at the top level and survives import.
    const survey = {
      meta: {
        scanId: "survey-1",
        timestamp: "2026-07-01T10:00:00.000Z",
        platform: "android" as const,
      },
      nearbyNetworks: [
        { ssid: "CafeGuest", bssid: "00:11:22:33:44:55", security: "Open", channel: 6, band: "2.4 GHz", signal: -58 },
        { ssid: "Office", bssid: "66:77:88:99:AA:BB", security: "WPA3", channel: 36, band: "5 GHz", signal: -72 },
      ],
    };
    assert.equal(AndroidScanImport.safeParse(survey).success, true);
    const result = androidImportToScanResult(survey);
    // The connected-AP fields degrade to honest sentinels...
    assert.equal(result.wifi.ssid, null);
    assert.equal(result.wifi.bssid, "unknown");
    assert.equal(result.wifi.security, "unknown");
    // ...but the nearby survey is preserved (BSSIDs lowercased).
    assert.deepEqual(
      result.wifi.nearbyNetworks.map((n) => n.bssid),
      ["00:11:22:33:44:55", "66:77:88:99:aa:bb"]
    );
    assert.doesNotThrow(() => NetworkScanResult.parse(result));
    assert.doesNotThrow(() => scoreAllStandards(result));
    assert.doesNotThrow(() => analyseAllPersonas(result));
  });

  it("prefers the top-level nearby list over the legacy nested one", () => {
    // Both locations populated (a transitional export): the decoupled
    // top-level field wins; the nested legacy list is ignored.
    const both = {
      ...fullExport,
      nearbyNetworks: [
        { ssid: "TopLevel", bssid: "aa:aa:aa:aa:aa:aa", security: "WPA2", channel: 1, band: "2.4 GHz", signal: -50 },
      ],
    };
    const result = androidImportToScanResult(both);
    assert.deepEqual(
      result.wifi.nearbyNetworks.map((n) => n.ssid),
      ["TopLevel"]
    );
  });

  it("fires the high-severity weaker-security rogue-AP rule on an Open evil twin of the WPA2 network", () => {
    // The core payoff of exporting nearby networks: the phone labels the
    // connected network "WPA2" and the evil twin "Open" — coarse labels the
    // rogue-AP rule used to score as unknown (index -1), so the rule could
    // never fire on imported scans.
    const withEvilTwin = androidImportToScanResult({
      ...fullExport,
      wifi: {
        ...fullExport.wifi,
        nearbyNetworks: [
          {
            ssid: "HomeNet", // same SSID as the connected AP
            bssid: "de:ad:be:ef:00:01",
            security: "Open",
            channel: 36,
            band: "5 GHz",
            signal: -48,
          },
        ],
      },
    });
    const rogue = detectRogueAPs(withEvilTwin.wifi);
    assert.equal(rogue.findings.length, 1);
    assert.equal(rogue.findings[0].severity, "high");
    assert.ok(rogue.findings[0].indicators.includes("weaker_security"));
    assert.ok(rogue.findings[0].indicators.includes("different_bssid"));
    assert.equal(rogue.riskLevel, "danger");
  });

  it("normalises security labels into the canonical vocabulary on import", () => {
    const result = androidImportToScanResult({
      ...fullExport,
      wifi: {
        ...fullExport.wifi,
        security: "WPA2",
        nearbyNetworks: [
          { ssid: "Cafe", bssid: "de:ad:be:ef:00:02", security: "Open", channel: 1, band: "2.4 GHz", signal: -60 },
        ],
      },
    });
    // Coarse phone labels are already canonical — they pass through
    // unchanged rather than gaining a fabricated Personal/Enterprise mode.
    assert.equal(result.wifi.security, "WPA2");
    assert.equal(result.wifi.nearbyNetworks[0].security, "Open");
    // The "unknown" sentinel survives normalisation.
    const minimal = androidImportToScanResult({
      meta: { scanId: "abc", timestamp: "2026-07-01T10:00:00.000Z", platform: "android" },
    });
    assert.equal(minimal.wifi.security, "unknown");
  });

  it("produces a result the analyser and standards scorers accept", () => {
    const result = androidImportToScanResult(fullExport);
    assert.doesNotThrow(() => scoreAllStandards(result));
    assert.doesNotThrow(() => analyseAllPersonas(result));
  });
});
