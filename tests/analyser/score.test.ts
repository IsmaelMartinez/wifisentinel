import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { computeSecurityScore } from "../../src/analyser/score.js";

function baseScan(): any {
  return {
    security: {
      firewall: { enabled: true, stealthMode: true },
      vpn: { active: true },
      proxy: { enabled: false },
      kernelParams: { ipForwarding: false, icmpRedirects: false },
    },
    network: {
      dns: {
        hijackTestResult: "clean",
        dnssecSupported: true,
        anomalies: [],
      },
    },
    localServices: [],
    intrusionIndicators: undefined,
    hiddenDevices: undefined,
    traffic: undefined,
  };
}

describe("computeSecurityScore", () => {
  it("returns 10 when everything is secure", () => {
    const score = computeSecurityScore(baseScan());
    assert.equal(score, 10);
  });

  it("reduces score by 2 when firewall is disabled", () => {
    const scan = baseScan();
    scan.security.firewall.enabled = false;
    const score = computeSecurityScore(scan);
    assert.equal(score, 8);
  });

  it("reduces score by 0.5 when firewall lacks stealth mode", () => {
    const scan = baseScan();
    scan.security.firewall.stealthMode = false;
    const score = computeSecurityScore(scan);
    assert.equal(score, 9.5);
  });

  it("reduces score by 1 when VPN is inactive", () => {
    const scan = baseScan();
    scan.security.vpn.active = false;
    const score = computeSecurityScore(scan);
    assert.equal(score, 9);
  });

  it("reduces score by 2 when DNS is hijacked", () => {
    const scan = baseScan();
    scan.network.dns.hijackTestResult = "intercepted";
    const score = computeSecurityScore(scan);
    assert.equal(score, 8);
  });

  it("reduces score by 0.5 when DNSSEC is not supported", () => {
    const scan = baseScan();
    scan.network.dns.dnssecSupported = false;
    const score = computeSecurityScore(scan);
    assert.equal(score, 9.5);
  });

  it("reduces score by 0.5 when DNS anomalies exist", () => {
    const scan = baseScan();
    scan.network.dns.anomalies = ["anomaly1"];
    const score = computeSecurityScore(scan);
    assert.equal(score, 9.5);
  });

  it("reduces score for exposed services, capped at 1.5", () => {
    const scan = baseScan();
    scan.localServices = [
      { exposedToNetwork: true },
      { exposedToNetwork: true },
      { exposedToNetwork: true },
    ];
    const score = computeSecurityScore(scan);
    assert.equal(score, 9.1);

    // Cap: 6 exposed services would be 1.8, but capped at 1.5
    scan.localServices = Array.from({ length: 6 }, () => ({ exposedToNetwork: true }));
    const cappedScore = computeSecurityScore(scan);
    assert.equal(cappedScore, 8.5);
  });

  it("reduces score for intrusion indicators", () => {
    const scan = baseScan();
    scan.intrusionIndicators = {
      arpAnomalies: [{ severity: "high" }],
      suspiciousHosts: [{ severity: "high" }],
      scanDetection: [{ source: "x", type: "y", detail: "z" }],
    };
    const score = computeSecurityScore(scan);
    // -0.5 (arp) -0.5 (host) -0.3 (scan) = -1.3
    assert.equal(score, 8.7);
  });

  it("reduces score by 1 when suspected cameras found", () => {
    const scan = baseScan();
    scan.hiddenDevices = { suspectedCameras: [{ ip: "1.2.3.4" }] };
    const score = computeSecurityScore(scan);
    assert.equal(score, 9);
  });

  it("reduces score for kernel ipForwarding and icmpRedirects", () => {
    const scan = baseScan();
    scan.security.kernelParams.ipForwarding = true;
    scan.security.kernelParams.icmpRedirects = true;
    const score = computeSecurityScore(scan);
    assert.equal(score, 9.2);
  });

  it("reduces score by 0.5 when proxy is enabled", () => {
    const scan = baseScan();
    scan.security.proxy.enabled = true;
    const score = computeSecurityScore(scan);
    assert.equal(score, 9.5);
  });

  it("reduces score for unencrypted traffic, capped at 1", () => {
    const scan = baseScan();
    scan.traffic = {
      unencrypted: Array.from({ length: 10 }, () => ({ dest: "x", port: 80, protocol: "http" })),
    };
    const score = computeSecurityScore(scan);
    assert.equal(score, 9);
  });

  it("clamps score to 0 when many penalties stack", () => {
    const scan = baseScan();
    scan.security.firewall.enabled = false;                       // -2
    scan.security.vpn.active = false;                             // -1
    scan.network.dns.hijackTestResult = "intercepted";            // -2
    scan.network.dns.dnssecSupported = false;                     // -0.5
    scan.network.dns.anomalies = ["a"];                           // -0.5
    scan.security.kernelParams.ipForwarding = true;               // -0.5
    scan.security.kernelParams.icmpRedirects = true;              // -0.3
    scan.security.proxy.enabled = true;                           // -0.5
    scan.hiddenDevices = { suspectedCameras: [{ ip: "x" }] };    // -1
    scan.localServices = Array.from({ length: 6 }, () => ({ exposedToNetwork: true })); // -1.5
    scan.traffic = { unencrypted: Array.from({ length: 10 }, () => ({ dest: "x", port: 80, protocol: "http" })) }; // -1
    scan.intrusionIndicators = {
      arpAnomalies: [{ severity: "high" }, { severity: "high" }],
      suspiciousHosts: [{ severity: "high" }],
      scanDetection: [{ source: "x", type: "y", detail: "z" }],
    }; // -1 -0.5 -0.3 = -1.8
    const score = computeSecurityScore(scan);
    assert.equal(score, 0);
  });

  it("score never exceeds 10", () => {
    const score = computeSecurityScore(baseScan());
    assert.ok(score <= 10);
  });
});
