import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  scoreIeee80211,
  scoreNist800153,
  scoreOwaspIot,
} from "../../src/analyser/standards/index.js";
import type { Finding, StandardScore } from "../../src/analyser/standards/index.js";
import { cleanScan } from "./fixtures.js";

function finding(score: StandardScore, id: string): Finding {
  const f = score.findings.find((x) => x.id === id);
  assert.ok(f, `finding ${id} missing`);
  return f;
}

function withProtocol(protocol: string) {
  const scan = cleanScan();
  scan.wifi.protocol = protocol;
  return scan;
}

describe("protocol generation checks", () => {
  // [protocol, OWASP-IoT-4 status, IEEE-1.1 status]
  const table: Array<[string, Finding["status"], Finding["status"]]> = [
    ["802.11a", "fail", "fail"],
    ["802.11b", "fail", "fail"],
    ["802.11g", "fail", "fail"],
    ["802.11n", "pass", "partial"],
    ["802.11ac", "pass", "partial"],
    ["802.11ax", "pass", "pass"],
    ["802.11be", "pass", "pass"],
    ["Unknown", "not-applicable", "not-applicable"],
  ];

  for (const [protocol, owasp, ieee] of table) {
    it(`${protocol}: OWASP-IoT-4 ${owasp}, IEEE-1.1 ${ieee}`, () => {
      const scan = withProtocol(protocol);
      assert.equal(finding(scoreOwaspIot(scan), "OWASP-IoT-4").status, owasp);
      assert.equal(finding(scoreIeee80211(scan), "IEEE-1.1").status, ieee);
    });
  }

  it("OWASP-IoT-4 still fails an unencrypted network on a modern PHY", () => {
    const scan = withProtocol("802.11ax");
    scan.wifi.security = "Open";
    assert.equal(finding(scoreOwaspIot(scan), "OWASP-IoT-4").status, "fail");
  });

  it("OWASP-IoT-4 fails an unencrypted network whose PHY is unknown", () => {
    const scan = withProtocol("Unknown");
    scan.wifi.security = "WEP";
    assert.equal(finding(scoreOwaspIot(scan), "OWASP-IoT-4").status, "fail");
  });
});

describe("NIST-W-5.1 security logging", () => {
  it("passes when packet analysis resolves to tshark", () => {
    const scan = cleanScan();
    scan.meta.toolchain = { packetAnalysis: "tshark" };
    assert.equal(finding(scoreNist800153(scan), "NIST-W-5.1").status, "pass");
  });

  it("passes when packet analysis resolves to tcpdump", () => {
    const scan = cleanScan();
    scan.meta.toolchain = { packetAnalysis: "tcpdump" };
    assert.equal(finding(scoreNist800153(scan), "NIST-W-5.1").status, "pass");
  });

  it("is partial when no packet capture tool resolved", () => {
    const scan = cleanScan();
    scan.meta.toolchain = { packetAnalysis: null };
    assert.equal(finding(scoreNist800153(scan), "NIST-W-5.1").status, "partial");
    scan.meta.toolchain = {};
    assert.equal(finding(scoreNist800153(scan), "NIST-W-5.1").status, "partial");
  });
});
