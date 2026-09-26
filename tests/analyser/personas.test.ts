import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  analyseAsCompliance,
  analyseAsNetEngineer,
  analyseAsRedTeam,
  consensusRating,
} from "../../src/analyser/personas/index.js";
import { cleanScan } from "./fixtures.js";

describe("consensusRating", () => {
  it("returns minimal for no ratings", () => {
    assert.equal(consensusRating([]), "minimal");
  });

  it("returns the mode", () => {
    assert.equal(consensusRating(["low", "low", "critical"]), "low");
  });

  it("breaks ties toward the higher severity", () => {
    assert.equal(consensusRating(["critical", "low"]), "critical");
    assert.equal(consensusRating(["low", "critical"]), "critical");
    assert.equal(consensusRating(["medium", "medium", "high", "high", "minimal"]), "high");
  });
});

describe("compliance audit-logging insight", () => {
  it("does not fire on a scan the toolchain cannot judge", () => {
    const toolchains: Array<Record<string, string | null>> = [{}, { packetAnalysis: "tshark" }, { packetAnalysis: null }];
    for (const toolchain of toolchains) {
      const scan = cleanScan();
      scan.meta.toolchain = toolchain;
      const ids = analyseAsCompliance(scan).insights.map((i) => i.id);
      assert.ok(!ids.includes("co-no-audit-logging"), JSON.stringify(toolchain));
    }
  });

  it("leaves a clean scan with no compliance insights", () => {
    assert.deepEqual(analyseAsCompliance(cleanScan()).insights, []);
  });
});

describe("fallback priority actions", () => {
  it("red-team does not recommend closing ports when the only insight is VPN-off", () => {
    const scan = cleanScan();
    scan.security.vpn.active = false;
    const analysis = analyseAsRedTeam(scan);
    assert.deepEqual(analysis.insights.map((i) => i.id), ["rt-vpn-inactive"]);
    assert.equal(analysis.priorityActions.length, 1);
    assert.doesNotMatch(analysis.priorityActions[0], /port/i);
    assert.match(analysis.priorityActions[0], /VPN/);
  });

  it("net-engineer does not recommend DNS work when the only insight is marginal SNR", () => {
    const scan = cleanScan();
    scan.wifi.snr = 12;
    const analysis = analyseAsNetEngineer(scan);
    assert.deepEqual(analysis.insights.map((i) => i.id), ["ne-fair-snr"]);
    assert.equal(analysis.priorityActions.length, 1);
    assert.doesNotMatch(analysis.priorityActions[0], /DNS/);
    assert.match(analysis.priorityActions[0], /SNR|signal|interference/i);
  });

  it("returns no actions when there are no insights", () => {
    assert.deepEqual(analyseAsRedTeam(cleanScan()).priorityActions, []);
    assert.deepEqual(analyseAsNetEngineer(cleanScan()).priorityActions, []);
  });
});
