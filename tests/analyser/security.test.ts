import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  classifySecurity,
  isSecurityDowngrade,
  type WpaTier,
} from "../../src/analyser/security.js";
import {
  analyseAsCompliance,
  analyseAsPrivacy,
  analyseAsRedTeam,
} from "../../src/analyser/personas/index.js";
import {
  scoreCisWireless,
  scoreIeee80211,
  scoreNist800153,
} from "../../src/analyser/standards/index.js";
import type { StandardScore } from "../../src/analyser/standards/index.js";
import { cleanScan } from "./fixtures.js";

// [source, raw label, family, level, weak, unencrypted, WPA tier]
type Row = [string, string, string, number, boolean, boolean, WpaTier];
const TABLE: Row[] = [
  ["macOS", "WPA3 Personal", "wpa3", 7, false, false, "wpa3"],
  ["macOS", "WPA3 Enterprise", "wpa3", 7, false, false, "wpa3"],
  ["macOS", "WPA3 Transitional", "wpa2/wpa3", 6, false, false, "wpa3"],
  ["macOS", "WPA2/WPA3 Personal", "wpa2/wpa3", 6, false, false, "wpa3"],
  ["macOS", "WPA2 Personal", "wpa2", 5, false, false, "wpa2"],
  ["macOS", "WPA2 Enterprise", "wpa2", 5, false, false, "wpa2"],
  ["macOS", "WPA/WPA2 Personal", "wpa/wpa2", 4, false, false, "wpa2"],
  ["macOS", "WEP", "wep", 1, true, true, "below"],
  ["macOS", "None", "open", 0, true, true, "below"],
  ["macOS", "Enhanced Open", "owe", 2, false, false, "below"],
  ["nmcli", "WPA3", "wpa3", 7, false, false, "wpa3"],
  ["nmcli", "WPA2 WPA3", "wpa2/wpa3", 6, false, false, "wpa3"],
  ["nmcli", "WPA2", "wpa2", 5, false, false, "wpa2"],
  ["nmcli", "WPA1 WPA2", "wpa/wpa2", 4, false, false, "wpa2"],
  ["nmcli", "WPA1", "wpa", 3, true, false, "below"],
  ["nmcli", "OWE", "owe", 2, false, false, "below"],
  ["nmcli", "--", "open", 0, true, true, "below"],
  ["iw", "WPA2", "wpa2", 5, false, false, "wpa2"],
  ["iw", "WPA/WPA2", "wpa/wpa2", 4, false, false, "wpa2"],
  ["iw", "WPA", "wpa", 3, true, false, "below"],
  ["iw", "Open", "open", 0, true, true, "below"],
  ["sentinel", "Unknown", "unknown", -1, false, false, "unknown"],
  ["sentinel", "unknown", "unknown", -1, false, false, "unknown"],
];

const TIER_STATUS: Record<WpaTier, string> = {
  wpa3: "pass",
  wpa2: "partial",
  below: "fail",
  unknown: "not-applicable",
};

function status(score: StandardScore, id: string): string | undefined {
  return score.findings.find((f) => f.id === id)?.status;
}

describe("classifySecurity", () => {
  for (const [source, raw, family, level, weak, unencrypted, wpaTier] of TABLE) {
    it(`${source} "${raw}"`, () => {
      const c = classifySecurity(raw);
      assert.deepEqual(
        { family: c.family, level: c.level, weak: c.weak, unencrypted: c.unencrypted, wpaTier: c.wpaTier },
        { family, level, weak, unencrypted, wpaTier },
      );
    });
  }
});

describe("classifySecurity mode", () => {
  it("reads the authentication mode when the label states one", () => {
    assert.equal(classifySecurity("WPA2 Enterprise").mode, "Enterprise");
    assert.equal(classifySecurity("WPA3 Personal").mode, "Personal");
    assert.equal(classifySecurity("WPA2").mode, undefined);
  });
});

describe("personas and standards agree with classifySecurity", () => {
  for (const [source, raw, , , weak, , wpaTier] of TABLE) {
    it(`${source} "${raw}"`, () => {
      const scan = cleanScan();
      scan.wifi.security = raw;

      assert.equal(
        analyseAsRedTeam(scan).insights.some((i) => i.id === "rt-weak-wifi-encryption"),
        weak,
      );
      assert.equal(
        analyseAsCompliance(scan).insights.some((i) => i.id === "co-weak-encryption"),
        weak,
      );
      assert.equal(
        analyseAsPrivacy(scan).insights.some((i) => i.id === "pr-weak-wifi-privacy"),
        weak,
      );

      const expected = TIER_STATUS[wpaTier];
      assert.equal(status(scoreCisWireless(scan), "CIS-W-1.1"), expected);
      assert.equal(status(scoreNist800153(scan), "NIST-W-2.1"), expected);
      assert.equal(status(scoreIeee80211(scan), "IEEE-4.1"), expected);
    });
  }
});

describe("isSecurityDowngrade", () => {
  it("treats WPA3 -> WPA2 as a downgrade", () => {
    assert.equal(isSecurityDowngrade("WPA3 Personal", "WPA2 Personal"), true);
  });

  it("does not treat an upgrade or an unknown side as a downgrade", () => {
    assert.equal(isSecurityDowngrade("WPA2 Personal", "WPA3 Personal"), false);
    assert.equal(isSecurityDowngrade("unknown", "WEP"), false);
    assert.equal(isSecurityDowngrade("WPA3 Personal", "Unknown"), false);
  });

  it("treats Enterprise -> Personal as a downgrade", () => {
    assert.equal(isSecurityDowngrade("WPA2 Enterprise", "WPA3 Personal"), true);
  });
});
