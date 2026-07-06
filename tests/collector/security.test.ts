import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  securityFamily,
  securityMode,
  normaliseSecurity,
  securityStrength,
  isWeakerSecurity,
  isWeakSecurity,
  securityChanged,
} from "../../src/collector/schema/security.js";

describe("securityFamily", () => {
  it("classifies macOS system_profiler labels", () => {
    assert.equal(securityFamily("WPA2 Personal"), "wpa2");
    assert.equal(securityFamily("WPA3 Personal"), "wpa3");
    assert.equal(securityFamily("WPA2/WPA3 Personal"), "wpa2/wpa3");
    assert.equal(securityFamily("WPA3 Transitional"), "wpa2/wpa3");
    assert.equal(securityFamily("WPA2 Enterprise"), "wpa2");
    assert.equal(securityFamily("None"), "open");
    assert.equal(securityFamily("WEP"), "wep");
    assert.equal(securityFamily("Enhanced Open"), "owe");
  });

  it("classifies nmcli labels", () => {
    assert.equal(securityFamily("WPA2"), "wpa2");
    assert.equal(securityFamily("WPA1 WPA2"), "wpa/wpa2");
    assert.equal(securityFamily("WPA2 WPA3"), "wpa2/wpa3");
    assert.equal(securityFamily("WPA2 802.1X"), "wpa2");
    assert.equal(securityFamily("--"), "open");
  });

  it("classifies iw-fallback labels", () => {
    assert.equal(securityFamily("WPA/WPA2"), "wpa/wpa2");
    assert.equal(securityFamily("WPA"), "wpa");
    assert.equal(securityFamily("Open"), "open");
  });

  it("classifies the Android companion's coarse labels", () => {
    assert.equal(securityFamily("WPA3"), "wpa3");
    assert.equal(securityFamily("WPA2"), "wpa2");
    assert.equal(securityFamily("WPA"), "wpa");
    assert.equal(securityFamily("WEP"), "wep");
    assert.equal(securityFamily("Open"), "open");
    assert.equal(securityFamily("unknown"), "unknown");
  });

  it("maps sentinels and unrecognised strings to unknown", () => {
    assert.equal(securityFamily("Unknown"), "unknown");
    assert.equal(securityFamily(""), "unknown");
    assert.equal(securityFamily("FutureProto9000"), "unknown");
  });
});

describe("securityMode", () => {
  it("detects modes across vocabularies", () => {
    assert.equal(securityMode("WPA2 Personal"), "Personal");
    assert.equal(securityMode("WPA2-PSK"), "Personal");
    assert.equal(securityMode("WPA3 SAE"), "Personal");
    assert.equal(securityMode("WPA2 Enterprise"), "Enterprise");
    assert.equal(securityMode("WPA2 802.1X"), "Enterprise");
    assert.equal(securityMode("WPA2-EAP"), "Enterprise");
  });

  it("returns undefined when the source is coarse", () => {
    assert.equal(securityMode("WPA2"), undefined);
    assert.equal(securityMode("Open"), undefined);
    assert.equal(securityMode("unknown"), undefined);
  });
});

describe("normaliseSecurity", () => {
  it("keeps canonical macOS labels stable", () => {
    assert.equal(normaliseSecurity("WPA2 Personal"), "WPA2 Personal");
    assert.equal(normaliseSecurity("WPA3 Enterprise"), "WPA3 Enterprise");
    assert.equal(normaliseSecurity("WPA2/WPA3 Personal"), "WPA2/WPA3 Personal");
  });

  it("folds every source's open/none spelling into Open", () => {
    assert.equal(normaliseSecurity("None"), "Open");
    assert.equal(normaliseSecurity("Open"), "Open");
    assert.equal(normaliseSecurity("--"), "Open");
  });

  it("rewrites tool-specific spellings into the canonical vocabulary", () => {
    assert.equal(normaliseSecurity("WPA1 WPA2"), "WPA/WPA2");
    assert.equal(normaliseSecurity("WPA2 802.1X"), "WPA2 Enterprise");
    assert.equal(normaliseSecurity("WPA3 Transitional"), "WPA2/WPA3");
    assert.equal(normaliseSecurity("wpa2-psk"), "WPA2 Personal");
  });

  it("leaves the phone's coarse labels mode-less rather than fabricating a mode", () => {
    assert.equal(normaliseSecurity("WPA2"), "WPA2");
    assert.equal(normaliseSecurity("WPA3"), "WPA3");
  });

  it("passes unrecognised strings through trimmed", () => {
    assert.equal(normaliseSecurity("unknown"), "unknown");
    assert.equal(normaliseSecurity("  FutureProto9000  "), "FutureProto9000");
  });
});

describe("securityStrength / isWeakerSecurity", () => {
  it("orders families weakest to strongest", () => {
    const ordered = ["Open", "WEP", "Enhanced Open", "WPA", "WPA/WPA2", "WPA2", "WPA2/WPA3", "WPA3"];
    for (let i = 1; i < ordered.length; i++) {
      assert.ok(
        securityStrength(ordered[i - 1]) < securityStrength(ordered[i]),
        `${ordered[i - 1]} should rank below ${ordered[i]}`
      );
    }
  });

  it("compares across vocabularies (the imported-scan evil-twin case)", () => {
    // Phone-labelled current network vs phone-labelled open evil twin.
    assert.equal(isWeakerSecurity("Open", "WPA2"), true);
    // Mixed vocabularies in either direction.
    assert.equal(isWeakerSecurity("Open", "WPA2 Personal"), true);
    assert.equal(isWeakerSecurity("WEP", "WPA2"), true);
    assert.equal(isWeakerSecurity("WPA2", "WPA2 Personal"), false);
    assert.equal(isWeakerSecurity("WPA2 Personal", "WPA2"), false);
  });

  it("treats an Enterprise -> Personal twin as weaker, but never infers a missing mode", () => {
    assert.equal(isWeakerSecurity("WPA2 Personal", "WPA2 Enterprise"), true);
    assert.equal(isWeakerSecurity("WPA2 Enterprise", "WPA2 Personal"), false);
    // The phone's coarse "WPA2" doesn't know its mode — not a downgrade.
    assert.equal(isWeakerSecurity("WPA2", "WPA2 Enterprise"), false);
  });

  it("refuses to compare unknowns", () => {
    assert.equal(securityStrength("unknown"), -1);
    assert.equal(isWeakerSecurity("unknown", "WPA3"), false);
    assert.equal(isWeakerSecurity("Open", "unknown"), false);
  });
});

describe("isWeakSecurity", () => {
  it("flags open, WEP, and WPA1-only as weak in any vocabulary", () => {
    for (const s of ["Open", "None", "WEP", "WPA", "WPA Personal", "--"]) {
      assert.equal(isWeakSecurity(s), true, `${s} should be weak`);
    }
  });

  it("does not flag encrypted-modern or unmeasured labels", () => {
    for (const s of ["WPA2", "WPA2 Personal", "WPA/WPA2", "WPA3", "unknown", "Unknown"]) {
      assert.equal(isWeakSecurity(s), false, `${s} should not be weak`);
    }
  });
});

describe("securityChanged", () => {
  it("stays quiet when a coarse label meets a mode-qualified label of the same family", () => {
    // The rf --compare cross-source case: phone-imported baseline vs macOS current.
    assert.equal(securityChanged("WPA2 Personal", "WPA2"), false);
    assert.equal(securityChanged("WPA2", "WPA2 Personal"), false);
    assert.equal(securityChanged("WPA3", "WPA3 Personal"), false);
  });

  it("reports family changes across vocabularies", () => {
    assert.equal(securityChanged("Open", "WPA2"), true);
    assert.equal(securityChanged("WPA2 Personal", "WPA3"), true);
  });

  it("reports mode changes only when both sides state one", () => {
    assert.equal(securityChanged("WPA2 Personal", "WPA2 Enterprise"), true);
    assert.equal(securityChanged("WPA2", "WPA2 Enterprise"), false);
  });

  it("never reports against an unknown side", () => {
    assert.equal(securityChanged("unknown", "WPA2"), false);
    assert.equal(securityChanged("WPA2", "Unknown"), false);
  });
});
