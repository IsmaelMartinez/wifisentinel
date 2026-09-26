import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyseAllPersonas, PERSONAS } from "../../src/analyser/personas/index.js";
import {
  FullAnalysis,
  actionsFor,
  consensusActions,
  type Insight,
  type PersonaSpec,
} from "../../src/analyser/personas/types.js";
import { scoreAllStandards } from "../../src/analyser/standards/index.js";
import { ComplianceReport } from "../../src/analyser/standards/types.js";
import { analyseReconAllPersonas } from "../../src/analyser/recon-personas.js";
import type { NetworkScanResult } from "../../src/collector/schema/scan-result.js";
import { cleanScan, noisyScan, weakRecon } from "./fixtures.js";

/** Scans that between them raise every Wi-Fi persona insight. */
function scans(): NetworkScanResult[] {
  const firewallOn = noisyScan();
  firewallOn.security.firewall.enabled = true;
  firewallOn.wifi.snr = 12;
  firewallOn.intrusionIndicators = undefined;
  const crowded = cleanScan();
  crowded.network.hosts = Array.from({ length: 21 }, (_, i) => ({ ip: `10.0.0.${i}`, mac: `m${i}`, vendor: "V" }));
  return [noisyScan(), firewallOn, crowded];
}

function insight(id: string, severity: Insight["severity"], recommendation = `fix ${id}`): Insight {
  return {
    id,
    title: id,
    severity,
    category: "test",
    description: "",
    technicalDetail: "",
    recommendation,
    affectedAssets: [],
    references: [],
  };
}

const spec = (actions: PersonaSpec["actions"], fallback?: boolean): PersonaSpec => ({
  persona: "red-team",
  displayName: "Test",
  perspective: "",
  actions,
  fallback,
});

describe("persona references", () => {
  it("every Wi-Fi persona reference resolves to a real standards Finding.id", () => {
    const findingIds = new Set(scoreAllStandards(cleanScan()).standards.flatMap((s) => s.findings.map((f) => f.id)));
    const seen = new Set<string>();
    for (const scan of scans()) {
      for (const analysis of analyseAllPersonas(scan).analyses) {
        for (const i of analysis.insights) {
          seen.add(i.id.replace(/-\d+\.\d+\.\d+\.\d+$/, ""));
          for (const ref of i.references) {
            assert.ok(findingIds.has(ref), `${i.id} references unknown finding ${ref}`);
          }
        }
      }
    }
    // Guard against the fixtures silently stopping to exercise the personas.
    assert.equal(seen.size, 62, "fixtures no longer raise every Wi-Fi persona insight");
  });
});

describe("actionsFor", () => {
  it("returns mapped actions in map order, defaulting text to the recommendation", () => {
    const insights = [insight("b", "high"), insight("a", "low")];
    const actions = actionsFor(insights, spec({ a: { key: "ka" }, b: { key: "kb", text: "Do B" } }));
    assert.deepEqual(actions, ["fix a", "Do B"]);
  });

  it("never turns a passing (info) insight into an action", () => {
    assert.deepEqual(actionsFor([insight("a", "info")], spec({ a: { key: "ka" } })), []);
  });

  it("falls back to the most severe insight only when the persona opts in", () => {
    const insights = [insight("x", "low"), insight("y", "high")];
    assert.deepEqual(actionsFor(insights, spec({})), []);
    assert.deepEqual(actionsFor(insights, spec({}, true)), ["fix y"]);
  });

  it("caps priority actions at five", () => {
    const ids = ["a", "b", "c", "d", "e", "f"];
    const map = Object.fromEntries(ids.map((id) => [id, { key: id }]));
    assert.equal(actionsFor(ids.map((id) => insight(id, "high")), spec(map)).length, 5);
  });

  it("every persona action map only names insights that persona can raise", () => {
    const raised = new Map<string, Set<string>>();
    for (const scan of scans()) {
      for (const a of analyseAllPersonas(scan).analyses) {
        const set = raised.get(a.persona) ?? new Set();
        a.insights.forEach((i) => set.add(i.id));
        raised.set(a.persona, set);
      }
    }
    for (const [s] of PERSONAS) {
      for (const id of Object.keys(s.actions)) {
        assert.ok(raised.get(s.persona)?.has(id), `${s.persona} maps unknown insight ${id}`);
      }
    }
  });
});

describe("consensusActions", () => {
  it("merges different wordings of the same remediation and ranks by persona count", () => {
    const merged = consensusActions([
      [{ key: "dns", text: "Switch to encrypted DNS" }, { key: "fw", text: "Enable the firewall" }],
      [{ key: "dns", text: "Deploy DoH/DoT" }],
      [{ key: "dns", text: "Enable encrypted DNS" }, { key: "dns", text: "Hide DNS queries" }],
    ]);
    assert.deepEqual(merged, ["Switch to encrypted DNS", "Enable the firewall"]);
  });

  it("gives one Wi-Fi consensus action per remediation", () => {
    const actions = analyseAllPersonas(noisyScan()).consensusActions;
    assert.equal(actions.filter((a) => /encrypted DNS/i.test(a)).length, 1);
    assert.equal(actions.filter((a) => /firewall/i.test(a)).length, 1);
    assert.equal(new Set(actions).size, actions.length);
  });

  it("gives one recon consensus action per remediation", () => {
    const actions = analyseReconAllPersonas(weakRecon()).consensusActions;
    assert.equal(actions.filter((a) => /HSTS|Strict-Transport-Security/.test(a)).length, 1);
    assert.equal(actions.filter((a) => /certificate/i.test(a)).length, 1);
  });
});

describe("typed rating and grade fields", () => {
  it("rejects a consensus rating outside RiskRating", () => {
    const analysis = analyseAllPersonas(cleanScan());
    assert.equal(FullAnalysis.safeParse(analysis).success, true);
    assert.equal(FullAnalysis.safeParse({ ...analysis, consensusRating: "severe" }).success, false);
  });

  it("rejects an overall grade outside Grade", () => {
    const report = scoreAllStandards(cleanScan());
    assert.equal(ComplianceReport.safeParse(report).success, true);
    assert.equal(ComplianceReport.safeParse({ ...report, overallGrade: "E" }).success, false);
  });
});
