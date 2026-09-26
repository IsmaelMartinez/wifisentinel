import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Command } from "commander";
import {
  AndroidScanImport,
  androidImportToScanResult,
} from "../../src/collector/android-import.js";
import {
  computeAnalysis,
  registerScanCommands,
  reportAndSave,
  type ScanAnalysis,
} from "../../src/commands/scan.js";
import { registerWatchCommand, abortableSleep } from "../../src/commands/watch.js";
import { parsePositiveInt } from "../../src/commands/options.js";
import type { saveScan } from "../../src/store/index.js";

function makeScan() {
  return androidImportToScanResult(
    AndroidScanImport.parse({
      meta: { scanId: "spy00000-1111", timestamp: "2026-07-01T10:00:00.000Z", platform: "android" },
      wifi: { ssid: "TestNet", bssid: "aa:bb:cc:dd:ee:ff", security: "WPA2", signal: -50 },
      hosts: [{ ip: "192.168.1.10" }],
    }),
  );
}

function spies() {
  const calls = { compute: 0, saved: [] as Parameters<typeof saveScan>[] };
  let computed: ScanAnalysis | undefined;
  const deps = {
    computeAnalysis: (r: Parameters<typeof computeAnalysis>[0]) => {
      calls.compute++;
      computed = computeAnalysis(r);
      computed.analysis.consensusActions = ["SPY-MARKER action"];
      return computed;
    },
    saveScan: (...args: Parameters<typeof saveScan>) => {
      calls.saved.push(args);
    },
  };
  return { calls, deps, computed: () => computed! };
}

describe("scan pipeline", () => {
  for (const output of ["terminal", "json"] as const) {
    it(`computes analysis once and shares it between the ${output} reporter and the store`, () => {
      const result = makeScan();
      const { calls, deps, computed } = spies();

      const rendered = reportAndSave(result, { output, analyse: true, save: true }, deps);

      assert.equal(calls.compute, 1);
      assert.equal(calls.saved.length, 1);
      const [, compliance, analysis, rf] = calls.saved[0];
      assert.equal(compliance, computed().compliance);
      assert.equal(analysis, computed().analysis);
      assert.equal(rf, computed().rfAnalysis);
      assert.ok(rendered.includes("SPY-MARKER action"), "reporter used the shared analysis");
    });
  }

  it("still analyses once when not saving", () => {
    const { calls, deps } = spies();
    reportAndSave(makeScan(), { output: "terminal", save: false }, deps);
    assert.equal(calls.compute, 1);
    assert.equal(calls.saved.length, 0);
  });
});

describe("scan command options", () => {
  const program = new Command();
  registerScanCommands(program);
  registerWatchCommand(program);
  const cmd = (name: string) => program.commands.find(c => c.name() === name)!;
  const longFlags = (name: string) => new Set(cmd(name).options.map(o => o.long));

  it("scan, analyse and watch share the live-scan options", () => {
    for (const flag of ["--events", "--monitor-interface", "--traffic-duration", "--stealth", "--no-save"]) {
      for (const name of ["scan", "analyse", "watch"]) {
        assert.ok(longFlags(name).has(flag), `${name} is missing ${flag}`);
      }
    }
  });

  it("help output shows no duplicate defaults", () => {
    for (const name of ["scan", "analyse", "watch"]) {
      const help = cmd(name).helpInformation();
      assert.ok(!/\(default: [^)]*\)\s*\(default:/.test(help), `${name} help repeats a default`);
    }
    const watchFlags = cmd("watch").options.map(o => o.long);
    assert.ok(!watchFlags.includes("--alert-new-hosts"));
    assert.ok(watchFlags.includes("--no-alert-new-hosts"));
  });

  it("validates --otel against the known exporters on every command that accepts it", () => {
    for (const name of ["scan", "analyse", "watch"]) {
      const otel = cmd(name).options.find(o => o.long === "--otel")!;
      assert.deepEqual(otel.argChoices, ["console", "otlp", "none"], name);
      assert.equal(otel.defaultValue, "none");
    }
  });

  it("rejects non-positive or non-numeric counts", () => {
    assert.equal(parsePositiveInt("5"), 5);
    for (const bad of ["0", "abc", "-3", "2.5"]) {
      assert.throws(() => parsePositiveInt(bad));
    }
  });
});

describe("watch shutdown", () => {
  it("abortable sleep returns within a second of abort", async () => {
    const stop = new AbortController();
    const started = Date.now();
    setTimeout(() => stop.abort(), 20);
    await abortableSleep(5 * 60 * 1000, stop.signal);
    assert.ok(Date.now() - started < 1000);
  });
});
