// src/commands/scan.ts — `scan` and `analyse`: one live scan, analysed once,
// rendered and persisted from the same result.
import { writeFileSync } from "node:fs";
import type { Command } from "commander";
import { collectNetworkScan } from "../collector/index.js";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import { scoreAllStandards } from "../analyser/standards/index.js";
import { analyseAllPersonas } from "../analyser/personas/index.js";
import { analyseRF } from "../analyser/rf/index.js";
import type { ComplianceReport } from "../analyser/standards/types.js";
import type { FullAnalysis } from "../analyser/personas/types.js";
import type { RFAnalysis } from "../analyser/rf/types.js";
import { runScanWithProgress } from "../reporter/progress.renderer.js";
import { renderTerminalReport } from "../reporter/terminal.reporter.js";
import { renderFullAnalysisReport } from "../reporter/analysis.reporter.js";
import { renderJsonReport } from "../reporter/json.reporter.js";
import { saveScan } from "../store/index.js";
import { initTelemetry, shutdownTelemetry } from "../telemetry/index.js";
import {
  addScanOptions,
  outputFormatOption,
  telemetryOptions,
  toScanOptions,
  type ScanCliOptions,
} from "./options.js";

export interface ScanAnalysis {
  compliance: ComplianceReport;
  analysis: FullAnalysis;
  rfAnalysis: RFAnalysis;
}

export function computeAnalysis(result: NetworkScanResult): ScanAnalysis {
  return {
    compliance: scoreAllStandards(result),
    analysis: analyseAllPersonas(result),
    rfAnalysis: analyseRF(result),
  };
}

export interface ReportOptions {
  output: "terminal" | "json";
  analyse?: boolean;
  verbose?: boolean;
  save: boolean;
}

export interface ReportDeps {
  computeAnalysis: (result: NetworkScanResult) => ScanAnalysis;
  saveScan: typeof saveScan;
}

const defaultDeps: ReportDeps = { computeAnalysis, saveScan };

export function renderReport(
  result: NetworkScanResult,
  computed: ScanAnalysis,
  opts: Pick<ReportOptions, "output" | "analyse" | "verbose">,
): string {
  if (opts.output === "json") {
    return opts.analyse ? renderJsonReport(result, computed) : JSON.stringify(result, null, 2);
  }
  return opts.analyse
    ? renderFullAnalysisReport(result, computed, opts.verbose)
    : renderTerminalReport(result, computed.rfAnalysis);
}

/**
 * Analyses the scan once, renders it and saves it to history. Returns the
 * rendered report so the caller decides where it goes.
 */
export function reportAndSave(
  result: NetworkScanResult,
  opts: ReportOptions,
  deps: ReportDeps = defaultDeps,
): string {
  const computed = deps.computeAnalysis(result);
  const output = renderReport(result, computed, opts);
  if (opts.save) {
    deps.saveScan(result, computed.compliance, computed.analysis, computed.rfAnalysis);
  }
  return output;
}

type ScanCommandOptions = ScanCliOptions & {
  output: "terminal" | "json";
  file?: string;
  analyse?: boolean;
};

async function runScan(opts: ScanCommandOptions, label: string): Promise<void> {
  initTelemetry(telemetryOptions(opts));

  try {
    if (opts.verbose) {
      console.error(`[wifisentinel] Starting network ${label}...`);
    }
    if (opts.stealth && opts.verbose) {
      console.error("[wifisentinel] Stealth mode: passive discovery, randomised port timing, no speed test, no traffic capture");
    }
    const scanOpts = toScanOptions(opts);

    if (opts.events) {
      const { ScanEventEmitter } = await import("../collector/scan-events.js");
      const emitter = new ScanEventEmitter();
      emitter.on("event", (e) => {
        process.stdout.write(emitter.toJSON(e) + "\n");
      });
      const result = await collectNetworkScan({ ...scanOpts, emitter });
      if (opts.save) {
        const computed = computeAnalysis(result);
        saveScan(result, computed.compliance, computed.analysis, computed.rfAnalysis);
      }
      return;
    }

    const useProgress = opts.output !== "json" && process.stdout.isTTY;
    const result = useProgress
      ? await runScanWithProgress(scanOpts)
      : await collectNetworkScan(scanOpts);

    const output = reportAndSave(result, opts);

    if (opts.file) {
      writeFileSync(opts.file, output, "utf-8");
      console.error(`[wifisentinel] Report written to ${opts.file}`);
    } else {
      console.log(output);
    }
    if (opts.save && opts.verbose) {
      console.error("[wifisentinel] Scan saved to history.");
    }
  } catch (err) {
    console.error(`[wifisentinel] ${label[0].toUpperCase()}${label.slice(1)} failed:`, err);
    process.exitCode = 1;
  } finally {
    await shutdownTelemetry();
  }
}

export function registerScanCommands(program: Command): void {
  const scan = program
    .command("scan")
    .description("Scan the current network and produce a security report")
    .addOption(outputFormatOption())
    .option("-f, --file <path>", "Write output to file instead of stdout")
    .option("--analyse", "Include multi-persona analysis in the output");
  addScanOptions(scan).action((opts: ScanCommandOptions) => runScan(opts, "scan"));

  const analyse = program
    .command("analyse")
    .description("Scan the network and produce a multi-persona security analysis")
    .addOption(outputFormatOption())
    .option("-f, --file <path>", "Write output to file instead of stdout");
  addScanOptions(analyse).action((opts: ScanCommandOptions) =>
    runScan({ ...opts, analyse: true }, "analysis"),
  );
}
