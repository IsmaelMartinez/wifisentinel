#!/usr/bin/env node
import { Command } from "commander";
import { collectNetworkScan } from "./collector/index.js";
import { renderTerminalReport } from "./reporter/terminal.reporter.js";
import { renderAnalysisReport } from "./reporter/analysis.reporter.js";
import { renderJsonReport } from "./reporter/json.reporter.js";
import { initTelemetry, shutdownTelemetry } from "./telemetry/index.js";
import { registerTVCommands } from "./tools/tv/tv-commands.js";
import { registerHistoryCommand } from "./commands/history.js";
import { registerDiffCommand } from "./commands/diff.js";
import { registerTrendCommand } from "./commands/trend.js";
import { registerScheduleCommand } from "./commands/schedule.js";
import { registerRFCommand } from "./commands/rf.js";
import { registerExportCommand } from "./commands/export.js";
import { registerReconCommand } from "./commands/recon.js";
import { registerReconHistoryCommand } from "./commands/recon-history.js";
import { saveScan } from "./store/index.js";
import { analyseRF } from "./analyser/rf/index.js";
import { scoreAllStandards } from "./analyser/standards/index.js";
import { analyseAllPersonas } from "./analyser/personas/index.js";

const program = new Command();

program
  .name("wifisentinel")
  .description("Multi-persona WiFi/network security analyser")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan the current network and produce a security report")
  .option(
    "-o, --output <format>",
    "Output format: terminal, json",
    "terminal"
  )
  .option("-f, --file <path>", "Write output to file instead of stdout")
  .option("--skip-ports", "Skip port scanning on discovered hosts")
  .option("--skip-traffic", "Skip traffic analysis")
  .option("--skip-speed", "Skip speed test")
  .option("--otel <exporter>", "OTEL exporter: console, otlp, none", "none")
  .option("-v, --verbose", "Verbose output to stderr")
  .option("--analyse", "Include multi-persona analysis in the output")
  .option("--no-save", "Skip saving scan to history")
  .action(async (opts) => {
    initTelemetry({
      tracing: opts.otel as "console" | "otlp" | "none",
      metrics: opts.otel === "none" ? "none" : "console",
    });

    try {
      if (opts.verbose) {
        console.error("[wifisentinel] Starting network scan...");
      }

      const result = await collectNetworkScan({
        skipPortScan: opts.skipPorts,
        skipTraffic: opts.skipTraffic,
        skipSpeed: opts.skipSpeed,
        verbose: opts.verbose,
      });

      let output: string;
      if (opts.output === "json") {
        output = opts.analyse
          ? renderJsonReport(result)
          : JSON.stringify(result, null, 2);
      } else {
        output = opts.analyse
          ? renderAnalysisReport(result, { verbose: opts.verbose })
          : renderTerminalReport(result);
      }

      if (opts.file) {
        const { writeFileSync } = await import("node:fs");
        writeFileSync(opts.file, output, "utf-8");
        console.error(`[wifisentinel] Report written to ${opts.file}`);
      } else {
        console.log(output);
      }

      if (opts.save) {
        const compliance = scoreAllStandards(result);
        const analysis = analyseAllPersonas(result);
        const rfAnalysis = analyseRF(result);
        saveScan(result, compliance, analysis, rfAnalysis);
        if (opts.verbose) {
          console.error("[wifisentinel] Scan saved to history.");
        }
      }
    } catch (err) {
      console.error("[wifisentinel] Scan failed:", err);
      process.exit(1);
    } finally {
      await shutdownTelemetry();
    }
  });

program
  .command("analyse")
  .description("Scan the network and produce a multi-persona security analysis")
  .option(
    "-o, --output <format>",
    "Output format: terminal, json",
    "terminal"
  )
  .option("-f, --file <path>", "Write output to file instead of stdout")
  .option("--skip-ports", "Skip port scanning on discovered hosts")
  .option("--skip-traffic", "Skip traffic analysis")
  .option("--skip-speed", "Skip speed test")
  .option("--otel <exporter>", "OTEL exporter: console, otlp, none", "none")
  .option("-v, --verbose", "Show detailed findings per standard/persona")
  .option("--no-save", "Skip saving scan to history")
  .action(async (opts) => {
    initTelemetry({
      tracing: opts.otel as "console" | "otlp" | "none",
      metrics: opts.otel === "none" ? "none" : "console",
    });

    try {
      if (opts.verbose) {
        console.error("[wifisentinel] Starting network scan + analysis...");
      }

      const result = await collectNetworkScan({
        skipPortScan: opts.skipPorts,
        skipTraffic: opts.skipTraffic,
        skipSpeed: opts.skipSpeed,
        verbose: opts.verbose,
      });

      let output: string;
      if (opts.output === "json") {
        output = renderJsonReport(result);
      } else {
        output = renderAnalysisReport(result, { verbose: opts.verbose });
      }

      if (opts.file) {
        const { writeFileSync } = await import("node:fs");
        writeFileSync(opts.file, output, "utf-8");
        console.error(`[wifisentinel] Report written to ${opts.file}`);
      } else {
        console.log(output);
      }

      if (opts.save) {
        const compliance = scoreAllStandards(result);
        const analysis = analyseAllPersonas(result);
        const rfAnalysis = analyseRF(result);
        saveScan(result, compliance, analysis, rfAnalysis);
        if (opts.verbose) {
          console.error("[wifisentinel] Scan saved to history.");
        }
      }
    } catch (err) {
      console.error("[wifisentinel] Analysis failed:", err);
      process.exit(1);
    } finally {
      await shutdownTelemetry();
    }
  });

registerTVCommands(program);
registerHistoryCommand(program);
registerDiffCommand(program);
registerTrendCommand(program);
registerScheduleCommand(program);
registerRFCommand(program);
registerExportCommand(program);
registerReconCommand(program);
registerReconHistoryCommand(program);

program.parse();
