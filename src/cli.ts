#!/usr/bin/env node
import { Command } from "commander";
import { collectNetworkScan } from "./collector/index.js";
import { renderTerminalReport } from "./reporter/terminal.reporter.js";
import { initTelemetry, shutdownTelemetry } from "./telemetry/index.js";

const program = new Command();

program
  .name("netaudit")
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
  .action(async (opts) => {
    initTelemetry({
      tracing: opts.otel as "console" | "otlp" | "none",
      metrics: opts.otel === "none" ? "none" : "console",
    });

    try {
      if (opts.verbose) {
        console.error("[netaudit] Starting network scan...");
      }

      const result = await collectNetworkScan({
        skipPortScan: opts.skipPorts,
        skipTraffic: opts.skipTraffic,
        skipSpeed: opts.skipSpeed,
        verbose: opts.verbose,
      });

      let output: string;
      if (opts.output === "json") {
        output = JSON.stringify(result, null, 2);
      } else {
        output = renderTerminalReport(result);
      }

      if (opts.file) {
        const { writeFileSync } = await import("node:fs");
        writeFileSync(opts.file, output, "utf-8");
        console.error(`[netaudit] Report written to ${opts.file}`);
      } else {
        console.log(output);
      }
    } catch (err) {
      console.error("[netaudit] Scan failed:", err);
      process.exit(1);
    } finally {
      await shutdownTelemetry();
    }
  });

program.parse();
