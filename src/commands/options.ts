// src/commands/options.ts — option sets and parsers shared across commands.
import { InvalidArgumentError, Option, type Command } from "commander";
import type { ScanOptions } from "../collector/index.js";

export function parsePositiveInt(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) {
    throw new InvalidArgumentError("Must be a positive integer.");
  }
  return n;
}

export function outputFormatOption(): Option {
  return new Option("-o, --output <format>", "Output format")
    .choices(["terminal", "json"])
    .default("terminal");
}

/** Options that control a live network scan, shared by scan, analyse and watch. */
export function addScanOptions(cmd: Command): Command {
  return cmd
    .option("--skip-ports", "Skip port scanning on discovered hosts")
    .option("--skip-traffic", "Skip traffic analysis")
    .option("--traffic-duration <seconds>", "Traffic capture duration in seconds (default 8)", parsePositiveInt)
    .option("--skip-speed", "Skip speed test")
    .option("--no-vendor-lookup", "Skip the gateway MAC vendor lookup (bundled OUI database; no network calls)")
    .option("--monitor-interface <iface>", "Enable deauth detection via monitor mode on this interface")
    .option("--stealth", "Reduce network footprint: passive host discovery, randomised port timing, random DNS test domains, skip speed test")
    .option("--events", "Output scan events as NDJSON instead of a report")
    .option("--no-save", "Skip saving scan results to history")
    .addOption(
      new Option("--otel <exporter>", "OTEL exporter")
        .choices(["console", "otlp", "none"])
        .default("none"),
    )
    .option("-v, --verbose", "Verbose output to stderr and detailed findings in reports");
}

export interface ScanCliOptions {
  skipPorts?: boolean;
  skipTraffic?: boolean;
  trafficDuration?: number;
  skipSpeed?: boolean;
  vendorLookup: boolean;
  monitorInterface?: string;
  stealth?: boolean;
  events?: boolean;
  save: boolean;
  otel: "console" | "otlp" | "none";
  verbose?: boolean;
}

export function toScanOptions(opts: ScanCliOptions): ScanOptions {
  return {
    skipPortScan: opts.skipPorts,
    skipTraffic: opts.skipTraffic || opts.stealth,
    trafficDuration: opts.trafficDuration,
    skipSpeed: opts.skipSpeed || opts.stealth,
    skipVendorLookup: !opts.vendorLookup,
    verbose: opts.verbose,
    stealth: opts.stealth,
    monitorInterface: opts.monitorInterface,
  };
}

export function telemetryOptions(opts: Pick<ScanCliOptions, "otel">) {
  return {
    tracing: opts.otel,
    metrics: opts.otel === "none" ? ("none" as const) : ("console" as const),
  };
}
