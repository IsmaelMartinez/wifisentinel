// src/commands/watch.ts — Continuous monitoring with configurable intervals
import type { Command } from "commander";
import { collectNetworkScan, type ScanOptions } from "../collector/index.js";
import { ScanEventEmitter } from "../collector/scan-events.js";
import { detectChanges } from "../analyser/diff.js";
import { computeSecurityScore } from "../analyser/score.js";
import { scoreAllStandards } from "../analyser/standards/index.js";
import { analyseAllPersonas } from "../analyser/personas/index.js";
import { analyseRF } from "../analyser/rf/index.js";
import { saveScan } from "../store/index.js";
import { renderWatchBaseline, renderWatchCycle } from "../reporter/watch.reporter.js";
import { initTelemetry, shutdownTelemetry } from "../telemetry/index.js";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";


function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function registerWatchCommand(program: Command): void {
  program
    .command("watch")
    .description("Continuously scan the network and alert on changes")
    .option("--interval <minutes>", "Scan interval in minutes", "5")
    .option("--skip-ports", "Skip port scanning")
    .option("--skip-speed", "Skip speed test")
    .option("--skip-traffic", "Skip traffic analysis")
    .option("--no-vendor-lookup", "Skip MAC vendor lookups")
    .option("--events", "Output NDJSON events to stdout")
    .option("--alert-new-hosts", "Alert on new hosts (default: true)", true)
    .option("--no-alert-new-hosts", "Disable alerts on new hosts")
    .option("--alert-dropped-hosts", "Alert on dropped hosts (default: true)", true)
    .option("--no-alert-dropped-hosts", "Disable alerts on dropped hosts")
    .option("--alert-security-change", "Alert on security posture changes (default: true)", true)
    .option("--no-alert-security-change", "Disable alerts on security posture changes")
    .option("--otel <exporter>", "OTEL exporter: console, otlp, none", "none")
    .option("--no-save", "Skip saving scan results to history")
    .option("-v, --verbose", "Verbose output")
    .option("--stealth", "Reduce network footprint: passive host discovery, randomised port timing, random DNS test domains, skip speed test")
    .action(async (opts) => {
      const parsed = parseFloat(opts.interval);
      const intervalMs = (Number.isNaN(parsed) ? 5 : Math.max(1, parsed)) * 60 * 1000;
      const useEvents = opts.events === true;

      initTelemetry({
        tracing: opts.otel as "console" | "otlp" | "none",
        metrics: opts.otel === "none" ? "none" : "console",
      });

      const scanOpts: ScanOptions = {
        skipPortScan: opts.skipPorts,
        skipTraffic: opts.skipTraffic || opts.stealth,
        skipSpeed: opts.skipSpeed || opts.stealth,
        skipVendorLookup: !opts.vendorLookup,
        verbose: opts.verbose,
        stealth: opts.stealth,
      };

      let running = true;
      let previousResult: NetworkScanResult | undefined;
      let cycle = 0;

      const shutdown = () => {
        console.error("\n[wifisentinel] Stopping after current scan completes...");
        running = false;
      };

      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);

      try {
        while (running) {
          cycle++;
          const emitter = new ScanEventEmitter();

          if (useEvents) {
            emitter.on("event", (e) => {
              process.stdout.write(emitter.toJSON(e) + "\n");
            });
            emitter.watchCycleStart(cycle);
          }

          scanOpts.emitter = emitter;

          if (opts.verbose && !useEvents) {
            console.error(`[wifisentinel] Starting scan cycle #${cycle}...`);
          }

          const result = await collectNetworkScan(scanOpts);
          const score = computeSecurityScore(result);

          // Save to history
          if (opts.save !== false) {
            const compliance = scoreAllStandards(result);
            const analysis = analyseAllPersonas(result);
            const rfAnalysis = analyseRF(result);
            saveScan(result, compliance, analysis, rfAnalysis);
          }

          if (cycle === 1) {
            // Baseline scan
            if (useEvents) {
              emitter.watchCycleComplete(cycle, 0);
            } else {
              console.log(renderWatchBaseline(result, score));
            }
          } else {
            // Compare with previous
            const allChanges = detectChanges(previousResult!, result);

            // Filter changes based on alert flags
            const filteredChanges = allChanges.filter((change) => {
              if (change.type === "host:joined" && !opts.alertNewHosts) return false;
              if (change.type === "host:left" && !opts.alertDroppedHosts) return false;
              if (
                (change.type === "security:changed" || change.type === "wifi:changed") &&
                !opts.alertSecurityChange
              )
                return false;
              return true;
            });

            if (useEvents) {
              for (const change of filteredChanges) {
                emitter.watchAlert(change);
              }
              emitter.watchCycleComplete(cycle, filteredChanges.length);
            } else {
              console.log(renderWatchCycle(cycle, result, score, filteredChanges));
            }
          }

          previousResult = result;

          if (!running) break;
          await sleep(intervalMs);
        }
      } catch (err) {
        if (!useEvents) {
          console.error("[wifisentinel] Watch failed:", err);
        }
        await shutdownTelemetry();
        process.exit(1);
      }
    });
}
