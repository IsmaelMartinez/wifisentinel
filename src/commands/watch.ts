// src/commands/watch.ts — Continuous monitoring with configurable intervals
import { setTimeout as delay } from "node:timers/promises";
import type { Command } from "commander";
import { collectNetworkScan } from "../collector/index.js";
import { ScanEventEmitter } from "../collector/scan-events.js";
import { detectChanges } from "../analyser/diff.js";
import { computeSecurityScore } from "../analyser/score.js";
import { saveScan } from "../store/index.js";
import { renderWatchBaseline, renderWatchCycle } from "../reporter/watch.reporter.js";
import { initTelemetry, shutdownTelemetry } from "../telemetry/index.js";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import { computeAnalysis } from "./scan.js";
import { addScanOptions, telemetryOptions, toScanOptions, type ScanCliOptions } from "./options.js";

/** Sleeps for `ms`, resolving early (without throwing) when `signal` aborts. */
export async function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  try {
    await delay(ms, undefined, { signal });
  } catch (err) {
    if (!signal.aborted) throw err;
  }
}

type WatchOptions = ScanCliOptions & {
  interval: string;
  alertNewHosts: boolean;
  alertDroppedHosts: boolean;
  alertSecurityChange: boolean;
};

export function registerWatchCommand(program: Command): void {
  const watch = program
    .command("watch")
    .description("Continuously scan the network and alert on changes")
    .option("--interval <minutes>", "Scan interval in minutes", "5")
    .option("--no-alert-new-hosts", "Disable alerts on new hosts")
    .option("--no-alert-dropped-hosts", "Disable alerts on dropped hosts")
    .option("--no-alert-security-change", "Disable alerts on security posture changes");

  addScanOptions(watch).action(async (opts: WatchOptions) => {
    const parsed = parseFloat(opts.interval);
    const intervalMs = (Number.isNaN(parsed) ? 5 : Math.max(1, parsed)) * 60 * 1000;
    const useEvents = opts.events === true;

    initTelemetry(telemetryOptions(opts));
    const scanOpts = toScanOptions(opts);

    const stop = new AbortController();
    let previousResult: NetworkScanResult | undefined;
    let cycle = 0;

    const shutdown = () => {
      if (stop.signal.aborted) {
        // Second signal: don't wait for the in-flight scan.
        process.exit(130);
      }
      console.error("\n[wifisentinel] Stopping (press Ctrl+C again to abort the current scan)...");
      stop.abort();
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);

    try {
      while (!stop.signal.aborted) {
        cycle++;
        const emitter = new ScanEventEmitter();

        if (useEvents) {
          emitter.on("event", (e) => {
            process.stdout.write(emitter.toJSON(e) + "\n");
          });
          emitter.watchCycleStart(cycle);
        }

        if (opts.verbose && !useEvents) {
          console.error(`[wifisentinel] Starting scan cycle #${cycle}...`);
        }

        const result = await collectNetworkScan({ ...scanOpts, emitter });
        const score = computeSecurityScore(result);

        if (opts.save) {
          const computed = computeAnalysis(result);
          saveScan(result, computed.compliance, computed.analysis, computed.rfAnalysis);
        }

        if (previousResult === undefined) {
          // Baseline scan
          if (useEvents) {
            emitter.watchCycleComplete(cycle, 0);
          } else {
            console.log(renderWatchBaseline(result, score));
          }
        } else {
          const filteredChanges = detectChanges(previousResult, result).filter((change) => {
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
        await abortableSleep(intervalMs, stop.signal);
      }
    } catch (err) {
      if (!useEvents) {
        console.error("[wifisentinel] Watch failed:", err);
      }
      process.exitCode = 1;
    } finally {
      process.off("SIGINT", shutdown);
      process.off("SIGTERM", shutdown);
      await shutdownTelemetry();
    }
  });
}
