// src/commands/rf.ts
import chalk from "chalk";
import type { Command } from "commander";
import { scanWifi } from "../collector/scanners/wifi.scanner.js";
import { analyseRF } from "../analyser/rf/index.js";
import { renderRFReport } from "../reporter/rf.reporter.js";
import { loadScan, listScans, type IndexEntry } from "../store/index.js";
import { pad } from "../reporter/render-helpers.js";

function renderSignalTrend(entries: IndexEntry[], scans: Array<{ wifi: { signal: number; snr: number; txRate: number; channel: number; nearbyNetworks: { length: number } } }>): string {
  const lines: string[] = [];

  lines.push(chalk.bold("  WiFi Signal Trends"));
  lines.push("");

  const header =
    pad(chalk.bold("DATE"), 16) +
    pad(chalk.bold("SIGNAL"), 9) +
    pad(chalk.bold("SNR"), 6) +
    pad(chalk.bold("TX RATE"), 10) +
    pad(chalk.bold("CH"), 5) +
    chalk.bold("NEARBY");
  lines.push("  " + header);
  lines.push("  " + chalk.dim("─".repeat(55)));

  // Render oldest first
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i];
    const w = scans[i].wifi;
    const date = new Date(e.timestamp).toLocaleDateString("en-GB", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
    lines.push("  " +
      pad(chalk.dim(date), 16) +
      pad(String(w.signal), 9) +
      pad(String(w.snr), 6) +
      pad(w.txRate + " Mbps", 10) +
      pad(String(w.channel), 5) +
      String(w.nearbyNetworks.length),
    );
  }

  // Summary line
  if (scans.length >= 2) {
    const first = scans[scans.length - 1].wifi;
    const last = scans[0].wifi;
    const signalDir = last.signal > first.signal ? chalk.green("improving") : last.signal < first.signal ? chalk.red("declining") : chalk.yellow("stable");
    const snrDir = last.snr > first.snr ? chalk.green("improving") : last.snr < first.snr ? chalk.red("declining") : chalk.yellow("stable");
    const nearbyFirst = scans[scans.length - 1].wifi.nearbyNetworks.length;
    const nearbyLast = scans[0].wifi.nearbyNetworks.length;
    const nearbyDir = nearbyLast > nearbyFirst ? chalk.yellow("growing") : nearbyLast < nearbyFirst ? chalk.green("shrinking") : chalk.dim("stable");

    lines.push("  " + chalk.dim("─".repeat(55)));
    lines.push(`  Signal: ${signalDir}  SNR: ${snrDir}  Nearby APs: ${nearbyDir}`);
  }

  return lines.join("\n");
}

export function registerRFCommand(program: Command): void {
  program
    .command("rf")
    .description("Analyse WiFi RF environment (channel map, rogue APs)")
    .option("--json", "Output as JSON")
    .option("--compare <scanId>", "Compare against a stored scan")
    .option("--trend", "Show WiFi signal trends over time")
    .option("-n, --limit <count>", "Number of scans for --trend", "10")
    .action(async (opts) => {
      try {
        // Trend mode: read from store, no live scan
        if (opts.trend) {
          const entries = listScans({ limit: parseInt(opts.limit, 10) });
          if (entries.length === 0) {
            console.log(chalk.dim("No scans in history. Run 'wifisentinel scan' first."));
            return;
          }
          const scans = entries.map(e => {
            const stored = loadScan(e.scanId);
            return stored.scan;
          });

          if (opts.json) {
            const data = entries.map((e, i) => ({
              scanId: e.scanId,
              timestamp: e.timestamp,
              signal: scans[i].wifi.signal,
              snr: scans[i].wifi.snr,
              txRate: scans[i].wifi.txRate,
              channel: scans[i].wifi.channel,
              nearbyNetworks: scans[i].wifi.nearbyNetworks.length,
            }));
            console.log(JSON.stringify(data, null, 2));
            return;
          }

          console.log(renderSignalTrend(entries, scans));
          return;
        }

        // Live RF scan
        const wifi = await scanWifi();
        // Build a minimal result object for analyseRF
        const minimalResult = { wifi } as any;

        let baseline: { wifi: typeof wifi; meta: { scanId: string; timestamp: string } } | undefined;
        if (opts.compare) {
          const stored = loadScan(opts.compare);
          baseline = {
            wifi: stored.scan.wifi,
            meta: { scanId: stored.scan.meta.scanId, timestamp: stored.scan.meta.timestamp },
          };
        }

        const analysis = analyseRF(minimalResult, baseline);

        if (opts.json) {
          console.log(JSON.stringify(analysis, null, 2));
          return;
        }

        console.log("");
        console.log(chalk.bold.cyan("  RF INTELLIGENCE"));
        console.log("");
        console.log(renderRFReport(analysis));
        console.log("");
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(message));
        process.exit(1);
      }
    });
}
