// src/commands/trend.ts
import chalk from "chalk";
import type { Command } from "commander";
import { parsePositiveInt } from "./options.js";
import { listScans, type IndexEntry } from "../store/index.js";
import {
  isKnownSource,
  partialTrendNote,
  sourceCell,
  splitBySource,
} from "../store/source.js";
import { pad, TEAL, AMBER, RED, gradeColor, riskColor } from "../reporter/render-helpers.js";

function computeTrendDirection(entries: IndexEntry[]): string {
  if (entries.length < 2) return "insufficient data";
  const mid = Math.floor(entries.length / 2);
  // entries are newest-first, so reverse for chronological
  const chronological = [...entries].reverse();
  const firstHalf = chronological.slice(0, mid);
  const secondHalf = chronological.slice(mid);
  const avgFirst = firstHalf.reduce((s, e) => s + e.securityScore, 0) / firstHalf.length;
  const avgSecond = secondHalf.reduce((s, e) => s + e.securityScore, 0) / secondHalf.length;
  const delta = avgSecond - avgFirst;
  if (delta > 0.3) return TEAL("improving");
  if (delta < -0.3) return RED("declining");
  return AMBER("stable");
}

export function registerTrendCommand(program: Command): void {
  program
    .command("trend")
    .description("Show security score trends over time")
    .option("-n, --limit <count>", "Number of scans to show", parsePositiveInt, 10)
    .option("--ssid <name>", "Filter by SSID")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const entries = listScans({
        limit: opts.limit,
        ssid: opts.ssid,
      });

      if (entries.length === 0) {
        console.log(chalk.dim("No scans found. Run 'wifisentinel scan' to record one."));
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }

      // Header
      const header =
        pad(chalk.bold("DATE"), 14) +
        pad(chalk.bold("SCORE"), 8) +
        pad(chalk.bold("GRADE"), 8) +
        pad(chalk.bold("RISK"), 12) +
        pad(chalk.bold("HOSTS"), 8) +
        chalk.bold("SOURCE");
      console.log(header);
      console.log(chalk.dim("─".repeat(60)));

      // Render newest-first (already sorted that way)
      const chronological = [...entries].reverse();
      for (const e of chronological) {
        const date = new Date(e.timestamp).toLocaleDateString("en-GB", {
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        });
        const gc = gradeColor(e.complianceGrade);
        const rc = riskColor(e.consensusRisk);

        console.log(
          pad(chalk.dim(date), 14) +
          pad(e.securityScore.toFixed(1), 8) +
          pad(gc(e.complianceGrade), 8) +
          pad(rc(e.consensusRisk.toUpperCase()), 12) +
          pad(String(e.hostCount), 8) +
          chalk.dim(sourceCell(e)),
        );
      }

      // Summary line — a partial import (Android companion) scores against
      // sentinel-filled data, so a mixed history would oscillate with the
      // source rather than the network. Compute over full scans when both are
      // present; an all-partial history is still self-consistent.
      //
      // Pre-source index entries carry no provenance — assuming "full" for them
      // would fold a phone import written before the source fields existed back
      // into the maths. Gate them out once any sourced entries are present; if
      // the whole history predates the fields, keep them (there is nothing
      // better to summarise over, and it stays self-consistent).
      const sourced = entries.filter((e) => isKnownSource(e));
      const summarised = sourced.length > 0 ? sourced : entries;
      const unsourcedExcluded = entries.length - summarised.length;
      const { full, partial } = splitBySource(summarised, (e) => e);
      const scored = full.length > 0 ? full : summarised;
      const scores = scored.map(e => e.securityScore);
      const avg = (scores.reduce((s, v) => s + v, 0) / scores.length).toFixed(1);
      const best = Math.max(...scores).toFixed(1);
      const worst = Math.min(...scores).toFixed(1);
      const trend = computeTrendDirection(scored);

      console.log(chalk.dim("─".repeat(60)));
      console.log(`Avg: ${chalk.bold(avg)}  Best: ${TEAL(best)}  Worst: ${RED(worst)}  Trend: ${trend}`);
      const note = partialTrendNote(full.length, partial.length);
      if (note) console.log(chalk.dim(note));
      if (unsourcedExcluded > 0) {
        console.log(
          chalk.dim(
            `- ${unsourcedExcluded} unsourced scan${unsourcedExcluded === 1 ? "" : "s"} (pre-index-upgrade) excluded from the summary above`,
          ),
        );
      }
    });
}
