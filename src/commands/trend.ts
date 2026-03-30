// src/commands/trend.ts
import chalk from "chalk";
import type { Command } from "commander";
import { listScans, type IndexEntry } from "../store/index.js";
import { pad } from "../reporter/render-helpers.js";

function riskColor(risk: string): (s: string) => string {
  if (risk === "critical") return chalk.red.bold;
  if (risk === "high") return chalk.red;
  if (risk === "medium") return chalk.yellow;
  return chalk.green;
}

function gradeColor(grade: string): (s: string) => string {
  if (grade === "A" || grade === "B") return chalk.green;
  if (grade === "C" || grade === "D") return chalk.yellow;
  return chalk.red;
}

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
  if (delta > 0.3) return chalk.green("improving");
  if (delta < -0.3) return chalk.red("declining");
  return chalk.yellow("stable");
}

export function registerTrendCommand(program: Command): void {
  program
    .command("trend")
    .description("Show security score trends over time")
    .option("-n, --limit <count>", "Number of scans to show", "10")
    .option("--ssid <name>", "Filter by SSID")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const entries = listScans({
        limit: parseInt(opts.limit, 10),
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
        chalk.bold("HOSTS");
      console.log(header);
      console.log(chalk.dim("─".repeat(50)));

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
          String(e.hostCount),
        );
      }

      // Summary line
      const scores = entries.map(e => e.securityScore);
      const avg = (scores.reduce((s, v) => s + v, 0) / scores.length).toFixed(1);
      const best = Math.max(...scores).toFixed(1);
      const worst = Math.min(...scores).toFixed(1);
      const trend = computeTrendDirection(entries);

      console.log(chalk.dim("─".repeat(50)));
      console.log(`Avg: ${chalk.bold(avg)}  Best: ${chalk.green(best)}  Worst: ${chalk.red(worst)}  Trend: ${trend}`);
    });
}
