import chalk from "chalk";
import type { Command } from "commander";
import { listScans } from "../store/index.js";
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

export function registerHistoryCommand(program: Command): void {
  program
    .command("history")
    .description("List past network scans")
    .option("-n, --limit <count>", "Number of scans to show", "20")
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
        pad(chalk.bold("DATE"), 22) +
        pad(chalk.bold("SSID"), 20) +
        pad(chalk.bold("SCORE"), 8) +
        pad(chalk.bold("GRADE"), 8) +
        pad(chalk.bold("RISK"), 12) +
        chalk.bold("HOSTS");
      console.log(header);
      console.log(chalk.dim("─".repeat(76)));

      for (const e of entries) {
        const date = new Date(e.timestamp).toLocaleString("en-GB", {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
        });
        const ssid = e.ssid ?? chalk.dim("(hidden)");
        const gc = gradeColor(e.complianceGrade);
        const rc = riskColor(e.consensusRisk);

        console.log(
          pad(chalk.dim(date), 22) +
          pad(ssid, 20) +
          pad(e.securityScore.toFixed(1), 8) +
          pad(gc(e.complianceGrade), 8) +
          pad(rc(e.consensusRisk.toUpperCase()), 12) +
          String(e.hostCount),
        );
      }

      console.log(chalk.dim(`\n${entries.length} scan(s) shown.`));
    });
}
