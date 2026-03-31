import chalk from "chalk";
import type { Command } from "commander";
import { listRecons } from "../store/recon-store.js";
import { pad } from "../reporter/render-helpers.js";

export function registerReconHistoryCommand(program: Command): void {
  program
    .command("recon-history")
    .description("List past reconnaissance scans")
    .option("-n, --limit <count>", "Number of recons to show", "20")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const entries = listRecons({ limit: parseInt(opts.limit, 10) });

      if (entries.length === 0) {
        console.log(chalk.dim("No recon scans found. Run 'wifisentinel recon <domain>' to record one."));
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }

      const header =
        pad(chalk.bold("DATE"), 22) +
        pad(chalk.bold("DOMAIN"), 30) +
        pad(chalk.bold("TLS"), 6) +
        pad(chalk.bold("HEADERS"), 10) +
        pad(chalk.bold("GRADE"), 8) +
        chalk.bold("SUBS");
      console.log(header);
      console.log(chalk.dim("\u2500".repeat(80)));

      for (const e of entries) {
        const date = new Date(e.timestamp).toLocaleString("en-GB", {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
        });
        console.log(
          pad(chalk.dim(date), 22) +
          pad(e.domain, 30) +
          pad(e.tlsGrade, 6) +
          pad(e.headersGrade, 10) +
          pad(e.overallGrade, 8) +
          String(e.subdomainCount),
        );
      }

      console.log(chalk.dim(`\n${entries.length} recon(s) shown.`));
    });
}
