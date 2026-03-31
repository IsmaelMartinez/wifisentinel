import chalk from "chalk";
import { writeFileSync } from "node:fs";
import type { Command } from "commander";
import { loadScan } from "../store/index.js";
import { analyseRF } from "../analyser/rf/index.js";
import { renderHtmlReport } from "../reporter/html.reporter.js";

export function registerExportCommand(program: Command): void {
  program
    .command("export <scanId>")
    .description("Export a scan report as HTML")
    .option("-o, --output <path>", "Output file path")
    .option("--stdout", "Write to stdout instead of file")
    .action((scanId: string, opts) => {
      try {
        const stored = loadScan(scanId);
        if (!stored.rfAnalysis) {
          stored.rfAnalysis = analyseRF(stored.scan);
        }
        const html = renderHtmlReport(stored);

        if (opts.stdout) {
          process.stdout.write(html);
          return;
        }

        const date = stored.scan.meta.timestamp.split("T")[0];
        const outputPath = opts.output ?? `wifisentinel-report-${date}.html`;
        writeFileSync(outputPath, html, "utf-8");
        console.log(chalk.green(`Report written to ${outputPath}`));
      } catch (err: any) {
        console.error(chalk.red(err.message));
        process.exit(1);
      }
    });
}
