import chalk from "chalk";
import type { Command } from "commander";
import { collectRecon } from "../collector/recon/index.js";
import { analyseReconAllPersonas } from "../analyser/recon-personas.js";
import { renderReconReport, renderReconAnalysisReport } from "../reporter/recon.reporter.js";
import { renderReconJsonReport } from "../reporter/recon-json.reporter.js";
import { saveRecon } from "../store/recon-store.js";

export function registerReconCommand(program: Command): void {
  program
    .command("recon <domain>")
    .description("External reconnaissance scan of a domain")
    .option("-o, --output <format>", "Output format: terminal, json", "terminal")
    .option("-f, --file <path>", "Write output to file")
    .option("--analyse", "Include multi-persona analysis")
    .option("--no-save", "Skip saving to history")
    .option("-v, --verbose", "Verbose output")
    .option("--zone-transfer", "Attempt DNS zone transfers (may trigger security alerts)")
    .option("--shodan-key <key>", "Shodan API key (or set SHODAN_API_KEY env var)")
    .option("--censys-id <id>", "Censys API ID (or set CENSYS_API_ID env var)")
    .option("--censys-secret <secret>", "Censys API secret (or set CENSYS_API_SECRET env var)")
    .action(async (domain: string, opts) => {
      try {
        const result = await collectRecon(domain, {
          verbose: opts.verbose,
          zoneTransfer: opts.zoneTransfer,
          shodanKey: opts.shodanKey,
          censysId: opts.censysId,
          censysSecret: opts.censysSecret,
        });

        let output: string;
        if (opts.output === "json") {
          output = opts.analyse
            ? renderReconJsonReport(result)
            : JSON.stringify(result, null, 2);
        } else {
          if (opts.analyse) {
            const analysis = analyseReconAllPersonas(result);
            output = renderReconAnalysisReport(result, analysis, opts.verbose);
          } else {
            output = renderReconReport(result);
          }
        }

        if (opts.file) {
          const { writeFileSync } = await import("node:fs");
          writeFileSync(opts.file, output, "utf-8");
          console.error(chalk.green(`Report written to ${opts.file}`));
        } else {
          console.log(output);
        }

        if (opts.save) {
          const analysis = analyseReconAllPersonas(result);
          saveRecon(result, analysis);
          if (opts.verbose) {
            console.error("[wifisentinel] Recon saved to history.");
          }
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`Recon failed: ${message}`));
        process.exit(1);
      }
    });
}
