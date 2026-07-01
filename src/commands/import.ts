import { readFileSync } from "node:fs";
import chalk from "chalk";
import type { Command } from "commander";
import {
  AndroidScanImport,
  androidImportToScanResult,
} from "../collector/android-import.js";
import { saveScan } from "../store/index.js";
import { scoreAllStandards } from "../analyser/standards/index.js";
import { analyseAllPersonas } from "../analyser/personas/index.js";

export function registerImportCommand(program: Command): void {
  program
    .command("import")
    .description(
      "Import a scan exported by the WiFi Sentinel Android companion app"
    )
    .argument("<path>", "Path to the exported JSON file")
    .option(
      "--source <name>",
      "Source platform of the export (only 'android' is supported)",
      "android"
    )
    .action((path: string, opts: { source: string }) => {
      if (opts.source !== "android") {
        console.error(
          chalk.red(
            `Unsupported import source "${opts.source}". Only "android" is supported.`
          )
        );
        process.exit(1);
      }

      let raw: unknown;
      try {
        raw = JSON.parse(readFileSync(path, "utf-8"));
      } catch (err) {
        console.error(
          chalk.red(`Could not read or parse "${path}": ${(err as Error).message}`)
        );
        process.exit(1);
      }

      const parsed = AndroidScanImport.safeParse(raw);
      if (!parsed.success) {
        console.error(
          chalk.red("Import file is not a valid Android scan export:")
        );
        for (const issue of parsed.error.issues) {
          const where = issue.path.join(".") || "(root)";
          console.error(chalk.dim(`  • ${where}: ${issue.message}`));
        }
        process.exit(1);
      }

      const result = androidImportToScanResult(parsed.data);
      const compliance = scoreAllStandards(result);
      const analysis = analyseAllPersonas(result);
      saveScan(result, compliance, analysis);

      console.log(
        chalk.green("✓") +
          ` Imported Android scan ${chalk.bold(result.meta.scanId.slice(0, 8))}` +
          (result.wifi.ssid ? ` (${result.wifi.ssid})` : "") +
          "."
      );
      console.log(
        chalk.dim(
          "  Flagged as a partial scan. View it with 'wifisentinel history'."
        )
      );
    });
}
