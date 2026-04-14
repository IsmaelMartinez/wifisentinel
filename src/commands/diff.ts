// src/commands/diff.ts
import chalk from "chalk";
import type { Command } from "commander";
import { loadScan } from "../store/index.js";
import { diffScans, type FieldChange, type HostChange } from "../store/diff.js";

function directionMarker(dir: string): string {
  if (dir === "improved") return chalk.green("+");
  if (dir === "regressed") return chalk.red("-");
  return chalk.yellow("~");
}

function renderFieldChanges(label: string, changes: FieldChange[]): void {
  if (changes.length === 0) return;
  console.log(chalk.bold(`\n  ${label}`));
  for (const c of changes) {
    console.log(`  ${directionMarker(c.direction)} ${c.field}: ${chalk.dim(String(c.from))} -> ${String(c.to)}`);
  }
}

function renderHostChanges(changes: HostChange[]): void {
  if (changes.length === 0) return;
  console.log(chalk.bold("\n  Hosts"));
  for (const h of changes) {
    const vendor = h.vendor ? ` (${h.vendor})` : "";
    if (h.type === "added") {
      console.log(`  ${chalk.green("+")} ${h.ip}  ${chalk.dim(h.mac)}${vendor}`);
    } else if (h.type === "removed") {
      console.log(`  ${chalk.red("-")} ${h.ip}  ${chalk.dim(h.mac)}${vendor}`);
    } else {
      console.log(`  ${chalk.yellow("~")} ${h.ip}  ${chalk.dim(h.mac)}${vendor}`);
      for (const c of h.changes ?? []) {
        console.log(`      ${directionMarker(c.direction)} ${c.field}: ${chalk.dim(String(c.from))} -> ${String(c.to)}`);
      }
    }
  }
}

export function registerDiffCommand(program: Command): void {
  program
    .command("diff <scan1> <scan2>")
    .description("Compare two scan results")
    .option("--json", "Output as JSON")
    .action((scan1: string, scan2: string, opts) => {
      try {
        const a = loadScan(scan1);
        const b = loadScan(scan2);
        const diff = diffScans(a, b);

        if (opts.json) {
          console.log(JSON.stringify(diff, null, 2));
          return;
        }

        const dateA = new Date(diff.fromTimestamp).toLocaleString();
        const dateB = new Date(diff.toTimestamp).toLocaleString();
        console.log(chalk.bold("Scan Comparison"));
        console.log(chalk.dim(`  From: ${diff.fromScanId.slice(0, 8)}  ${dateA}`));
        console.log(chalk.dim(`  To:   ${diff.toScanId.slice(0, 8)}  ${dateB}`));

        const hasChanges = diff.wifi.length > 0 ||
          diff.security.length > 0 ||
          diff.hosts.length > 0 ||
          diff.compliance.overall.delta !== 0 ||
          diff.personas.some(p => p.direction !== "unchanged");

        if (!hasChanges) {
          console.log(chalk.green("\n  No significant changes between scans."));
          return;
        }

        renderFieldChanges("WiFi", diff.wifi);
        renderFieldChanges("Security Posture", diff.security);
        renderHostChanges(diff.hosts);

        // Compliance
        const cd = diff.compliance;
        if (cd.overall.delta !== 0 || cd.standards.some(s => s.delta !== 0)) {
          console.log(chalk.bold("\n  Compliance"));
          const sign = cd.overall.delta > 0 ? "+" : "";
          const color = cd.overall.delta > 0 ? chalk.green : cd.overall.delta < 0 ? chalk.red : chalk.dim;
          console.log(`  ${color(sign + cd.overall.delta)} Overall: ${cd.overall.from}% -> ${cd.overall.to}%`);
          for (const s of cd.standards) {
            if (s.delta === 0) continue;
            const ss = s.delta > 0 ? "+" : "";
            const sc = s.delta > 0 ? chalk.green : chalk.red;
            console.log(`  ${sc(ss + s.delta)} ${s.name}: ${s.from}% -> ${s.to}%`);
          }
        }

        // Personas
        const personaChanges = diff.personas.filter(p => p.direction !== "unchanged");
        if (personaChanges.length > 0) {
          console.log(chalk.bold("\n  Persona Risk Ratings"));
          for (const p of personaChanges) {
            console.log(`  ${directionMarker(p.direction)} ${p.persona}: ${p.fromRisk} -> ${p.toRisk}`);
          }
        }

        console.log("");
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(message));
        process.exit(1);
      }
    });
}
