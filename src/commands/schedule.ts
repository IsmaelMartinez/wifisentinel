// src/commands/schedule.ts
import { execFileSync } from "node:child_process";
import { writeFileSync, unlinkSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import chalk from "chalk";
import type { Command } from "commander";
import { listScans } from "../store/index.js";

const PLIST_LABEL = "com.wifisentinel.scan";

function getPlistPath(): string {
  return join(homedir(), "Library", "LaunchAgents", `${PLIST_LABEL}.plist`);
}

/**
 * Resolve this package's own compiled CLI entry point. Under tsx this module
 * is `src/commands/schedule.ts`, so point at the built `dist/cli.js`; once
 * compiled it is `dist/commands/schedule.js`, a sibling of `dist/cli.js`.
 */
export function getBinaryPath(moduleUrl: string = import.meta.url): string {
  const relative = moduleUrl.endsWith(".ts") ? "../../dist/cli.js" : "../cli.js";
  return fileURLToPath(new URL(relative, moduleUrl));
}

export function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** POSIX single-quote a value for a shell command line. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

const CRON_QUOTED: Record<string, string> = {
  // Close the single-quoted run, emit an escaped quote, reopen.
  "'": "'\\''",
  // Emit backslashes outside the quotes as `\\` so a path backslash can never
  // sit directly before a `%` and swallow cron's `\%` escape.
  "\\": "'\\\\'",
  // Cron turns an unescaped `%` into a newline before the shell runs (quotes
  // don't help); it unescapes `\%` back to `%`.
  "%": "\\%",
};

/** Shell-quote a value for a crontab command line, escaping for cron too. */
export function cronQuote(value: string): string {
  return `'${value.replace(/['\\%]/g, (c) => CRON_QUOTED[c])}'`;
}

export interface ScheduleTarget {
  nodePath: string;
  binaryPath: string;
  logPath: string;
  intervalHours: number;
}

export function buildPlist(t: ScheduleTarget): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${xmlEscape(t.nodePath)}</string>
    <string>${xmlEscape(t.binaryPath)}</string>
    <string>scan</string>
    <string>--analyse</string>
  </array>
  <key>StartInterval</key>
  <integer>${t.intervalHours * 3600}</integer>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(t.logPath)}</string>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>`;
}

/**
 * Cron's hour step restarts at midnight, so only divisors of 24 give an even
 * interval that matches launchd's StartInterval.
 */
export function buildCronLine(t: ScheduleTarget): string {
  const n = t.intervalHours;
  if (!Number.isInteger(n) || n < 1 || 24 % n !== 0) {
    throw new Error(
      `Interval ${n}h does not divide 24; cron supports 1, 2, 3, 4, 6, 8, 12 or 24.`,
    );
  }
  // Crontab is line-based, so a line break in a path would end the entry.
  for (const p of [t.nodePath, t.binaryPath, t.logPath]) {
    if (/[\r\n]/.test(p)) throw new Error(`Cannot schedule a path containing a line break: ${JSON.stringify(p)}`);
  }
  const hours = n === 24 ? "0" : `*/${n}`;
  return `0 ${hours} * * * ${cronQuote(t.nodePath)} ${cronQuote(t.binaryPath)} scan --analyse > /dev/null 2>> ${cronQuote(t.logPath)}`;
}

/** Parse `--interval`; undefined unless it is a whole number of hours ≥ 1 (no `1.5` or `6foo`). */
export function parseIntervalHours(raw: string): number | undefined {
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 ? n : undefined;
}

function resolveTarget(intervalHours: number): ScheduleTarget {
  const binaryPath = getBinaryPath();
  if (!existsSync(binaryPath)) {
    throw new Error(`CLI entry point not found at ${binaryPath}; run "npm run build" first.`);
  }
  return {
    nodePath: getNodePath(),
    binaryPath,
    logPath: join(homedir(), ".wifisentinel", "schedule.log"),
    intervalHours,
  };
}

function getNodePath(): string {
  try {
    return execFileSync("which", ["node"], {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return "/usr/local/bin/node";
  }
}

function enableMacOS(intervalHours: number): void {
  const plist = buildPlist(resolveTarget(intervalHours));

  const plistPath = getPlistPath();
  writeFileSync(plistPath, plist, "utf-8");

  try {
    execFileSync("launchctl", ["unload", plistPath], { stdio: "pipe" });
  } catch {
    // Ignore if not loaded
  }
  execFileSync("launchctl", ["load", plistPath]);

  console.log(chalk.green(`Scheduled scanning enabled (every ${intervalHours}h).`));
  console.log(chalk.dim(`Plist: ${plistPath}`));
  console.log(chalk.dim(`Log:   ~/.wifisentinel/schedule.log`));
}

function enableLinux(intervalHours: number): void {
  const cronLine = buildCronLine(resolveTarget(intervalHours));
  const marker = "# wifisentinel-scheduled-scan";

  let existing = "";
  try {
    existing = execFileSync("crontab", ["-l"], { encoding: "utf-8" });
  } catch {
    // No crontab
  }

  // Remove old entry if present
  const lines = existing.split("\n").filter(l => !l.includes(marker));
  lines.push(`${cronLine} ${marker}`);

  execFileSync("crontab", ["-"], {
    input: lines.join("\n") + "\n",
    encoding: "utf-8",
  });

  console.log(chalk.green(`Scheduled scanning enabled (every ${intervalHours}h).`));
  console.log(chalk.dim(`Cron: ${cronLine}`));
}

function disableMacOS(): void {
  const plistPath = getPlistPath();
  if (!existsSync(plistPath)) {
    console.log(chalk.dim("No scheduled scan found."));
    return;
  }
  try {
    execFileSync("launchctl", ["unload", plistPath], { stdio: "pipe" });
  } catch {
    // Ignore
  }
  unlinkSync(plistPath);
  console.log(chalk.green("Scheduled scanning disabled."));
}

function disableLinux(): void {
  const marker = "# wifisentinel-scheduled-scan";
  let existing: string;
  try {
    existing = execFileSync("crontab", ["-l"], { encoding: "utf-8" });
  } catch {
    console.log(chalk.dim("No scheduled scan found."));
    return;
  }
  const lines = existing.split("\n").filter(l => !l.includes(marker));
  execFileSync("crontab", ["-"], {
    input: lines.join("\n") + "\n",
    encoding: "utf-8",
  });
  console.log(chalk.green("Scheduled scanning disabled."));
}

function showStatus(): void {
  const isMac = process.platform === "darwin";

  if (isMac) {
    const plistPath = getPlistPath();
    if (!existsSync(plistPath)) {
      console.log(chalk.dim("Scheduled scanning is not enabled."));
      return;
    }
    const content = readFileSync(plistPath, "utf-8");
    const intervalMatch = content.match(/<key>StartInterval<\/key>\s*<integer>(\d+)<\/integer>/);
    const intervalHours = intervalMatch ? parseInt(intervalMatch[1], 10) / 3600 : "unknown";
    console.log(chalk.green(`Scheduled scanning is enabled (every ${intervalHours}h).`));
  } else {
    try {
      const crontab = execFileSync("crontab", ["-l"], { encoding: "utf-8" });
      const marker = "# wifisentinel-scheduled-scan";
      const line = crontab.split("\n").find(l => l.includes(marker));
      if (line) {
        console.log(chalk.green(`Scheduled scanning is enabled.`));
        console.log(chalk.dim(`Cron: ${line.replace(marker, "").trim()}`));
      } else {
        console.log(chalk.dim("Scheduled scanning is not enabled."));
        return;
      }
    } catch {
      console.log(chalk.dim("Scheduled scanning is not enabled."));
      return;
    }
  }

  // Show last scan time from history
  const scans = listScans({ limit: 1 });
  if (scans.length > 0) {
    const last = new Date(scans[0].timestamp).toLocaleString();
    console.log(chalk.dim(`Last scan: ${last}`));
  }
}

export function registerScheduleCommand(program: Command): void {
  const schedule = program
    .command("schedule")
    .description("Manage scheduled network scanning");

  schedule
    .command("enable")
    .description("Enable periodic scanning")
    .option("-i, --interval <hours>", "Scan interval in hours", "6")
    .action((opts) => {
      const interval = parseIntervalHours(opts.interval);
      if (interval === undefined) {
        console.error(chalk.red("Interval must be a positive integer (hours)."));
        process.exit(1);
      }
      try {
        if (process.platform === "darwin") {
          enableMacOS(interval);
        } else {
          enableLinux(interval);
        }
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(1);
      }
    });

  schedule
    .command("disable")
    .description("Disable periodic scanning")
    .action(() => {
      if (process.platform === "darwin") {
        disableMacOS();
      } else {
        disableLinux();
      }
    });

  schedule
    .command("status")
    .description("Show scheduling status")
    .action(() => {
      showStatus();
    });
}
