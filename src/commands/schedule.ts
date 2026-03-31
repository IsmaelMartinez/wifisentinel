// src/commands/schedule.ts
import { execFileSync, execSync } from "node:child_process";
import { writeFileSync, unlinkSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";
import type { Command } from "commander";
import { listScans } from "../store/index.js";

const PLIST_LABEL = "com.wifisentinel.scan";

function getPlistPath(): string {
  return join(homedir(), "Library", "LaunchAgents", `${PLIST_LABEL}.plist`);
}

function getBinaryPath(): string {
  // Resolve from package.json bin entry
  const distCli = join(process.cwd(), "dist", "cli.js");
  if (existsSync(distCli)) return distCli;
  // Fallback: try global install
  try {
    // command -v is a shell builtin — hardcoded tool name, not user input
    return execSync("command -v wifisentinel", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return distCli; // best guess
  }
}

function getNodePath(): string {
  try {
    // command -v is a shell builtin — hardcoded tool name, not user input
    return execSync("command -v node", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return "/usr/local/bin/node";
  }
}

function enableMacOS(intervalHours: number): void {
  const nodePath = getNodePath();
  const binaryPath = getBinaryPath();
  const intervalSeconds = intervalHours * 3600;

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${nodePath}</string>
    <string>${binaryPath}</string>
    <string>scan</string>
    <string>--analyse</string>
  </array>
  <key>StartInterval</key>
  <integer>${intervalSeconds}</integer>
  <key>StandardErrorPath</key>
  <string>${join(homedir(), ".wifisentinel", "schedule.log")}</string>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>`;

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
  const binaryPath = getBinaryPath();
  const nodePath = getNodePath();
  const cronExpr = `0 */${intervalHours} * * *`;
  const cronLine = `${cronExpr} ${nodePath} ${binaryPath} scan --analyse > /dev/null 2>> ${join(homedir(), ".wifisentinel", "schedule.log")}`;
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
  let existing = "";
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
      const interval = parseInt(opts.interval, 10);
      if (isNaN(interval) || interval < 1) {
        console.error(chalk.red("Interval must be a positive integer (hours)."));
        process.exit(1);
      }
      if (process.platform === "darwin") {
        enableMacOS(interval);
      } else {
        enableLinux(interval);
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
