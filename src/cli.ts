#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { Command } from "commander";
import { registerScanCommands } from "./commands/scan.js";
import { registerHistoryCommand } from "./commands/history.js";
import { registerDiffCommand } from "./commands/diff.js";
import { registerTrendCommand } from "./commands/trend.js";
import { registerScheduleCommand } from "./commands/schedule.js";
import { registerRFCommand } from "./commands/rf.js";
import { registerExportCommand } from "./commands/export.js";
import { registerReconCommand } from "./commands/recon.js";
import { registerReconHistoryCommand } from "./commands/recon-history.js";
import { registerWatchCommand } from "./commands/watch.js";
import { registerDevicesCommand } from "./commands/devices.js";
import { registerImportCommand } from "./commands/import.js";

// package.json sits one level above both src/ (tsx) and dist/ (built).
const { version } = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf-8"),
) as { version: string };

const program = new Command();

program
  .name("wifisentinel")
  .description("Multi-persona WiFi/network security analyser")
  .version(version);

registerScanCommands(program);
registerHistoryCommand(program);
registerDiffCommand(program);
registerTrendCommand(program);
registerScheduleCommand(program);
registerRFCommand(program);
registerExportCommand(program);
registerReconCommand(program);
registerReconHistoryCommand(program);
registerWatchCommand(program);
registerDevicesCommand(program);
registerImportCommand(program);

program.parse();
