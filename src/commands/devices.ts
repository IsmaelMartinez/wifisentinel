// src/commands/devices.ts — Device presence timeline from scan history
import chalk from "chalk";
import type { Command } from "commander";
import { listScans, loadScan } from "../store/index.js";
import { buildPresenceReport, normaliseMac } from "../analyser/devices/tracker.js";
import type { DeviceTimeline, PresenceReport } from "../analyser/devices/types.js";
import { pad } from "../reporter/render-helpers.js";

function formatDate(ts: string): string {
  if (!ts) return "-";
  return new Date(ts).toLocaleString("en-GB", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatRelative(ts: string, now: Date = new Date()): string {
  const diffMs = now.getTime() - new Date(ts).getTime();
  if (!Number.isFinite(diffMs) || diffMs < 0) return "just now";
  const mins = Math.round(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  return `${days}d ago`;
}

function renderDeviceTable(devices: DeviceTimeline[]): void {
  const header =
    pad(chalk.bold("MAC"), 20) +
    pad(chalk.bold("NAME"), 24) +
    pad(chalk.bold("VENDOR"), 22) +
    pad(chalk.bold("SCANS"), 9) +
    pad(chalk.bold("LAST SEEN"), 14) +
    chalk.bold("STATUS");
  console.log(header);
  console.log(chalk.dim("─".repeat(100)));

  for (const d of devices) {
    const name = d.hostnames[0] ?? d.deviceTypes[0] ?? "-";
    const vendor = d.vendors[0] ?? "-";
    const scans = `${d.scanCount}/${d.totalScans}`;
    const lastSeen = formatRelative(d.lastSeen);
    const status = d.currentlyPresent
      ? chalk.green("● present")
      : chalk.dim("○ absent");
    const macDisplay = d.isCamera ? chalk.magenta(d.mac + "*") : d.mac;

    const nameCell = name === "-" ? chalk.dim(name) : name;
    const vendorCell = vendor === "-" ? chalk.dim(vendor) : vendor;

    console.log(
      pad(macDisplay, 20) +
      pad(nameCell.slice(0, 60), 24) +
      pad(vendorCell.slice(0, 60), 22) +
      pad(scans, 9) +
      pad(chalk.dim(lastSeen), 14) +
      status,
    );
  }
}

function renderDeviceDetail(d: DeviceTimeline): void {
  console.log(chalk.bold(`\n  ${d.mac}`));
  console.log(
    chalk.dim("  Status:      ") +
      (d.currentlyPresent ? chalk.green("present") : chalk.dim("absent")),
  );
  if (d.hostnames.length > 0) {
    console.log(chalk.dim("  Hostnames:   ") + d.hostnames.join(", "));
  }
  if (d.vendors.length > 0) {
    console.log(chalk.dim("  Vendors:     ") + d.vendors.join(", "));
  }
  if (d.deviceTypes.length > 0) {
    console.log(chalk.dim("  Device type: ") + d.deviceTypes.join(", "));
  }
  if (d.ips.length > 0) {
    console.log(chalk.dim("  IPs seen:    ") + d.ips.join(", "));
  }
  console.log(chalk.dim("  First seen:  ") + formatDate(d.firstSeen));
  console.log(chalk.dim("  Last seen:   ") + formatDate(d.lastSeen));
  console.log(
    chalk.dim("  Presence:    ") +
      `${d.scanCount}/${d.totalScans} scans (${(d.presenceRatio * 100).toFixed(0)}%)`,
  );

  if (d.sessions.length > 0) {
    console.log(chalk.bold("\n  Sessions"));
    for (const s of d.sessions) {
      const line =
        s.scanCount === 1
          ? `  • ${formatDate(s.start)} (single scan)`
          : `  • ${formatDate(s.start)} → ${formatDate(s.end)} (${s.scanCount} scans)`;
      console.log(chalk.dim(line));
    }
  }

  if (d.isCamera) {
    console.log(chalk.magenta("\n  ⚠ Flagged as a suspected camera in at least one scan"));
  }
}

export function registerDevicesCommand(program: Command): void {
  program
    .command("devices")
    .description("Track device presence across scan history (join/leave timeline)")
    .option("-n, --limit <count>", "Number of scans to include", "50")
    .option("--ssid <name>", "Filter by SSID")
    .option("--active", "Show only currently present devices")
    .option("--mac <mac>", "Show detailed timeline for a specific MAC (prefix match)")
    .option("--since <date>", "Only include scans at or after this ISO date")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const limit = parseInt(opts.limit, 10);
      const entries = listScans({
        limit: Number.isFinite(limit) && limit > 0 ? limit : 50,
        ssid: opts.ssid,
      });

      if (entries.length === 0) {
        console.log(chalk.dim("No scans found. Run 'wifisentinel scan' to record some."));
        return;
      }

      let stored = entries.map((e) => loadScan(e.scanId));

      if (opts.since) {
        const parsed = new Date(opts.since);
        if (Number.isNaN(parsed.getTime())) {
          console.error(chalk.red(`Invalid --since date: ${opts.since}`));
          process.exit(1);
          return;
        }
        const sinceTs = parsed.toISOString();
        stored = stored.filter((s) => s.scan.meta.timestamp >= sinceTs);
      }

      if (stored.length === 0) {
        console.log(chalk.dim("No scans match the filter."));
        return;
      }

      const report: PresenceReport = buildPresenceReport(stored, {
        ssid: opts.ssid,
      });

      let devices = report.devices;
      if (opts.active) {
        devices = devices.filter((d) => d.currentlyPresent);
      }

      if (opts.mac) {
        const needle = normaliseMac(opts.mac);
        const device = report.devices.find(
          (d) => d.mac === needle || d.mac.startsWith(needle),
        );
        if (!device) {
          console.error(chalk.red(`No device matching "${opts.mac}" found in history.`));
          process.exit(1);
          return;
        }
        if (opts.json) {
          console.log(JSON.stringify(device, null, 2));
          return;
        }
        renderDeviceDetail(device);
        console.log("");
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify({ ...report, devices }, null, 2));
        return;
      }

      console.log(chalk.bold.cyan("\n  DEVICE PRESENCE"));
      console.log(
        chalk.dim(
          `  Window: ${formatDate(report.windowStart)} → ${formatDate(report.windowEnd)}  (${report.totalScans} scans)`,
        ),
      );
      if (report.ssidFilter) {
        console.log(chalk.dim(`  SSID:   ${report.ssidFilter}`));
      }
      console.log("");

      if (devices.length === 0) {
        console.log(chalk.dim("  No devices found."));
        return;
      }

      renderDeviceTable(devices);

      const activeCount = devices.filter((d) => d.currentlyPresent).length;
      const total = devices.length;
      console.log(
        chalk.dim(`\n  ${total} unique device(s) — ${activeCount} currently present\n`),
      );
    });
}
