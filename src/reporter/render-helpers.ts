import chalk, { type ChalkInstance } from "chalk";
import figures from "figures";

// Accessible colour constants — distinguishable under all common CVD types
const TEAL = chalk.hex("#4ec9b0");
const RED = chalk.hex("#f44747");
const AMBER = chalk.hex("#cca700");
const BLUE = chalk.hex("#569cd6");

export let W = 72; // inner width of report boxes

export function getTerminalWidth(): number {
  return process.stdout.columns ?? 80;
}

export function refreshWidth(): void {
  W = Math.max(40, getTerminalWidth() - 8);
}

export type Status = "pass" | "fail" | "warn" | "info" | "n/a";

export function statusIcon(status: Status): string {
  switch (status) {
    case "pass":
      return TEAL(`${figures.tick} Pass`);
    case "fail":
      return RED(`${figures.cross} Fail`);
    case "warn":
      return AMBER(`${figures.warning} Warn`);
    case "info":
      return BLUE(`${figures.info} Info`);
    case "n/a":
      return chalk.dim(`${figures.circleDotted} N/A`);
  }
}

export function hRule(left: string, fill: string, right: string, width = W + 2): string {
  return left + fill.repeat(width) + right;
}

export function boxLine(content: string): string {
  return "║" + " " + content.padEnd(W) + " " + "║";
}

export function sectionHeader(title: string): string {
  const bar = chalk.cyan(hRule("├", "─", "┤"));
  const label = chalk.cyan("│") + " " + chalk.cyan.bold(` ${title} `).padEnd(W + 10) + chalk.cyan("│");
  return bar + "\n" + label;
}

export function pad(s: string, width: number): string {
  // strip ANSI before measuring
  // eslint-disable-next-line no-control-regex
  const plain = s.replace(/\x1B\[[0-9;]*m/g, "");
  const diff = width - plain.length;
  return s + (diff > 0 ? " ".repeat(diff) : "");
}

export function row(content: string): string {
  return chalk.cyan("│") + " " + pad(content, W) + " " + chalk.cyan("│");
}

export function scoreBar(score: number): string {
  const filled = Math.round(score);
  const empty = 10 - filled;
  const color = score >= 7 ? TEAL : score >= 4 ? AMBER : RED;
  return color("■".repeat(filled)) + chalk.gray("□".repeat(empty));
}

export function boolStatus(value: boolean, goodWhenTrue: boolean): string {
  const good = goodWhenTrue ? value : !value;
  return good ? TEAL("✔") : RED("✘");
}

export function severityColor(severity: "critical" | "high" | "medium" | "low"): ChalkInstance {
  if (severity === "critical") return RED.bold;
  if (severity === "high") return RED;
  if (severity === "medium") return AMBER;
  return chalk.dim;
}

export function signalBar(signal: number): string {
  const pct = Math.max(0, Math.min(100, ((signal + 100) / 70) * 100));
  const bars = Math.round(pct / 10);
  const filled = "█".repeat(bars);
  const empty = "░".repeat(10 - bars);
  const color = pct > 70 ? TEAL : pct > 40 ? AMBER : RED;
  return color(filled) + chalk.gray(empty) + chalk.dim(` ${signal} dBm`);
}

export function snrLabel(snr: number): string {
  if (snr >= 25) return TEAL("Excellent");
  if (snr >= 15) return TEAL("Good");
  if (snr >= 10) return AMBER("Fair");
  return RED("Poor");
}
