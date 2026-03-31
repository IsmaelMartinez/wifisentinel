import chalk, { type ChalkInstance } from "chalk";

export const W = 72; // inner width of report boxes

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
  const color = score >= 7 ? chalk.green : score >= 4 ? chalk.yellow : chalk.red;
  return color("■".repeat(filled)) + chalk.gray("□".repeat(empty));
}

export function boolStatus(value: boolean, goodWhenTrue: boolean): string {
  const good = goodWhenTrue ? value : !value;
  return good ? chalk.green("✔") : chalk.red("✘");
}

export function severityColor(severity: "high" | "medium" | "low"): ChalkInstance {
  if (severity === "high") return chalk.red;
  if (severity === "medium") return chalk.yellow;
  return chalk.dim;
}

export function signalBar(signal: number): string {
  const pct = Math.max(0, Math.min(100, ((signal + 100) / 70) * 100));
  const bars = Math.round(pct / 10);
  const filled = "█".repeat(bars);
  const empty = "░".repeat(10 - bars);
  const color = pct > 70 ? chalk.green : pct > 40 ? chalk.yellow : chalk.red;
  return color(filled) + chalk.gray(empty) + chalk.dim(` ${signal} dBm`);
}

export function snrLabel(snr: number): string {
  if (snr >= 25) return chalk.green("Excellent");
  if (snr >= 15) return chalk.green("Good");
  if (snr >= 10) return chalk.yellow("Fair");
  return chalk.red("Poor");
}
