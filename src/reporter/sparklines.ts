import sparkly from "sparkly";
import chalk from "chalk";

const TEAL = chalk.hex("#4ec9b0");
const AMBER = chalk.hex("#cca700");
const RED = chalk.hex("#f44747");

export function renderSparkline(values: number[]): string {
  if (values.length === 0) return "";
  return sparkly(values);
}

export function renderScoreTrend(scores: number[]): string {
  if (scores.length < 2) return "";
  const spark = renderSparkline(scores);
  const first = scores[0];
  const last = scores[scores.length - 1];
  const diff = last - first;
  let direction: string;
  let color: (s: string) => string;
  if (diff > 0.3) { direction = "improving"; color = TEAL; }
  else if (diff < -0.3) { direction = "degrading"; color = RED; }
  else { direction = "stable"; color = AMBER; }
  return `${spark} ${color(`${last.toFixed(1)} (${direction})`)}`;
}

export function renderSignalTrend(signals: number[]): string {
  if (signals.length < 2) return "";
  const spark = renderSparkline(signals.map(s => s + 100));
  const avg = signals.reduce((a, b) => a + b, 0) / signals.length;
  return `${spark} ${chalk.dim(`${avg.toFixed(0)} dBm avg`)}`;
}
