import chalk, { type ChalkInstance } from "chalk";
import figures from "figures";
import terminalLink from "terminal-link";

// Accessible colour constants — distinguishable under all common CVD types
export const TEAL = chalk.hex("#4ec9b0");
export const RED = chalk.hex("#f44747");
export const AMBER = chalk.hex("#cca700");
export const BLUE = chalk.hex("#569cd6");

export let W = 72; // inner width of report boxes

export function getTerminalWidth(): number {
  return process.stdout.columns ?? 80;
}

export function refreshWidth(): void {
  W = Math.max(40, getTerminalWidth() - 8);
}

type Colour = (s: string) => string;

/**
 * Status glyph for compliance findings (pass/fail/partial/not-applicable),
 * recon header checks (pass/fail/missing) and generic warn/info states.
 */
export function statusIcon(status: string): string {
  switch (status) {
    case "pass":
      return TEAL(figures.tick);
    case "fail":
      return RED(figures.cross);
    case "partial":
      return AMBER("◐");
    case "warn":
      return AMBER(figures.warning);
    case "info":
      return BLUE(figures.info);
    default:
      return chalk.dim("—");
  }
}

/** Letter grades: A/B good, C/D fair, anything else poor. */
export function gradeColor(grade: string): Colour {
  if (grade === "A" || grade === "B") return TEAL;
  if (grade === "C" || grade === "D") return AMBER;
  return RED;
}

/** Consensus or persona risk ratings. */
export function riskColor(rating: string): Colour {
  if (rating === "critical") return RED.bold;
  if (rating === "high") return RED;
  if (rating === "medium") return AMBER;
  if (rating === "low" || rating === "minimal") return TEAL;
  return chalk.dim;
}

const PERSONA_ACCENTS: Record<string, Colour> = {
  "red-team": RED,
  "blue-team": BLUE,
  "compliance": TEAL,
  "net-engineer": AMBER,
  "privacy": chalk.magenta,
};

export function personaAccent(persona: string): Colour {
  return PERSONA_ACCENTS[persona] ?? chalk.white;
}

export function hRule(left: string, fill: string, right: string, width = W + 2): string {
  return left + fill.repeat(width) + right;
}

export function boxLine(content: string): string {
  return "║" + " " + pad(content, W) + " " + "║";
}

export function sectionHeader(title: string): string {
  const bar = chalk.cyan(hRule("├", "─", "┤"));
  const label = chalk.cyan("│") + " " + pad(chalk.cyan.bold(` ${title} `), W) + " " + chalk.cyan("│");
  return bar + "\n" + label;
}

// eslint-disable-next-line no-control-regex
const ANSI_SGR = /\x1B\[[0-9;]*m/g;
// OSC 8 hyperlink open/close (`link()` via terminal-link), terminated by BEL or ESC \.
// eslint-disable-next-line no-control-regex
const OSC8 = /\x1B\]8;[^\x07\x1B]*(?:\x07|\x1B\\)/g;

export function visibleLength(s: string): number {
  return s.replace(ANSI_SGR, "").replace(OSC8, "").length;
}

export function pad(s: string, width: number): string {
  const diff = width - visibleLength(s);
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

/** Finding, insight, alert and RF severities; low and info are muted. */
export function severityColor(severity: string): ChalkInstance {
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

// Method-aware latency helpers live next to the schema (they're pure and
// shared with the dashboard and personas); re-exported here for the
// terminal reporter and existing test imports.
export {
  isPingLatency,
  latencyBands,
  latencyMethodLabel,
  latencyMethodNote,
} from "../collector/schema/latency.js";

export function snrLabel(snr: number): string {
  if (snr >= 25) return TEAL("Excellent");
  if (snr >= 15) return TEAL("Good");
  if (snr >= 10) return AMBER("Fair");
  return RED("Poor");
}

export function link(text: string, url: string): string {
  return terminalLink(text, url, { fallback: (text, url) => `${text} (${url})` });
}
