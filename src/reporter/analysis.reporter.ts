import chalk from "chalk";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import type { ComplianceReport, FindingStatus } from "../analyser/standards/types.js";
import type { FullAnalysis, PersonaAnalysis } from "../analyser/personas/types.js";
import type { RFAnalysis } from "../analyser/rf/types.js";
import {
  W,
  TEAL,
  RED,
  AMBER,
  hRule,
  sectionHeader,
  row,
  scoreBar,
  link,
  gradeColor,
  riskColor,
  severityColor,
  personaAccent,
  statusIcon,
} from "./render-helpers.js";
import { renderTerminalReport } from "./terminal.reporter.js";

/** Persona output shared by the network (FullAnalysis) and recon analyses. */
export interface PersonaReport {
  analyses: PersonaAnalysis[];
  consensusRating: string;
  consensusActions: string[];
}

// ─── Compliance renderers ─────────────────────────────────────────────────

export function renderComplianceSummary(report: ComplianceReport): string {
  const gc = gradeColor(report.overallGrade);
  const bar = scoreBar(report.overallScore / 10);
  const lines: string[] = [
    sectionHeader("COMPLIANCE SUMMARY"),
    row(""),
    row(`  Overall Grade: ${gc(report.overallGrade)}   Score: ${bar}  ${chalk.bold(String(report.overallScore) + "%")}`),
    row(""),
  ];

  for (const std of report.standards) {
    const sc = gradeColor(std.grade);
    const stdBar = scoreBar(std.score / 10);
    const fails = std.findings.filter(f => f.status === "fail").length;
    const partials = std.findings.filter(f => f.status === "partial").length;
    const passes = std.findings.filter(f => f.status === "pass").length;
    const na = std.findings.filter(f => f.status === "not-applicable").length;

    lines.push(row(`  ${sc(std.grade)}  ${stdBar}  ${chalk.bold(std.name)} ${chalk.dim(`v${std.version}`)}`));
    lines.push(row(chalk.dim(`     ${std.score}%  │  ${RED(String(fails) + " fail")}  ${AMBER(String(partials) + " partial")}  ${TEAL(String(passes) + " pass")}  ${chalk.dim(String(na) + " n/a")}`)));
  }

  lines.push(row(""));
  return lines.join("\n");
}

export function renderComplianceDetails(report: ComplianceReport): string {
  const lines: string[] = [
    sectionHeader("COMPLIANCE DETAILS"),
    row(""),
  ];

  for (const std of report.standards) {
    lines.push(row(chalk.bold(`  ${std.name} ${chalk.dim(`(${std.standard} v${std.version})`)}`)));
    lines.push(row(chalk.dim(`  ${std.summary}`)));
    lines.push(row(""));

    // Group by status: fail first, then partial, then pass, then n/a
    const statusOrder: FindingStatus[] = ["fail", "partial", "pass", "not-applicable"];
    for (const status of statusOrder) {
      const group = std.findings.filter(f => f.status === status);
      if (group.length === 0) continue;

      for (const finding of group) {
        const sev = severityColor(finding.severity);
        lines.push(row(`  ${statusIcon(finding.status)}  ${sev(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`));
        lines.push(row(chalk.dim(`     ${finding.description}`)));
        if (finding.status !== "pass" && finding.status !== "not-applicable") {
          const rec = finding.recommendation.replace(
            /(https?:\/\/[^\s.,;:!?)\]]+)/g,
            (url) => link(url, url),
          );
          lines.push(row(chalk.dim(`     → ${rec}`)));
        }
        if (finding.evidence) {
          lines.push(row(chalk.dim(`     Evidence: ${finding.evidence}`)));
        }
      }
    }

    lines.push(row(""));
  }

  return lines.join("\n");
}

// ─── Persona renderers ───────────────────────────────────────────────────

export function renderPersonaSummary(analysis: PersonaReport): string {
  const rc = riskColor(analysis.consensusRating);
  const lines: string[] = [
    sectionHeader("PERSONA ANALYSIS SUMMARY"),
    row(""),
    row(`  Consensus Risk: ${rc(analysis.consensusRating.toUpperCase())}`),
    row(""),
  ];

  if (analysis.consensusActions.length > 0) {
    lines.push(row(chalk.bold("  Priority Actions (consensus):")));
    for (const action of analysis.consensusActions.slice(0, 8)) {
      lines.push(row(`    ${AMBER("→")} ${action}`));
    }
    lines.push(row(""));
  }

  for (const pa of analysis.analyses) {
    const accent = personaAccent(pa.persona);
    const rc2 = riskColor(pa.riskRating);
    lines.push(row(`  ${accent("●")} ${accent(pa.displayName)}  ${chalk.dim("risk:")} ${rc2(pa.riskRating.toUpperCase())}`));
    lines.push(row(chalk.dim(`    ${pa.executiveSummary}`)));
  }

  lines.push(row(""));
  return lines.join("\n");
}

export function renderPersonaDetails(analysis: PersonaReport): string {
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const lines: string[] = [
    sectionHeader("PERSONA ANALYSIS DETAILS"),
    row(""),
  ];

  for (const pa of analysis.analyses) {
    const accent = personaAccent(pa.persona);
    const rc = riskColor(pa.riskRating);

    lines.push(row(chalk.cyan(hRule("┌", "─", "┐", W - 2))));
    lines.push(row(`${accent("█")} ${accent(pa.displayName)} — ${chalk.dim(pa.perspective)}`));
    lines.push(row(`  Risk: ${rc(pa.riskRating.toUpperCase())}`));
    lines.push(row(""));

    // Sort insights by severity
    const sorted = [...pa.insights].sort(
      (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
    );

    for (const insight of sorted) {
      const sev = severityColor(insight.severity);
      lines.push(row(`  ${sev(`[${insight.severity.toUpperCase()}]`)} ${chalk.bold(insight.title)}`));
      lines.push(row(chalk.dim(`    ${insight.description}`)));
      if (insight.technicalDetail) {
        lines.push(row(chalk.dim(`    Technical: ${insight.technicalDetail}`)));
      }
      lines.push(row(chalk.dim(`    → ${insight.recommendation}`)));
      if (insight.affectedAssets.length > 0) {
        lines.push(row(chalk.dim(`    Assets: ${insight.affectedAssets.join(", ")}`)));
      }
      lines.push(row(""));
    }

    if (pa.priorityActions.length > 0) {
      lines.push(row(chalk.bold("  Priority Actions:")));
      for (const action of pa.priorityActions) {
        lines.push(row(`    ${accent("→")} ${action}`));
      }
      lines.push(row(""));
    }

    lines.push(row(chalk.cyan(hRule("└", "─", "┘", W - 2))));
    lines.push(row(""));
  }

  return lines.join("\n");
}

// ─── Combined report ──────────────────────────────────────────────────────

export function renderFullAnalysisReport(
  result: NetworkScanResult,
  computed: { compliance: ComplianceReport; analysis: FullAnalysis; rfAnalysis: RFAnalysis },
  verbose = false,
): string {
  const { compliance, analysis } = computed;
  // The scan report ends with ╚═╝ from the scorecard; the analysis sections
  // follow it.
  const sections: string[] = [
    renderTerminalReport(result, computed.rfAnalysis),
  ];

  sections.push(renderComplianceSummary(compliance));
  sections.push(renderPersonaSummary(analysis));

  if (verbose) {
    sections.push(renderComplianceDetails(compliance));
    sections.push(renderPersonaDetails(analysis));
  }

  // Final closing border
  sections.push(chalk.cyan(hRule("╚", "═", "╝")));

  return sections.filter(Boolean).join("\n");
}
