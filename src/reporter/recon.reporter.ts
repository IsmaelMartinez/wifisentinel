import chalk from "chalk";
import type { ReconResult } from "../collector/recon/schema.js";
import type { FullReconAnalysis } from "../analyser/recon-personas.js";
import {
  W,
  TEAL,
  AMBER,
  RED,
  hRule,
  boxLine,
  sectionHeader,
  pad,
  row,
  scoreBar,
  gradeColor,
  statusIcon,
} from "./render-helpers.js";
import { renderPersonaSummary, renderPersonaDetails } from "./analysis.reporter.js";

// ─── Section renderers ────────────────────────────────────────────────────

function renderHeader(result: ReconResult): string {
  const { meta } = result;
  const ts = new Date(meta.timestamp).toLocaleString();
  const title = "EXTERNAL RECONNAISSANCE";
  const titlePad = Math.floor((W - title.length) / 2);

  return [
    chalk.cyan(hRule("╔", "═", "╗")),
    chalk.cyan("║") + " ".repeat(W + 2) + chalk.cyan("║"),
    chalk.cyan("║") + " ".repeat(titlePad) + chalk.cyan.bold(title) + " ".repeat(W + 2 - titlePad - title.length) + chalk.cyan("║"),
    chalk.cyan("║") + " ".repeat(W + 2) + chalk.cyan("║"),
    boxLine(chalk.dim(`Domain   : ${meta.domain}`)),
    boxLine(chalk.dim(`Recon ID : ${meta.reconId}`)),
    boxLine(chalk.dim(`Time     : ${ts}  (${meta.duration}ms)`)),
    chalk.cyan("║") + " ".repeat(W + 2) + chalk.cyan("║"),
    chalk.cyan(hRule("╚", "═", "╝")),
  ].join("\n");
}

function renderDns(result: ReconResult): string {
  const { dns } = result;
  const lines: string[] = [
    sectionHeader("DNS ENUMERATION"),
    row(""),
    row(chalk.bold("  Records")),
  ];

  if (dns.records.length === 0) {
    lines.push(row(chalk.dim("    (no records found)")));
  } else {
    for (const rec of dns.records.slice(0, 20)) {
      lines.push(row(`    ${pad(rec.type, 8)} ${pad(rec.name, 30)} ${chalk.dim(`TTL=${rec.ttl}`)}  ${rec.value}`));
    }
    if (dns.records.length > 20) {
      lines.push(row(chalk.dim(`    ... and ${dns.records.length - 20} more`)));
    }
  }

  lines.push(row(""));
  lines.push(row(chalk.bold("  Nameservers")));
  if (dns.nameservers.length === 0) {
    lines.push(row(chalk.dim("    (none found)")));
  } else {
    lines.push(row(`    ${dns.nameservers.join("  ")}`));
  }

  lines.push(row(""));
  lines.push(row(chalk.bold("  Subdomains (DNS brute)")));
  if (dns.subdomains.length === 0) {
    lines.push(row(chalk.dim("    (none resolved)")));
  } else {
    for (const sub of dns.subdomains.slice(0, 15)) {
      lines.push(row(`    ${TEAL(sub.name)}  ${chalk.dim(sub.ips.join(", "))}`));
    }
    if (dns.subdomains.length > 15) {
      lines.push(row(chalk.dim(`    ... and ${dns.subdomains.length - 15} more`)));
    }
  }

  lines.push(row(""));
  const ztStatus = dns.zoneTransfer.vulnerable
    ? RED("VULNERABLE — zone transfer succeeded")
    : dns.zoneTransfer.attempted
      ? TEAL("secure — zone transfer refused")
      : chalk.dim("not tested");
  lines.push(row(`  Zone Transfer  ${ztStatus}`));
  if (dns.zoneTransfer.server) {
    lines.push(row(chalk.dim(`    Server: ${dns.zoneTransfer.server}`)));
  }

  lines.push(row(""));
  return lines.join("\n");
}

function renderTls(result: ReconResult): string {
  const { tls } = result;
  const gc = gradeColor(tls.grade);
  const lines: string[] = [
    sectionHeader("TLS / SSL"),
    row(""),
    row(`  Grade        ${gc(tls.grade)}`),
    row(`  Protocol     ${chalk.cyan(tls.protocol)}`),
    row(`  Cipher       ${chalk.dim(tls.cipher)}`),
    row(`  Chain Depth  ${tls.chainDepth}`),
    row(""),
    row(chalk.bold("  Certificate")),
    row(`    Issuer       ${tls.certificate.issuer}`),
    row(`    Subject      ${tls.certificate.subject}`),
    row(`    Valid From   ${tls.certificate.validFrom}`),
    row(`    Valid To     ${tls.certificate.validTo}`),
    row(`    Expiry       ${tls.certificate.daysUntilExpiry > 30 ? TEAL(tls.certificate.daysUntilExpiry + " days") : tls.certificate.daysUntilExpiry > 0 ? AMBER(tls.certificate.daysUntilExpiry + " days") : RED("EXPIRED")}`),
    row(`    Self-signed  ${tls.certificate.selfSigned ? RED("yes") : TEAL("no")}`),
  ];

  if (tls.certificate.sans.length > 0) {
    lines.push(row(`    SANs         ${tls.certificate.sans.slice(0, 5).join(", ")}${tls.certificate.sans.length > 5 ? chalk.dim(` +${tls.certificate.sans.length - 5} more`) : ""}`));
  }

  if (tls.issues.length > 0) {
    lines.push(row(""));
    lines.push(row(AMBER("  Issues:")));
    for (const issue of tls.issues) {
      lines.push(row(AMBER(`    ⚠  ${issue}`)));
    }
  }

  lines.push(row(""));
  return lines.join("\n");
}

function renderHeaders(result: ReconResult): string {
  const { headers } = result;
  const gc = gradeColor(headers.grade);
  const lines: string[] = [
    sectionHeader("HTTP SECURITY HEADERS"),
    row(""),
    row(`  URL          ${chalk.dim(headers.url)}`),
    row(`  Status       ${headers.statusCode}`),
    row(`  Grade        ${gc(headers.grade)}   Score: ${chalk.bold(String(headers.score) + "/100")}`),
    row(""),
  ];

  for (const h of headers.headers) {
    const icon = statusIcon(h.status);
    const val = h.value ? chalk.dim(` (${h.value.length > 40 ? h.value.slice(0, 40) + "..." : h.value})`) : "";
    lines.push(row(`  ${icon}  ${pad(h.header, 30)} ${chalk.dim(h.detail)}${val}`));
  }

  lines.push(row(""));
  return lines.join("\n");
}

function renderWhois(result: ReconResult): string {
  const { whois } = result;
  const lines: string[] = [
    sectionHeader("WHOIS"),
    row(""),
    row(`  Registrar    ${whois.registrar ?? chalk.dim("unknown")}`),
    row(`  Created      ${whois.createdDate ?? chalk.dim("unknown")}`),
    row(`  Expires      ${whois.expiryDate ?? chalk.dim("unknown")}`),
    row(`  Updated      ${whois.updatedDate ?? chalk.dim("unknown")}`),
    row(`  DNSSEC       ${whois.dnssec ? TEAL("enabled") : AMBER("not enabled")}`),
    row(`  Registrant   ${whois.registrant ?? chalk.dim("redacted")}`),
  ];

  if (whois.nameservers.length > 0) {
    lines.push(row(`  Nameservers  ${whois.nameservers.join(", ")}`));
  }

  lines.push(row(""));
  return lines.join("\n");
}

function renderCrt(result: ReconResult): string {
  const { crt } = result;
  const lines: string[] = [
    sectionHeader("CERTIFICATE TRANSPARENCY"),
    row(""),
    row(`  Unique subdomains: ${chalk.bold(String(crt.uniqueSubdomains.length))}`),
  ];

  if (crt.uniqueSubdomains.length > 0) {
    lines.push(row(""));
    for (const sub of crt.uniqueSubdomains.slice(0, 20)) {
      lines.push(row(`    ${chalk.dim(sub)}`));
    }
    if (crt.uniqueSubdomains.length > 20) {
      lines.push(row(chalk.dim(`    ... and ${crt.uniqueSubdomains.length - 20} more`)));
    }
  }

  lines.push(row(""));
  return lines.join("\n");
}

function renderShodan(result: ReconResult): string {
  const { shodan } = result;
  if (!shodan) return "";

  const lines: string[] = [
    sectionHeader("SHODAN"),
    row(""),
    row(`  IP           ${TEAL(shodan.ip || chalk.dim("unknown"))}`),
    row(`  ISP          ${shodan.isp ?? chalk.dim("unknown")}`),
    row(`  OS           ${shodan.os ?? chalk.dim("unknown")}`),
    row(`  Last Scan    ${shodan.lastScanDate ?? chalk.dim("unknown")}`),
    row(""),
  ];

  if (shodan.openPorts.length > 0) {
    lines.push(row(chalk.bold("  Open Ports")));
    lines.push(row(`    ${shodan.openPorts.join("  ")}`));
    lines.push(row(""));
  }

  if (shodan.services.length > 0) {
    lines.push(row(chalk.bold("  Services")));
    for (const svc of shodan.services.slice(0, 15)) {
      const label = [svc.product, svc.version].filter(Boolean).join(" ") || chalk.dim("unknown");
      lines.push(row(`    ${pad(String(svc.port) + "/" + svc.transport, 12)} ${label}`));
    }
    if (shodan.services.length > 15) {
      lines.push(row(chalk.dim(`    ... and ${shodan.services.length - 15} more`)));
    }
    lines.push(row(""));
  }

  if (shodan.vulns.length > 0) {
    lines.push(row(RED.bold("  Vulnerabilities")));
    for (const vuln of shodan.vulns.slice(0, 10)) {
      lines.push(row(`    ${RED("⚠")} ${vuln}`));
    }
    if (shodan.vulns.length > 10) {
      lines.push(row(chalk.dim(`    ... and ${shodan.vulns.length - 10} more`)));
    }
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderCensys(result: ReconResult): string {
  const { censys } = result;
  if (!censys) return "";

  const lines: string[] = [
    sectionHeader("CENSYS"),
    row(""),
    row(`  Autonomous System  ${censys.autonomousSystem ?? chalk.dim("unknown")}`),
    row(`  Location           ${censys.location ?? chalk.dim("unknown")}`),
    row(""),
  ];

  if (censys.services.length > 0) {
    lines.push(row(chalk.bold("  Services")));
    for (const svc of censys.services.slice(0, 15)) {
      lines.push(row(`    ${pad(String(svc.port) + "/" + svc.transportProtocol, 12)} ${TEAL(svc.serviceName || chalk.dim("unknown"))}`));
    }
    if (censys.services.length > 15) {
      lines.push(row(chalk.dim(`    ... and ${censys.services.length - 15} more`)));
    }
    lines.push(row(""));
  }

  if (censys.certificates.length > 0) {
    lines.push(row(chalk.bold("  Certificates")));
    for (const cert of censys.certificates.slice(0, 5)) {
      lines.push(row(`    ${AMBER(cert.length > 60 ? cert.slice(0, 60) + "..." : cert)}`));
    }
    if (censys.certificates.length > 5) {
      lines.push(row(chalk.dim(`    ... and ${censys.certificates.length - 5} more`)));
    }
    lines.push(row(""));
  }

  return lines.join("\n");
}

function renderScorecard(result: ReconResult): string {
  const tlsGrade = result.tls.grade;
  const headersGrade = result.headers.grade;
  const gradeValues: Record<string, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };
  const avg = ((gradeValues[tlsGrade] ?? 0) + (gradeValues[headersGrade] ?? 0)) / 2;
  const overall = avg >= 3.5 ? "A" : avg >= 2.5 ? "B" : avg >= 1.5 ? "C" : avg >= 0.5 ? "D" : "F";
  const gc = gradeColor(overall);

  const bar = scoreBar(Math.round(avg * 2.5));

  return [
    sectionHeader("SCORECARD"),
    row(""),
    row(`  TLS Grade       ${gradeColor(tlsGrade)(tlsGrade)}`),
    row(`  Headers Grade   ${gradeColor(headersGrade)(headersGrade)}`),
    row(`  Overall         ${gc(overall)}   ${bar}`),
    row(""),
    chalk.cyan(hRule("╚", "═", "╝")),
  ].join("\n");
}

// ─── Public API ───────────────────────────────────────────────────────────

export function renderReconReport(result: ReconResult): string {
  return [
    renderHeader(result),
    renderDns(result),
    renderTls(result),
    renderHeaders(result),
    renderWhois(result),
    renderCrt(result),
    renderShodan(result),
    renderCensys(result),
    renderScorecard(result),
  ].filter(Boolean).join("\n");
}

export function renderReconAnalysisReport(
  result: ReconResult,
  analysis: FullReconAnalysis,
  verbose?: boolean,
): string {
  const sections: string[] = [
    renderHeader(result),
    renderDns(result),
    renderTls(result),
    renderHeaders(result),
    renderWhois(result),
    renderCrt(result),
    renderShodan(result),
    renderCensys(result),
    renderPersonaSummary(analysis),
  ].filter(Boolean);

  if (verbose) {
    sections.push(renderPersonaDetails(analysis));
  }

  sections.push(renderScorecard(result));

  return sections.join("\n");
}
