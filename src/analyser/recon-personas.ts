import type { ReconResult } from "../collector/recon/schema.js";
import type { Insight, PersonaAnalysis, RiskRating } from "./personas/types.js";
import {
  riskFromInsights,
  consensusRating,
  consensusActions,
} from "./personas/types.js";

export interface FullReconAnalysis {
  reconId: string;
  timestamp: string;
  domain: string;
  analyses: PersonaAnalysis[];
  consensusRating: string;
  consensusActions: string[];
  overallGrade: string;
}

// ---------------------------------------------------------------------------
// Grade helpers
// ---------------------------------------------------------------------------

const GRADE_VALUES: Record<string, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };

function gradeToNumber(grade: string): number {
  return GRADE_VALUES[grade] ?? 0;
}

function numberToGrade(n: number): string {
  if (n >= 3.5) return "A";
  if (n >= 2.5) return "B";
  if (n >= 1.5) return "C";
  if (n >= 0.5) return "D";
  return "F";
}

// ---------------------------------------------------------------------------
// Red Team
// ---------------------------------------------------------------------------

function analyseRedTeam(r: ReconResult): PersonaAnalysis {
  const insights: Insight[] = [];

  if (r.dns.zoneTransfer.vulnerable) {
    insights.push({
      id: "rr-zone-transfer",
      title: "DNS zone transfer is permitted — full zone disclosure",
      severity: "critical",
      category: "dns",
      description:
        "An unrestricted zone transfer exposes every DNS record in the domain, giving an attacker a complete map of hosts, mail servers, and internal naming conventions.",
      technicalDetail: `Zone transfer succeeded against ${r.dns.zoneTransfer.server ?? "nameserver"} for ${r.dns.domain}.`,
      recommendation:
        "Restrict AXFR to authorised secondary nameservers only. Apply ACLs on all NS hosts.",
      affectedAssets: [r.dns.domain],
      references: ["OWASP-Info-Gathering"],
    });
  }

  if (r.tls.grade === "D" || r.tls.grade === "F") {
    insights.push({
      id: "rr-weak-tls",
      title: `TLS grade ${r.tls.grade} — weak or broken transport security`,
      severity: "high",
      category: "tls",
      description:
        "A poor TLS grade means the connection can be intercepted or downgraded by an attacker using well-known techniques.",
      technicalDetail: `Protocol: ${r.tls.protocol}, cipher: ${r.tls.cipher}. Issues: ${r.tls.issues.join("; ") || "none listed"}.`,
      recommendation:
        "Upgrade to TLS 1.2+ with strong cipher suites. Replace expired or self-signed certificates.",
      affectedAssets: [r.tls.domain],
      references: ["PCI-DSS-4.1"],
    });
  }

  const hsts = r.headers.headers.find((h) => h.header === "Strict-Transport-Security");
  if (!hsts || hsts.status !== "pass") {
    insights.push({
      id: "rr-missing-hsts",
      title: "HSTS missing or misconfigured — downgrade attacks possible",
      severity: "medium",
      category: "headers",
      description:
        "Without a strong HSTS policy, browsers may connect over plain HTTP first, allowing an attacker to intercept and redirect traffic before the TLS upgrade.",
      technicalDetail: hsts ? `HSTS present but failing: ${hsts.detail}` : "HSTS header not found.",
      recommendation:
        "Set Strict-Transport-Security with max-age >= 31536000 and includeSubDomains.",
      affectedAssets: [r.headers.domain],
      references: ["OWASP-Transport"],
    });
  }

  const csp = r.headers.headers.find((h) => h.header === "Content-Security-Policy");
  if (!csp || csp.status !== "pass") {
    insights.push({
      id: "rr-missing-csp",
      title: "Content-Security-Policy missing — XSS and injection risk",
      severity: "medium",
      category: "headers",
      description:
        "Without CSP an attacker who finds an injection point can execute arbitrary scripts with no browser-side mitigation.",
      technicalDetail: csp ? `CSP present but failing: ${csp.detail}` : "CSP header not found.",
      recommendation: "Deploy a restrictive Content-Security-Policy header.",
      affectedAssets: [r.headers.domain],
      references: ["OWASP-XSS"],
    });
  }

  const sensitivePatterns = /\b(dev|staging|admin|test)\b/i;
  const exposedSubs = r.crt.uniqueSubdomains.filter((s) => sensitivePatterns.test(s));
  if (exposedSubs.length > 0) {
    insights.push({
      id: "rr-exposed-subdomains",
      title: `${exposedSubs.length} sensitive subdomain(s) exposed via certificate transparency`,
      severity: "high",
      category: "ct",
      description:
        "Dev, staging, admin, or test subdomains discovered in CT logs are often less hardened and provide easier footholds for attackers.",
      technicalDetail: `Exposed subdomains: ${exposedSubs.join(", ")}.`,
      recommendation:
        "Use wildcard certificates or internal CAs for non-production environments. Restrict access to sensitive subdomains.",
      affectedAssets: exposedSubs,
      references: ["OWASP-Info-Gathering"],
    });
  }

  if (r.tls.certificate.daysUntilExpiry >= 0 && r.tls.certificate.daysUntilExpiry <= 30) {
    insights.push({
      id: "rr-cert-expiring",
      title: `Certificate expires in ${r.tls.certificate.daysUntilExpiry} days`,
      severity: "medium",
      category: "tls",
      description:
        "An expiring certificate will cause browser warnings and service disruption, which attackers can exploit to phish users via look-alike domains.",
      technicalDetail: `Certificate for ${r.tls.domain} valid until ${r.tls.certificate.validTo} (${r.tls.certificate.daysUntilExpiry} days remaining).`,
      recommendation: "Renew the certificate before expiry. Implement automated renewal.",
      affectedAssets: [r.tls.domain],
      references: ["PCI-DSS-4.1"],
    });
  }

  return {
    persona: "red-team",
    displayName: "Red Team",
    perspective:
      "Identifies exploitable weaknesses in the domain's external attack surface that an attacker would target.",
    riskRating: riskFromInsights(insights),
    executiveSummary: buildRedTeamSummary(insights, r.meta.domain),
    insights,
    priorityActions: deriveRedTeamActions(insights),
  };
}

function buildRedTeamSummary(insights: Insight[], domain: string): string {
  const critCount = insights.filter((i) => i.severity === "critical").length;
  const highCount = insights.filter((i) => i.severity === "high").length;
  if (critCount > 0) {
    return `${domain} has critical external weaknesses. ${critCount} critical and ${highCount} high-severity issue(s) give an attacker clear paths to compromise.`;
  }
  if (highCount > 0) {
    return `${domain} has notable external weaknesses. ${highCount} high-severity finding(s) would allow a motivated attacker to gain useful reconnaissance or access.`;
  }
  if (insights.length > 0) {
    return `${domain} has a moderate external attack surface with ${insights.length} finding(s). No critical footholds, but configuration gaps provide reconnaissance value.`;
  }
  return `${domain} presents a hardened external posture. No significant attack vectors were identified.`;
}

function deriveRedTeamActions(insights: Insight[]): string[] {
  const actions: string[] = [];
  const ids = new Set(insights.map((i) => i.id));
  if (ids.has("rr-zone-transfer")) actions.push("Restrict DNS zone transfers to authorised secondaries");
  if (ids.has("rr-weak-tls")) actions.push("Upgrade TLS configuration to grade B or above");
  if (ids.has("rr-exposed-subdomains")) actions.push("Restrict access to dev/staging/admin subdomains");
  if (ids.has("rr-missing-hsts")) actions.push("Deploy HSTS with adequate max-age");
  if (ids.has("rr-missing-csp")) actions.push("Implement a Content-Security-Policy header");
  if (ids.has("rr-cert-expiring")) actions.push("Renew the expiring TLS certificate");
  return actions.slice(0, 5);
}

// ---------------------------------------------------------------------------
// Blue Team
// ---------------------------------------------------------------------------

function analyseBlueTeam(r: ReconResult): PersonaAnalysis {
  const insights: Insight[] = [];

  const hsts = r.headers.headers.find((h) => h.header === "Strict-Transport-Security");
  insights.push({
    id: "rb-hsts",
    title: hsts?.status === "pass" ? "HSTS is properly configured" : "HSTS is not adequately configured",
    severity: hsts?.status === "pass" ? "info" : "medium",
    category: "headers",
    description: hsts?.status === "pass"
      ? "HSTS is set with an adequate max-age, protecting against protocol downgrade attacks."
      : "HSTS is missing or has an insufficient max-age, leaving the domain vulnerable to SSL stripping.",
    technicalDetail: hsts ? hsts.detail : "HSTS header not present.",
    recommendation: hsts?.status === "pass"
      ? "Maintain the current HSTS configuration."
      : "Set Strict-Transport-Security with max-age >= 31536000 and includeSubDomains.",
    affectedAssets: [r.headers.domain],
    references: ["OWASP-Transport"],
  });

  const csp = r.headers.headers.find((h) => h.header === "Content-Security-Policy");
  insights.push({
    id: "rb-csp",
    title: csp?.status === "pass" ? "CSP is deployed" : "CSP is not deployed",
    severity: csp?.status === "pass" ? "info" : "medium",
    category: "headers",
    description: csp?.status === "pass"
      ? "Content-Security-Policy is present, providing browser-side XSS mitigation."
      : "No CSP header was found, leaving the application without browser-enforced script restrictions.",
    technicalDetail: csp ? csp.detail : "CSP header not present.",
    recommendation: csp?.status === "pass"
      ? "Review CSP directives periodically for completeness."
      : "Deploy a restrictive Content-Security-Policy.",
    affectedAssets: [r.headers.domain],
    references: ["OWASP-XSS"],
  });

  const passCount = r.headers.headers.filter((h) => h.status === "pass").length;
  const totalChecks = r.headers.headers.length;
  const headerCoverage = totalChecks > 0 ? passCount / totalChecks : 0;
  insights.push({
    id: "rb-header-coverage",
    title: headerCoverage >= 0.8 ? "Security header coverage is good" : "Security header coverage is incomplete",
    severity: headerCoverage >= 0.8 ? "info" : "medium",
    category: "headers",
    description: `${passCount} of ${totalChecks} security headers pass. ${headerCoverage >= 0.8 ? "Coverage is adequate." : "Gaps leave the application exposed to common browser-based attacks."}`,
    technicalDetail: `Headers passing: ${passCount}/${totalChecks} (${Math.round(headerCoverage * 100)}%).`,
    recommendation: headerCoverage >= 0.8
      ? "Maintain current header configuration."
      : "Address missing or misconfigured security headers.",
    affectedAssets: [r.headers.domain],
    references: ["OWASP-Headers"],
  });

  insights.push({
    id: "rb-dnssec",
    title: r.whois.dnssec ? "DNSSEC is enabled" : "DNSSEC is not enabled",
    severity: r.whois.dnssec ? "info" : "medium",
    category: "dns",
    description: r.whois.dnssec
      ? "DNSSEC protects against DNS spoofing by cryptographically signing records."
      : "Without DNSSEC, DNS responses can be forged, enabling cache poisoning and redirection attacks.",
    technicalDetail: `DNSSEC status from WHOIS: ${r.whois.dnssec ? "signed" : "unsigned"}.`,
    recommendation: r.whois.dnssec
      ? "Maintain DNSSEC signing and monitor for key rotation."
      : "Enable DNSSEC on the domain to protect against DNS spoofing.",
    affectedAssets: [r.dns.domain],
    references: ["NIST-800-81"],
  });

  const certValid = r.tls.certificate.daysUntilExpiry > 0 && !r.tls.certificate.selfSigned;
  insights.push({
    id: "rb-cert-chain",
    title: certValid ? "Certificate chain is valid" : "Certificate chain has issues",
    severity: certValid ? "info" : "high",
    category: "tls",
    description: certValid
      ? "The TLS certificate is valid, not self-signed, and has a healthy expiry window."
      : "The certificate is self-signed or expired, which will cause trust warnings and may indicate a compromised certificate chain.",
    technicalDetail: `Issuer: ${r.tls.certificate.issuer}, expiry: ${r.tls.certificate.validTo}, days remaining: ${r.tls.certificate.daysUntilExpiry}, self-signed: ${r.tls.certificate.selfSigned}.`,
    recommendation: certValid
      ? "Continue monitoring certificate expiry."
      : "Replace the certificate with one from a trusted CA and ensure it is not expired.",
    affectedAssets: [r.tls.domain],
    references: ["PCI-DSS-4.1"],
  });

  return {
    persona: "blue-team",
    displayName: "Blue Team",
    perspective:
      "Evaluates defensive controls and detection capabilities protecting the domain's external surface.",
    riskRating: riskFromInsights(insights),
    executiveSummary: buildBlueTeamSummary(insights, r.meta.domain),
    insights,
    priorityActions: deriveBlueTeamActions(insights),
  };
}

function buildBlueTeamSummary(insights: Insight[], domain: string): string {
  const failing = insights.filter((i) => i.severity !== "info");
  if (failing.length === 0) {
    return `${domain} has strong defensive controls across all checked areas. All security headers, DNSSEC, and certificate checks pass.`;
  }
  return `${domain} has ${failing.length} defensive gap(s) that should be addressed to strengthen the external security posture.`;
}

function deriveBlueTeamActions(insights: Insight[]): string[] {
  const actions: string[] = [];
  for (const i of insights) {
    if (i.severity !== "info") {
      actions.push(i.recommendation);
    }
  }
  return actions.slice(0, 5);
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

function analyseCompliance(r: ReconResult): PersonaAnalysis {
  const insights: Insight[] = [];

  const tlsOk = r.tls.protocol.includes("TLSv1.2") || r.tls.protocol.includes("TLSv1.3");
  insights.push({
    id: "rc-tls-version",
    title: tlsOk ? "TLS 1.2+ in use (PCI-DSS compliant)" : "TLS version below 1.2 (PCI-DSS non-compliant)",
    severity: tlsOk ? "info" : "high",
    category: "compliance",
    description: tlsOk
      ? "The server negotiates TLS 1.2 or higher, meeting PCI-DSS requirements for transport encryption."
      : "PCI-DSS requires TLS 1.2 or higher. The current protocol version does not meet this requirement.",
    technicalDetail: `Negotiated protocol: ${r.tls.protocol}.`,
    recommendation: tlsOk
      ? "Continue enforcing TLS 1.2+ and disable older protocols."
      : "Upgrade the server to support TLS 1.2 or 1.3 and disable older versions.",
    affectedAssets: [r.tls.domain],
    references: ["PCI-DSS-4.1"],
  });

  const hsts = r.headers.headers.find((h) => h.header === "Strict-Transport-Security");
  const hstsOk = hsts?.status === "pass";
  insights.push({
    id: "rc-hsts",
    title: hstsOk ? "HSTS present (PCI-DSS/OWASP compliant)" : "HSTS missing (PCI-DSS/OWASP non-compliant)",
    severity: hstsOk ? "info" : "medium",
    category: "compliance",
    description: hstsOk
      ? "HSTS is properly configured, meeting both PCI-DSS transport and OWASP header requirements."
      : "Both PCI-DSS and OWASP recommend HSTS to prevent protocol downgrade attacks.",
    technicalDetail: hsts ? hsts.detail : "HSTS header not present.",
    recommendation: hstsOk
      ? "Maintain HSTS configuration."
      : "Deploy HSTS with max-age >= 31536000.",
    affectedAssets: [r.headers.domain],
    references: ["PCI-DSS-4.1", "OWASP-Transport"],
  });

  const securityHeaders = r.headers.headers.filter((h) => h.header !== "Server");
  const missingHeaders = securityHeaders.filter((h) => h.status !== "pass");
  insights.push({
    id: "rc-headers-completeness",
    title: missingHeaders.length === 0
      ? "All OWASP-recommended security headers present"
      : `${missingHeaders.length} OWASP-recommended security header(s) missing or misconfigured`,
    severity: missingHeaders.length === 0 ? "info" : "medium",
    category: "compliance",
    description: missingHeaders.length === 0
      ? "All recommended security headers are deployed per OWASP guidance."
      : `Missing or failing headers: ${missingHeaders.map((h) => h.header).join(", ")}.`,
    technicalDetail: `${securityHeaders.length - missingHeaders.length}/${securityHeaders.length} security headers pass.`,
    recommendation: missingHeaders.length === 0
      ? "Continue maintaining security header coverage."
      : `Deploy the following headers: ${missingHeaders.map((h) => h.header).join(", ")}.`,
    affectedAssets: [r.headers.domain],
    references: ["OWASP-Headers"],
  });

  const certValid = r.tls.certificate.daysUntilExpiry > 0 && !r.tls.certificate.selfSigned;
  insights.push({
    id: "rc-cert-validity",
    title: certValid ? "TLS certificate is valid" : "TLS certificate validity issue",
    severity: certValid ? "info" : "high",
    category: "compliance",
    description: certValid
      ? "The certificate is issued by a trusted CA and is within its validity period."
      : "An expired or self-signed certificate violates compliance requirements for trusted transport.",
    technicalDetail: `Valid to: ${r.tls.certificate.validTo}, self-signed: ${r.tls.certificate.selfSigned}, days remaining: ${r.tls.certificate.daysUntilExpiry}.`,
    recommendation: certValid
      ? "Monitor certificate expiry and renew proactively."
      : "Replace the certificate with a valid one from a trusted CA.",
    affectedAssets: [r.tls.domain],
    references: ["PCI-DSS-4.1"],
  });

  return {
    persona: "compliance",
    displayName: "Compliance",
    perspective:
      "Assesses the domain against PCI-DSS, OWASP, and industry compliance requirements for external-facing services.",
    riskRating: riskFromInsights(insights),
    executiveSummary: buildComplianceSummary(insights, r.meta.domain),
    insights,
    priorityActions: deriveComplianceActions(insights),
  };
}

function buildComplianceSummary(insights: Insight[], domain: string): string {
  const nonCompliant = insights.filter((i) => i.severity !== "info");
  if (nonCompliant.length === 0) {
    return `${domain} meets all checked compliance requirements for PCI-DSS transport encryption, OWASP security headers, and certificate validity.`;
  }
  return `${domain} has ${nonCompliant.length} compliance gap(s) across PCI-DSS and OWASP requirements that require remediation.`;
}

function deriveComplianceActions(insights: Insight[]): string[] {
  const actions: string[] = [];
  for (const i of insights) {
    if (i.severity !== "info") {
      actions.push(i.recommendation);
    }
  }
  return actions.slice(0, 5);
}

// ---------------------------------------------------------------------------
// Net Engineer
// ---------------------------------------------------------------------------

function analyseNetEngineer(r: ReconResult): PersonaAnalysis {
  const insights: Insight[] = [];

  const mxRecords = r.dns.records.filter((rec) => rec.type === "MX");
  insights.push({
    id: "rn-mx",
    title: mxRecords.length > 0 ? "MX records configured" : "No MX records found",
    severity: mxRecords.length > 0 ? "info" : "medium",
    category: "dns",
    description: mxRecords.length > 0
      ? `${mxRecords.length} MX record(s) configured for mail delivery.`
      : "No MX records found. Email delivery to this domain will fail.",
    technicalDetail: mxRecords.length > 0
      ? `MX records: ${mxRecords.map((m) => m.value).join(", ")}.`
      : "dig MX returned no results.",
    recommendation: mxRecords.length > 0
      ? "Verify MX priorities and ensure backup MX is configured."
      : "Add MX records if the domain should receive email.",
    affectedAssets: [r.dns.domain],
    references: ["RFC-5321"],
  });

  const txtRecords = r.dns.records.filter((rec) => rec.type === "TXT");
  const hasSPF = txtRecords.some((rec) => rec.value.toLowerCase().startsWith("v=spf1"));
  insights.push({
    id: "rn-spf",
    title: hasSPF ? "SPF record present" : "No SPF record found",
    severity: hasSPF ? "info" : "medium",
    category: "dns",
    description: hasSPF
      ? "An SPF record is configured, helping prevent email spoofing."
      : "Without an SPF record, attackers can send emails appearing to come from this domain.",
    technicalDetail: hasSPF
      ? `SPF: ${txtRecords.find((rec) => rec.value.toLowerCase().startsWith("v=spf1"))!.value}`
      : "No TXT record starting with v=spf1 found.",
    recommendation: hasSPF
      ? "Review SPF record for completeness and avoid using +all."
      : "Add an SPF TXT record to authorise legitimate mail senders.",
    affectedAssets: [r.dns.domain],
    references: ["RFC-7208"],
  });

  const nsCount = r.dns.nameservers.length;
  insights.push({
    id: "rn-ns-redundancy",
    title: nsCount >= 2 ? `NS redundancy adequate (${nsCount} nameservers)` : `Insufficient NS redundancy (${nsCount} nameserver)`,
    severity: nsCount >= 2 ? "info" : "high",
    category: "dns",
    description: nsCount >= 2
      ? `${nsCount} nameservers provide adequate redundancy for DNS resolution.`
      : "A single nameserver is a single point of failure. If it goes down, the domain becomes unresolvable.",
    technicalDetail: `Nameservers: ${r.dns.nameservers.join(", ") || "none found"}.`,
    recommendation: nsCount >= 2
      ? "Ensure nameservers are geographically distributed."
      : "Add at least one additional nameserver for redundancy.",
    affectedAssets: r.dns.nameservers.length > 0 ? r.dns.nameservers : [r.dns.domain],
    references: ["RFC-1034"],
  });

  const aRecords = r.dns.records.filter((rec) => rec.type === "A" || rec.type === "AAAA");
  const lowTtl = aRecords.filter((rec) => rec.ttl < 300);
  const highTtl = aRecords.filter((rec) => rec.ttl > 86400);
  if (lowTtl.length > 0) {
    insights.push({
      id: "rn-ttl-low",
      title: `${lowTtl.length} record(s) with very low TTL (<300s)`,
      severity: "low",
      category: "dns",
      description:
        "Very low TTLs cause frequent DNS lookups, increasing resolution latency and load on nameservers.",
      technicalDetail: `Low-TTL records: ${lowTtl.map((rec) => `${rec.name} ${rec.type} TTL=${rec.ttl}`).join(", ")}.`,
      recommendation: "Unless in the middle of a migration, increase TTLs to at least 300 seconds.",
      affectedAssets: lowTtl.map((rec) => rec.name),
      references: ["RFC-1034"],
    });
  }
  if (highTtl.length > 0) {
    insights.push({
      id: "rn-ttl-high",
      title: `${highTtl.length} record(s) with very high TTL (>86400s)`,
      severity: "low",
      category: "dns",
      description:
        "Very high TTLs delay propagation of DNS changes, which can cause extended outages during migrations or incident response.",
      technicalDetail: `High-TTL records: ${highTtl.map((rec) => `${rec.name} ${rec.type} TTL=${rec.ttl}`).join(", ")}.`,
      recommendation: "Consider reducing TTLs to 3600s or less for operational flexibility.",
      affectedAssets: highTtl.map((rec) => rec.name),
      references: ["RFC-1034"],
    });
  }

  return {
    persona: "net-engineer",
    displayName: "Net Engineer",
    perspective:
      "Evaluates DNS configuration quality, redundancy, and operational best practices for the domain.",
    riskRating: riskFromInsights(insights),
    executiveSummary: buildNetEngineerSummary(insights, r.meta.domain),
    insights,
    priorityActions: deriveNetEngineerActions(insights),
  };
}

function buildNetEngineerSummary(insights: Insight[], domain: string): string {
  const issues = insights.filter((i) => i.severity !== "info");
  if (issues.length === 0) {
    return `${domain} DNS configuration is well structured with adequate redundancy, SPF, and MX records.`;
  }
  return `${domain} DNS configuration has ${issues.length} issue(s) affecting reliability or email deliverability.`;
}

function deriveNetEngineerActions(insights: Insight[]): string[] {
  const actions: string[] = [];
  for (const i of insights) {
    if (i.severity !== "info") {
      actions.push(i.recommendation);
    }
  }
  return actions.slice(0, 5);
}

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

function analysePrivacy(r: ReconResult): PersonaAnalysis {
  const insights: Insight[] = [];

  const server = r.headers.headers.find((h) => h.header === "Server");
  if (server?.present && server.status === "fail") {
    insights.push({
      id: "rp-server-leak",
      title: "Server header reveals software version",
      severity: "medium",
      category: "headers",
      description:
        "The Server header exposes the web server software and version, giving attackers a head start on finding applicable CVEs.",
      technicalDetail: `Server header value: ${server.value}.`,
      recommendation: "Remove or generalise the Server header to prevent version disclosure.",
      affectedAssets: [r.headers.domain],
      references: ["OWASP-Info-Gathering"],
    });
  }

  const referrer = r.headers.headers.find((h) => h.header === "Referrer-Policy");
  if (!referrer || referrer.status !== "pass") {
    insights.push({
      id: "rp-referrer-policy",
      title: "Referrer-Policy missing or weak",
      severity: "medium",
      category: "headers",
      description:
        "Without a Referrer-Policy, full URLs (including query parameters that may contain tokens or PII) leak to third-party sites via the Referer header.",
      technicalDetail: referrer ? referrer.detail : "Referrer-Policy header not present.",
      recommendation: "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
      affectedAssets: [r.headers.domain],
      references: ["OWASP-Privacy"],
    });
  }

  const permissions = r.headers.headers.find((h) => h.header === "Permissions-Policy");
  if (!permissions || permissions.status !== "pass") {
    insights.push({
      id: "rp-permissions-policy",
      title: "Permissions-Policy missing",
      severity: "low",
      category: "headers",
      description:
        "Without Permissions-Policy, embedded content can access browser features like camera, microphone, and geolocation without restriction.",
      technicalDetail: permissions ? permissions.detail : "Permissions-Policy header not present.",
      recommendation: "Deploy a Permissions-Policy to restrict browser feature access.",
      affectedAssets: [r.headers.domain],
      references: ["OWASP-Privacy"],
    });
  }

  const whoisRedacted = r.whois.registrant === null ||
    r.whois.registrant.toLowerCase().includes("redacted") ||
    r.whois.registrant.toLowerCase().includes("privacy") ||
    r.whois.registrant.toLowerCase().includes("proxy");
  if (!whoisRedacted) {
    insights.push({
      id: "rp-whois-exposed",
      title: "WHOIS data not redacted — registrant information exposed",
      severity: "low",
      category: "whois",
      description:
        "The domain WHOIS record exposes registrant details, which can be used for social engineering, targeted phishing, or building a profile of the organisation.",
      technicalDetail: `Registrant: ${r.whois.registrant}.`,
      recommendation: "Enable WHOIS privacy protection through the registrar.",
      affectedAssets: [r.whois.domain],
      references: ["GDPR-Art-5"],
    });
  }

  return {
    persona: "privacy",
    displayName: "Privacy",
    perspective:
      "Assesses information leakage and privacy exposure from the domain's external configuration.",
    riskRating: riskFromInsights(insights),
    executiveSummary: buildPrivacySummary(insights, r.meta.domain),
    insights,
    priorityActions: derivePrivacyActions(insights),
  };
}

function buildPrivacySummary(insights: Insight[], domain: string): string {
  if (insights.length === 0) {
    return `${domain} has minimal privacy exposure. Server headers are clean, privacy-related headers are deployed, and WHOIS data is redacted.`;
  }
  const medCount = insights.filter((i) => i.severity === "medium").length;
  return `${domain} has ${insights.length} privacy concern(s)${medCount > 0 ? `, ${medCount} at medium severity` : ""}. Information leakage from headers or WHOIS could aid targeted attacks.`;
}

function derivePrivacyActions(insights: Insight[]): string[] {
  const actions: string[] = [];
  for (const i of insights) {
    actions.push(i.recommendation);
  }
  return actions.slice(0, 5);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function analyseReconAllPersonas(result: ReconResult): FullReconAnalysis {
  const analyses: PersonaAnalysis[] = [
    analyseRedTeam(result),
    analyseBlueTeam(result),
    analyseCompliance(result),
    analyseNetEngineer(result),
    analysePrivacy(result),
  ];

  const ratings = analyses.map((a) => a.riskRating) as RiskRating[];
  const allActions = analyses.map((a) => a.priorityActions);

  const tlsGrade = gradeToNumber(result.tls.grade);
  const headersGrade = gradeToNumber(result.headers.grade);
  const overallGrade = numberToGrade((tlsGrade + headersGrade) / 2);

  return {
    reconId: result.meta.reconId,
    timestamp: result.meta.timestamp,
    domain: result.meta.domain,
    analyses,
    consensusRating: consensusRating(ratings),
    consensusActions: consensusActions(allActions),
    overallGrade,
  };
}
