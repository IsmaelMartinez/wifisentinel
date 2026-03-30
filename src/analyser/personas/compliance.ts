import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { Insight, PersonaAnalysis } from "./types.js";
import { riskFromInsights } from "./types.js";

const PERSONA_ID = "compliance" as const;
const DISPLAY_NAME = "Compliance Officer";
const PERSPECTIVE =
  "Assesses adherence to regulatory frameworks, industry standards, and organisational security policies.";

export function analyseAsCompliance(
  result: NetworkScanResult,
): PersonaAnalysis {
  const insights: Insight[] = [];

  // --- Encryption controls ---
  const weakPatterns = ["WEP", "WPA ", "Open", "None"];
  const isWeak = weakPatterns.some((p) =>
    result.wifi.security.toUpperCase().startsWith(p.toUpperCase()),
  );
  if (isWeak) {
    insights.push({
      id: "co-weak-encryption",
      title:
        "Non-compliant wireless encryption — fails minimum data protection requirements",
      severity: "critical",
      category: "data-protection",
      description: `The current wireless encryption standard (${result.wifi.security}) does not meet the minimum cryptographic requirements mandated by CIS Wireless benchmarks and NIST guidelines. This is a control failure that must be documented and remediated.`,
      technicalDetail: `Wi-Fi security: ${result.wifi.security}. SSID: "${result.wifi.ssid ?? "(hidden)"}", BSSID: ${result.wifi.bssid}.`,
      recommendation:
        "Remediation required: upgrade to WPA3-Personal or WPA2-AES. Document the finding in the risk register and set a remediation deadline.",
      affectedAssets: [result.wifi.bssid, result.wifi.ssid ?? "(hidden)"],
      references: ["CIS-W-1.1", "NIST-800-153-3.2", "IEEE-802.11-9.4"],
    });
  }

  // --- Firewall control ---
  if (!result.security.firewall.enabled) {
    insights.push({
      id: "co-firewall-control-failure",
      title: "Firewall control not implemented — access control requirement unmet",
      severity: "critical",
      category: "access-control",
      description: `A host-based firewall is a mandatory control under CIS and NIST frameworks. Its absence constitutes a control failure that must be reported in the next compliance audit.`,
      technicalDetail: `macOS Application Firewall: disabled. Stealth mode: ${result.security.firewall.stealthMode}.`,
      recommendation:
        "Enable the firewall immediately. Document the gap period. Update the control assessment to reflect current status.",
      affectedAssets: [result.meta.hostname],
      references: ["CIS-W-5.1", "NIST-800-153-5.1"],
    });
  }

  // --- DNSSEC and DNS security controls ---
  if (!result.network.dns.dnssecSupported) {
    insights.push({
      id: "co-dnssec-not-implemented",
      title: "DNSSEC validation not implemented — integrity control gap",
      severity: "medium",
      category: "data-protection",
      description: `DNSSEC is recommended by NIST SP 800-81 and CIS benchmarks to ensure DNS response integrity. Without it, DNS-based attacks cannot be detected through validation, creating an audit finding.`,
      technicalDetail: `DNSSEC supported: false. DNS servers: ${result.network.dns.servers.join(", ")}. DoH/DoT: ${result.network.dns.dohDotEnabled}.`,
      recommendation:
        "Implement DNSSEC-validating resolvers. Document in the remediation plan with target completion date.",
      affectedAssets: result.network.dns.servers,
      references: ["CIS-W-4.1", "NIST-800-153-3.3"],
    });
  }

  if (result.network.dns.hijackTestResult === "intercepted") {
    insights.push({
      id: "co-dns-integrity-compromised",
      title: "DNS integrity compromised — data in transit control violated",
      severity: "high",
      category: "data-protection",
      description: `DNS query interception violates data-in-transit integrity requirements. This finding indicates either ISP manipulation or an active attack, both of which constitute control failures.`,
      technicalDetail: `DNS hijack test result: intercepted. Configured DNS servers: ${result.network.dns.servers.join(", ")}.`,
      recommendation:
        "Switch to encrypted DNS transport (DoH/DoT). Document the interception finding and notify the security team.",
      affectedAssets: result.network.dns.servers,
      references: ["CIS-W-4.1", "NIST-800-153-3.3"],
    });
  }

  // --- Asset inventory completeness ---
  const totalHosts = result.network.hosts.length;
  const unknownVendor = result.network.hosts.filter((h) => !h.vendor).length;
  const unknownDevices = result.hiddenDevices?.unknownDevices ?? [];
  if (unknownVendor > 0 || unknownDevices.length > 0) {
    insights.push({
      id: "co-incomplete-asset-inventory",
      title: "Asset inventory incomplete — device identification gaps found",
      severity: "medium",
      category: "asset-management",
      description: `Asset management controls require a complete inventory of all network-connected devices. ${unknownVendor} host(s) have no vendor identification and ${unknownDevices.length} device(s) are completely unclassified. This is an audit finding under asset management requirements.`,
      technicalDetail: `Total hosts: ${totalHosts}. Without vendor: ${unknownVendor}. Unknown/unclassified devices: ${unknownDevices.length}.`,
      recommendation:
        "Complete the asset inventory. Implement 802.1X network access control. Establish a process for registering and classifying new devices.",
      affectedAssets: [
        ...result.network.hosts
          .filter((h) => !h.vendor)
          .map((h) => h.ip),
        ...unknownDevices.map((d) => d.ip),
      ],
      references: ["CIS-W-2.1", "NIST-800-153-2.1"],
    });
  }

  // --- Audit trail / logging ---
  const hasOtel = Object.keys(result.meta.toolchain).some((k) =>
    k.toLowerCase().includes("otel"),
  );
  if (!hasOtel) {
    insights.push({
      id: "co-no-audit-logging",
      title: "No OpenTelemetry instrumentation detected — audit trail gap",
      severity: "medium",
      category: "audit-trail",
      description: `Compliance frameworks require adequate audit logging for security events. Without OTEL or equivalent instrumentation, there is no verifiable audit trail for incident investigation or regulatory review.`,
      technicalDetail: `Toolchain entries: ${Object.keys(result.meta.toolchain).join(", ")}. No OTEL-related tooling detected.`,
      recommendation:
        "Implement OpenTelemetry instrumentation for security-relevant events. Configure log export to a tamper-evident store.",
      affectedAssets: [result.meta.hostname],
      references: ["NIST-800-153-6.2"],
    });
  }

  // --- Unencrypted traffic ---
  if (result.traffic && result.traffic.unencrypted.length > 0) {
    insights.push({
      id: "co-unencrypted-data-transit",
      title: `${result.traffic.unencrypted.length} unencrypted data flow(s) — data-in-transit encryption control failure`,
      severity: "high",
      category: "data-protection",
      description: `Data-in-transit encryption is a mandatory control. Each unencrypted flow represents a control failure that must be documented, risk-assessed, and remediated or accepted with a formal risk exception.`,
      technicalDetail: `Unencrypted flows: ${result.traffic.unencrypted.map((u) => `${u.protocol}→${u.dest}:${u.port}`).join(", ")}.`,
      recommendation:
        "Enforce TLS on all data flows. Create a formal exception process for any flow that cannot be encrypted.",
      affectedAssets: result.traffic.unencrypted.map(
        (u) => `${u.dest}:${u.port}`,
      ),
      references: ["CIS-W-3.2", "NIST-800-153-3.2"],
    });
  }

  // --- Vendor/third-party device management ---
  const cameras = result.hiddenDevices?.suspectedCameras ?? [];
  if (cameras.length > 0) {
    insights.push({
      id: "co-unmanaged-cameras",
      title: `${cameras.length} suspected camera(s) — vendor management and privacy review required`,
      severity: "high",
      category: "vendor-management",
      description: `Camera devices introduce data protection obligations under privacy regulations. Each camera vendor must be assessed for data handling practices, firmware update policies, and data retention controls.`,
      technicalDetail: `Suspected cameras: ${cameras.map((c) => `${c.ip} (${c.vendor ?? "unknown vendor"})`).join(", ")}.`,
      recommendation:
        "Conduct a vendor security assessment for each camera manufacturer. Document data flows and retention policies.",
      affectedAssets: cameras.map((c) => c.ip),
      references: ["OWASP-IoT-1", "NIST-800-153-2.2"],
    });
  }

  // --- Risk management: double NAT ---
  if (result.network.topology.doubleNat) {
    insights.push({
      id: "co-double-nat-risk",
      title: "Double NAT topology — network architecture risk not documented",
      severity: "low",
      category: "risk-management",
      description: `Double NAT introduces complexity that may affect security control effectiveness and incident response capability. This network architecture decision should be documented in the risk register with justification.`,
      technicalDetail: `Double NAT detected. Hop count: ${result.network.topology.hops.length}. Gateway: ${result.network.gateway.ip}.`,
      recommendation:
        "Document the double NAT configuration in the risk register. Assess impact on security monitoring and incident response.",
      affectedAssets: [result.network.gateway.ip],
      references: ["NIST-800-153-4.1"],
    });
  }

  // --- MAC randomisation ---
  if (!result.wifi.macRandomised) {
    insights.push({
      id: "co-mac-not-randomised",
      title: "MAC address randomisation disabled — privacy control gap",
      severity: "low",
      category: "data-protection",
      description: `MAC randomisation is a privacy-enhancing control recommended to prevent device tracking across networks. Its absence may constitute a finding under data protection regulations that require data minimisation.`,
      technicalDetail: `MAC randomisation: disabled on interface ${result.network.interface}.`,
      recommendation:
        "Enable MAC address randomisation. Document the privacy control in the data protection impact assessment.",
      affectedAssets: [result.meta.hostname],
      references: ["IEEE-802.11-11.1"],
    });
  }

  // --- Exposed local services ---
  const exposed = result.localServices.filter((s) => s.exposedToNetwork);
  if (exposed.length > 0) {
    insights.push({
      id: "co-exposed-services",
      title: `${exposed.length} service(s) exposed to network — access control review required`,
      severity: "medium",
      category: "access-control",
      description: `Each network-exposed service must be documented, authorised, and monitored under access control policies. Services bound to 0.0.0.0 without explicit authorisation represent an access control finding.`,
      technicalDetail: `Exposed services: ${exposed.map((s) => `${s.port}/${s.process} on ${s.bindAddress}`).join(", ")}.`,
      recommendation:
        "Review and authorise each exposed service. Bind to loopback where network access is not required. Document approved exceptions.",
      affectedAssets: exposed.map((s) => `${s.bindAddress}:${s.port}`),
      references: ["CIS-W-5.2", "NIST-800-153-5.1"],
    });
  }

  const priorityActions = deriveActions(insights);

  return {
    persona: PERSONA_ID,
    displayName: DISPLAY_NAME,
    perspective: PERSPECTIVE,
    riskRating: riskFromInsights(insights),
    executiveSummary: buildSummary(insights),
    insights,
    priorityActions,
  };
}

function buildSummary(insights: Insight[]): string {
  const critCount = insights.filter((i) => i.severity === "critical").length;
  const highCount = insights.filter((i) => i.severity === "high").length;
  const categories = new Set(insights.map((i) => i.category));

  if (critCount > 0) {
    return `Critical control failures identified. ${critCount} mandatory control(s) are not implemented, requiring immediate remediation and formal documentation in the risk register. Audit readiness is compromised across ${categories.size} control domain(s).`;
  }
  if (highCount > 0) {
    return `Several high-priority compliance findings require attention. ${highCount} control gap(s) across ${categories.size} domain(s) need remediation or formal risk acceptance. A compliance review should be scheduled.`;
  }
  if (insights.length > 0) {
    return `The environment has ${insights.length} compliance finding(s) across ${categories.size} control domain(s). Most mandatory controls are in place, though several recommendations should be addressed in the next audit cycle.`;
  }
  return `All assessed controls are in place. No compliance findings were identified. The environment meets the minimum requirements of the assessed frameworks.`;
}

function deriveActions(insights: Insight[]): string[] {
  const actions: string[] = [];
  const ids = new Set(insights.map((i) => i.id));

  if (ids.has("co-firewall-control-failure"))
    actions.push(
      "Enable the host firewall to satisfy mandatory access control requirements",
    );
  if (ids.has("co-weak-encryption"))
    actions.push(
      "Upgrade wireless encryption to meet minimum cryptographic standards",
    );
  if (ids.has("co-unencrypted-data-transit"))
    actions.push(
      "Enforce TLS on all data flows to meet data-in-transit requirements",
    );
  if (ids.has("co-incomplete-asset-inventory"))
    actions.push(
      "Complete the asset inventory and implement device registration controls",
    );
  if (ids.has("co-unmanaged-cameras"))
    actions.push(
      "Conduct vendor security assessments for detected camera devices",
    );
  if (ids.has("co-dns-integrity-compromised"))
    actions.push("Remediate DNS interception to restore data integrity controls");
  if (ids.has("co-no-audit-logging"))
    actions.push("Implement audit logging with OpenTelemetry instrumentation");

  return actions.slice(0, 5);
}
