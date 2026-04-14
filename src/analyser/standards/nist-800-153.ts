import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import {
  type Finding,
  type StandardScore,
  computeGrade,
  computeScore,
} from "./types.js";

const STANDARD = "nist-800-153" as const;

function checkMacRandomisation(result: NetworkScanResult): Finding {
  return {
    id: "NIST-W-1.1",
    standard: STANDARD,
    title: "MAC address randomisation",
    severity: "medium",
    status: result.wifi.macRandomised ? "pass" : "fail",
    description:
      "MAC randomisation prevents tracking across networks by using a different address on each connection.",
    recommendation: result.wifi.macRandomised
      ? "No action needed."
      : "Enable private/random Wi-Fi address in the OS network settings.",
    evidence: `MAC randomised: ${result.wifi.macRandomised}`,
  };
}

function checkClientIsolation(result: NetworkScanResult): Finding {
  const isolation = result.security.clientIsolation;
  return {
    id: "NIST-W-1.2",
    standard: STANDARD,
    title: "Wireless client isolation",
    severity: "medium",
    status:
      isolation === null ? "not-applicable" : isolation ? "pass" : "fail",
    description:
      "Client isolation limits the attack surface by preventing direct communication between wireless clients.",
    recommendation:
      isolation === true
        ? "No action needed."
        : "Enable client isolation on the access point.",
    evidence:
      isolation === null
        ? "Status unknown"
        : `Client isolation: ${isolation ? "enabled" : "disabled"}`,
  };
}

function checkEncryptionStrength(result: NetworkScanResult): Finding {
  const sec = result.wifi.security.toLowerCase();
  const isWpa3 = sec.includes("wpa3");
  const isWpa2 = sec.includes("wpa2");
  const isWep = sec.includes("wep");

  let status: Finding["status"];
  if (isWpa3) status = "pass";
  else if (isWpa2 && !isWep) status = "partial";
  else status = "fail";

  return {
    id: "NIST-W-2.1",
    standard: STANDARD,
    title: "Encryption protocol strength",
    severity: "critical",
    status,
    description:
      "NIST recommends the strongest available encryption. WPA3 provides simultaneous authentication of equals (SAE).",
    recommendation: isWpa3
      ? "No action needed."
      : "Migrate to WPA3. If devices lack WPA3 support, use WPA2 with AES-CCMP only.",
    evidence: `Protocol: ${result.wifi.security}`,
  };
}

function checkKeyManagement(result: NetworkScanResult): Finding {
  const sec = result.wifi.security.toLowerCase();
  const hasEnterprise =
    sec.includes("enterprise") || sec.includes("802.1x") || sec.includes("eap");
  const hasPersonal =
    sec.includes("personal") || sec.includes("psk") || sec.includes("sae");

  return {
    id: "NIST-W-2.2",
    standard: STANDARD,
    title: "Key management approach",
    severity: "medium",
    status: hasEnterprise ? "pass" : hasPersonal ? "partial" : "fail",
    description:
      "Enterprise authentication (802.1X/EAP) provides individual credentials and stronger key management than pre-shared keys.",
    recommendation: hasEnterprise
      ? "No action needed."
      : "Consider migrating to WPA-Enterprise with RADIUS for environments with multiple users.",
    evidence: `Security mode: ${result.wifi.security}`,
  };
}

function checkIntrusionDetection(result: NetworkScanResult): Finding {
  const hasIntrusion = !!result.intrusionIndicators;

  return {
    id: "NIST-W-3.1",
    standard: STANDARD,
    title: "Intrusion detection capability",
    severity: "high",
    status: hasIntrusion ? "pass" : "fail",
    description:
      "Wireless networks should be monitored for intrusion attempts, rogue access points, and anomalous activity.",
    recommendation: hasIntrusion
      ? "No action needed — intrusion monitoring is active."
      : "Enable network intrusion detection. Run scans regularly with full monitoring.",
    evidence: hasIntrusion
      ? `ARP monitoring: active, scan detection: active`
      : "Intrusion detection not available in this scan",
  };
}

function checkArpMonitoring(result: NetworkScanResult): Finding {
  const indicators = result.intrusionIndicators;
  if (!indicators) {
    return {
      id: "NIST-W-3.2",
      standard: STANDARD,
      title: "ARP spoofing monitoring",
      severity: "high",
      status: "not-applicable",
      description: "ARP monitoring was not performed during this scan.",
      recommendation: "Run the scan with intrusion detection enabled.",
    };
  }
  const anomalyCount = indicators.arpAnomalies.length;
  return {
    id: "NIST-W-3.2",
    standard: STANDARD,
    title: "ARP spoofing monitoring",
    severity: "high",
    status: anomalyCount === 0 ? "pass" : "fail",
    description:
      "ARP spoofing is a common attack vector on wireless LANs. Continuous monitoring detects and mitigates this threat.",
    recommendation:
      anomalyCount === 0
        ? "No anomalies detected."
        : "Investigate ARP anomalies and consider deploying Dynamic ARP Inspection (DAI).",
    evidence: `ARP anomalies detected: ${anomalyCount}`,
  };
}

function checkDoubleNat(result: NetworkScanResult): Finding {
  const doubleNat = result.network.topology.doubleNat;
  return {
    id: "NIST-W-4.1",
    standard: STANDARD,
    title: "Network architecture — double NAT",
    severity: "medium",
    status: doubleNat ? "fail" : "pass",
    description:
      "Double NAT creates routing complexity and can interfere with VPN, IPsec, and other security mechanisms.",
    recommendation: doubleNat
      ? "Eliminate double NAT by configuring one device as a bridge or placing it in the DMZ."
      : "No action needed.",
    evidence: `Double NAT: ${doubleNat ? "detected" : "not detected"}, hops: ${result.network.topology.hops.length}`,
  };
}

function checkGatewaySecurity(result: NetworkScanResult): Finding {
  const gw = result.network.gateway;
  const firewallEnabled = result.security.firewall.enabled;

  return {
    id: "NIST-W-4.2",
    standard: STANDARD,
    title: "Gateway security posture",
    severity: "high",
    status: firewallEnabled ? "pass" : "fail",
    description:
      "The network gateway should have firewall protection enabled to control inbound and outbound traffic.",
    recommendation: firewallEnabled
      ? "No action needed."
      : "Enable firewall on the host and ensure the gateway has its own firewall enabled.",
    evidence: `Gateway: ${gw.ip} (${gw.vendor ?? "unknown vendor"}), host firewall: ${firewallEnabled ? "enabled" : "disabled"}`,
  };
}

function checkIpForwarding(result: NetworkScanResult): Finding {
  const forwarding = result.security.kernelParams.ipForwarding;
  return {
    id: "NIST-W-4.3",
    standard: STANDARD,
    title: "IP forwarding disabled",
    severity: "high",
    status: forwarding ? "fail" : "pass",
    description:
      "IP forwarding on endpoint devices can allow the device to be used as a router, facilitating man-in-the-middle attacks.",
    recommendation: forwarding
      ? "Disable IP forwarding unless this device is intentionally acting as a router."
      : "No action needed.",
    evidence: `IP forwarding: ${forwarding ? "enabled" : "disabled"}`,
  };
}

function checkIcmpRedirects(result: NetworkScanResult): Finding {
  const redirects = result.security.kernelParams.icmpRedirects;
  return {
    id: "NIST-W-4.4",
    standard: STANDARD,
    title: "ICMP redirects disabled",
    severity: "medium",
    status: redirects ? "fail" : "pass",
    description:
      "ICMP redirects can be exploited to reroute traffic through an attacker-controlled host.",
    recommendation: redirects
      ? "Disable ICMP redirect acceptance in kernel/network settings."
      : "No action needed.",
    evidence: `ICMP redirects: ${redirects ? "accepted" : "rejected"}`,
  };
}

function checkLogging(result: NetworkScanResult): Finding {
  const hasOtel = !!result.meta.toolchain["otel"];
  const hasTshark = !!result.meta.toolchain["tshark"];

  return {
    id: "NIST-W-5.1",
    standard: STANDARD,
    title: "Security logging capability",
    severity: "medium",
    status: hasOtel || hasTshark ? "pass" : "partial",
    description:
      "Comprehensive logging supports incident response and forensic analysis of security events.",
    recommendation:
      hasOtel || hasTshark
        ? "No action needed — logging infrastructure is available."
        : "Set up OTEL telemetry and traffic capture for comprehensive security logging.",
    evidence: `OTEL: ${hasOtel ? "available" : "not available"}, tshark: ${hasTshark ? "available" : "not available"}`,
  };
}

export function scoreNist800153(result: NetworkScanResult): StandardScore {
  const findings: Finding[] = [
    checkMacRandomisation(result),
    checkClientIsolation(result),
    checkEncryptionStrength(result),
    checkKeyManagement(result),
    checkIntrusionDetection(result),
    checkArpMonitoring(result),
    checkDoubleNat(result),
    checkGatewaySecurity(result),
    checkIpForwarding(result),
    checkIcmpRedirects(result),
    checkLogging(result),
  ];

  const score = computeScore(findings);
  const passing = findings.filter((f) => f.status === "pass").length;
  const applicable = findings.filter(
    (f) => f.status !== "not-applicable"
  ).length;

  return {
    standard: STANDARD,
    name: "NIST SP 800-153 — Guidelines for Securing WLANs",
    version: "2012",
    score,
    maxScore: 100,
    grade: computeGrade(score),
    findings,
    summary: `${passing}/${applicable} applicable controls passed (score: ${score}/100).`,
  };
}
