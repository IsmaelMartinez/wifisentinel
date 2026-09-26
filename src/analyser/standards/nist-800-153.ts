import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import { classifySecurity } from "../security.js";
import {
  type Finding,
  type FindingSpec,
  type StandardScore,
  UNKNOWN_SECURITY_FIX,
  buildStandardScore,
  finding,
  wpaTierStatus,
} from "./types.js";

const STANDARD = "nist-800-153" as const;
const check = (spec: FindingSpec): Finding => finding(STANDARD, spec);

function checkMacRandomisation(result: NetworkScanResult): Finding {
  const randomised = result.wifi.macRandomised;
  return check({
    id: "NIST-W-1.1",
    title: "MAC address randomisation",
    severity: "medium",
    status: randomised ? "pass" : "fail",
    description:
      "MAC randomisation prevents tracking across networks by using a different address on each connection.",
    fix: "Enable private/random Wi-Fi address in the OS network settings.",
    evidence: `MAC randomised: ${randomised}`,
  });
}

function checkClientIsolation(result: NetworkScanResult): Finding {
  const isolation = result.security.clientIsolation;
  return check({
    id: "NIST-W-1.2",
    title: "Wireless client isolation",
    severity: "medium",
    status: isolation === null ? "not-applicable" : isolation ? "pass" : "fail",
    description:
      "Client isolation limits the attack surface by preventing direct communication between wireless clients.",
    fix: "Enable client isolation on the access point.",
    evidence:
      isolation === null
        ? "Status unknown"
        : `Client isolation: ${isolation ? "enabled" : "disabled"}`,
  });
}

function checkEncryptionStrength(result: NetworkScanResult): Finding {
  const { wpaTier } = classifySecurity(result.wifi.security);
  return check({
    id: "NIST-W-2.1",
    title: "Encryption protocol strength",
    severity: "critical",
    status: wpaTierStatus(wpaTier),
    description:
      "NIST recommends the strongest available encryption. WPA3 provides simultaneous authentication of equals (SAE).",
    fix:
      wpaTier === "unknown"
        ? UNKNOWN_SECURITY_FIX
        : "Migrate to WPA3. If devices lack WPA3 support, use WPA2 with AES-CCMP only.",
    evidence: `Protocol: ${result.wifi.security}`,
  });
}

function checkKeyManagement(result: NetworkScanResult): Finding {
  const { mode } = classifySecurity(result.wifi.security);
  return check({
    id: "NIST-W-2.2",
    title: "Key management approach",
    severity: "medium",
    status: mode === "Enterprise" ? "pass" : mode === "Personal" ? "partial" : "fail",
    description:
      "Enterprise authentication (802.1X/EAP) provides individual credentials and stronger key management than pre-shared keys.",
    fix: "Consider migrating to WPA-Enterprise with RADIUS for environments with multiple users.",
    evidence: `Security mode: ${result.wifi.security}`,
  });
}

function checkIntrusionDetection(result: NetworkScanResult): Finding {
  const hasIntrusion = !!result.intrusionIndicators;
  return check({
    id: "NIST-W-3.1",
    title: "Intrusion detection capability",
    severity: "high",
    status: hasIntrusion ? "pass" : "fail",
    description:
      "Wireless networks should be monitored for intrusion attempts, rogue access points, and anomalous activity.",
    ok: "No action needed — intrusion monitoring is active.",
    fix: "Enable network intrusion detection. Run scans regularly with full monitoring.",
    evidence: hasIntrusion
      ? `ARP monitoring: active, scan detection: active`
      : "Intrusion detection not available in this scan",
  });
}

function checkArpMonitoring(result: NetworkScanResult): Finding {
  const indicators = result.intrusionIndicators;
  if (!indicators) {
    return check({
      id: "NIST-W-3.2",
      title: "ARP spoofing monitoring",
      severity: "high",
      status: "not-applicable",
      description: "ARP monitoring was not performed during this scan.",
      fix: "Run the scan with intrusion detection enabled.",
    });
  }
  const anomalyCount = indicators.arpAnomalies.length;
  return check({
    id: "NIST-W-3.2",
    title: "ARP spoofing monitoring",
    severity: "high",
    status: anomalyCount === 0 ? "pass" : "fail",
    description:
      "ARP spoofing is a common attack vector on wireless LANs. Continuous monitoring detects and mitigates this threat.",
    ok: "No anomalies detected.",
    fix: "Investigate ARP anomalies and consider deploying Dynamic ARP Inspection (DAI).",
    evidence: `ARP anomalies detected: ${anomalyCount}`,
  });
}

function checkDoubleNat(result: NetworkScanResult): Finding {
  const doubleNat = result.network.topology.doubleNat;
  return check({
    id: "NIST-W-4.1",
    title: "Network architecture — double NAT",
    severity: "medium",
    status: doubleNat ? "fail" : "pass",
    description:
      "Double NAT creates routing complexity and can interfere with VPN, IPsec, and other security mechanisms.",
    fix: "Eliminate double NAT by configuring one device as a bridge or placing it in the DMZ.",
    evidence: `Double NAT: ${doubleNat ? "detected" : "not detected"}, hops: ${result.network.topology.hops.length}`,
  });
}

function checkGatewaySecurity(result: NetworkScanResult): Finding {
  const gw = result.network.gateway;
  const firewallEnabled = result.security.firewall.enabled;
  return check({
    id: "NIST-W-4.2",
    title: "Gateway security posture",
    severity: "high",
    status: firewallEnabled ? "pass" : "fail",
    description:
      "The network gateway should have firewall protection enabled to control inbound and outbound traffic.",
    fix: "Enable firewall on the host and ensure the gateway has its own firewall enabled.",
    evidence: `Gateway: ${gw.ip} (${gw.vendor ?? "unknown vendor"}), host firewall: ${firewallEnabled ? "enabled" : "disabled"}`,
  });
}

function checkIpForwarding(result: NetworkScanResult): Finding {
  const forwarding = result.security.kernelParams.ipForwarding;
  return check({
    id: "NIST-W-4.3",
    title: "IP forwarding disabled",
    severity: "high",
    status: forwarding ? "fail" : "pass",
    description:
      "IP forwarding on endpoint devices can allow the device to be used as a router, facilitating man-in-the-middle attacks.",
    fix: "Disable IP forwarding unless this device is intentionally acting as a router.",
    evidence: `IP forwarding: ${forwarding ? "enabled" : "disabled"}`,
  });
}

function checkIcmpRedirects(result: NetworkScanResult): Finding {
  const redirects = result.security.kernelParams.icmpRedirects;
  return check({
    id: "NIST-W-4.4",
    title: "ICMP redirects disabled",
    severity: "medium",
    status: redirects ? "fail" : "pass",
    description:
      "ICMP redirects can be exploited to reroute traffic through an attacker-controlled host.",
    fix: "Disable ICMP redirect acceptance in kernel/network settings.",
    evidence: `ICMP redirects: ${redirects ? "accepted" : "rejected"}`,
  });
}

function checkLogging(result: NetworkScanResult): Finding {
  // Toolchain keys are capability names; packetAnalysis resolves to tshark or
  // tcpdump, either of which can record traffic for forensic review.
  const captureTool = result.meta.toolchain["packetAnalysis"] ?? null;
  return check({
    id: "NIST-W-5.1",
    title: "Security logging capability",
    severity: "medium",
    status: captureTool ? "pass" : "partial",
    description:
      "Comprehensive logging supports incident response and forensic analysis of security events.",
    ok: "No action needed — packet capture is available for security logging.",
    fix: "Install tshark or tcpdump so network traffic can be captured for security logging.",
    evidence: `Packet capture tool: ${captureTool ?? "not available"}`,
  });
}

export function scoreNist800153(result: NetworkScanResult): StandardScore {
  return buildStandardScore(STANDARD, "NIST SP 800-153 — Guidelines for Securing WLANs", "2012", [
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
  ]);
}
