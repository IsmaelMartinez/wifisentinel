import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import {
  type Finding,
  type StandardScore,
  computeGrade,
  computeScore,
} from "./types.js";

const STANDARD = "owasp-iot" as const;

/** Common management/admin ports that may indicate weak default configs. */
const MANAGEMENT_PORTS = new Set([
  23, 80, 443, 8080, 8443, 8888, 161, 162, 179, 1900, 5000, 7547,
]);

/** Ports commonly associated with insecure/plaintext protocols. */
const INSECURE_SERVICE_PORTS = new Set([
  21, 23, 25, 69, 80, 110, 143, 161, 445, 513, 514, 1883, 5060,
]);

function checkWeakPasswords(result: NetworkScanResult): Finding {
  // Infer from hosts with open management ports (telnet, HTTP admin panels)
  const hostsWithAdmin = result.network.hosts.filter((h) =>
    h.ports?.some((p) => (p.port === 23 || p.port === 80) && p.state === "open")
  );

  return {
    id: "OWASP-IoT-1",
    standard: STANDARD,
    title: "Weak, guessable, or hardcoded passwords",
    severity: "critical",
    status: hostsWithAdmin.length === 0 ? "pass" : "fail",
    description:
      "Devices with open Telnet or HTTP management ports are often accessible with default credentials.",
    recommendation:
      hostsWithAdmin.length === 0
        ? "No action needed."
        : "Change default credentials on all devices. Disable Telnet and use SSH/HTTPS for management.",
    evidence:
      hostsWithAdmin.length > 0
        ? `${hostsWithAdmin.length} host(s) with open admin ports (e.g. ${hostsWithAdmin[0].ip}${hostsWithAdmin[0].vendor ? ` - ${hostsWithAdmin[0].vendor}` : ""})`
        : "No hosts with exposed default management ports",
  };
}

function checkInsecureServices(result: NetworkScanResult): Finding {
  const insecureHosts = result.network.hosts.filter((h) =>
    h.ports?.some(
      (p) => INSECURE_SERVICE_PORTS.has(p.port) && p.state === "open"
    )
  );
  const insecurePorts = result.network.hosts.flatMap(
    (h) =>
      h.ports?.filter(
        (p) => INSECURE_SERVICE_PORTS.has(p.port) && p.state === "open"
      ) ?? []
  );

  return {
    id: "OWASP-IoT-2",
    standard: STANDARD,
    title: "Insecure network services",
    severity: "high",
    status: insecurePorts.length === 0 ? "pass" : "fail",
    description:
      "Unnecessary or insecure services (Telnet, FTP, unencrypted MQTT) increase the attack surface.",
    recommendation:
      insecurePorts.length === 0
        ? "No action needed."
        : "Disable unnecessary services. Replace plaintext protocols with encrypted alternatives (SSH, SFTP, MQTTS).",
    evidence:
      insecurePorts.length > 0
        ? `${insecurePorts.length} insecure service(s) across ${insecureHosts.length} host(s)`
        : "No insecure network services detected",
  };
}

function checkInsecureInterfaces(result: NetworkScanResult): Finding {
  // Check for exposed management ports on the local host
  const exposedMgmt = result.localServices.filter(
    (s) => MANAGEMENT_PORTS.has(s.port) && s.exposedToNetwork
  );

  return {
    id: "OWASP-IoT-3",
    standard: STANDARD,
    title: "Insecure ecosystem interfaces",
    severity: "high",
    status: exposedMgmt.length === 0 ? "pass" : "fail",
    description:
      "Management interfaces exposed to the network can be exploited if not properly secured.",
    recommendation:
      exposedMgmt.length === 0
        ? "No action needed."
        : "Bind management services to localhost only or restrict access with firewall rules.",
    evidence:
      exposedMgmt.length > 0
        ? `${exposedMgmt.length} management port(s) exposed (e.g. ${exposedMgmt[0].port}/${exposedMgmt[0].process})`
        : "No management ports exposed to network",
  };
}

function checkUpdateMechanism(result: NetworkScanResult): Finding {
  // Infer from protocol version — older protocols suggest unmaintained firmware
  const sec = result.wifi.security.toLowerCase();
  const isWep = sec.includes("wep");
  const isLegacy = isWep || sec === "none" || sec === "open";
  const proto = result.wifi.protocol.toLowerCase();
  const isOldProto =
    proto.includes("802.11b") ||
    proto.includes("802.11a") ||
    proto.includes("802.11g");

  const outdated = isLegacy || isOldProto;

  return {
    id: "OWASP-IoT-4",
    standard: STANDARD,
    title: "Lack of secure update mechanism",
    severity: "high",
    status: outdated ? "fail" : "pass",
    description:
      "Devices running outdated protocols likely lack automated secure update mechanisms, leaving known vulnerabilities unpatched.",
    recommendation: outdated
      ? "Update device firmware. Replace end-of-life hardware that no longer receives security updates."
      : "No action needed — current protocol versions suggest maintained devices.",
    evidence: `Protocol: ${result.wifi.protocol}, security: ${result.wifi.security}`,
  };
}

function checkOutdatedComponents(result: NetworkScanResult): Finding {
  const sec = result.wifi.security.toLowerCase();
  const isWep = sec.includes("wep");
  const isWpa1 = sec.includes("wpa") && !sec.includes("wpa2") && !sec.includes("wpa3");

  const nearby = result.wifi.nearbyNetworks;
  const insecureNearby = nearby.filter((n) => {
    const s = n.security.toLowerCase();
    return s.includes("wep") || s === "none" || s === "open";
  });

  return {
    id: "OWASP-IoT-5",
    standard: STANDARD,
    title: "Use of insecure or outdated components",
    severity: "high",
    status: isWep || isWpa1 ? "fail" : insecureNearby.length > 0 ? "partial" : "pass",
    description:
      "Deprecated protocols (WEP, WPA1) have known exploits. Nearby insecure networks can also pose risks.",
    recommendation:
      isWep || isWpa1
        ? "Immediately upgrade to WPA2 or WPA3."
        : insecureNearby.length > 0
          ? "Your network is secure, but nearby insecure networks could be used for evil twin attacks."
          : "No action needed.",
    evidence: `Current: ${result.wifi.security}. Nearby insecure networks: ${insecureNearby.length}`,
  };
}

function checkPrivacyProtection(result: NetworkScanResult): Finding {
  const macRandom = result.wifi.macRandomised;
  const traffic = result.traffic;
  const mdnsLeaks = traffic?.mdnsLeaks.length ?? 0;
  const dnsAnomalies = result.network.dns.anomalies.length;

  let status: Finding["status"];
  if (macRandom && mdnsLeaks === 0 && dnsAnomalies === 0) status = "pass";
  else if (macRandom || (mdnsLeaks === 0 && dnsAnomalies === 0))
    status = "partial";
  else status = "fail";

  const evidenceParts = [
    `MAC randomisation: ${macRandom ? "enabled" : "disabled"}`,
    `mDNS leaks: ${mdnsLeaks}`,
    `DNS anomalies: ${dnsAnomalies}`,
  ];

  return {
    id: "OWASP-IoT-6",
    standard: STANDARD,
    title: "Insufficient privacy protection",
    severity: "medium",
    status,
    description:
      "Privacy leaks through MAC addresses, mDNS broadcasts, and DNS queries expose device identity and user behaviour.",
    recommendation:
      status === "pass"
        ? "No action needed."
        : "Enable MAC randomisation, configure mDNS scope, and use encrypted DNS.",
    evidence: evidenceParts.join(", "),
  };
}

function checkInsecureDataTransfer(result: NetworkScanResult): Finding {
  const traffic = result.traffic;
  if (!traffic) {
    return {
      id: "OWASP-IoT-7",
      standard: STANDARD,
      title: "Insecure data transfer and storage",
      severity: "high",
      status: "not-applicable",
      description: "Traffic capture was not performed during this scan.",
      recommendation: "Run the scan with traffic capture enabled.",
    };
  }

  const unencrypted = traffic.unencrypted.length;
  const dohEnabled = result.network.dns.dohDotEnabled;

  return {
    id: "OWASP-IoT-7",
    standard: STANDARD,
    title: "Insecure data transfer and storage",
    severity: "high",
    status: unencrypted === 0 && dohEnabled ? "pass" : unencrypted === 0 ? "partial" : "fail",
    description:
      "Data in transit must be encrypted. Unencrypted HTTP, DNS, and other protocols leak sensitive information.",
    recommendation:
      unencrypted === 0 && dohEnabled
        ? "No action needed."
        : unencrypted === 0
          ? "Enable DNS-over-HTTPS/TLS for full encryption coverage."
          : "Eliminate unencrypted traffic. Enforce HTTPS and encrypted DNS.",
    evidence: `Unencrypted flows: ${unencrypted}, DoH/DoT: ${dohEnabled ? "enabled" : "disabled"}`,
  };
}

function checkDeviceManagement(result: NetworkScanResult): Finding {
  const hidden = result.hiddenDevices;
  const unknownCount = hidden?.unknownDevices.length ?? 0;
  const totalHosts = result.network.hosts.length;
  const identifiedHosts = result.network.hosts.filter(
    (h) => h.vendor || h.hostname || h.deviceType
  ).length;

  const identificationRate =
    totalHosts > 0 ? identifiedHosts / totalHosts : 1;

  let status: Finding["status"];
  if (unknownCount === 0 && identificationRate >= 0.8) status = "pass";
  else if (unknownCount <= 2 && identificationRate >= 0.5) status = "partial";
  else status = "fail";

  return {
    id: "OWASP-IoT-8",
    standard: STANDARD,
    title: "Lack of device management",
    severity: "medium",
    status,
    description:
      "All devices on the network should be identified and managed. Unknown devices may indicate unauthorised access.",
    recommendation:
      status === "pass"
        ? "No action needed."
        : "Identify all unknown devices. Implement network access control (NAC) or MAC filtering.",
    evidence: `Total hosts: ${totalHosts}, identified: ${identifiedHosts}, unknown devices flagged: ${unknownCount}`,
  };
}

export function scoreOwaspIot(result: NetworkScanResult): StandardScore {
  const findings: Finding[] = [
    checkWeakPasswords(result),
    checkInsecureServices(result),
    checkInsecureInterfaces(result),
    checkUpdateMechanism(result),
    checkOutdatedComponents(result),
    checkPrivacyProtection(result),
    checkInsecureDataTransfer(result),
    checkDeviceManagement(result),
  ];

  const score = computeScore(findings);
  const passing = findings.filter((f) => f.status === "pass").length;
  const applicable = findings.filter(
    (f) => f.status !== "not-applicable"
  ).length;

  return {
    standard: STANDARD,
    name: "OWASP IoT Top 10",
    version: "2018",
    score,
    maxScore: 100,
    grade: computeGrade(score),
    findings,
    summary: `${passing}/${applicable} applicable controls passed (score: ${score}/100).`,
  };
}
