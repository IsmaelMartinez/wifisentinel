import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import { classifySecurity } from "../security.js";
import {
  type Finding,
  type FindingSpec,
  type FindingStatus,
  type StandardScore,
  buildStandardScore,
  finding,
} from "./types.js";
import { wifiGeneration } from "./protocol.js";

const STANDARD = "owasp-iot" as const;
const check = (spec: FindingSpec): Finding => finding(STANDARD, spec);

/** 802.11a/b/g — generations that predate WPA2-era firmware support. */
const LAST_LEGACY_GENERATION = 3;

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
  return check({
    id: "OWASP-IoT-1",
    title: "Weak, guessable, or hardcoded passwords",
    severity: "critical",
    status: hostsWithAdmin.length === 0 ? "pass" : "fail",
    description:
      "Devices with open Telnet or HTTP management ports are often accessible with default credentials.",
    fix: "Change default credentials on all devices. Disable Telnet and use SSH/HTTPS for management.",
    evidence:
      hostsWithAdmin.length > 0
        ? `${hostsWithAdmin.length} host(s) with open admin ports (e.g. ${hostsWithAdmin[0].ip}${hostsWithAdmin[0].vendor ? ` - ${hostsWithAdmin[0].vendor}` : ""})`
        : "No hosts with exposed default management ports",
  });
}

function checkInsecureServices(result: NetworkScanResult): Finding {
  const isInsecure = (p: { port: number; state: string }) =>
    INSECURE_SERVICE_PORTS.has(p.port) && p.state === "open";
  const insecureHosts = result.network.hosts.filter((h) => h.ports?.some(isInsecure));
  const insecurePorts = result.network.hosts.flatMap((h) => h.ports?.filter(isInsecure) ?? []);
  return check({
    id: "OWASP-IoT-2",
    title: "Insecure network services",
    severity: "high",
    status: insecurePorts.length === 0 ? "pass" : "fail",
    description:
      "Unnecessary or insecure services (Telnet, FTP, unencrypted MQTT) increase the attack surface.",
    fix: "Disable unnecessary services. Replace plaintext protocols with encrypted alternatives (SSH, SFTP, MQTTS).",
    evidence:
      insecurePorts.length > 0
        ? `${insecurePorts.length} insecure service(s) across ${insecureHosts.length} host(s)`
        : "No insecure network services detected",
  });
}

function checkInsecureInterfaces(result: NetworkScanResult): Finding {
  // Check for exposed management ports on the local host
  const exposedMgmt = result.localServices.filter(
    (s) => MANAGEMENT_PORTS.has(s.port) && s.exposedToNetwork
  );
  return check({
    id: "OWASP-IoT-3",
    title: "Insecure ecosystem interfaces",
    severity: "high",
    status: exposedMgmt.length === 0 ? "pass" : "fail",
    description:
      "Management interfaces exposed to the network can be exploited if not properly secured.",
    fix: "Bind management services to localhost only or restrict access with firewall rules.",
    evidence:
      exposedMgmt.length > 0
        ? `${exposedMgmt.length} management port(s) exposed (e.g. ${exposedMgmt[0].port}/${exposedMgmt[0].process})`
        : "No management ports exposed to network",
  });
}

function checkUpdateMechanism(result: NetworkScanResult): Finding {
  // Infer from protocol version — older protocols suggest unmaintained firmware
  const isLegacy = classifySecurity(result.wifi.security).unencrypted;
  const generation = wifiGeneration(result.wifi.protocol);
  const isOldProto = generation !== undefined && generation <= LAST_LEGACY_GENERATION;
  const outdated = isLegacy || isOldProto;
  // With a usable cipher and no PHY reading there is nothing to infer from.
  const unmeasured = !outdated && generation === undefined;

  return check({
    id: "OWASP-IoT-4",
    title: "Lack of secure update mechanism",
    severity: "high",
    status: outdated ? "fail" : unmeasured ? "not-applicable" : "pass",
    description:
      "Devices running outdated protocols likely lack automated secure update mechanisms, leaving known vulnerabilities unpatched.",
    ok: "No action needed — current protocol versions suggest maintained devices.",
    fix: outdated
      ? "Update device firmware. Replace end-of-life hardware that no longer receives security updates."
      : "No action needed — the Wi-Fi protocol generation was not reported.",
    evidence: `Protocol: ${result.wifi.protocol}, security: ${result.wifi.security}`,
  });
}

function checkOutdatedComponents(result: NetworkScanResult): Finding {
  const { family } = classifySecurity(result.wifi.security);
  const deprecated = family === "wep" || family === "wpa";
  const insecureNearby = result.wifi.nearbyNetworks.filter(
    (n) => classifySecurity(n.security).unencrypted,
  );
  return check({
    id: "OWASP-IoT-5",
    title: "Use of insecure or outdated components",
    severity: "high",
    status: deprecated ? "fail" : insecureNearby.length > 0 ? "partial" : "pass",
    description:
      "Deprecated protocols (WEP, WPA1) have known exploits. Nearby insecure networks can also pose risks.",
    fix: deprecated
      ? "Immediately upgrade to WPA2 or WPA3."
      : "Your network is secure, but nearby insecure networks could be used for evil twin attacks.",
    evidence: `Current: ${result.wifi.security}. Nearby insecure networks: ${insecureNearby.length}`,
  });
}

function checkPrivacyProtection(result: NetworkScanResult): Finding {
  const macRandom = result.wifi.macRandomised;
  const mdnsLeaks = result.traffic?.mdnsLeaks.length ?? 0;
  const dnsAnomalies = result.network.dns.anomalies.length;
  const noLeaks = mdnsLeaks === 0 && dnsAnomalies === 0;

  let status: FindingStatus;
  if (macRandom && noLeaks) status = "pass";
  else if (macRandom || noLeaks) status = "partial";
  else status = "fail";

  return check({
    id: "OWASP-IoT-6",
    title: "Insufficient privacy protection",
    severity: "medium",
    status,
    description:
      "Privacy leaks through MAC addresses, mDNS broadcasts, and DNS queries expose device identity and user behaviour.",
    fix: "Enable MAC randomisation, configure mDNS scope, and use encrypted DNS.",
    evidence: [
      `MAC randomisation: ${macRandom ? "enabled" : "disabled"}`,
      `mDNS leaks: ${mdnsLeaks}`,
      `DNS anomalies: ${dnsAnomalies}`,
    ].join(", "),
  });
}

function checkInsecureDataTransfer(result: NetworkScanResult): Finding {
  const traffic = result.traffic;
  if (!traffic) {
    return check({
      id: "OWASP-IoT-7",
      title: "Insecure data transfer and storage",
      severity: "high",
      status: "not-applicable",
      description: "Traffic capture was not performed during this scan.",
      fix: "Run the scan with traffic capture enabled.",
    });
  }

  const unencrypted = traffic.unencrypted.length;
  const dohEnabled = result.network.dns.dohDotEnabled;
  return check({
    id: "OWASP-IoT-7",
    title: "Insecure data transfer and storage",
    severity: "high",
    status: unencrypted === 0 && dohEnabled ? "pass" : unencrypted === 0 ? "partial" : "fail",
    description:
      "Data in transit must be encrypted. Unencrypted HTTP, DNS, and other protocols leak sensitive information.",
    fix:
      unencrypted === 0
        ? "Enable DNS-over-HTTPS/TLS for full encryption coverage."
        : "Eliminate unencrypted traffic. Enforce HTTPS and encrypted DNS.",
    evidence: `Unencrypted flows: ${unencrypted}, DoH/DoT: ${dohEnabled ? "enabled" : "disabled"}`,
  });
}

function checkDeviceManagement(result: NetworkScanResult): Finding {
  const unknownCount = result.hiddenDevices?.unknownDevices.length ?? 0;
  const totalHosts = result.network.hosts.length;
  const identifiedHosts = result.network.hosts.filter(
    (h) => h.vendor || h.hostname || h.deviceType
  ).length;
  const identificationRate = totalHosts > 0 ? identifiedHosts / totalHosts : 1;

  let status: FindingStatus;
  if (unknownCount === 0 && identificationRate >= 0.8) status = "pass";
  else if (unknownCount <= 2 && identificationRate >= 0.5) status = "partial";
  else status = "fail";

  return check({
    id: "OWASP-IoT-8",
    title: "Lack of device management",
    severity: "medium",
    status,
    description:
      "All devices on the network should be identified and managed. Unknown devices may indicate unauthorised access.",
    fix: "Identify all unknown devices. Implement network access control (NAC) or MAC filtering.",
    evidence: `Total hosts: ${totalHosts}, identified: ${identifiedHosts}, unknown devices flagged: ${unknownCount}`,
  });
}

export function scoreOwaspIot(result: NetworkScanResult): StandardScore {
  return buildStandardScore(STANDARD, "OWASP IoT Top 10", "2018", [
    checkWeakPasswords(result),
    checkInsecureServices(result),
    checkInsecureInterfaces(result),
    checkUpdateMechanism(result),
    checkOutdatedComponents(result),
    checkPrivacyProtection(result),
    checkInsecureDataTransfer(result),
    checkDeviceManagement(result),
  ]);
}
