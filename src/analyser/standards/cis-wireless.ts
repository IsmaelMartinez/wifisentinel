import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import {
  type Finding,
  type StandardScore,
  computeGrade,
  computeScore,
} from "./types.js";

const STANDARD = "cis-wireless" as const;

const DEFAULT_SSIDS = new Set([
  "linksys",
  "netgear",
  "default",
  "dlink",
  "wireless",
  "home",
  "setup",
  "admin",
  "router",
  "tp-link",
  "asus",
  "belkin",
  "xfinity",
  "att",
  "spectrum",
  "virginmedia",
  "sky",
  "bt-wifi",
  "bt hub",
]);

function checkEncryption(result: NetworkScanResult): Finding {
  const sec = result.wifi.security.toLowerCase();
  const isWpa3 = sec.includes("wpa3");
  const isWpa2 = sec.includes("wpa2");
  const isWep = sec.includes("wep");

  let status: Finding["status"] = "fail";
  if (isWpa3) status = "pass";
  else if (isWpa2 && !isWep) status = "partial";

  return {
    id: "CIS-W-1.1",
    standard: STANDARD,
    title: "Strong wireless encryption",
    severity: "high",
    status,
    description:
      "Network should use WPA3 or at minimum WPA2. WEP and open networks are insecure.",
    recommendation: isWpa3
      ? "No action needed."
      : "Upgrade to WPA3-Personal or WPA3-Enterprise on the access point.",
    evidence: `Security: ${result.wifi.security}`,
  };
}

function checkSsidName(result: NetworkScanResult): Finding {
  const ssid = result.wifi.ssid;
  if (!ssid) {
    return {
      id: "CIS-W-1.2",
      standard: STANDARD,
      title: "SSID not using default name",
      severity: "low",
      status: "not-applicable",
      description: "SSID is hidden or unavailable.",
      recommendation: "No action needed.",
    };
  }
  const isDefault = DEFAULT_SSIDS.has(ssid.toLowerCase().trim());
  return {
    id: "CIS-W-1.2",
    standard: STANDARD,
    title: "SSID not using default name",
    severity: "low",
    status: isDefault ? "fail" : "pass",
    description:
      "Default SSIDs reveal router manufacturer and indicate the network has not been hardened.",
    recommendation: isDefault
      ? "Change the SSID to a custom name that does not reveal the router model."
      : "No action needed.",
    evidence: `SSID: ${ssid}`,
  };
}

function checkClientIsolation(result: NetworkScanResult): Finding {
  const isolation = result.security.clientIsolation;
  return {
    id: "CIS-W-1.3",
    standard: STANDARD,
    title: "Client isolation enabled",
    severity: "medium",
    status:
      isolation === null ? "not-applicable" : isolation ? "pass" : "fail",
    description:
      "Client isolation prevents devices on the same network from communicating directly, limiting lateral movement.",
    recommendation:
      isolation === true
        ? "No action needed."
        : "Enable AP/client isolation on the wireless access point.",
    evidence:
      isolation === null
        ? "Client isolation status unknown"
        : `Client isolation: ${isolation ? "enabled" : "disabled"}`,
  };
}

function checkFirewall(result: NetworkScanResult): Finding {
  return {
    id: "CIS-W-2.1",
    standard: STANDARD,
    title: "Firewall enabled",
    severity: "high",
    status: result.security.firewall.enabled ? "pass" : "fail",
    description:
      "A host-based firewall should be enabled to filter inbound and outbound traffic.",
    recommendation: result.security.firewall.enabled
      ? "No action needed."
      : "Enable the host firewall (macOS: System Settings > Network > Firewall).",
    evidence: `Firewall: ${result.security.firewall.enabled ? "enabled" : "disabled"}`,
  };
}

function checkStealthMode(result: NetworkScanResult): Finding {
  return {
    id: "CIS-W-2.2",
    standard: STANDARD,
    title: "Stealth mode enabled",
    severity: "medium",
    status: result.security.firewall.stealthMode ? "pass" : "fail",
    description:
      "Stealth mode prevents the system from responding to probe requests, making it less visible on the network.",
    recommendation: result.security.firewall.stealthMode
      ? "No action needed."
      : "Enable stealth mode in firewall settings.",
    evidence: `Stealth mode: ${result.security.firewall.stealthMode ? "enabled" : "disabled"}`,
  };
}

function checkVpn(result: NetworkScanResult): Finding {
  const vpn = result.security.vpn;
  return {
    id: "CIS-W-3.1",
    standard: STANDARD,
    title: "VPN active on untrusted networks",
    severity: "medium",
    status: vpn.active ? "pass" : vpn.installed ? "partial" : "fail",
    description:
      "A VPN should be active when connected to untrusted wireless networks to protect traffic in transit.",
    recommendation: vpn.active
      ? "No action needed."
      : vpn.installed
        ? "Activate the VPN before using untrusted networks."
        : "Install and configure a VPN client.",
    evidence: `VPN installed: ${vpn.installed}, active: ${vpn.active}${vpn.provider ? `, provider: ${vpn.provider}` : ""}`,
  };
}

function checkUnencryptedTraffic(result: NetworkScanResult): Finding {
  const traffic = result.traffic;
  if (!traffic) {
    return {
      id: "CIS-W-3.2",
      standard: STANDARD,
      title: "No unencrypted traffic detected",
      severity: "high",
      status: "not-applicable",
      description: "Traffic capture was not performed during this scan.",
      recommendation: "Run the scan with traffic capture enabled.",
    };
  }
  const count = traffic.unencrypted.length;
  return {
    id: "CIS-W-3.2",
    standard: STANDARD,
    title: "No unencrypted traffic detected",
    severity: "high",
    status: count === 0 ? "pass" : "fail",
    description:
      "Unencrypted traffic (HTTP, Telnet, FTP) can be intercepted by attackers on the same network.",
    recommendation:
      count === 0
        ? "No action needed."
        : "Ensure all applications use TLS/HTTPS. Block unencrypted protocols at the firewall.",
    evidence: `Unencrypted flows detected: ${count}${count > 0 ? ` (e.g. ${traffic.unencrypted[0].protocol} to ${traffic.unencrypted[0].dest}:${traffic.unencrypted[0].port})` : ""}`,
  };
}

function checkDnsHijack(result: NetworkScanResult): Finding {
  const hijack = result.network.dns.hijackTestResult;
  return {
    id: "CIS-W-4.1",
    standard: STANDARD,
    title: "DNS not hijacked",
    severity: "high",
    status:
      hijack === "clean"
        ? "pass"
        : hijack === "intercepted"
          ? "fail"
          : "partial",
    description:
      "DNS hijacking redirects queries to a rogue server, enabling phishing and man-in-the-middle attacks.",
    recommendation:
      hijack === "clean"
        ? "No action needed."
        : "Use a trusted DNS provider (e.g. 1.1.1.1, 8.8.8.8) with DNS-over-HTTPS.",
    evidence: `DNS hijack test: ${hijack}`,
  };
}

function checkDnssec(result: NetworkScanResult): Finding {
  return {
    id: "CIS-W-4.2",
    standard: STANDARD,
    title: "DNSSEC support",
    severity: "medium",
    status: result.network.dns.dnssecSupported ? "pass" : "fail",
    description:
      "DNSSEC validates DNS responses using cryptographic signatures, preventing cache poisoning.",
    recommendation: result.network.dns.dnssecSupported
      ? "No action needed."
      : "Configure a DNSSEC-validating resolver.",
    evidence: `DNSSEC supported: ${result.network.dns.dnssecSupported}`,
  };
}

function checkDohDot(result: NetworkScanResult): Finding {
  return {
    id: "CIS-W-4.3",
    standard: STANDARD,
    title: "DNS over HTTPS/TLS enabled",
    severity: "low",
    status: result.network.dns.dohDotEnabled ? "pass" : "fail",
    description:
      "DoH/DoT encrypts DNS queries, preventing eavesdropping on browsing activity.",
    recommendation: result.network.dns.dohDotEnabled
      ? "No action needed."
      : "Enable DNS-over-HTTPS in the OS or browser settings.",
    evidence: `DoH/DoT: ${result.network.dns.dohDotEnabled ? "enabled" : "disabled"}`,
  };
}

function checkArpActivity(result: NetworkScanResult): Finding {
  const indicators = result.intrusionIndicators;
  if (!indicators) {
    return {
      id: "CIS-W-5.1",
      standard: STANDARD,
      title: "No suspicious ARP activity",
      severity: "high",
      status: "not-applicable",
      description:
        "Intrusion indicator analysis was not performed during this scan.",
      recommendation: "Run the scan with intrusion detection enabled.",
    };
  }
  const arpCount = indicators.arpAnomalies.length;
  return {
    id: "CIS-W-5.1",
    standard: STANDARD,
    title: "No suspicious ARP activity",
    severity: "high",
    status: arpCount === 0 ? "pass" : "fail",
    description:
      "ARP spoofing allows attackers to intercept traffic by poisoning the ARP cache.",
    recommendation:
      arpCount === 0
        ? "No action needed."
        : "Investigate ARP anomalies. Consider using static ARP entries for critical hosts.",
    evidence: `ARP anomalies: ${arpCount}${arpCount > 0 ? ` (${indicators.arpAnomalies[0].type}: ${indicators.arpAnomalies[0].detail})` : ""}`,
  };
}

function checkHiddenCameras(result: NetworkScanResult): Finding {
  const hidden = result.hiddenDevices;
  if (!hidden) {
    return {
      id: "CIS-W-5.2",
      standard: STANDARD,
      title: "No hidden cameras detected",
      severity: "medium",
      status: "not-applicable",
      description:
        "Hidden device detection was not performed during this scan.",
      recommendation: "Run the scan with device detection enabled.",
    };
  }
  const cameraCount = hidden.suspectedCameras.length;
  return {
    id: "CIS-W-5.2",
    standard: STANDARD,
    title: "No hidden cameras detected",
    severity: "medium",
    status: cameraCount === 0 ? "pass" : "fail",
    description:
      "Hidden cameras on the network may indicate a privacy violation.",
    recommendation:
      cameraCount === 0
        ? "No action needed."
        : "Investigate suspected camera devices and remove any unauthorised ones.",
    evidence: `Suspected cameras: ${cameraCount}${cameraCount > 0 ? ` (${hidden.suspectedCameras[0].ip}${hidden.suspectedCameras[0].vendor ? ` - ${hidden.suspectedCameras[0].vendor}` : ""})` : ""}`,
  };
}

export function scoreCisWireless(result: NetworkScanResult): StandardScore {
  const findings: Finding[] = [
    checkEncryption(result),
    checkSsidName(result),
    checkClientIsolation(result),
    checkFirewall(result),
    checkStealthMode(result),
    checkVpn(result),
    checkUnencryptedTraffic(result),
    checkDnsHijack(result),
    checkDnssec(result),
    checkDohDot(result),
    checkArpActivity(result),
    checkHiddenCameras(result),
  ];

  const score = computeScore(findings);
  const passing = findings.filter((f) => f.status === "pass").length;
  const applicable = findings.filter(
    (f) => f.status !== "not-applicable"
  ).length;

  return {
    standard: STANDARD,
    name: "CIS Wireless Network Benchmark",
    version: "1.0",
    score,
    maxScore: 100,
    grade: computeGrade(score),
    findings,
    summary: `${passing}/${applicable} applicable controls passed (score: ${score}/100).`,
  };
}
