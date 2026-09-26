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

const STANDARD = "cis-wireless" as const;
const check = (spec: FindingSpec): Finding => finding(STANDARD, spec);

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
  const { wpaTier } = classifySecurity(result.wifi.security);
  return check({
    id: "CIS-W-1.1",
    title: "Strong wireless encryption",
    severity: "high",
    status: wpaTierStatus(wpaTier),
    description:
      "Network should use WPA3 or at minimum WPA2. WEP and open networks are insecure.",
    fix:
      wpaTier === "unknown"
        ? UNKNOWN_SECURITY_FIX
        : "Upgrade to WPA3-Personal or WPA3-Enterprise on the access point.",
    evidence: `Security: ${result.wifi.security}`,
  });
}

function checkSsidName(result: NetworkScanResult): Finding {
  const ssid = result.wifi.ssid;
  if (!ssid) {
    return check({
      id: "CIS-W-1.2",
      title: "SSID not using default name",
      severity: "low",
      status: "not-applicable",
      description: "SSID is hidden or unavailable.",
      fix: "No action needed.",
    });
  }
  const isDefault = DEFAULT_SSIDS.has(ssid.toLowerCase().trim());
  return check({
    id: "CIS-W-1.2",
    title: "SSID not using default name",
    severity: "low",
    status: isDefault ? "fail" : "pass",
    description:
      "Default SSIDs reveal router manufacturer and indicate the network has not been hardened.",
    fix: "Change the SSID to a custom name that does not reveal the router model.",
    evidence: `SSID: ${ssid}`,
  });
}

function checkClientIsolation(result: NetworkScanResult): Finding {
  const isolation = result.security.clientIsolation;
  return check({
    id: "CIS-W-1.3",
    title: "Client isolation enabled",
    severity: "medium",
    status: isolation === null ? "not-applicable" : isolation ? "pass" : "fail",
    description:
      "Client isolation prevents devices on the same network from communicating directly, limiting lateral movement.",
    fix: "Enable AP/client isolation on the wireless access point.",
    evidence:
      isolation === null
        ? "Client isolation status unknown"
        : `Client isolation: ${isolation ? "enabled" : "disabled"}`,
  });
}

function checkFirewall(result: NetworkScanResult): Finding {
  const enabled = result.security.firewall.enabled;
  return check({
    id: "CIS-W-2.1",
    title: "Firewall enabled",
    severity: "high",
    status: enabled ? "pass" : "fail",
    description:
      "A host-based firewall should be enabled to filter inbound and outbound traffic.",
    fix: "Enable the host firewall (macOS: System Settings > Network > Firewall).",
    evidence: `Firewall: ${enabled ? "enabled" : "disabled"}`,
  });
}

function checkStealthMode(result: NetworkScanResult): Finding {
  const stealth = result.security.firewall.stealthMode;
  return check({
    id: "CIS-W-2.2",
    title: "Stealth mode enabled",
    severity: "medium",
    status: stealth ? "pass" : "fail",
    description:
      "Stealth mode prevents the system from responding to probe requests, making it less visible on the network.",
    fix: "Enable stealth mode in firewall settings.",
    evidence: `Stealth mode: ${stealth ? "enabled" : "disabled"}`,
  });
}

function checkVpn(result: NetworkScanResult): Finding {
  const vpn = result.security.vpn;
  return check({
    id: "CIS-W-3.1",
    title: "VPN active on untrusted networks",
    severity: "medium",
    status: vpn.active ? "pass" : vpn.installed ? "partial" : "fail",
    description:
      "A VPN should be active when connected to untrusted wireless networks to protect traffic in transit.",
    fix: vpn.installed
      ? "Activate the VPN before using untrusted networks."
      : "Install and configure a VPN client.",
    evidence: `VPN installed: ${vpn.installed}, active: ${vpn.active}${vpn.provider ? `, provider: ${vpn.provider}` : ""}`,
  });
}

function checkUnencryptedTraffic(result: NetworkScanResult): Finding {
  const traffic = result.traffic;
  if (!traffic) {
    return check({
      id: "CIS-W-3.2",
      title: "No unencrypted traffic detected",
      severity: "high",
      status: "not-applicable",
      description: "Traffic capture was not performed during this scan.",
      fix: "Run the scan with traffic capture enabled.",
    });
  }
  const count = traffic.unencrypted.length;
  return check({
    id: "CIS-W-3.2",
    title: "No unencrypted traffic detected",
    severity: "high",
    status: count === 0 ? "pass" : "fail",
    description:
      "Unencrypted traffic (HTTP, Telnet, FTP) can be intercepted by attackers on the same network.",
    fix: "Ensure all applications use TLS/HTTPS. Block unencrypted protocols at the firewall.",
    evidence: `Unencrypted flows detected: ${count}${count > 0 ? ` (e.g. ${traffic.unencrypted[0].protocol} to ${traffic.unencrypted[0].dest}:${traffic.unencrypted[0].port})` : ""}`,
  });
}

function checkDnsHijack(result: NetworkScanResult): Finding {
  const hijack = result.network.dns.hijackTestResult;
  return check({
    id: "CIS-W-4.1",
    title: "DNS not hijacked",
    severity: "high",
    status: hijack === "clean" ? "pass" : hijack === "intercepted" ? "fail" : "partial",
    description:
      "DNS hijacking redirects queries to a rogue server, enabling phishing and man-in-the-middle attacks.",
    fix: "Use a trusted DNS provider (e.g. 1.1.1.1, 8.8.8.8) with DNS-over-HTTPS.",
    evidence: `DNS hijack test: ${hijack}`,
  });
}

function checkDnssec(result: NetworkScanResult): Finding {
  const dnssec = result.network.dns.dnssecSupported;
  return check({
    id: "CIS-W-4.2",
    title: "DNSSEC support",
    severity: "medium",
    status: dnssec ? "pass" : "fail",
    description:
      "DNSSEC validates DNS responses using cryptographic signatures, preventing cache poisoning.",
    fix: "Configure a DNSSEC-validating resolver.",
    evidence: `DNSSEC supported: ${dnssec}`,
  });
}

function checkDohDot(result: NetworkScanResult): Finding {
  const enabled = result.network.dns.dohDotEnabled;
  return check({
    id: "CIS-W-4.3",
    title: "DNS over HTTPS/TLS enabled",
    severity: "low",
    status: enabled ? "pass" : "fail",
    description:
      "DoH/DoT encrypts DNS queries, preventing eavesdropping on browsing activity.",
    fix: "Enable DNS-over-HTTPS in the OS or browser settings.",
    evidence: `DoH/DoT: ${enabled ? "enabled" : "disabled"}`,
  });
}

function checkArpActivity(result: NetworkScanResult): Finding {
  const indicators = result.intrusionIndicators;
  if (!indicators) {
    return check({
      id: "CIS-W-5.1",
      title: "No suspicious ARP activity",
      severity: "high",
      status: "not-applicable",
      description:
        "Intrusion indicator analysis was not performed during this scan.",
      fix: "Run the scan with intrusion detection enabled.",
    });
  }
  const arpCount = indicators.arpAnomalies.length;
  return check({
    id: "CIS-W-5.1",
    title: "No suspicious ARP activity",
    severity: "high",
    status: arpCount === 0 ? "pass" : "fail",
    description:
      "ARP spoofing allows attackers to intercept traffic by poisoning the ARP cache.",
    fix: "Investigate ARP anomalies. Consider using static ARP entries for critical hosts.",
    evidence: `ARP anomalies: ${arpCount}${arpCount > 0 ? ` (${indicators.arpAnomalies[0].type}: ${indicators.arpAnomalies[0].detail})` : ""}`,
  });
}

function checkHiddenCameras(result: NetworkScanResult): Finding {
  const hidden = result.hiddenDevices;
  if (!hidden) {
    return check({
      id: "CIS-W-5.2",
      title: "No hidden cameras detected",
      severity: "medium",
      status: "not-applicable",
      description:
        "Hidden device detection was not performed during this scan.",
      fix: "Run the scan with device detection enabled.",
    });
  }
  const cameraCount = hidden.suspectedCameras.length;
  return check({
    id: "CIS-W-5.2",
    title: "No hidden cameras detected",
    severity: "medium",
    status: cameraCount === 0 ? "pass" : "fail",
    description:
      "Hidden cameras on the network may indicate a privacy violation.",
    fix: "Investigate suspected camera devices and remove any unauthorised ones.",
    evidence: `Suspected cameras: ${cameraCount}${cameraCount > 0 ? ` (${hidden.suspectedCameras[0].ip}${hidden.suspectedCameras[0].vendor ? ` - ${hidden.suspectedCameras[0].vendor}` : ""})` : ""}`,
  });
}

export function scoreCisWireless(result: NetworkScanResult): StandardScore {
  return buildStandardScore(STANDARD, "CIS Wireless Network Benchmark", "1.0", [
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
  ]);
}
