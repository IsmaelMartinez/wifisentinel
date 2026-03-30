import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { Insight, PersonaAnalysis } from "./types.js";
import { riskFromInsights } from "./types.js";

const PERSONA_ID = "blue-team" as const;
const DISPLAY_NAME = "Blue Team";
const PERSPECTIVE =
  "Evaluates defensive posture, detection capabilities, and incident response readiness to stop and contain threats.";

export function analyseAsBlueTeam(result: NetworkScanResult): PersonaAnalysis {
  const insights: Insight[] = [];

  // --- Firewall hardening assessment ---
  const fw = result.security.firewall;
  if (!fw.enabled) {
    insights.push({
      id: "bt-firewall-disabled",
      title: "Host firewall disabled — no perimeter defence in place",
      severity: "critical",
      category: "hardening",
      description: `The firewall is our first line of defence and it is completely down. Without it, we have no host-level filtering to block unauthorised inbound connections or contain lateral movement.`,
      technicalDetail: `macOS Application Firewall: enabled=${fw.enabled}, stealthMode=${fw.stealthMode}, autoAllowSigned=${fw.autoAllowSigned}, autoAllowDownloaded=${fw.autoAllowDownloaded}.`,
      recommendation:
        "Enable the firewall immediately. Enable stealth mode. Disable auto-allow for signed and downloaded applications to enforce explicit allow-listing.",
      affectedAssets: [result.meta.hostname],
      references: ["CIS-W-5.1", "NIST-800-153-5.1"],
    });
  } else {
    if (fw.autoAllowSigned || fw.autoAllowDownloaded) {
      insights.push({
        id: "bt-firewall-auto-allow",
        title: "Firewall auto-allow policies weaken defence in depth",
        severity: "medium",
        category: "hardening",
        description: `Auto-allowing signed or downloaded applications bypasses our explicit allow-listing policy. A trojanised but validly-signed binary would pass through unchecked.`,
        technicalDetail: `autoAllowSigned=${fw.autoAllowSigned}, autoAllowDownloaded=${fw.autoAllowDownloaded}.`,
        recommendation:
          "Disable auto-allow for both signed and downloaded applications. Maintain an explicit firewall allow-list.",
        affectedAssets: [result.meta.hostname],
        references: ["CIS-W-5.1.2"],
      });
    }
  }

  // --- VPN as defence layer ---
  if (!result.security.vpn.active) {
    insights.push({
      id: "bt-vpn-not-active",
      title: "VPN inactive reduces encrypted tunnel coverage",
      severity: "medium",
      category: "defense-in-depth",
      description: `An active VPN provides an additional encryption layer that protects traffic even if the Wi-Fi encryption is compromised. Without it, we lose a key defence-in-depth layer.`,
      technicalDetail: `VPN installed: ${result.security.vpn.installed}, active: false${result.security.vpn.provider ? `, provider: ${result.security.vpn.provider}` : ""}.`,
      recommendation:
        "Enforce always-on VPN policy on untrusted networks. Configure VPN kill-switch to prevent traffic leaks.",
      affectedAssets: [result.meta.hostname],
      references: ["NIST-800-153-4.3"],
    });
  }

  // --- Kernel hardening ---
  if (result.security.kernelParams.ipForwarding) {
    insights.push({
      id: "bt-ip-forwarding",
      title: "IP forwarding enabled weakens host hardening posture",
      severity: "high",
      category: "hardening",
      description: `IP forwarding should be disabled on endpoints. If a host is compromised, an attacker could use it to route traffic between segments, undermining our network segmentation controls.`,
      technicalDetail: `net.inet.ip.forwarding is enabled on ${result.meta.hostname}.`,
      recommendation:
        "Disable IP forwarding via sysctl: net.inet.ip.forwarding=0.",
      affectedAssets: [result.meta.hostname],
      references: ["CIS-W-5.3"],
    });
  }

  if (result.security.kernelParams.icmpRedirects) {
    insights.push({
      id: "bt-icmp-redirects",
      title: "ICMP redirects accepted — susceptible to route manipulation",
      severity: "medium",
      category: "hardening",
      description: `Accepting ICMP redirects allows an attacker to alter the host's routing table, potentially redirecting traffic through a malicious gateway. This is a classic detection gap.`,
      technicalDetail: `ICMP redirect acceptance is enabled on ${result.meta.hostname}.`,
      recommendation:
        "Disable ICMP redirect acceptance via sysctl configuration.",
      affectedAssets: [result.meta.hostname],
      references: ["CIS-W-5.4", "NIST-800-153-5.2"],
    });
  }

  // --- Intrusion detection capability ---
  if (result.intrusionIndicators) {
    const arpCount = result.intrusionIndicators.arpAnomalies.length;
    const susCount = result.intrusionIndicators.suspiciousHosts.length;
    const scanCount = result.intrusionIndicators.scanDetection.length;

    if (arpCount > 0 || susCount > 0 || scanCount > 0) {
      const severity =
        result.intrusionIndicators.arpAnomalies.some(
          (a) => a.severity === "high",
        ) ||
        result.intrusionIndicators.suspiciousHosts.some(
          (h) => h.severity === "high",
        )
          ? "high"
          : "medium";
      insights.push({
        id: "bt-intrusion-detected",
        title: `Intrusion indicators detected: ${arpCount} ARP anomalies, ${susCount} suspicious hosts, ${scanCount} scan events`,
        severity: severity as "high" | "medium",
        category: "detection",
        description: `Our detection layer has flagged anomalous activity. These indicators require triage and correlation with other log sources to determine if this is active compromise or benign network behaviour.`,
        technicalDetail: `ARP anomalies: ${result.intrusionIndicators.arpAnomalies.map((a) => `${a.type}: ${a.detail}`).join("; ")}. Suspicious hosts: ${result.intrusionIndicators.suspiciousHosts.map((h) => `${h.ip}: ${h.reason}`).join("; ")}.`,
        recommendation:
          "Triage all indicators. Correlate with SIEM data. Isolate confirmed suspicious hosts pending investigation.",
        affectedAssets: [
          ...result.intrusionIndicators.suspiciousHosts.map((h) => h.ip),
          ...result.intrusionIndicators.arpAnomalies.map((a) => a.detail),
        ],
        references: ["NIST-800-153-6.1"],
      });
    }
  } else {
    insights.push({
      id: "bt-no-intrusion-monitoring",
      title: "No intrusion indicator data available — detection gap identified",
      severity: "medium",
      category: "detection",
      description: `Without ARP monitoring, host anomaly detection, and scan detection, we are blind to active adversary presence on the network. This is a significant detection gap in our defensive posture.`,
      technicalDetail: `The scan did not produce intrusionIndicators data, indicating that monitoring collectors may not be running.`,
      recommendation:
        "Deploy ARP monitoring, network anomaly detection, and port scan detection. Feed alerts into a centralised SIEM.",
      affectedAssets: [result.meta.hostname],
      references: ["NIST-800-153-6.1", "CIS-W-6.1"],
    });
  }

  // --- DNS security ---
  const dns = result.network.dns;
  if (!dns.dnssecSupported) {
    insights.push({
      id: "bt-no-dnssec",
      title: "DNSSEC not supported — DNS responses are unverified",
      severity: "medium",
      category: "defense-in-depth",
      description: `Without DNSSEC validation, our resolver accepts forged DNS responses. An attacker performing DNS spoofing would go undetected.`,
      technicalDetail: `DNSSEC supported: false. DNS servers: ${dns.servers.join(", ")}.`,
      recommendation:
        "Configure a DNSSEC-validating resolver. Enable DoH or DoT for encrypted DNS transport.",
      affectedAssets: dns.servers,
      references: ["CIS-W-4.1", "NIST-800-153-3.3"],
    });
  }

  if (dns.hijackTestResult === "intercepted") {
    insights.push({
      id: "bt-dns-intercepted",
      title: "DNS interception detected — defensive monitoring is compromised",
      severity: "high",
      category: "detection",
      description: `DNS traffic is being intercepted, which means any DNS-based threat intelligence feeds and blocklists we rely on may be bypassed or tampered with. Our detection layer is undermined.`,
      technicalDetail: `DNS hijack test: intercepted. Configured DNS: ${dns.servers.join(", ")}.`,
      recommendation:
        "Switch to encrypted DNS (DoH/DoT) immediately. Verify DNS responses against known-good resolvers.",
      affectedAssets: dns.servers,
      references: ["CIS-W-4.1"],
    });
  }

  // --- Client isolation ---
  if (result.security.clientIsolation === false) {
    insights.push({
      id: "bt-no-client-isolation",
      title: "Client isolation disabled — containment of compromised hosts is limited",
      severity: "high",
      category: "defense-in-depth",
      description: `Without client isolation, a compromised device can freely communicate with every other host. Our ability to contain a breach is severely limited since the attacker can move laterally without crossing any segmentation boundary.`,
      technicalDetail: `Client isolation: disabled. Total hosts on segment: ${result.network.hosts.length}.`,
      recommendation:
        "Enable client isolation on the access point. Deploy VLAN segmentation for different device classes.",
      affectedAssets: result.network.hosts.map((h) => h.ip),
      references: ["CIS-W-2.3", "NIST-800-153-4.1"],
    });
  }

  // --- Unencrypted traffic detection ---
  if (result.traffic && result.traffic.unencrypted.length > 0) {
    insights.push({
      id: "bt-unencrypted-flows",
      title: `${result.traffic.unencrypted.length} unencrypted flow(s) detected — monitoring gap for encrypted baselines`,
      severity: "high",
      category: "detection",
      description: `Unencrypted traffic flows represent both a data exposure risk and a detection gap. Our security monitoring should flag and alert on any cleartext protocols as policy violations.`,
      technicalDetail: `Unencrypted flows: ${result.traffic.unencrypted.map((u) => `${u.protocol}→${u.dest}:${u.port}`).join(", ")}.`,
      recommendation:
        "Create detection rules to alert on cleartext protocol usage. Enforce TLS and block unencrypted egress.",
      affectedAssets: result.traffic.unencrypted.map(
        (u) => `${u.dest}:${u.port}`,
      ),
      references: ["CIS-W-3.2"],
    });
  }

  // --- Hidden devices / unknown assets ---
  const unknownDevices = result.hiddenDevices?.unknownDevices ?? [];
  if (unknownDevices.length > 0) {
    insights.push({
      id: "bt-unknown-devices",
      title: `${unknownDevices.length} unidentified device(s) on the network`,
      severity: "medium",
      category: "detection",
      description: `Devices we cannot identify represent a detection blind spot. Each could be an attacker-controlled implant, a rogue access point, or an unmanaged asset outside our hardening scope.`,
      technicalDetail: `Unknown devices: ${unknownDevices.map((d) => `${d.ip} (${d.mac}, ${d.vendor ?? "unknown vendor"})`).join(", ")}.`,
      recommendation:
        "Investigate and classify all unknown devices. Implement 802.1X network access control to prevent unauthorised devices.",
      affectedAssets: unknownDevices.map((d) => d.ip),
      references: ["CIS-W-2.1", "NIST-800-153-2.1"],
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
  const detectionGaps = insights.filter(
    (i) => i.category === "detection",
  ).length;

  if (critCount > 0) {
    return `The defensive posture has critical gaps. ${critCount} critical finding(s) indicate fundamental defence-in-depth failures that must be remediated before meaningful detection is possible. Hardening is the immediate priority.`;
  }
  if (highCount > 0) {
    return `Defence in depth is partially in place but ${highCount} high-severity gap(s) undermine containment and detection capabilities. ${detectionGaps} detection-related finding(s) indicate areas where adversary activity could go unnoticed.`;
  }
  if (insights.length > 0) {
    return `The defensive posture is reasonable with ${insights.length} finding(s) requiring attention. Most defence-in-depth layers are active, though hardening improvements and detection tuning would strengthen overall resilience.`;
  }
  return `The host demonstrates strong defensive posture with active firewall, VPN, and monitoring layers. Defence in depth is well-implemented across network, host, and application layers.`;
}

function deriveActions(insights: Insight[]): string[] {
  const actions: string[] = [];
  const ids = new Set(insights.map((i) => i.id));

  if (ids.has("bt-firewall-disabled"))
    actions.push("Enable the host firewall and stealth mode immediately");
  if (ids.has("bt-intrusion-detected"))
    actions.push(
      "Triage intrusion indicators and correlate with SIEM data",
    );
  if (ids.has("bt-no-client-isolation"))
    actions.push(
      "Enable client isolation to limit lateral movement and contain breaches",
    );
  if (ids.has("bt-ip-forwarding"))
    actions.push("Disable IP forwarding on endpoint hosts");
  if (ids.has("bt-dns-intercepted"))
    actions.push("Deploy encrypted DNS (DoH/DoT) to restore DNS integrity");
  if (ids.has("bt-unencrypted-flows"))
    actions.push(
      "Create detection rules for cleartext protocols and enforce TLS",
    );
  if (ids.has("bt-unknown-devices"))
    actions.push("Investigate and classify all unknown network devices");
  if (ids.has("bt-no-intrusion-monitoring"))
    actions.push(
      "Deploy network intrusion detection and ARP monitoring",
    );

  return actions.slice(0, 5);
}
