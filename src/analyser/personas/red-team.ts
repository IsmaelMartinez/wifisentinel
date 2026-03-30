import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { Insight, PersonaAnalysis } from "./types.js";
import { riskFromInsights } from "./types.js";

const PERSONA_ID = "red-team" as const;
const DISPLAY_NAME = "Red Team";
const PERSPECTIVE =
  "Identifies exploitable weaknesses an attacker would target to gain access, move laterally, and exfiltrate data.";

export function analyseAsRedTeam(result: NetworkScanResult): PersonaAnalysis {
  const insights: Insight[] = [];

  // --- Attack surface: open ports on network hosts ---
  for (const host of result.network.hosts) {
    const openPorts = (host.ports ?? []).filter((p) => p.state === "open");
    if (openPorts.length > 0) {
      const portList = openPorts.map((p) => `${p.port}/${p.service}`).join(", ");
      insights.push({
        id: `rt-open-ports-${host.ip}`,
        title: `Open ports on ${host.ip} expand the attack surface`,
        severity: openPorts.length >= 5 ? "high" : "medium",
        category: "attack-surface",
        description: `This host exposes ${openPorts.length} open port(s), each representing a potential foothold. An attacker would probe these services for default credentials, known CVEs, and misconfigurations.`,
        technicalDetail: `Host ${host.ip} (${host.mac}${host.vendor ? `, ${host.vendor}` : ""}) has open ports: ${portList}.`,
        recommendation:
          "Close unnecessary ports and ensure exposed services are patched and hardened. Apply network segmentation to restrict access.",
        affectedAssets: [host.ip, host.mac],
        references: ["NIST-800-153-4.2", "CIS-W-3.1"],
      });
    }
  }

  // --- Locally exposed services ---
  const exposed = result.localServices.filter((s) => s.exposedToNetwork);
  if (exposed.length > 0) {
    const svcList = exposed.map((s) => `${s.port}/${s.process}`).join(", ");
    insights.push({
      id: "rt-exposed-local-services",
      title: `${exposed.length} locally-bound service(s) exposed to the network`,
      severity: exposed.length >= 3 ? "high" : "medium",
      category: "attack-surface",
      description: `Services bound to 0.0.0.0 are reachable by any host on the network. An attacker on the same segment can enumerate and exploit these as pivot points.`,
      technicalDetail: `Exposed services: ${svcList}.`,
      recommendation:
        "Bind services to 127.0.0.1 unless network access is required. Use host-based firewall rules to restrict access.",
      affectedAssets: exposed.map((s) => `${s.bindAddress}:${s.port}`),
      references: ["CIS-W-5.2", "OWASP-IoT-6"],
    });
  }

  // --- Weak encryption / insecure wifi security ---
  const weakSecurityPatterns = ["WEP", "WPA ", "Open", "None"];
  const isWeak = weakSecurityPatterns.some((p) =>
    result.wifi.security.toUpperCase().startsWith(p.toUpperCase()),
  );
  if (isWeak) {
    insights.push({
      id: "rt-weak-wifi-encryption",
      title: "Weak or absent Wi-Fi encryption enables passive interception",
      severity: "critical",
      category: "credential-exposure",
      description: `The current Wi-Fi security (${result.wifi.security}) is trivially breakable. An attacker with a commodity adapter can capture and decrypt all traffic, harvest credentials, and inject packets.`,
      technicalDetail: `SSID "${result.wifi.ssid ?? "(hidden)"}" uses ${result.wifi.security} on channel ${result.wifi.channel}.`,
      recommendation:
        "Upgrade to WPA3-Personal or WPA2-AES at minimum. Disable legacy protocol support on the access point.",
      affectedAssets: [result.wifi.bssid, result.wifi.ssid ?? "(hidden SSID)"],
      references: ["CIS-W-1.1", "IEEE-802.11-9.4", "NIST-800-153-3.2"],
    });
  }

  // --- No client isolation = lateral movement ---
  if (result.security.clientIsolation === false) {
    insights.push({
      id: "rt-no-client-isolation",
      title: "No client isolation enables lateral movement between hosts",
      severity: "high",
      category: "lateral-movement",
      description: `Without client isolation, any compromised device can freely scan, attack, and pivot to every other host on the network. This is the first thing an attacker checks after gaining a foothold.`,
      technicalDetail: `Client isolation is disabled on the network. ${result.network.hosts.length} host(s) are reachable from any connected device.`,
      recommendation:
        "Enable AP isolation / client isolation on the wireless access point. Segment IoT and guest devices onto separate VLANs.",
      affectedAssets: result.network.hosts.map((h) => h.ip),
      references: ["CIS-W-2.3", "NIST-800-153-4.1"],
    });
  }

  // --- Firewall disabled = no perimeter ---
  if (!result.security.firewall.enabled) {
    insights.push({
      id: "rt-firewall-disabled",
      title: "Host firewall disabled removes the last line of defence",
      severity: "critical",
      category: "attack-surface",
      description: `With the firewall off, every listening port is directly reachable. An attacker doesn't need to bypass any filtering to reach running services.`,
      technicalDetail: `macOS Application Firewall is disabled. Stealth mode: ${result.security.firewall.stealthMode}.`,
      recommendation:
        "Enable the host firewall immediately and enable stealth mode to prevent port scan responses.",
      affectedAssets: [result.meta.hostname],
      references: ["CIS-W-5.1", "NIST-800-153-5.1"],
    });
  } else if (!result.security.firewall.stealthMode) {
    insights.push({
      id: "rt-stealth-mode-off",
      title: "Stealth mode disabled makes host visible to port scans",
      severity: "medium",
      category: "reconnaissance",
      description: `Without stealth mode the host responds to probing, confirming its existence and making service enumeration trivial during reconnaissance.`,
      technicalDetail: `Firewall is enabled but stealth mode is off. The host will respond to ICMP echo and closed-port RST packets.`,
      recommendation: "Enable stealth mode in the firewall settings.",
      affectedAssets: [result.meta.hostname],
      references: ["CIS-W-5.1.1"],
    });
  }

  // --- VPN not active ---
  if (!result.security.vpn.active) {
    insights.push({
      id: "rt-vpn-inactive",
      title: "No active VPN leaves traffic visible to local network observers",
      severity: "medium",
      category: "credential-exposure",
      description: `Without a VPN, an attacker on the same network segment can observe connection metadata and potentially intercept unencrypted traffic.`,
      technicalDetail: `VPN installed: ${result.security.vpn.installed}, active: false${result.security.vpn.provider ? `, provider: ${result.security.vpn.provider}` : ""}.`,
      recommendation:
        "Activate the VPN when on untrusted networks. Consider an always-on VPN policy.",
      affectedAssets: [result.meta.hostname],
      references: ["NIST-800-153-4.3"],
    });
  }

  // --- DNS hijacking detected ---
  if (result.network.dns.hijackTestResult === "intercepted") {
    insights.push({
      id: "rt-dns-hijack",
      title: "DNS queries are being intercepted — possible MITM position",
      severity: "high",
      category: "credential-exposure",
      description: `DNS interception means an attacker (or the ISP) can redirect resolution, enabling phishing, traffic inspection, and credential harvesting via forged DNS responses.`,
      technicalDetail: `DNS hijack test returned "intercepted". Configured servers: ${result.network.dns.servers.join(", ")}.`,
      recommendation:
        "Switch to encrypted DNS (DoH/DoT) and verify DNS responses with DNSSEC where possible.",
      affectedAssets: result.network.dns.servers,
      references: ["CIS-W-4.1", "NIST-800-153-3.3"],
    });
  }

  // --- Unencrypted traffic ---
  if (result.traffic && result.traffic.unencrypted.length > 0) {
    const flows = result.traffic.unencrypted
      .slice(0, 5)
      .map((u) => `${u.protocol}→${u.dest}:${u.port}`)
      .join(", ");
    insights.push({
      id: "rt-unencrypted-traffic",
      title: `${result.traffic.unencrypted.length} unencrypted traffic flow(s) detected`,
      severity: "high",
      category: "credential-exposure",
      description: `Unencrypted protocols transmit data in cleartext. An attacker with passive network access can harvest credentials, session tokens, and sensitive data.`,
      technicalDetail: `Captured unencrypted flows: ${flows}.`,
      recommendation:
        "Enforce TLS on all services. Block outbound cleartext protocols at the firewall.",
      affectedAssets: result.traffic.unencrypted.map(
        (u) => `${u.dest}:${u.port}`,
      ),
      references: ["CIS-W-3.2", "OWASP-IoT-7"],
    });
  }

  // --- mDNS leaks expose device inventory ---
  if (result.traffic && result.traffic.mdnsLeaks.length > 0) {
    const services = result.traffic.mdnsLeaks
      .map((m) => `${m.service} (${m.host})`)
      .join(", ");
    insights.push({
      id: "rt-mdns-leaks",
      title: "mDNS service advertisements expose device inventory to attackers",
      severity: "medium",
      category: "reconnaissance",
      description: `mDNS broadcasts enumerate available services and hostnames, giving an attacker a free reconnaissance map of the network without active scanning.`,
      technicalDetail: `Leaked mDNS services: ${services}.`,
      recommendation:
        "Disable mDNS/Bonjour on hosts that don't require it. Segment mDNS traffic to trusted VLANs only.",
      affectedAssets: result.traffic.mdnsLeaks.map((m) => m.host),
      references: ["CIS-W-3.3"],
    });
  }

  // --- Double NAT as recon signal ---
  if (result.network.topology.doubleNat) {
    insights.push({
      id: "rt-double-nat",
      title: "Double NAT reveals multi-layer network topology to attackers",
      severity: "low",
      category: "reconnaissance",
      description: `Double NAT indicates cascaded routers. An attacker can use this to map internal network architecture and identify additional pivot points between segments.`,
      technicalDetail: `Double NAT detected. Hops: ${result.network.topology.hops.map((h) => h.ip).join(" → ")}.`,
      recommendation:
        "If double NAT is unintentional, simplify the topology. If intentional, ensure both routers are hardened.",
      affectedAssets: result.network.topology.hops.map((h) => h.ip),
      references: ["NIST-800-153-4.1"],
    });
  }

  // --- IP forwarding enabled ---
  if (result.security.kernelParams.ipForwarding) {
    insights.push({
      id: "rt-ip-forwarding",
      title:
        "IP forwarding enabled turns this host into a potential pivot router",
      severity: "high",
      category: "lateral-movement",
      description: `With IP forwarding on, a compromised host can route traffic between network segments, enabling an attacker to reach otherwise-isolated subnets.`,
      technicalDetail: `Kernel parameter net.inet.ip.forwarding is enabled on ${result.meta.hostname}.`,
      recommendation:
        "Disable IP forwarding unless this host is intentionally functioning as a router.",
      affectedAssets: [result.meta.hostname],
      references: ["CIS-W-5.3", "NIST-800-153-5.2"],
    });
  }

  // --- Cameras and IoT as entry points ---
  const cameras = result.hiddenDevices?.suspectedCameras ?? [];
  if (cameras.length > 0) {
    insights.push({
      id: "rt-cameras-entry-point",
      title: `${cameras.length} suspected camera(s) present as high-value targets`,
      severity: "high",
      category: "attack-surface",
      description: `Network cameras typically run embedded firmware with infrequent patches, default credentials, and RTSP/HTTP interfaces. They are prime targets for establishing a persistent foothold.`,
      technicalDetail: `Cameras detected: ${cameras.map((c) => `${c.ip} (${c.vendor ?? "unknown"})`).join(", ")}. Indicators: ${cameras.flatMap((c) => c.cameraIndicators ?? []).join(", ")}.`,
      recommendation:
        "Isolate cameras on a dedicated VLAN. Change default credentials. Disable UPnP and remote access features.",
      affectedAssets: cameras.map((c) => c.ip),
      references: ["OWASP-IoT-1", "OWASP-IoT-3"],
    });
  }

  // --- Nearby networks as targets ---
  const openNearby = result.wifi.nearbyNetworks.filter(
    (n) => n.security === "Open" || n.security === "None",
  );
  if (openNearby.length > 0) {
    insights.push({
      id: "rt-open-nearby-networks",
      title: `${openNearby.length} open nearby network(s) could be used for evil twin attacks`,
      severity: "medium",
      category: "reconnaissance",
      description: `Open networks in proximity can be cloned by an attacker to create evil twin access points, tricking devices into auto-connecting and leaking credentials.`,
      technicalDetail: `Open nearby SSIDs: ${openNearby.map((n) => n.ssid ?? "(hidden)").join(", ")} on channels ${openNearby.map((n) => n.channel).join(", ")}.`,
      recommendation:
        "Remove saved open networks from device profiles. Use 802.1X or WPA3-SAE to prevent rogue AP association.",
      affectedAssets: openNearby.map(
        (n) => n.bssid ?? n.ssid ?? "(hidden)",
      ),
      references: ["IEEE-802.11-12.1", "CIS-W-1.2"],
    });
  }

  // --- Intrusion indicators ---
  if (result.intrusionIndicators) {
    const highSev = [
      ...result.intrusionIndicators.arpAnomalies.filter(
        (a) => a.severity === "high",
      ),
      ...result.intrusionIndicators.suspiciousHosts.filter(
        (h) => h.severity === "high",
      ),
    ];
    if (highSev.length > 0) {
      insights.push({
        id: "rt-active-intrusion-indicators",
        title:
          "High-severity intrusion indicators suggest active adversary presence",
        severity: "critical",
        category: "lateral-movement",
        description: `ARP anomalies and suspicious hosts at high severity indicate possible ARP spoofing, MITM attacks, or an already-compromised device on the network. This demands immediate investigation.`,
        technicalDetail: `${highSev.length} high-severity indicator(s): ${highSev.map((i) => ("type" in i ? i.type : i.reason)).join(", ")}.`,
        recommendation:
          "Investigate immediately. Isolate suspicious hosts. Capture packets for forensic analysis. Check for ARP cache poisoning.",
        affectedAssets: result.intrusionIndicators.suspiciousHosts.map(
          (h) => h.ip,
        ),
        references: ["NIST-800-153-6.1", "CIS-W-6.1"],
      });
    }
  }

  const priorityActions = deriveActions(result, insights);

  return {
    persona: PERSONA_ID,
    displayName: DISPLAY_NAME,
    perspective: PERSPECTIVE,
    riskRating: riskFromInsights(insights),
    executiveSummary: buildSummary(result, insights),
    insights,
    priorityActions,
  };
}

function buildSummary(
  result: NetworkScanResult,
  insights: Insight[],
): string {
  const critCount = insights.filter((i) => i.severity === "critical").length;
  const highCount = insights.filter((i) => i.severity === "high").length;
  const hostCount = result.network.hosts.length;

  if (critCount > 0) {
    return `This network presents critical attack opportunities. ${critCount} critical and ${highCount} high-severity weakness(es) were identified across ${hostCount} host(s). An attacker with local network access could establish a foothold with minimal effort and move laterally without impediment.`;
  }
  if (highCount > 0) {
    return `The attack surface has notable weaknesses. ${highCount} high-severity finding(s) across ${hostCount} host(s) would allow a motivated attacker to gain access and escalate. Remediation of key findings would significantly raise the cost of exploitation.`;
  }
  if (insights.length > 0) {
    return `The network has a moderate attack surface with ${insights.length} finding(s). While no critical footholds were identified, the exposed services and configuration gaps provide reconnaissance value and potential entry points for a persistent attacker.`;
  }
  return `The network presents a hardened posture from an attacker's perspective. No significant footholds or lateral movement opportunities were identified in this scan.`;
}

function deriveActions(
  result: NetworkScanResult,
  insights: Insight[],
): string[] {
  const actions: string[] = [];
  const ids = new Set(insights.map((i) => i.id));

  if (ids.has("rt-firewall-disabled"))
    actions.push("Enable the host firewall and stealth mode immediately");
  if (ids.has("rt-weak-wifi-encryption"))
    actions.push("Upgrade Wi-Fi encryption to WPA3 or WPA2-AES");
  if (ids.has("rt-active-intrusion-indicators"))
    actions.push(
      "Investigate and isolate hosts with high-severity intrusion indicators",
    );
  if (ids.has("rt-no-client-isolation"))
    actions.push("Enable client isolation to prevent lateral movement");
  if (ids.has("rt-ip-forwarding"))
    actions.push("Disable IP forwarding on non-router hosts");
  if (ids.has("rt-dns-hijack"))
    actions.push("Switch to encrypted DNS (DoH/DoT) to prevent interception");
  if (ids.has("rt-unencrypted-traffic"))
    actions.push("Eliminate unencrypted traffic flows — enforce TLS everywhere");
  if (ids.has("rt-cameras-entry-point"))
    actions.push("Isolate IoT and camera devices on a separate VLAN");

  if (actions.length === 0 && insights.length > 0) {
    actions.push("Review and close unnecessary open ports on network hosts");
  }

  return actions.slice(0, 5);
}
