import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { Insight, PersonaAnalysis } from "./types.js";
import { riskFromInsights } from "./types.js";

const PERSONA_ID = "privacy" as const;
const DISPLAY_NAME = "Privacy Advocate";
const PERSPECTIVE =
  "Evaluates the privacy implications of the network configuration, identifying tracking risks, data leaks, and surveillance exposure.";

export function analyseAsPrivacy(result: NetworkScanResult): PersonaAnalysis {
  const insights: Insight[] = [];

  // --- MAC randomisation ---
  if (!result.wifi.macRandomised) {
    insights.push({
      id: "pr-mac-not-randomised",
      title:
        "MAC address randomisation disabled — device is trackable across networks",
      severity: "high",
      category: "tracking",
      description: `Without MAC randomisation, this device broadcasts a persistent hardware identifier that can be used to track its presence across different networks, shops, transit systems, and public spaces. Any passive Wi-Fi probe collector can build a movement profile.`,
      technicalDetail: `MAC randomisation: disabled on interface ${result.network.interface}. The device's true MAC address is broadcast in probe requests and association frames.`,
      recommendation:
        "Enable MAC address randomisation in the operating system's Wi-Fi settings. This prevents cross-network tracking via probe request fingerprinting.",
      affectedAssets: [result.meta.hostname],
      references: ["IEEE-802.11-11.1"],
    });
  }

  // --- mDNS leaks ---
  if (result.traffic && result.traffic.mdnsLeaks.length > 0) {
    const leaks = result.traffic.mdnsLeaks;
    insights.push({
      id: "pr-mdns-exposure",
      title: `${leaks.length} mDNS service(s) broadcasting device information to the network`,
      severity: "high",
      category: "data-leaks",
      description: `mDNS broadcasts expose service names, hostnames, and device capabilities to every device on the network. This is a form of involuntary data disclosure — anyone on the same segment can enumerate your devices, their names, and the services they offer.`,
      technicalDetail: `Leaked mDNS services: ${leaks.map((m) => `${m.service} on ${m.host}`).join(", ")}.`,
      recommendation:
        "Disable mDNS/Bonjour on devices that don't require local discovery. Use firewall rules to block mDNS (port 5353) egress.",
      affectedAssets: leaks.map((m) => m.host),
      references: ["CIS-W-3.3"],
    });
  }

  // --- DNS query visibility ---
  if (!result.network.dns.dohDotEnabled) {
    insights.push({
      id: "pr-dns-not-encrypted",
      title:
        "DNS queries sent in plaintext — browsing activity is observable",
      severity: "high",
      category: "data-leaks",
      description: `Without encrypted DNS (DoH or DoT), every domain name lookup is visible in plaintext to anyone on the network path — including the ISP, network operator, and any attacker in a monitoring position. This creates a detailed log of browsing activity and application usage.`,
      technicalDetail: `DoH/DoT: disabled. DNS servers: ${result.network.dns.servers.join(", ")}. DNSSEC: ${result.network.dns.dnssecSupported}.`,
      recommendation:
        "Enable DNS over HTTPS (DoH) or DNS over TLS (DoT) on the system resolver. Use a privacy-respecting DNS provider.",
      affectedAssets: result.network.dns.servers,
      references: ["CIS-W-4.1", "NIST-800-153-3.3"],
    });
  }

  // --- DNS hijack = third-party surveillance ---
  if (result.network.dns.hijackTestResult === "intercepted") {
    insights.push({
      id: "pr-dns-intercepted",
      title: "DNS queries are being intercepted by a third party",
      severity: "critical",
      category: "surveillance",
      description: `A third party (likely the ISP or network operator) is intercepting DNS queries regardless of the configured resolver. This means your browsing history is being collected and potentially monetised. This is a direct privacy violation.`,
      technicalDetail: `DNS hijack test: intercepted. Configured servers: ${result.network.dns.servers.join(", ")} but queries are redirected to an unknown resolver.`,
      recommendation:
        "Switch to encrypted DNS (DoH/DoT) immediately to prevent interception. Consider a VPN for complete traffic privacy.",
      affectedAssets: result.network.dns.servers,
      references: ["CIS-W-4.1"],
    });
  }

  // --- Unencrypted traffic ---
  if (result.traffic && result.traffic.unencrypted.length > 0) {
    const flows = result.traffic.unencrypted;
    insights.push({
      id: "pr-unencrypted-traffic",
      title: `${flows.length} unencrypted traffic flow(s) expose communication content`,
      severity: "high",
      category: "data-leaks",
      description: `Unencrypted protocols transmit data in cleartext, meaning any observer on the network can read the full content of these communications — including login pages, form submissions, and API calls. Data minimisation requires encrypting all data in transit.`,
      technicalDetail: `Unencrypted flows: ${flows.map((u) => `${u.protocol}→${u.dest}:${u.port}`).join(", ")}.`,
      recommendation:
        "Enforce HTTPS/TLS on all connections. Use browser extensions like HTTPS Everywhere. Block cleartext protocols at the firewall.",
      affectedAssets: flows.map((u) => `${u.dest}:${u.port}`),
      references: ["CIS-W-3.2", "NIST-800-153-3.2"],
    });
  }

  // --- Camera surveillance ---
  const cameras = result.hiddenDevices?.suspectedCameras ?? [];
  if (cameras.length > 0) {
    insights.push({
      id: "pr-camera-surveillance",
      title: `${cameras.length} suspected camera(s) detected — potential surveillance risk`,
      severity: "critical",
      category: "surveillance",
      description: `Network cameras capable of recording video and audio are present on this network. Without knowing their operator, configuration, and data retention policies, these represent a direct surveillance risk. They may be recording without consent or transmitting footage to third parties.`,
      technicalDetail: `Suspected cameras: ${cameras.map((c) => `${c.ip} (${c.vendor ?? "unknown vendor"}, indicators: ${(c.cameraIndicators ?? []).join(", ")})`).join("; ")}.`,
      recommendation:
        "Identify the owner and purpose of each camera. Verify consent and data retention policies. Ensure cameras are not accessible from the internet.",
      affectedAssets: cameras.map((c) => c.ip),
      references: ["OWASP-IoT-1"],
    });
  }

  // --- Hidden/unknown devices ---
  const unknownDevices = result.hiddenDevices?.unknownDevices ?? [];
  if (unknownDevices.length > 0) {
    insights.push({
      id: "pr-unknown-devices",
      title: `${unknownDevices.length} unidentified device(s) — potential covert monitoring`,
      severity: "medium",
      category: "surveillance",
      description: `Unidentified devices on the network could be anything from forgotten IoT gadgets to deliberately planted surveillance equipment. Without positive identification, each represents a privacy risk that cannot be assessed.`,
      technicalDetail: `Unknown devices: ${unknownDevices.map((d) => `${d.ip} (${d.mac}, vendor: ${d.vendor ?? "unknown"})`).join(", ")}.`,
      recommendation:
        "Physically identify each unknown device. Remove any that are not authorised. Implement network access control to prevent rogue devices.",
      affectedAssets: unknownDevices.map((d) => d.ip),
      references: ["CIS-W-2.1"],
    });
  }

  // --- Nearby network fingerprinting ---
  const nearbyCount = result.wifi.nearbyNetworks.length;
  if (nearbyCount > 0) {
    const hiddenNearby = result.wifi.nearbyNetworks.filter(
      (n) => n.ssid === null,
    );
    insights.push({
      id: "pr-nearby-network-fingerprint",
      title: `${nearbyCount} nearby networks create a location fingerprint`,
      severity: "low",
      category: "tracking",
      description: `The set of visible Wi-Fi networks creates a unique location fingerprint. Applications and operating systems can use this fingerprint for geolocation even when GPS is disabled. ${hiddenNearby.length} hidden network(s) are also detectable and contribute to the fingerprint.`,
      technicalDetail: `${nearbyCount} nearby networks detected across channels. Hidden networks: ${hiddenNearby.length}. This fingerprint can be matched against wardriving databases for geolocation.`,
      recommendation:
        "Disable Wi-Fi scanning when not actively connecting. Review which applications have location permissions based on Wi-Fi.",
      affectedAssets: [result.meta.hostname],
      references: ["IEEE-802.11-11.2"],
    });
  }

  // --- VPN not active ---
  if (!result.security.vpn.active) {
    insights.push({
      id: "pr-vpn-inactive",
      title:
        "No VPN active — ISP and network operator can observe all traffic metadata",
      severity: "medium",
      category: "data-leaks",
      description: `Without a VPN, the ISP has full visibility into connection metadata: which servers you connect to, when, and how much data is exchanged. Combined with unencrypted DNS, this builds a complete browsing profile.`,
      technicalDetail: `VPN installed: ${result.security.vpn.installed}, active: false${result.security.vpn.provider ? `, provider: ${result.security.vpn.provider}` : ""}.`,
      recommendation:
        "Activate the VPN to encrypt all traffic and prevent ISP metadata collection. Choose a provider with a verified no-logs policy.",
      affectedAssets: [result.meta.hostname],
      references: ["NIST-800-153-4.3"],
    });
  }

  // --- Exposed local services leak information ---
  const exposed = result.localServices.filter((s) => s.exposedToNetwork);
  if (exposed.length > 0) {
    insights.push({
      id: "pr-exposed-services",
      title: `${exposed.length} exposed service(s) reveal device capabilities to the network`,
      severity: "medium",
      category: "network-exposure",
      description: `Services bound to 0.0.0.0 are discoverable by any device on the network. Each exposed service leaks information about what software is installed and what this device is used for — contributing to a device profile that can be used for targeting.`,
      technicalDetail: `Exposed services: ${exposed.map((s) => `${s.port}/${s.process}`).join(", ")}.`,
      recommendation:
        "Bind services to 127.0.0.1 unless network access is explicitly needed. Review which processes genuinely need to be reachable.",
      affectedAssets: exposed.map((s) => `${s.bindAddress}:${s.port}`),
      references: ["CIS-W-5.2"],
    });
  }

  // --- DNS query content analysis ---
  if (result.traffic && result.traffic.dnsQueries.length > 0) {
    const nonSecure = result.traffic.dnsQueries.filter((q) => !q.dnssec);
    if (nonSecure.length > 0) {
      insights.push({
        id: "pr-dns-queries-visible",
        title: `${nonSecure.length} DNS query(ies) sent without DNSSEC — domain lookups are tamper-able`,
        severity: "medium",
        category: "data-leaks",
        description: `DNS queries without DNSSEC validation can be forged, allowing an attacker to redirect traffic to phishing sites. The queried domains also reveal what services and websites are being used.`,
        technicalDetail: `Unvalidated queries to: ${nonSecure.slice(0, 5).map((q) => `${q.domain} via ${q.server}`).join(", ")}${nonSecure.length > 5 ? ` and ${nonSecure.length - 5} more` : ""}.`,
        recommendation:
          "Enable DNSSEC validation on the resolver. Use DoH/DoT to prevent query observation.",
        affectedAssets: [...new Set(nonSecure.map((q) => q.server))],
        references: ["CIS-W-4.1"],
      });
    }
  }

  // --- Weak Wi-Fi encryption ---
  const weakPatterns = ["WEP", "WPA ", "Open", "None"];
  const isWeak = weakPatterns.some((p) =>
    result.wifi.security.toUpperCase().startsWith(p.toUpperCase()),
  );
  if (isWeak) {
    insights.push({
      id: "pr-weak-wifi-privacy",
      title:
        "Weak Wi-Fi encryption means all wireless traffic is effectively public",
      severity: "critical",
      category: "data-leaks",
      description: `With ${result.wifi.security} encryption, any nearby observer can capture and decrypt all wireless traffic. This is equivalent to broadcasting all network activity over an open channel — every website, every message, every file transfer.`,
      technicalDetail: `Wi-Fi security: ${result.wifi.security}. All data on this wireless link should be considered observable.`,
      recommendation:
        "Upgrade to WPA3 immediately. In the meantime, use a VPN to encrypt all traffic within the weak wireless link.",
      affectedAssets: [result.wifi.bssid, result.meta.hostname],
      references: ["CIS-W-1.1", "IEEE-802.11-9.4"],
    });
  }

  // --- Client isolation and network exposure ---
  if (result.security.clientIsolation === false) {
    insights.push({
      id: "pr-no-client-isolation",
      title:
        "No client isolation — every device on the network can see your traffic",
      severity: "medium",
      category: "network-exposure",
      description: `Without client isolation, other devices on the network can perform ARP spoofing, packet sniffing, and service discovery against this host. Your device and its activities are fully visible to potentially untrusted neighbours.`,
      technicalDetail: `Client isolation: disabled. ${result.network.hosts.length} other host(s) on the same segment.`,
      recommendation:
        "Request client isolation from the network administrator. Use a VPN as a compensating control.",
      affectedAssets: [result.meta.hostname],
      references: ["CIS-W-2.3"],
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
  const trackingIssues = insights.filter(
    (i) => i.category === "tracking" || i.category === "surveillance",
  ).length;
  const leakIssues = insights.filter(
    (i) => i.category === "data-leaks",
  ).length;

  if (critCount > 0) {
    return `Severe privacy exposure detected. ${critCount} critical finding(s) indicate that private data is being actively intercepted or surveilled. ${trackingIssues} tracking/surveillance risk(s) and ${leakIssues} data leak(s) were identified. Immediate action is needed to restore privacy.`;
  }
  if (highCount > 0) {
    return `The privacy posture has significant weaknesses. ${highCount} high-severity finding(s) expose personal data, browsing activity, or device identity to network observers. Data minimisation principles are not being followed.`;
  }
  if (insights.length > 0) {
    return `The privacy posture has ${insights.length} finding(s) that could improve data minimisation and reduce the exposure surface. While no critical data leaks were identified, the current configuration reveals more information than necessary.`;
  }
  return `The privacy posture is strong. MAC randomisation, encrypted DNS, and VPN usage minimise the exposure surface. No significant tracking or data leak risks were identified.`;
}

function deriveActions(insights: Insight[]): string[] {
  const actions: string[] = [];
  const ids = new Set(insights.map((i) => i.id));

  if (ids.has("pr-dns-intercepted"))
    actions.push("Enable encrypted DNS (DoH/DoT) to stop DNS interception");
  if (ids.has("pr-camera-surveillance"))
    actions.push(
      "Identify and verify consent for all detected surveillance cameras",
    );
  if (ids.has("pr-weak-wifi-privacy"))
    actions.push(
      "Upgrade Wi-Fi encryption to WPA3 or use a VPN as a compensating control",
    );
  if (ids.has("pr-mac-not-randomised"))
    actions.push(
      "Enable MAC address randomisation to prevent cross-network tracking",
    );
  if (ids.has("pr-dns-not-encrypted"))
    actions.push("Switch to encrypted DNS to hide browsing activity from observers");
  if (ids.has("pr-mdns-exposure"))
    actions.push("Disable mDNS to stop broadcasting device information");
  if (ids.has("pr-vpn-inactive"))
    actions.push("Activate VPN to encrypt traffic and prevent ISP observation");
  if (ids.has("pr-unencrypted-traffic"))
    actions.push("Eliminate unencrypted traffic flows to prevent data exposure");

  return actions.slice(0, 5);
}
