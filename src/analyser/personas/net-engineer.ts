import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { Insight, PersonaAnalysis } from "./types.js";
import { riskFromInsights } from "./types.js";

const PERSONA_ID = "net-engineer" as const;
const DISPLAY_NAME = "Network Engineer";
const PERSPECTIVE =
  "Analyses network health, performance bottlenecks, and infrastructure reliability to ensure optimal throughput and availability.";

export function analyseAsNetEngineer(
  result: NetworkScanResult,
): PersonaAnalysis {
  const insights: Insight[] = [];

  // --- Signal quality ---
  const snr = result.wifi.snr;
  if (snr < 10) {
    insights.push({
      id: "ne-poor-snr",
      title: "Poor signal-to-noise ratio will severely impact throughput",
      severity: "high",
      category: "signal-quality",
      description: `An SNR of ${snr} dB is well below the 25 dB target for reliable data transfer. Expect high retransmission rates, connection drops, and degraded throughput across all clients. This is likely the dominant performance bottleneck.`,
      technicalDetail: `Signal: ${result.wifi.signal} dBm, Noise: ${result.wifi.noise} dBm, SNR: ${snr} dB. Protocol: ${result.wifi.protocol}, Channel: ${result.wifi.channel}, Band: ${result.wifi.band}.`,
      recommendation:
        "Relocate the access point or client closer together. Check for interference sources. Consider adding access points to improve coverage.",
      affectedAssets: [result.wifi.bssid, result.meta.hostname],
      references: ["IEEE-802.11-14.1"],
    });
  } else if (snr < 15) {
    insights.push({
      id: "ne-fair-snr",
      title: "Marginal SNR — throughput may degrade under contention",
      severity: "medium",
      category: "signal-quality",
      description: `An SNR of ${snr} dB is acceptable for basic connectivity but will struggle with high-bandwidth applications. Under contention from multiple clients, expect noticeable performance degradation.`,
      technicalDetail: `Signal: ${result.wifi.signal} dBm, Noise: ${result.wifi.noise} dBm, SNR: ${snr} dB.`,
      recommendation:
        "Improve signal path or reduce interference to achieve SNR above 25 dB for reliable performance.",
      affectedAssets: [result.wifi.bssid],
      references: ["IEEE-802.11-14.1"],
    });
  }

  // --- Channel congestion ---
  const sameChannel = result.wifi.nearbyNetworks.filter(
    (n) => n.channel === result.wifi.channel,
  );
  if (sameChannel.length >= 3) {
    insights.push({
      id: "ne-channel-congestion",
      title: `Channel ${result.wifi.channel} is congested with ${sameChannel.length} competing networks`,
      severity: "medium",
      category: "signal-quality",
      description: `${sameChannel.length} nearby networks share channel ${result.wifi.channel}, causing co-channel interference and contention overhead. Each competing network reduces available airtime and effective throughput.`,
      technicalDetail: `Nearby networks on ch${result.wifi.channel}: ${sameChannel.map((n) => `"${n.ssid ?? "(hidden)"}" at ${n.signal} dBm`).join(", ")}. Band: ${result.wifi.band}, Width: ${result.wifi.width}.`,
      recommendation:
        "Switch to a less congested channel. On 5 GHz, use DFS channels if supported. Consider enabling automatic channel selection.",
      affectedAssets: [result.wifi.bssid],
      references: ["IEEE-802.11-15.1"],
    });
  }

  // --- Speed test results ---
  if (result.speed) {
    const s = result.speed;

    if (s.rating === "poor" || s.rating === "unusable") {
      insights.push({
        id: "ne-poor-speed",
        title: `Speed test rated "${s.rating}" — significant performance issue`,
        severity: "high",
        category: "bandwidth",
        description: `Download ${s.download.speedMbps.toFixed(1)} Mbps and upload ${s.upload.speedMbps.toFixed(1)} Mbps are far below acceptable thresholds. This level of throughput will impact video calls, large transfers, and interactive applications.`,
        technicalDetail: `Download: ${s.download.speedMbps.toFixed(1)} Mbps (${s.download.bytesTransferred} bytes in ${s.download.durationMs} ms). Upload: ${s.upload.speedMbps.toFixed(1)} Mbps. Link rate: ${s.wifiLinkRate} Mbps. Effective utilisation: ${s.effectiveUtilisation.toFixed(1)}%.`,
        recommendation:
          "Check for bottlenecks: backhaul capacity, ISP plan limits, Wi-Fi interference, or congested uplinks. Run a wired speed test to isolate Wi-Fi vs backhaul issues.",
        affectedAssets: [result.meta.hostname, result.network.gateway.ip],
        references: ["IEEE-802.11-14.2"],
      });
    }

    // --- Low Wi-Fi utilisation ---
    if (s.wifiLinkRate > 0 && s.effectiveUtilisation < 20) {
      insights.push({
        id: "ne-low-wifi-utilisation",
        title: `Only ${s.effectiveUtilisation.toFixed(1)}% of Wi-Fi link rate is utilised`,
        severity: "medium",
        category: "bandwidth",
        description: `The Wi-Fi link rate is ${s.wifiLinkRate} Mbps but actual throughput is only ${s.download.speedMbps.toFixed(1)} Mbps. This large gap suggests a bottleneck outside the wireless link — likely the backhaul, ISP connection, or the test server.`,
        technicalDetail: `Link rate: ${s.wifiLinkRate} Mbps, download throughput: ${s.download.speedMbps.toFixed(1)} Mbps, utilisation: ${s.effectiveUtilisation.toFixed(1)}%.`,
        recommendation:
          "Test wired throughput to determine if the bottleneck is the wireless link or the upstream connection. Check ISP plan limits.",
        affectedAssets: [result.meta.hostname],
        references: ["IEEE-802.11-14.2"],
      });
    }

    // --- Packet loss ---
    if (s.packetLoss.gatewayPercent > 0 || s.packetLoss.internetPercent > 2) {
      const gw = s.packetLoss.gatewayPercent;
      const inet = s.packetLoss.internetPercent;
      const severity = gw > 5 || inet > 10 ? "high" : "medium";
      insights.push({
        id: "ne-packet-loss",
        title: `Packet loss detected: ${gw}% gateway, ${inet}% internet`,
        severity,
        category: "reliability",
        description: `Packet loss on the gateway link indicates local network issues (interference, buffer overflow, or faulty hardware). Internet packet loss may indicate ISP congestion or routing problems. Either will cause TCP retransmissions and degrade interactive applications.`,
        technicalDetail: `Gateway loss: ${gw}%, Internet loss: ${inet}%. Gateway latency: ${s.latency.gatewayMs.toFixed(1)} ms, Internet latency: ${s.latency.internetMs.toFixed(1)} ms.`,
        recommendation:
          "If gateway loss is non-zero, check the local link (cables, AP, interference). For internet loss, contact the ISP or check routing via traceroute.",
        affectedAssets: [result.network.gateway.ip],
        references: ["IEEE-802.11-14.3"],
      });
    }

    // --- High latency ---
    if (s.latency.gatewayMs > 20) {
      insights.push({
        id: "ne-high-gateway-latency",
        title: `Gateway latency ${s.latency.gatewayMs.toFixed(1)} ms is above normal threshold`,
        severity: s.latency.gatewayMs > 50 ? "high" : "medium",
        category: "reliability",
        description: `Gateway latency should be under 5 ms on a healthy local network. ${s.latency.gatewayMs.toFixed(1)} ms indicates congestion, bufferbloat, or a heavily loaded access point. This adds latency to every single connection.`,
        technicalDetail: `Gateway latency: ${s.latency.gatewayMs.toFixed(1)} ms, jitter: ${s.jitter.gatewayMs.toFixed(1)} ms. Internet latency: ${s.latency.internetMs.toFixed(1)} ms, jitter: ${s.jitter.internetMs.toFixed(1)} ms.`,
        recommendation:
          "Check for bufferbloat (run a bufferbloat test). Reduce client contention. Consider enabling SQM/QoS on the router.",
        affectedAssets: [result.network.gateway.ip],
        references: ["IEEE-802.11-14.3"],
      });
    }

    // --- High jitter ---
    if (s.jitter.internetMs > 30) {
      insights.push({
        id: "ne-high-jitter",
        title: `Internet jitter ${s.jitter.internetMs.toFixed(1)} ms will impact real-time applications`,
        severity: "medium",
        category: "reliability",
        description: `Jitter above 30 ms causes quality degradation for VoIP, video conferencing, and gaming. The inconsistent latency makes buffering difficult for real-time codecs.`,
        technicalDetail: `Internet jitter: ${s.jitter.internetMs.toFixed(1)} ms. Gateway jitter: ${s.jitter.gatewayMs.toFixed(1)} ms.`,
        recommendation:
          "Enable QoS prioritisation for real-time traffic. Check for competing bandwidth-heavy transfers.",
        affectedAssets: [result.network.gateway.ip],
        references: ["IEEE-802.11-14.3"],
      });
    }
  }

  // --- DNS resolution speed ---
  if (result.speed && result.speed.latency.dnsResolutionMs > 100) {
    insights.push({
      id: "ne-slow-dns",
      title: `DNS resolution at ${result.speed.latency.dnsResolutionMs} ms is slowing page loads`,
      severity: "medium",
      category: "dns-health",
      description: `DNS resolution should complete under 50 ms. At ${result.speed.latency.dnsResolutionMs} ms, every new connection pays a noticeable penalty. This accumulates into seconds of delay on content-rich pages.`,
      technicalDetail: `DNS resolution: ${result.speed.latency.dnsResolutionMs} ms. DNS servers: ${result.network.dns.servers.join(", ")}. DoH/DoT: ${result.network.dns.dohDotEnabled}.`,
      recommendation:
        "Switch to a faster DNS resolver (e.g., 1.1.1.1 or 8.8.8.8). Consider a local caching resolver.",
      affectedAssets: result.network.dns.servers,
      references: ["CIS-W-4.2"],
    });
  }

  // --- Double NAT ---
  if (result.network.topology.doubleNat) {
    insights.push({
      id: "ne-double-nat",
      title: "Double NAT adds latency and complicates port forwarding",
      severity: "medium",
      category: "architecture",
      description: `Double NAT means packets traverse two NAT translation tables, adding processing latency and making inbound port forwarding unreliable. UPnP and NAT-PMP will only reach the inner router. This complicates VPN, gaming, and any service requiring inbound connections.`,
      technicalDetail: `Double NAT detected. Hops: ${result.network.topology.hops.map((h) => `${h.ip} (${h.latencyMs} ms)`).join(" → ")}. Gateway: ${result.network.gateway.ip}.`,
      recommendation:
        "Put the inner router in bridge/AP mode or configure the outer device to pass through. If both are needed, set up port forwarding on both devices.",
      affectedAssets: [
        result.network.gateway.ip,
        ...result.network.topology.hops.map((h) => h.ip),
      ],
      references: ["NIST-800-153-4.1"],
    });
  }

  // --- High host density ---
  if (result.network.hosts.length > 20) {
    insights.push({
      id: "ne-high-host-density",
      title: `${result.network.hosts.length} hosts on a single segment — capacity planning concern`,
      severity: "medium",
      category: "capacity",
      description: `With ${result.network.hosts.length} hosts sharing one broadcast domain, ARP traffic, broadcast storms, and DHCP contention become significant. The access point's client handling capacity may be a limiting factor.`,
      technicalDetail: `Active hosts: ${result.network.hosts.length}. Subnet: ${result.network.subnet}. Gateway: ${result.network.gateway.ip}.`,
      recommendation:
        "Consider VLAN segmentation to reduce broadcast domain size. Evaluate the access point's maximum client recommendation.",
      affectedAssets: [result.network.gateway.ip],
      references: ["IEEE-802.11-15.2"],
    });
  }

  // --- DNS anomalies ---
  if (result.network.dns.anomalies.length > 0) {
    insights.push({
      id: "ne-dns-anomalies",
      title: `${result.network.dns.anomalies.length} DNS anomaly(ies) detected`,
      severity: "medium",
      category: "dns-health",
      description: `DNS anomalies can indicate misconfiguration, upstream resolver issues, or interception. Each anomaly should be investigated as it may affect name resolution reliability for all hosts.`,
      technicalDetail: `Anomalies: ${result.network.dns.anomalies.join("; ")}. DNS servers: ${result.network.dns.servers.join(", ")}.`,
      recommendation:
        "Investigate each anomaly. Verify DNS configuration against expected behaviour. Consider alternative resolvers.",
      affectedAssets: result.network.dns.servers,
      references: ["CIS-W-4.1"],
    });
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
  const highCount = insights.filter(
    (i) => i.severity === "high" || i.severity === "critical",
  ).length;
  const perfIssues = insights.filter(
    (i) =>
      i.category === "bandwidth" ||
      i.category === "reliability" ||
      i.category === "signal-quality",
  ).length;

  if (highCount > 0) {
    const speedRating = result.speed?.rating ?? "unknown";
    return `The network has ${highCount} significant performance issue(s) requiring attention. Speed test rating: ${speedRating}. ${perfIssues} finding(s) relate directly to throughput and reliability, likely impacting end-user experience.`;
  }
  if (insights.length > 0) {
    return `The network is functional with ${insights.length} optimisation opportunity(ies). Signal quality and basic connectivity are acceptable, though addressing the identified issues would improve throughput, reduce latency, and enhance reliability under load.`;
  }
  return `The network is performing well across all measured dimensions. Signal quality, throughput, and latency are within acceptable ranges. No significant bottlenecks or reliability concerns were identified.`;
}

function deriveActions(
  result: NetworkScanResult,
  insights: Insight[],
): string[] {
  const actions: string[] = [];
  const ids = new Set(insights.map((i) => i.id));

  if (ids.has("ne-poor-snr"))
    actions.push(
      "Improve signal-to-noise ratio — relocate AP, reduce interference sources",
    );
  if (ids.has("ne-poor-speed"))
    actions.push(
      "Investigate throughput bottleneck — run wired test to isolate Wi-Fi vs backhaul",
    );
  if (ids.has("ne-channel-congestion"))
    actions.push(
      "Switch to a less congested Wi-Fi channel to reduce co-channel interference",
    );
  if (ids.has("ne-packet-loss"))
    actions.push("Diagnose and resolve packet loss on the local link");
  if (ids.has("ne-high-gateway-latency"))
    actions.push(
      "Investigate gateway latency — check for bufferbloat and enable QoS",
    );
  if (ids.has("ne-double-nat"))
    actions.push(
      "Simplify network topology by eliminating double NAT",
    );
  if (ids.has("ne-slow-dns"))
    actions.push("Switch to a faster DNS resolver to reduce resolution latency");

  if (actions.length === 0 && insights.length > 0) {
    actions.push("Review DNS anomalies and optimise resolver configuration");
  }

  return actions.slice(0, 5);
}
