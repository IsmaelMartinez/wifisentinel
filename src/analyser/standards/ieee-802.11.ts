import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import {
  type Finding,
  type StandardScore,
  computeGrade,
  computeScore,
} from "./types.js";

const STANDARD = "ieee-802.11" as const;

function checkProtocolCompliance(result: NetworkScanResult): Finding {
  const proto = result.wifi.protocol.toLowerCase();
  const isAx = proto.includes("ax") || proto.includes("wifi 6") || proto.includes("802.11ax");
  const isAc = proto.includes("ac") || proto.includes("wifi 5") || proto.includes("802.11ac");
  const isN = proto.includes("n") || proto.includes("wifi 4") || proto.includes("802.11n");

  let status: Finding["status"];
  if (isAx) status = "pass";
  else if (isAc) status = "partial";
  else if (isN) status = "partial";
  else status = "fail";

  return {
    id: "IEEE-1.1",
    standard: STANDARD,
    title: "802.11 protocol generation",
    severity: "medium",
    status,
    description:
      "Modern 802.11ax (Wi-Fi 6) or 802.11ac (Wi-Fi 5) provides better performance, security, and spectrum efficiency.",
    recommendation:
      status === "pass"
        ? "No action needed."
        : "Upgrade to an 802.11ax (Wi-Fi 6) capable access point and client adapter.",
    evidence: `Protocol: ${result.wifi.protocol}`,
  };
}

function checkChannelSelection(result: NetworkScanResult): Finding {
  const ch = result.wifi.channel;
  const band = result.wifi.band.toLowerCase();
  const is5ghz = band.includes("5");
  const is6ghz = band.includes("6");

  // On 2.4 GHz, only channels 1, 6, 11 are non-overlapping
  const nonOverlapping24 = [1, 6, 11];
  let status: Finding["status"];
  if (is5ghz || is6ghz) {
    status = "pass";
  } else if (nonOverlapping24.includes(ch)) {
    status = "partial";
  } else {
    status = "fail";
  }

  return {
    id: "IEEE-2.1",
    standard: STANDARD,
    title: "Channel selection",
    severity: "low",
    status,
    description:
      "5 GHz and 6 GHz bands offer more non-overlapping channels and less interference. On 2.4 GHz, only channels 1, 6, and 11 should be used.",
    recommendation:
      is5ghz || is6ghz
        ? "No action needed — using 5/6 GHz band."
        : nonOverlapping24.includes(ch)
          ? "Consider migrating to 5 GHz for better performance."
          : `Switch to a non-overlapping 2.4 GHz channel (1, 6, or 11) or move to 5 GHz.`,
    evidence: `Channel: ${ch}, band: ${result.wifi.band}`,
  };
}

function checkChannelWidth(result: NetworkScanResult): Finding {
  const width = result.wifi.width.toLowerCase();
  const band = result.wifi.band.toLowerCase();
  const is5ghz = band.includes("5") || band.includes("6");

  // On 5 GHz, 80 MHz or 160 MHz is optimal; on 2.4 GHz, 20 MHz is best to avoid overlap
  let status: Finding["status"];
  if (is5ghz) {
    if (width.includes("80") || width.includes("160")) status = "pass";
    else if (width.includes("40")) status = "partial";
    else status = "fail";
  } else {
    if (width.includes("20")) status = "pass";
    else status = "partial";
  }

  return {
    id: "IEEE-2.2",
    standard: STANDARD,
    title: "Channel width configuration",
    severity: "low",
    status,
    description: is5ghz
      ? "On 5 GHz, wider channels (80/160 MHz) provide higher throughput."
      : "On 2.4 GHz, 20 MHz width minimises co-channel interference.",
    recommendation:
      status === "pass"
        ? "No action needed."
        : is5ghz
          ? "Configure 80 MHz or 160 MHz channel width on 5 GHz."
          : "Use 20 MHz width on 2.4 GHz to avoid overlap with neighbouring networks.",
    evidence: `Width: ${result.wifi.width}, band: ${result.wifi.band}`,
  };
}

function checkBandSelection(result: NetworkScanResult): Finding {
  const band = result.wifi.band.toLowerCase();
  const is5ghz = band.includes("5");
  const is6ghz = band.includes("6");

  return {
    id: "IEEE-2.3",
    standard: STANDARD,
    title: "Frequency band",
    severity: "low",
    status: is6ghz ? "pass" : is5ghz ? "pass" : "partial",
    description:
      "5 GHz and 6 GHz bands provide more capacity, less interference, and better security than 2.4 GHz.",
    recommendation:
      is5ghz || is6ghz
        ? "No action needed."
        : "Prefer 5 GHz band when available for reduced congestion and higher throughput.",
    evidence: `Band: ${result.wifi.band}`,
  };
}

function checkSignalQuality(result: NetworkScanResult): Finding {
  const snr = result.wifi.snr;
  let status: Finding["status"];
  // SNR thresholds: >30 excellent, 20-30 good, 10-20 fair, <10 poor
  if (snr >= 25) status = "pass";
  else if (snr >= 15) status = "partial";
  else status = "fail";

  return {
    id: "IEEE-3.1",
    standard: STANDARD,
    title: "Signal-to-noise ratio",
    severity: "medium",
    status,
    description:
      "Adequate SNR is required for reliable data transmission. Below 15 dB, error rates increase significantly.",
    recommendation:
      status === "pass"
        ? "No action needed."
        : "Reduce distance to the access point, eliminate interference sources, or add repeaters.",
    evidence: `SNR: ${snr} dB (signal: ${result.wifi.signal} dBm, noise: ${result.wifi.noise} dBm)`,
  };
}

function checkSignalStrength(result: NetworkScanResult): Finding {
  const signal = result.wifi.signal;
  let status: Finding["status"];
  // Signal thresholds: > -50 excellent, -50 to -67 good, -67 to -80 fair, < -80 poor
  if (signal >= -60) status = "pass";
  else if (signal >= -75) status = "partial";
  else status = "fail";

  return {
    id: "IEEE-3.2",
    standard: STANDARD,
    title: "Signal strength (RSSI)",
    severity: "medium",
    status,
    description:
      "Signal strength below -75 dBm results in degraded performance, increased retransmissions, and potential disconnections.",
    recommendation:
      status === "pass"
        ? "No action needed."
        : "Move closer to the access point or add additional access points for coverage.",
    evidence: `Signal: ${signal} dBm`,
  };
}

function checkSecurityProtocol(result: NetworkScanResult): Finding {
  const sec = result.wifi.security.toLowerCase();
  const isWpa3 = sec.includes("wpa3");
  const isWpa2 = sec.includes("wpa2");

  return {
    id: "IEEE-4.1",
    standard: STANDARD,
    title: "Security protocol compliance",
    severity: "high",
    status: isWpa3 ? "pass" : isWpa2 ? "partial" : "fail",
    description:
      "IEEE 802.11 mandates robust security. WPA3 (802.11-2020) is the current standard; WPA2 remains acceptable.",
    recommendation: isWpa3
      ? "No action needed."
      : isWpa2
        ? "Plan migration to WPA3 for enhanced security."
        : "Immediately upgrade to WPA2 or WPA3.",
    evidence: `Security: ${result.wifi.security}`,
  };
}

function checkTransmitRate(result: NetworkScanResult): Finding {
  const txRate = result.wifi.txRate;
  let status: Finding["status"];
  if (txRate >= 200) status = "pass";
  else if (txRate >= 50) status = "partial";
  else status = "fail";

  return {
    id: "IEEE-3.3",
    standard: STANDARD,
    title: "Transmit rate",
    severity: "low",
    status,
    description:
      "The negotiated transmit rate reflects link quality. Low rates indicate poor conditions or legacy protocol negotiation.",
    recommendation:
      status === "pass"
        ? "No action needed."
        : "Investigate signal quality, interference, and protocol negotiation.",
    evidence: `Tx rate: ${txRate} Mbps`,
  };
}

function checkNearbyNetworkDensity(result: NetworkScanResult): Finding {
  const nearby = result.wifi.nearbyNetworks;
  const sameChannel = nearby.filter(
    (n) => n.channel === result.wifi.channel
  ).length;

  let status: Finding["status"];
  if (sameChannel === 0) status = "pass";
  else if (sameChannel <= 3) status = "partial";
  else status = "fail";

  return {
    id: "IEEE-5.1",
    standard: STANDARD,
    title: "Co-channel interference",
    severity: "medium",
    status,
    description:
      "Multiple networks on the same channel cause co-channel interference, reducing throughput and reliability.",
    recommendation:
      status === "pass"
        ? "No action needed."
        : "Switch to a less congested channel or move to 5 GHz band.",
    evidence: `Nearby networks on channel ${result.wifi.channel}: ${sameChannel} (total nearby: ${nearby.length})`,
  };
}

function checkCountryCode(result: NetworkScanResult): Finding {
  const cc = result.wifi.countryCode;
  const hasCode = cc.length > 0 && cc !== "X0" && cc !== "--";

  return {
    id: "IEEE-2.4",
    standard: STANDARD,
    title: "Regulatory domain configured",
    severity: "low",
    status: hasCode ? "pass" : "fail",
    description:
      "The country code determines permitted channels, power levels, and DFS requirements per local regulations.",
    recommendation: hasCode
      ? "No action needed."
      : "Set the correct country/regulatory domain on the access point.",
    evidence: `Country code: ${cc || "(not set)"}`,
  };
}

export function scoreIeee80211(result: NetworkScanResult): StandardScore {
  const findings: Finding[] = [
    checkProtocolCompliance(result),
    checkChannelSelection(result),
    checkChannelWidth(result),
    checkBandSelection(result),
    checkSignalQuality(result),
    checkSignalStrength(result),
    checkSecurityProtocol(result),
    checkTransmitRate(result),
    checkNearbyNetworkDensity(result),
    checkCountryCode(result),
  ];

  const score = computeScore(findings);
  const passing = findings.filter((f) => f.status === "pass").length;
  const applicable = findings.filter(
    (f) => f.status !== "not-applicable"
  ).length;

  return {
    standard: STANDARD,
    name: "IEEE 802.11 Wireless LAN Compliance",
    version: "802.11-2020",
    score,
    maxScore: 100,
    grade: computeGrade(score),
    findings,
    summary: `${passing}/${applicable} applicable controls passed (score: ${score}/100).`,
  };
}
