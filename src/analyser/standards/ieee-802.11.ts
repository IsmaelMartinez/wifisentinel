import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import { classifySecurity } from "../security.js";
import {
  type Finding,
  type FindingSpec,
  type FindingStatus,
  type StandardScore,
  UNKNOWN_SECURITY_FIX,
  buildStandardScore,
  finding,
  wpaTierStatus,
} from "./types.js";
import { wifiGeneration } from "./protocol.js";

const STANDARD = "ieee-802.11" as const;
const check = (spec: FindingSpec): Finding => finding(STANDARD, spec);

/** Pass at or above `pass`, partial at or above `partial`, else fail. */
function threshold(value: number, pass: number, partial: number): FindingStatus {
  if (value >= pass) return "pass";
  return value >= partial ? "partial" : "fail";
}

function checkProtocolCompliance(result: NetworkScanResult): Finding {
  // Wi-Fi 6 (ax) and 7 (be) pass; Wi-Fi 4/5 (n/ac) are partial; a/b/g fail.
  const generation = wifiGeneration(result.wifi.protocol);
  const status = generation === undefined ? "not-applicable" : threshold(generation, 6, 4);
  return check({
    id: "IEEE-1.1",
    title: "802.11 protocol generation",
    severity: "medium",
    status,
    description:
      "Modern 802.11ax (Wi-Fi 6) or 802.11ac (Wi-Fi 5) provides better performance, security, and spectrum efficiency.",
    fix:
      status === "not-applicable"
        ? "No action needed."
        : "Upgrade to an 802.11ax (Wi-Fi 6) capable access point and client adapter.",
    evidence: `Protocol: ${result.wifi.protocol}`,
  });
}

function checkChannelSelection(result: NetworkScanResult): Finding {
  const ch = result.wifi.channel;
  const band = result.wifi.band.toLowerCase();
  const highBand = band.includes("5") || band.includes("6");
  // On 2.4 GHz, only channels 1, 6, 11 are non-overlapping
  const nonOverlapping = [1, 6, 11].includes(ch);
  return check({
    id: "IEEE-2.1",
    title: "Channel selection",
    severity: "low",
    status: highBand ? "pass" : nonOverlapping ? "partial" : "fail",
    description:
      "5 GHz and 6 GHz bands offer more non-overlapping channels and less interference. On 2.4 GHz, only channels 1, 6, and 11 should be used.",
    ok: "No action needed — using 5/6 GHz band.",
    fix: nonOverlapping
      ? "Consider migrating to 5 GHz for better performance."
      : `Switch to a non-overlapping 2.4 GHz channel (1, 6, or 11) or move to 5 GHz.`,
    evidence: `Channel: ${ch}, band: ${result.wifi.band}`,
  });
}

function checkChannelWidth(result: NetworkScanResult): Finding {
  const width = result.wifi.width.toLowerCase();
  const band = result.wifi.band.toLowerCase();
  const is5ghz = band.includes("5") || band.includes("6");

  // On 5 GHz, 80 MHz or 160 MHz is optimal; on 2.4 GHz, 20 MHz is best to avoid overlap
  let status: FindingStatus;
  if (is5ghz) {
    if (width.includes("80") || width.includes("160")) status = "pass";
    else if (width.includes("40")) status = "partial";
    else status = "fail";
  } else {
    status = width.includes("20") ? "pass" : "partial";
  }

  return check({
    id: "IEEE-2.2",
    title: "Channel width configuration",
    severity: "low",
    status,
    description: is5ghz
      ? "On 5 GHz, wider channels (80/160 MHz) provide higher throughput."
      : "On 2.4 GHz, 20 MHz width minimises co-channel interference.",
    fix: is5ghz
      ? "Configure 80 MHz or 160 MHz channel width on 5 GHz."
      : "Use 20 MHz width on 2.4 GHz to avoid overlap with neighbouring networks.",
    evidence: `Width: ${result.wifi.width}, band: ${result.wifi.band}`,
  });
}

function checkBandSelection(result: NetworkScanResult): Finding {
  const band = result.wifi.band.toLowerCase();
  const highBand = band.includes("5") || band.includes("6");
  return check({
    id: "IEEE-2.3",
    title: "Frequency band",
    severity: "low",
    status: highBand ? "pass" : "partial",
    description:
      "5 GHz and 6 GHz bands provide more capacity, less interference, and better security than 2.4 GHz.",
    fix: "Prefer 5 GHz band when available for reduced congestion and higher throughput.",
    evidence: `Band: ${result.wifi.band}`,
  });
}

function checkSignalQuality(result: NetworkScanResult): Finding {
  const snr = result.wifi.snr;
  return check({
    id: "IEEE-3.1",
    title: "Signal-to-noise ratio",
    severity: "medium",
    // SNR thresholds: >30 excellent, 20-30 good, 10-20 fair, <10 poor
    status: threshold(snr, 25, 15),
    description:
      "Adequate SNR is required for reliable data transmission. Below 15 dB, error rates increase significantly.",
    fix: "Reduce distance to the access point, eliminate interference sources, or add repeaters.",
    evidence: `SNR: ${snr} dB (signal: ${result.wifi.signal} dBm, noise: ${result.wifi.noise} dBm)`,
  });
}

function checkSignalStrength(result: NetworkScanResult): Finding {
  const signal = result.wifi.signal;
  return check({
    id: "IEEE-3.2",
    title: "Signal strength (RSSI)",
    severity: "medium",
    // Signal thresholds: > -50 excellent, -50 to -67 good, -67 to -80 fair, < -80 poor
    status: threshold(signal, -60, -75),
    description:
      "Signal strength below -75 dBm results in degraded performance, increased retransmissions, and potential disconnections.",
    fix: "Move closer to the access point or add additional access points for coverage.",
    evidence: `Signal: ${signal} dBm`,
  });
}

function checkSecurityProtocol(result: NetworkScanResult): Finding {
  const { wpaTier } = classifySecurity(result.wifi.security);
  return check({
    id: "IEEE-4.1",
    title: "Security protocol compliance",
    severity: "high",
    status: wpaTierStatus(wpaTier),
    description:
      "IEEE 802.11 mandates robust security. WPA3 (802.11-2020) is the current standard; WPA2 remains acceptable.",
    fix:
      wpaTier === "wpa2"
        ? "Plan migration to WPA3 for enhanced security."
        : wpaTier === "unknown"
          ? UNKNOWN_SECURITY_FIX
          : "Immediately upgrade to WPA2 or WPA3.",
    evidence: `Security: ${result.wifi.security}`,
  });
}

function checkTransmitRate(result: NetworkScanResult): Finding {
  const txRate = result.wifi.txRate;
  return check({
    id: "IEEE-3.3",
    title: "Transmit rate",
    severity: "low",
    status: threshold(txRate, 200, 50),
    description:
      "The negotiated transmit rate reflects link quality. Low rates indicate poor conditions or legacy protocol negotiation.",
    fix: "Investigate signal quality, interference, and protocol negotiation.",
    evidence: `Tx rate: ${txRate} Mbps`,
  });
}

function checkNearbyNetworkDensity(result: NetworkScanResult): Finding {
  const nearby = result.wifi.nearbyNetworks;
  const sameChannel = nearby.filter((n) => n.channel === result.wifi.channel).length;
  return check({
    id: "IEEE-5.1",
    title: "Co-channel interference",
    severity: "medium",
    status: sameChannel === 0 ? "pass" : sameChannel <= 3 ? "partial" : "fail",
    description:
      "Multiple networks on the same channel cause co-channel interference, reducing throughput and reliability.",
    fix: "Switch to a less congested channel or move to 5 GHz band.",
    evidence: `Nearby networks on channel ${result.wifi.channel}: ${sameChannel} (total nearby: ${nearby.length})`,
  });
}

function checkCountryCode(result: NetworkScanResult): Finding {
  const cc = result.wifi.countryCode;
  const hasCode = cc.length > 0 && cc !== "X0" && cc !== "--";
  return check({
    id: "IEEE-2.4",
    title: "Regulatory domain configured",
    severity: "low",
    status: hasCode ? "pass" : "fail",
    description:
      "The country code determines permitted channels, power levels, and DFS requirements per local regulations.",
    fix: "Set the correct country/regulatory domain on the access point.",
    evidence: `Country code: ${cc || "(not set)"}`,
  });
}

export function scoreIeee80211(result: NetworkScanResult): StandardScore {
  return buildStandardScore(STANDARD, "IEEE 802.11 Wireless LAN Compliance", "802.11-2020", [
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
  ]);
}
