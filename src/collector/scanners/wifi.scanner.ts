import { run } from "../exec.js";
import type { NetworkScanResult, NearbyNetwork } from "../schema/scan-result.js";

type WifiResult = NetworkScanResult["wifi"];

function parseChannel(raw: string): { channel: number; band: string; width: string } {
  // e.g. "6 (2GHz)", "36,+1 (5GHz)", "6 (2.4 GHz, 20 MHz)"
  const chanMatch = raw.match(/^(\d+)/);
  const channel = chanMatch ? parseInt(chanMatch[1], 10) : 0;

  let band = "unknown";
  if (/5\s*GHz/i.test(raw) || /5GHz/i.test(raw)) {
    band = "5GHz";
  } else if (/6\s*GHz/i.test(raw) || /6GHz/i.test(raw)) {
    band = "6GHz";
  } else if (/2\.4\s*GHz/i.test(raw) || /2GHz/i.test(raw) || channel <= 14) {
    band = "2.4GHz";
  }

  let width = "20MHz";
  const widthMatch = raw.match(/(\d+)\s*MHz/i);
  if (widthMatch) {
    width = `${widthMatch[1]}MHz`;
  } else if (raw.includes("+1") || raw.includes("-1")) {
    width = "40MHz";
  }

  return { channel, band, width };
}

function parseSignalNoise(signalStr: string, noiseStr: string): { signal: number; noise: number; snr: number } {
  const signal = parseInt(signalStr, 10) || 0;
  const noise = parseInt(noiseStr, 10) || 0;
  const snr = noise !== 0 ? signal - noise : 0;
  return { signal, noise, snr };
}

function parseTxRate(raw: string): number {
  const match = raw.match(/([\d.]+)/);
  return match ? parseFloat(match[1]) : 0;
}

function parseMacRandomised(raw: string): boolean {
  const lower = raw.toLowerCase();
  return lower === "enabled" || lower === "yes" || lower === "true";
}

/**
 * Parse a single Wi-Fi network block from system_profiler output.
 * The block is the indented lines under a network SSID heading.
 */
function parseNetworkBlock(block: string): Partial<NearbyNetwork> & { ssid?: string | null } {
  const get = (key: string): string => {
    const re = new RegExp(`^\\s*${key}:\\s*(.+)$`, "im");
    const m = block.match(re);
    return m ? m[1].trim() : "";
  };

  const ssidRaw = get("SSID");
  const ssid = ssidRaw || null;
  const bssid = get("BSSID") || get("Network ID") || undefined;
  const security = get("Security") || get("Network Security") || "Unknown";
  const protocol = get("PHY Mode") || get("802.11 Protocol") || "Unknown";

  const channelRaw = get("Channel");
  const { channel } = parseChannel(channelRaw);

  const signalRaw = get("Signal / Noise") || get("Signal");
  let signal: number;
  let noise: number;
  if (signalRaw.includes("/")) {
    const parts = signalRaw.split("/");
    signal = parseInt(parts[0].trim(), 10) || 0;
    noise = parseInt(parts[1]?.trim() ?? "0", 10) || 0;
  } else {
    signal = parseInt(signalRaw, 10) || 0;
    const noiseRaw = get("Noise");
    noise = parseInt(noiseRaw, 10) || 0;
  }

  return { ssid, bssid, security, protocol, channel, signal, noise };
}

/**
 * Parse system_profiler SPAirPortDataType output.
 */
function parseSystemProfiler(output: string): WifiResult {
  const defaults: WifiResult = {
    ssid: null,
    bssid: "",
    protocol: "Unknown",
    channel: 0,
    band: "unknown",
    width: "20MHz",
    security: "Unknown",
    signal: 0,
    noise: 0,
    snr: 0,
    txRate: 0,
    macRandomised: false,
    countryCode: "",
    nearbyNetworks: [],
  };

  const get = (key: string): string => {
    const re = new RegExp(`^\\s*${key}:\\s*(.+)$`, "im");
    const m = output.match(re);
    return m ? m[1].trim() : "";
  };

  const ssid = get("Current Network Information") || null;
  // system_profiler uses a heading like: "      MySSID:"
  // Current connection info is under "Current Network Information:" block
  const currentMatch = output.match(/Current Network Information:\s*\n([\s\S]*?)(?:\n\s{4,}\S|\n\s*Other Local Wi-Fi Networks:|$)/i);
  const currentBlock = currentMatch ? currentMatch[1] : output;

  // Extract SSID from "Current Network Information:" heading line that follows
  const ssidMatch = output.match(/Current Network Information:\s*\n\s+(.+?):\s*\n/i);
  const currentSsid = ssidMatch ? ssidMatch[1].trim() : null;

  const getFromBlock = (block: string, key: string): string => {
    const re = new RegExp(`^\\s*${key}:\\s*(.+)$`, "im");
    const m = block.match(re);
    return m ? m[1].trim() : "";
  };

  const bssid = getFromBlock(currentBlock, "BSSID") || get("BSSID") || "";
  const protocol = getFromBlock(currentBlock, "PHY Mode") || get("PHY Mode") || "Unknown";
  const channelRaw = getFromBlock(currentBlock, "Channel") || get("Channel") || "0";
  const { channel, band, width } = parseChannel(channelRaw);
  const security = getFromBlock(currentBlock, "Security") || get("Security") || "Unknown";
  const countryCode = getFromBlock(currentBlock, "Country Code") || get("Country Code") || "";
  const txRate = parseTxRate(getFromBlock(currentBlock, "Transmit Rate") || get("Transmit Rate") || "0");
  const macRandRaw = getFromBlock(currentBlock, "MAC Address Randomization") || get("MAC Address Randomization") || "";
  const macRandomised = parseMacRandomised(macRandRaw);

  const signalNoiseRaw = getFromBlock(currentBlock, "Signal / Noise") || get("Signal / Noise") || "";
  let signal: number;
  let noise: number;
  if (signalNoiseRaw.includes("/")) {
    const parts = signalNoiseRaw.split("/");
    signal = parseInt(parts[0].trim(), 10) || 0;
    noise = parseInt(parts[1]?.trim() ?? "0", 10) || 0;
  } else {
    signal = parseInt(signalNoiseRaw, 10) || 0;
    noise = 0;
  }
  const snr = noise !== 0 ? signal - noise : 0;

  // Parse nearby networks from "Other Local Wi-Fi Networks:" section
  // Format: 12-space indented SSID heading, 14-space indented properties
  const nearbyNetworks: NearbyNetwork[] = [];
  const nearbyMatch = output.match(/Other Local Wi-Fi Networks:\s*\n([\s\S]*?)(?:\n {0,7}\S|$)/);
  if (nearbyMatch) {
    const nearbySection = nearbyMatch[1];
    // Split on lines that look like SSID headings (12 spaces + name + colon)
    const blocks = nearbySection.split(/\n(?= {12}\S)/);
    for (const block of blocks) {
      if (!block.trim()) continue;
      // First line is the SSID: "            <redacted>:" or "            MyNetwork:"
      const headingMatch = block.match(/^\s{8,}(.+?):\s*$/m);
      const ssid = headingMatch ? headingMatch[1].trim() : null;
      // Parse properties from the block
      const getVal = (key: string): string => {
        const re = new RegExp(`^\\s+${key}:\\s*(.+)$`, "im");
        const m = block.match(re);
        return m ? m[1].trim() : "";
      };
      const phyMode = getVal("PHY Mode");
      const channelRaw = getVal("Channel");
      const securityVal = getVal("Security");
      const signalNoise = getVal("Signal / Noise");
      if (!channelRaw && !phyMode && !signalNoise) continue; // not a real block
      const { channel } = parseChannel(channelRaw);
      let sig = 0, noi = 0;
      if (signalNoise.includes("/")) {
        const parts = signalNoise.split("/");
        sig = parseInt(parts[0].replace(/dBm/i, "").trim(), 10) || 0;
        noi = parseInt(parts[1]?.replace(/dBm/i, "").trim() ?? "0", 10) || 0;
      }
      nearbyNetworks.push({
        ssid: ssid === "<redacted>" ? "(hidden)" : ssid,
        security: securityVal || "Unknown",
        protocol: phyMode || "Unknown",
        channel,
        signal: sig,
        noise: noi,
      });
    }
  }

  return {
    ...defaults,
    ssid: currentSsid,
    bssid,
    protocol,
    channel,
    band,
    width,
    security,
    signal,
    noise,
    snr,
    txRate,
    macRandomised,
    countryCode,
    nearbyNetworks,
  };
}

/**
 * Fallback: parse networksetup -getairportnetwork output.
 * Only gives SSID; other fields will be defaults.
 */
function parseNetworksetup(output: string): Partial<WifiResult> {
  // "Current Wi-Fi Network: MySSID"
  const match = output.match(/Current Wi-Fi Network:\s*(.+)/i);
  return { ssid: match ? match[1].trim() : null };
}

export async function scanWifi(): Promise<WifiResult> {
  const defaults: WifiResult = {
    ssid: null,
    bssid: "",
    protocol: "Unknown",
    channel: 0,
    band: "unknown",
    width: "20MHz",
    security: "Unknown",
    signal: 0,
    noise: 0,
    snr: 0,
    txRate: 0,
    macRandomised: false,
    countryCode: "",
    nearbyNetworks: [],
  };

  const profilerResult = run("system_profiler", ["SPAirPortDataType"]);
  if (profilerResult.exitCode === 0 && profilerResult.stdout.length > 0) {
    try {
      return parseSystemProfiler(profilerResult.stdout);
    } catch {
      // fall through to networksetup fallback
    }
  }

  // Fallback: networksetup
  const nsResult = run("networksetup", ["-getairportnetwork", "en0"]);
  if (nsResult.exitCode === 0 && nsResult.stdout.length > 0) {
    const partial = parseNetworksetup(nsResult.stdout);
    return { ...defaults, ...partial };
  }

  return defaults;
}
