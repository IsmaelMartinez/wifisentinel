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

function parseTxRate(raw: string): number {
  const match = raw.match(/([\d.]+)/);
  return match ? parseFloat(match[1]) : 0;
}

function parseMacRandomised(raw: string): boolean {
  const lower = raw.toLowerCase();
  return lower === "enabled" || lower === "yes" || lower === "true";
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

// ---------------------------------------------------------------------------
// Linux WiFi helpers
// ---------------------------------------------------------------------------

function findLinuxWifiInterface(): string {
  const routeResult = run("ip", ["route", "show", "default"]);
  const routeMatch = routeResult.stdout.match(/dev (\S+)/);
  if (routeMatch) return routeMatch[1];

  const iwResult = run("iw", ["dev"]);
  const ifaceMatch = iwResult.stdout.match(/Interface\s+(\S+)/);
  if (ifaceMatch) return ifaceMatch[1];

  return "wlan0";
}

function bandFromFrequency(freqMhz: number): string {
  if (freqMhz < 3000) return "2.4GHz";
  if (freqMhz <= 6000) return "5GHz";
  return "6GHz";
}

function channelFromFrequency(freqMhz: number): number {
  if (freqMhz >= 2412 && freqMhz <= 2484) {
    if (freqMhz === 2484) return 14;
    return (freqMhz - 2407) / 5;
  }
  if (freqMhz >= 5170 && freqMhz <= 5825) {
    return (freqMhz - 5000) / 5;
  }
  return 0;
}

function isLocallyAdministeredMac(mac: string): boolean {
  const firstOctet = parseInt(mac.split(":")[0], 16);
  return (firstOctet & 0x02) !== 0;
}

async function scanWifiLinux(): Promise<WifiResult> {
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

  const iface = findLinuxWifiInterface();

  // Current connection info via iw dev <iface> link
  let ssid: string | null = null;
  let bssid = "";
  let signal = 0;
  let frequency = 0;
  let txRate = 0;

  const linkResult = run("iw", ["dev", iface, "link"]);
  if (linkResult.exitCode === 0 && !linkResult.stdout.includes("Not connected")) {
    const bssidMatch = linkResult.stdout.match(/Connected to ([0-9a-f:]+)/i);
    if (bssidMatch) bssid = bssidMatch[1];

    const ssidMatch = linkResult.stdout.match(/SSID:\s*(.+)/);
    if (ssidMatch) ssid = ssidMatch[1].trim();

    const freqMatch = linkResult.stdout.match(/freq:\s*(\d+)/);
    if (freqMatch) frequency = parseInt(freqMatch[1], 10);

    const signalMatch = linkResult.stdout.match(/signal:\s*(-?\d+)/);
    if (signalMatch) signal = parseInt(signalMatch[1], 10);

    const txMatch = linkResult.stdout.match(/tx bitrate:\s*([\d.]+)/);
    if (txMatch) txRate = parseFloat(txMatch[1]);
  }

  const channel = frequency ? channelFromFrequency(frequency) : 0;
  const band = frequency ? bandFromFrequency(frequency) : "unknown";

  // MAC randomisation check
  const linkShowResult = run("ip", ["link", "show", iface]);
  let macRandomised = false;
  const macShowMatch = linkShowResult.stdout.match(
    /link\/ether\s+([0-9a-f:]+)/i
  );
  if (macShowMatch) {
    macRandomised = isLocallyAdministeredMac(macShowMatch[1]);
  }

  // Nearby networks and security via nmcli
  let security = "Unknown";
  const nearbyNetworks: NearbyNetwork[] = [];

  const nmcliResult = run("nmcli", [
    "-t",
    "-f",
    "SSID,SECURITY,SIGNAL,CHAN,MODE,BSSID",
    "device",
    "wifi",
    "list",
  ]);

  if (nmcliResult.exitCode === 0 && nmcliResult.stdout.length > 0) {
    for (const line of nmcliResult.stdout.split("\n")) {
      if (!line.trim()) continue;
      // nmcli -t uses : as delimiter, but BSSID contains colons escaped as \:
      const unescaped = line.replace(/\\:/g, "\uFFFF");
      const parts = unescaped.split(":");
      const netSsid = parts[0]?.replace(/\uFFFF/g, ":") || null;
      const netSecurity = parts[1]?.replace(/\uFFFF/g, ":") || "Unknown";
      const netSignal = parseInt(parts[2] ?? "0", 10);
      const netChannel = parseInt(parts[3] ?? "0", 10);
      const netBssid = parts[5]?.replace(/\uFFFF/g, ":").trim() || undefined;

      if (netSsid === ssid && netBssid?.toLowerCase() === bssid.toLowerCase()) {
        security = netSecurity;
      } else if (netSsid) {
        nearbyNetworks.push({
          ssid: netSsid,
          bssid: netBssid,
          security: netSecurity,
          protocol: "Unknown",
          channel: netChannel,
          signal: netSignal,
          noise: 0,
        });
      }
    }
  } else {
    // Fallback: try iw scan (may need sudo, fail gracefully)
    const scanResult = run("iw", ["dev", iface, "scan"]);
    if (scanResult.exitCode === 0) {
      const blocks = scanResult.stdout.split(/^BSS /m);
      for (const block of blocks) {
        if (!block.trim()) continue;
        const bssidScan = block.match(/^([0-9a-f:]+)/i)?.[1] || undefined;
        const ssidScan = block.match(/SSID:\s*(.+)/)?.[1]?.trim() || null;
        const freqScan = block.match(/freq:\s*(\d+)/);
        const signalScan = block.match(/signal:\s*(-?[\d.]+)/);
        const chanScan = freqScan
          ? channelFromFrequency(parseInt(freqScan[1], 10))
          : 0;

        if (bssidScan?.toLowerCase() === bssid.toLowerCase()) {
          // Current network — extract security
          if (block.includes("RSN:")) security = "WPA2";
          if (block.includes("WPA:")) security = security === "WPA2" ? "WPA/WPA2" : "WPA";
          if (!block.includes("RSN:") && !block.includes("WPA:")) security = "Open";
        } else if (ssidScan) {
          let netSec = "Open";
          if (block.includes("RSN:")) netSec = "WPA2";
          if (block.includes("WPA:")) netSec = netSec === "WPA2" ? "WPA/WPA2" : "WPA";

          nearbyNetworks.push({
            ssid: ssidScan,
            bssid: bssidScan,
            security: netSec,
            protocol: "Unknown",
            channel: chanScan,
            signal: signalScan ? parseFloat(signalScan[1]) : 0,
            noise: 0,
          });
        }
      }
    }
  }

  return {
    ...defaults,
    ssid,
    bssid,
    protocol: "Unknown",
    channel,
    band,
    security,
    signal,
    noise: 0,
    snr: 0,
    txRate,
    macRandomised,
    nearbyNetworks,
  };
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function scanWifi(): Promise<WifiResult> {
  if (process.platform === "linux") {
    return scanWifiLinux();
  }

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
