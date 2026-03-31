// src/analyser/rf/channel-map.ts
import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { ChannelInfo, ChannelMap } from "./types.js";

/** 2.4 GHz channels 1-14. A 20 MHz signal on channel N overlaps N-2 to N+2. */
const CHANNELS_2_4 = Array.from({ length: 14 }, (_, i) => i + 1);

/** Common 5 GHz channels (UNII-1 through UNII-3). */
const CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];

/** Non-overlapping 2.4 GHz channels for recommendations. */
const NON_OVERLAPPING_2_4 = [1, 6, 11];

/**
 * Convert signal dBm to a linear weight (0-1).
 * -30 dBm (strongest typical) -> 1.0, -100 dBm (noise floor) -> 0.0
 */
function signalWeight(signal: number): number {
  const clamped = Math.max(-100, Math.min(-30, signal));
  return (clamped + 100) / 70;
}

/**
 * Compute saturation score (0-100) for a channel given direct and overlapping networks.
 * Factors: network count, cumulative signal weight, overlap penalty.
 */
function computeSaturation(directNetworks: number, directSignalSum: number, overlapNetworks: number, overlapSignalSum: number): number {
  // Direct networks contribute fully, overlapping networks contribute at 50%
  const effectiveLoad = directSignalSum + overlapSignalSum * 0.5;
  const effectiveCount = directNetworks + overlapNetworks * 0.5;

  // Saturation: each strong network (~1.0 weight) contributes ~25 points,
  // capped at 100. Empty channel = 0.
  const score = Math.min(100, Math.round(effectiveLoad * 25 + effectiveCount * 5));
  return score;
}

function channelBand(channel: number): "2.4GHz" | "5GHz" {
  return channel <= 14 ? "2.4GHz" : "5GHz";
}

interface NetworkEntry {
  ssid: string | null;
  signal: number;
  security: string;
  channel: number;
}

export function buildChannelMap(wifi: NetworkScanResult["wifi"]): ChannelMap {
  // Combine current network + nearby networks into a single list
  const allNetworks: NetworkEntry[] = [
    { ssid: wifi.ssid, signal: wifi.signal, security: wifi.security, channel: wifi.channel },
    ...wifi.nearbyNetworks.map(n => ({
      ssid: n.ssid,
      signal: n.signal,
      security: n.security,
      channel: n.channel,
    })),
  ];

  const currentBand = channelBand(wifi.channel);
  const channelList = currentBand === "2.4GHz" ? CHANNELS_2_4 : CHANNELS_5;

  const channels: ChannelInfo[] = channelList.map(ch => {
    const band = channelBand(ch);
    const directNets = allNetworks.filter(n => n.channel === ch && channelBand(n.channel) === band);
    const directSignalSum = directNets.reduce((sum, n) => sum + signalWeight(n.signal), 0);

    // Overlap: 2.4 GHz only, channels within +/- 2
    let overlapNets: NetworkEntry[] = [];
    let overlapSignalSum = 0;
    if (band === "2.4GHz") {
      overlapNets = allNetworks.filter(n =>
        channelBand(n.channel) === "2.4GHz" &&
        n.channel !== ch &&
        Math.abs(n.channel - ch) <= 2
      );
      overlapSignalSum = overlapNets.reduce((sum, n) => sum + signalWeight(n.signal), 0);
    }

    const saturationScore = computeSaturation(
      directNets.length, directSignalSum,
      overlapNets.length, overlapSignalSum,
    );

    return {
      channel: ch,
      band,
      networkCount: directNets.length,
      overlapCount: overlapNets.length,
      saturationScore,
      networks: directNets.map(n => ({ ssid: n.ssid, signal: n.signal, security: n.security })),
    };
  });

  // Find current channel saturation
  const currentInfo = channels.find(c => c.channel === wifi.channel);
  const currentSaturation = currentInfo?.saturationScore ?? 0;

  // Recommend: least-saturated non-overlapping channel in same band
  const candidates = currentBand === "2.4GHz"
    ? channels.filter(c => NON_OVERLAPPING_2_4.includes(c.channel))
    : channels;

  const best = candidates.reduce((a, b) => a.saturationScore <= b.saturationScore ? a : b);

  let recommendedChannel = best.channel;
  let recommendationReason: string;

  if (best.channel === wifi.channel) {
    recommendedChannel = wifi.channel;
    recommendationReason = `Current channel ${wifi.channel} is already optimal (saturation ${currentSaturation}%)`;
  } else {
    recommendationReason = `Channel ${best.channel} has saturation ${best.saturationScore}% vs current ${currentSaturation}%`;
  }

  return {
    channels,
    currentChannel: wifi.channel,
    currentBand,
    currentSaturation,
    recommendedChannel,
    recommendationReason,
  };
}
