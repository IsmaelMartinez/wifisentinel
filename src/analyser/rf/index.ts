// src/analyser/rf/index.ts
import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { RFAnalysis } from "./types.js";
import { buildChannelMap } from "./channel-map.js";
import { detectRogueAPs } from "./rogue-ap.js";
import { detectEnvironmentChanges } from "./environment.js";

export { buildChannelMap } from "./channel-map.js";
export { detectRogueAPs } from "./rogue-ap.js";
export { detectEnvironmentChanges } from "./environment.js";
export type {
  RFAnalysis,
  ChannelMap,
  ChannelInfo,
  RogueAPAnalysis,
  RogueAPFinding,
  EnvironmentAnalysis,
  EnvironmentChange,
} from "./types.js";

export function analyseRF(
  result: { wifi: NetworkScanResult["wifi"] },
  baseline?: { wifi: NetworkScanResult["wifi"]; meta: { scanId: string; timestamp: string } },
): RFAnalysis {
  const channelMap = buildChannelMap(result.wifi);
  const rogueAPs = detectRogueAPs(result.wifi);
  const environment = baseline
    ? detectEnvironmentChanges(result.wifi, baseline.wifi, baseline.meta)
    : undefined;

  return { channelMap, rogueAPs, environment };
}
