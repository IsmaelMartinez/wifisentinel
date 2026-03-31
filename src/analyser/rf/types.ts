// src/analyser/rf/types.ts
import { z } from "zod";

export const ChannelInfo = z.object({
  channel: z.number(),
  band: z.enum(["2.4GHz", "5GHz"]),
  networkCount: z.number(),
  overlapCount: z.number(),
  saturationScore: z.number(),
  networks: z.array(z.object({
    ssid: z.string().nullable(),
    signal: z.number(),
    security: z.string(),
  })),
});
export type ChannelInfo = z.infer<typeof ChannelInfo>;

export const ChannelMap = z.object({
  channels: z.array(ChannelInfo),
  currentChannel: z.number(),
  currentBand: z.string(),
  currentSaturation: z.number(),
  recommendedChannel: z.number(),
  recommendationReason: z.string(),
});
export type ChannelMap = z.infer<typeof ChannelMap>;

export const RogueAPFinding = z.object({
  ssid: z.string(),
  bssid: z.string().optional(),
  channel: z.number(),
  signal: z.number(),
  security: z.string(),
  indicators: z.array(z.string()),
  severity: z.enum(["high", "medium", "low"]),
  description: z.string(),
});
export type RogueAPFinding = z.infer<typeof RogueAPFinding>;

export const RogueAPAnalysis = z.object({
  findings: z.array(RogueAPFinding),
  riskLevel: z.enum(["clear", "suspicious", "danger"]),
});
export type RogueAPAnalysis = z.infer<typeof RogueAPAnalysis>;

export const EnvironmentChange = z.object({
  type: z.enum(["new_ap", "disappeared_ap", "security_change", "signal_anomaly", "channel_change"]),
  ssid: z.string().nullable(),
  bssid: z.string().optional(),
  detail: z.string(),
  severity: z.enum(["high", "medium", "low"]),
});
export type EnvironmentChange = z.infer<typeof EnvironmentChange>;

export const EnvironmentAnalysis = z.object({
  baselineScanId: z.string(),
  baselineTimestamp: z.string(),
  changes: z.array(EnvironmentChange),
  summary: z.string(),
});
export type EnvironmentAnalysis = z.infer<typeof EnvironmentAnalysis>;

export const RFAnalysis = z.object({
  channelMap: ChannelMap,
  rogueAPs: RogueAPAnalysis,
  environment: EnvironmentAnalysis.optional(),
});
export type RFAnalysis = z.infer<typeof RFAnalysis>;
