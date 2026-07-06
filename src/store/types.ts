import { z } from "zod";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import type { ComplianceReport } from "../analyser/standards/types.js";
import type { FullAnalysis } from "../analyser/personas/types.js";
import type { RFAnalysis } from "../analyser/rf/types.js";

export const IndexEntry = z.object({
  scanId: z.string(),
  timestamp: z.string(),
  ssid: z.string().nullable(),
  securityScore: z.number(),
  complianceGrade: z.string(),
  consensusRisk: z.string(),
  hostCount: z.number(),
  filename: z.string(),
  // Scan source, so trend consumers can gate or annotate series without
  // loading every scan file. Optional: entries written before these fields
  // existed stay valid (`wifisentinel rebuild-index` backfills them).
  platform: z.string().optional(),
  partial: z.boolean().optional(),
});
export type IndexEntry = z.infer<typeof IndexEntry>;

export const ScanIndex = z.array(IndexEntry);
export type ScanIndex = z.infer<typeof ScanIndex>;

export interface StoredScan {
  scan: NetworkScanResult;
  compliance: ComplianceReport;
  analysis: FullAnalysis;
  rfAnalysis?: RFAnalysis;
}
