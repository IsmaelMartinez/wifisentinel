// dashboard/lib/store.ts
import { listScans, loadScan, type IndexEntry, type StoredScan } from "@wifisentinel/store/index.js";
import { analyseRF, type RFAnalysis } from "@wifisentinel/analyser/rf/index.js";

export type { IndexEntry, StoredScan };
export type { RFAnalysis };

export function getScans(options?: { limit?: number; ssid?: string }): IndexEntry[] {
  return listScans(options);
}

export function getScan(id: string): StoredScan {
  return loadScan(id);
}

export function getRFAnalysis(id: string): RFAnalysis {
  const stored = loadScan(id);
  if (stored.rfAnalysis) return stored.rfAnalysis;
  // Recompute for scans saved before RF analysis was added
  return analyseRF(stored.scan);
}
