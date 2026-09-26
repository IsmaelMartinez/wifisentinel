// dashboard/lib/store.ts
import { listScans, loadScan, type IndexEntry, type StoredScan } from "@wifisentinel/store/index.js";
import { analyseRF, type RFAnalysis } from "@wifisentinel/analyser/rf/index.js";

export type { IndexEntry, StoredScan };
export type { RFAnalysis };

export function getScans(options?: { limit?: number; ssid?: string }): IndexEntry[] {
  return listScans(options);
}

// Scans saved before RF analysis was added have no `rfAnalysis`; recompute it
// here so every caller sees one.
export function getScan(id: string): StoredScan & { rfAnalysis: RFAnalysis } {
  const stored = loadScan(id);
  return { ...stored, rfAnalysis: stored.rfAnalysis ?? analyseRF(stored.scan) };
}
