import { join } from "node:path";
import { homedir } from "node:os";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import type { ComplianceReport } from "../analyser/standards/types.js";
import type { FullAnalysis } from "../analyser/personas/types.js";
import type { RFAnalysis } from "../analyser/rf/types.js";
import { ScanIndex, type IndexEntry, type StoredScan } from "./types.js";
import { computeSecurityScore } from "../analyser/score.js";
import { createJsonStore } from "./json-store.js";

export type { IndexEntry, StoredScan } from "./types.js";

export function getStorePath(): string {
  if (process.platform === "linux" && process.env.XDG_DATA_HOME) {
    return join(process.env.XDG_DATA_HOME, "wifisentinel");
  }
  return join(homedir(), ".wifisentinel");
}

const store = createJsonStore<IndexEntry, StoredScan>({
  root: getStorePath,
  dataDir: "scans",
  indexFile: "index.json",
  indexSchema: ScanIndex,
  noun: "Scan",
  listCommand: "wifisentinel history",
  reindexCommand: "wifisentinel history --reindex",
  idOf: e => e.scanId,
  timestampOf: e => e.timestamp,
  filenameOf: e => e.filename,
  keyOf: s => ({ id: s.scan.meta.scanId, timestamp: s.scan.meta.timestamp }),
  toEntry: ({ scan, compliance, analysis }, filename) => ({
    scanId: scan.meta.scanId,
    timestamp: scan.meta.timestamp,
    ssid: scan.wifi.ssid,
    securityScore: computeSecurityScore(scan),
    complianceGrade: compliance.overallGrade,
    consensusRisk: analysis.consensusRating,
    hostCount: scan.network.hosts.length,
    filename,
    platform: scan.meta.platform,
    ...(scan.meta.partial !== undefined ? { partial: scan.meta.partial } : {}),
  }),
});

export function saveScan(
  result: NetworkScanResult,
  compliance: ComplianceReport,
  analysis: FullAnalysis,
  rfAnalysis?: RFAnalysis,
): void {
  store.save({ scan: result, compliance, analysis, rfAnalysis });
}

export interface ListOptions {
  limit?: number;
  ssid?: string;
}

export function listScans(options: ListOptions = {}): IndexEntry[] {
  let entries = store.list();
  if (options.ssid) {
    entries = entries.filter(e => e.ssid === options.ssid);
  }
  if (options.limit) {
    entries = entries.slice(0, options.limit);
  }
  return entries;
}

export function loadScan(scanId: string): StoredScan {
  return store.load(scanId);
}

/** Loads the scans behind entries from `listScans` with no further index reads. */
export function loadScans(entries: IndexEntry[]): StoredScan[] {
  return store.loadMany(entries);
}

export function rebuildIndex(): IndexEntry[] {
  return store.rebuildIndex();
}
