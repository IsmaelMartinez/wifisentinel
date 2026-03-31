import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import type { ComplianceReport } from "../analyser/standards/types.js";
import type { FullAnalysis } from "../analyser/personas/types.js";
import type { RFAnalysis } from "../analyser/rf/types.js";
import { ScanIndex, type IndexEntry, type StoredScan } from "./types.js";
import { computeSecurityScore } from "../analyser/score.js";

export type { IndexEntry, StoredScan } from "./types.js";

export function getStorePath(): string {
  if (process.platform === "linux" && process.env.XDG_DATA_HOME) {
    return join(process.env.XDG_DATA_HOME, "wifisentinel");
  }
  return join(homedir(), ".wifisentinel");
}

function getScansDir(): string {
  return join(getStorePath(), "scans");
}

function getIndexPath(): string {
  return join(getStorePath(), "index.json");
}

function ensureDirs(): void {
  const scansDir = getScansDir();
  mkdirSync(scansDir, { recursive: true });
}

function readIndex(): IndexEntry[] {
  const indexPath = getIndexPath();
  if (!existsSync(indexPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(indexPath, "utf-8"));
    return ScanIndex.parse(raw);
  } catch {
    return [];
  }
}

function writeIndex(entries: IndexEntry[]): void {
  writeFileSync(getIndexPath(), JSON.stringify(entries, null, 2), "utf-8");
}

function makeFilename(timestamp: string, scanId: string): string {
  const datePart = timestamp.replace(/:/g, "-").replace(/\.\d+Z$/, "");
  const idPrefix = scanId.slice(0, 8);
  return `${datePart}_${idPrefix}.json`;
}

export function saveScan(
  result: NetworkScanResult,
  compliance: ComplianceReport,
  analysis: FullAnalysis,
  rfAnalysis?: RFAnalysis,
): void {
  ensureDirs();

  const filename = makeFilename(result.meta.timestamp, result.meta.scanId);
  const stored: StoredScan = { scan: result, compliance, analysis, rfAnalysis };
  writeFileSync(join(getScansDir(), filename), JSON.stringify(stored, null, 2), "utf-8");

  const entry: IndexEntry = {
    scanId: result.meta.scanId,
    timestamp: result.meta.timestamp,
    ssid: result.wifi.ssid,
    securityScore: computeSecurityScore(result),
    complianceGrade: compliance.overallGrade,
    consensusRisk: analysis.consensusRating,
    hostCount: result.network.hosts.length,
    filename,
  };

  const index = readIndex();
  index.push(entry);
  index.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  writeIndex(index);
}

export interface ListOptions {
  limit?: number;
  ssid?: string;
}

export function listScans(options: ListOptions = {}): IndexEntry[] {
  let entries = readIndex();
  if (entries.length === 0) {
    entries = rebuildIndex();
  }
  if (options.ssid) {
    entries = entries.filter(e => e.ssid === options.ssid);
  }
  if (options.limit) {
    entries = entries.slice(0, options.limit);
  }
  return entries;
}

const SAFE_FILENAME = /^[\w.-]+\.json$/;

export function loadScan(scanId: string): StoredScan {
  const entries = readIndex();
  const entry = entries.find(
    e => e.scanId === scanId || e.scanId.startsWith(scanId),
  );
  if (!entry) {
    throw new Error(
      `Scan "${scanId}" not found. Run "wifisentinel history" to list available scans.`,
    );
  }
  if (!SAFE_FILENAME.test(entry.filename)) {
    throw new Error(`Invalid filename in index: ${entry.filename}`);
  }
  const filePath = join(getScansDir(), entry.filename);
  if (!existsSync(filePath)) {
    throw new Error(
      `Scan file missing: ${entry.filename}. Run "wifisentinel rebuild-index" to repair.`,
    );
  }
  return JSON.parse(readFileSync(filePath, "utf-8")) as StoredScan;
}

export function rebuildIndex(): IndexEntry[] {
  ensureDirs();
  const scansDir = getScansDir();
  const files = readdirSync(scansDir).filter(f => f.endsWith(".json"));
  const entries: IndexEntry[] = [];

  for (const filename of files) {
    try {
      const raw = JSON.parse(readFileSync(join(scansDir, filename), "utf-8")) as StoredScan;
      entries.push({
        scanId: raw.scan.meta.scanId,
        timestamp: raw.scan.meta.timestamp,
        ssid: raw.scan.wifi.ssid,
        securityScore: computeSecurityScore(raw.scan),
        complianceGrade: raw.compliance.overallGrade,
        consensusRisk: raw.analysis.consensusRating,
        hostCount: raw.scan.network.hosts.length,
        filename,
      });
    } catch {
      // skip corrupt files
    }
  }

  entries.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  writeIndex(entries);
  return entries;
}
