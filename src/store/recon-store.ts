import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { getStorePath } from "./index.js";
import type { ReconResult } from "../collector/recon/schema.js";
import type { FullReconAnalysis } from "../analyser/recon-personas.js";

const SAFE_FILENAME = /^[\w.-]+\.json$/;

const ReconIndexEntrySchema = z.object({
  reconId: z.string(),
  timestamp: z.string(),
  domain: z.string(),
  tlsGrade: z.string(),
  headersGrade: z.string(),
  overallGrade: z.string(),
  subdomainCount: z.number(),
  filename: z.string(),
});

export type ReconIndexEntry = z.infer<typeof ReconIndexEntrySchema>;

const ReconIndex = z.array(ReconIndexEntrySchema);

export interface StoredRecon {
  recon: ReconResult;
  analysis?: FullReconAnalysis;
}

function getReconsDir(): string {
  return join(getStorePath(), "recons");
}

function getIndexPath(): string {
  return join(getStorePath(), "recon-index.json");
}

function ensureDirs(): void {
  mkdirSync(getReconsDir(), { recursive: true });
}

function readIndex(): ReconIndexEntry[] {
  const indexPath = getIndexPath();
  if (!existsSync(indexPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(indexPath, "utf-8"));
    return ReconIndex.parse(raw);
  } catch {
    return [];
  }
}

function writeIndex(entries: ReconIndexEntry[]): void {
  writeFileSync(getIndexPath(), JSON.stringify(entries, null, 2), "utf-8");
}

function makeFilename(timestamp: string, reconId: string): string {
  const datePart = timestamp.replace(/:/g, "-").replace(/\.\d+Z$/, "");
  const idPrefix = reconId.slice(0, 8);
  return `${datePart}_${idPrefix}.json`;
}

export function saveRecon(result: ReconResult, analysis?: FullReconAnalysis): void {
  ensureDirs();

  const filename = makeFilename(result.meta.timestamp, result.meta.reconId);
  const stored: StoredRecon = { recon: result, analysis };
  writeFileSync(join(getReconsDir(), filename), JSON.stringify(stored, null, 2), "utf-8");

  const gradeValues: Record<string, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };
  const avg = ((gradeValues[result.tls.grade] ?? 0) + (gradeValues[result.headers.grade] ?? 0)) / 2;
  const overallGrade = avg >= 3.5 ? "A" : avg >= 2.5 ? "B" : avg >= 1.5 ? "C" : avg >= 0.5 ? "D" : "F";

  const entry: ReconIndexEntry = {
    reconId: result.meta.reconId,
    timestamp: result.meta.timestamp,
    domain: result.meta.domain,
    tlsGrade: result.tls.grade,
    headersGrade: result.headers.grade,
    overallGrade,
    subdomainCount: result.crt.uniqueSubdomains.length,
    filename,
  };

  const index = readIndex();
  index.push(entry);
  index.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  writeIndex(index);
}

export interface ListReconsOptions {
  limit?: number;
  domain?: string;
}

export function listRecons(options: ListReconsOptions = {}): ReconIndexEntry[] {
  let entries = readIndex();
  if (options.domain) {
    entries = entries.filter(e => e.domain === options.domain);
  }
  if (options.limit) {
    entries = entries.slice(0, options.limit);
  }
  return entries;
}

export function loadRecon(reconId: string): StoredRecon {
  const entries = readIndex();
  const entry = entries.find(
    e => e.reconId === reconId || e.reconId.startsWith(reconId),
  );
  if (!entry) {
    throw new Error(
      `Recon "${reconId}" not found. Run "wifisentinel recon-history" to list available scans.`,
    );
  }
  if (!SAFE_FILENAME.test(entry.filename)) {
    throw new Error(`Invalid filename in index: ${entry.filename}`);
  }
  const filePath = join(getReconsDir(), entry.filename);
  if (!existsSync(filePath)) {
    throw new Error(`Recon file missing: ${entry.filename}.`);
  }
  return JSON.parse(readFileSync(filePath, "utf-8")) as StoredRecon;
}
