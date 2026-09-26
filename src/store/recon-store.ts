import { z } from "zod";
import { getStorePath } from "./index.js";
import { createJsonStore } from "./json-store.js";
import type { ReconResult } from "../collector/recon/schema.js";
import type { FullReconAnalysis } from "../analyser/recon-personas.js";

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

export interface StoredRecon {
  recon: ReconResult;
  analysis?: FullReconAnalysis;
}

const store = createJsonStore<ReconIndexEntry, StoredRecon>({
  root: getStorePath,
  dataDir: "recons",
  indexFile: "recon-index.json",
  indexSchema: z.array(ReconIndexEntrySchema),
  noun: "Recon",
  listCommand: "wifisentinel recon-history",
  reindexCommand: "wifisentinel recon-history --reindex",
  idOf: e => e.reconId,
  timestampOf: e => e.timestamp,
  filenameOf: e => e.filename,
  keyOf: s => ({ id: s.recon.meta.reconId, timestamp: s.recon.meta.timestamp }),
  toEntry: ({ recon, analysis }, filename) => ({
    reconId: recon.meta.reconId,
    timestamp: recon.meta.timestamp,
    domain: recon.meta.domain,
    tlsGrade: recon.tls.grade,
    headersGrade: recon.headers.grade,
    // The analyser owns the overall-grade formula; records saved without an
    // analysis have no grade to index.
    overallGrade: analysis?.overallGrade ?? "-",
    subdomainCount: recon.crt.uniqueSubdomains.length,
    filename,
  }),
});

export function saveRecon(result: ReconResult, analysis: FullReconAnalysis): void {
  store.save({ recon: result, analysis });
}

export interface ListReconsOptions {
  limit?: number;
  domain?: string;
}

export function listRecons(options: ListReconsOptions = {}): ReconIndexEntry[] {
  let entries = store.list();
  if (options.domain) {
    entries = entries.filter(e => e.domain === options.domain);
  }
  if (options.limit) {
    entries = entries.slice(0, options.limit);
  }
  return entries;
}

export function rebuildReconIndex(): ReconIndexEntry[] {
  return store.rebuildIndex();
}
