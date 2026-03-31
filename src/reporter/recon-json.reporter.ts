import type { ReconResult } from "../collector/recon/schema.js";
import { analyseReconAllPersonas } from "../analyser/recon-personas.js";

export function renderReconJsonReport(result: ReconResult): string {
  const analysis = analyseReconAllPersonas(result);
  return JSON.stringify({ recon: result, analysis }, null, 2);
}
