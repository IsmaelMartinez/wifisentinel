import type { ReconResult } from "../collector/recon/schema.js";
import type { FullReconAnalysis } from "../analyser/recon-personas.js";

export function renderReconJsonReport(result: ReconResult, analysis: FullReconAnalysis): string {
  return JSON.stringify({ recon: result, analysis }, null, 2);
}
