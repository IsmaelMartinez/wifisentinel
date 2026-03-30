import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import { scoreAllStandards } from "../analyser/standards/index.js";
import { analyseAllPersonas } from "../analyser/personas/index.js";

export function renderJsonReport(
  result: NetworkScanResult,
  options?: { pretty?: boolean },
): string {
  const compliance = scoreAllStandards(result);
  const analysis = analyseAllPersonas(result);

  const combined = {
    scan: result,
    compliance,
    analysis,
  };

  return options?.pretty !== false
    ? JSON.stringify(combined, null, 2)
    : JSON.stringify(combined);
}
