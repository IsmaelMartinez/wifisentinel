import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import type { ComplianceReport } from "../analyser/standards/types.js";
import type { FullAnalysis } from "../analyser/personas/types.js";

export function renderJsonReport(
  result: NetworkScanResult,
  computed: { compliance: ComplianceReport; analysis: FullAnalysis },
  options?: { pretty?: boolean },
): string {
  const combined = {
    scan: result,
    compliance: computed.compliance,
    analysis: computed.analysis,
  };

  return options?.pretty !== false
    ? JSON.stringify(combined, null, 2)
    : JSON.stringify(combined);
}
