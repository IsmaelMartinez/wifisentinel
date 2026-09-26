import type { NetworkScanResult } from "../collector/schema/scan-result.js";
import type { ComplianceReport } from "../analyser/standards/types.js";
import type { FullAnalysis } from "../analyser/personas/types.js";

export function renderJsonReport(
  result: NetworkScanResult,
  computed: { compliance: ComplianceReport; analysis: FullAnalysis },
): string {
  return JSON.stringify(
    { scan: result, compliance: computed.compliance, analysis: computed.analysis },
    null,
    2,
  );
}
