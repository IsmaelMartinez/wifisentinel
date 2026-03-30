import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import { scoreCisWireless } from "./cis-wireless.js";
import { scoreIeee80211 } from "./ieee-802.11.js";
import { scoreNist800153 } from "./nist-800-153.js";
import { scoreOwaspIot } from "./owasp-iot.js";
import { type ComplianceReport, computeGrade } from "./types.js";

export { scoreCisWireless } from "./cis-wireless.js";
export { scoreIeee80211 } from "./ieee-802.11.js";
export { scoreNist800153 } from "./nist-800-153.js";
export { scoreOwaspIot } from "./owasp-iot.js";

export type {
  ComplianceReport,
  Finding,
  FindingStatus,
  Grade,
  Severity,
  StandardId,
  StandardScore,
} from "./types.js";

export { computeGrade, computeScore, SEVERITY_WEIGHTS } from "./types.js";

export function scoreAllStandards(result: NetworkScanResult): ComplianceReport {
  const standards = [
    scoreCisWireless(result),
    scoreNist800153(result),
    scoreIeee80211(result),
    scoreOwaspIot(result),
  ];

  const overallScore =
    standards.length > 0
      ? Math.round(
          standards.reduce((sum, s) => sum + s.score, 0) / standards.length
        )
      : 0;

  return {
    scanId: result.meta.scanId,
    timestamp: result.meta.timestamp,
    overallScore,
    overallGrade: computeGrade(overallScore),
    standards,
  };
}
