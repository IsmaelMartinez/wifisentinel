import { z } from "zod";
import type { WpaTier } from "../security.js";
import { Severity } from "../personas/types.js";

export { Severity };

export const StandardId = z.enum([
  "cis-wireless",
  "nist-800-153",
  "ieee-802.11",
  "owasp-iot",
]);
export type StandardId = z.infer<typeof StandardId>;

export const FindingStatus = z.enum([
  "pass",
  "fail",
  "partial",
  "not-applicable",
]);
export type FindingStatus = z.infer<typeof FindingStatus>;

export const Grade = z.enum(["A", "B", "C", "D", "F"]);
export type Grade = z.infer<typeof Grade>;

export const Finding = z.object({
  id: z.string(),
  standard: StandardId,
  title: z.string(),
  severity: Severity,
  status: FindingStatus,
  description: z.string(),
  recommendation: z.string(),
  evidence: z.string().optional(),
});
export type Finding = z.infer<typeof Finding>;

export const StandardScore = z.object({
  standard: StandardId,
  name: z.string(),
  version: z.string(),
  score: z.number().min(0).max(100),
  maxScore: z.literal(100),
  grade: Grade,
  findings: z.array(Finding),
  summary: z.string(),
});
export type StandardScore = z.infer<typeof StandardScore>;

export const ComplianceReport = z.object({
  scanId: z.string(),
  timestamp: z.string(),
  overallScore: z.number().min(0).max(100),
  overallGrade: Grade,
  standards: z.array(StandardScore),
});
export type ComplianceReport = z.infer<typeof ComplianceReport>;

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** Status for a "WPA3, else at least WPA2" encryption check. */
export function wpaTierStatus(tier: WpaTier): FindingStatus {
  if (tier === "wpa3") return "pass";
  if (tier === "wpa2") return "partial";
  if (tier === "unknown") return "not-applicable";
  return "fail";
}

export const UNKNOWN_SECURITY_FIX =
  "Security mode was not reported — confirm the access point uses WPA3, or WPA2 at minimum.";

export interface FindingSpec {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  description: string;
  /** Recommendation whenever the control does not pass. */
  fix: string;
  /** Recommendation when it passes. */
  ok?: string;
  evidence?: string;
}

export function finding(standard: StandardId, spec: FindingSpec): Finding {
  return {
    id: spec.id,
    standard,
    title: spec.title,
    severity: spec.severity,
    status: spec.status,
    description: spec.description,
    recommendation: spec.status === "pass" ? (spec.ok ?? "No action needed.") : spec.fix,
    ...(spec.evidence === undefined ? {} : { evidence: spec.evidence }),
  };
}

export function buildStandardScore(
  standard: StandardId,
  name: string,
  version: string,
  findings: Finding[],
): StandardScore {
  const score = computeScore(findings);
  const passing = findings.filter((f) => f.status === "pass").length;
  const applicable = findings.filter((f) => f.status !== "not-applicable").length;
  return {
    standard,
    name,
    version,
    score,
    maxScore: 100,
    grade: computeGrade(score),
    findings,
    summary: `${passing}/${applicable} applicable controls passed (score: ${score}/100).`,
  };
}

export function computeGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function computeScore(findings: Finding[]): number {
  let earned = 0;
  let max = 0;
  for (const f of findings) {
    const weight = SEVERITY_WEIGHTS[f.severity];
    if (weight === 0) continue;
    max += weight;
    if (f.status === "pass") {
      earned += weight;
    } else if (f.status === "partial") {
      earned += weight * 0.5;
    }
    // "fail" and "not-applicable" earn nothing; n/a also doesn't count toward max
    if (f.status === "not-applicable") {
      max -= weight;
    }
  }
  if (max === 0) return 100;
  return Math.round((earned / max) * 100);
}
