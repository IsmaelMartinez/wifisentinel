import { z } from "zod";

export const PersonaId = z.enum([
  "red-team",
  "blue-team",
  "compliance",
  "net-engineer",
  "privacy",
]);
export type PersonaId = z.infer<typeof PersonaId>;

export const Severity = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof Severity>;

export const Insight = z.object({
  id: z.string(),
  title: z.string(),
  severity: Severity,
  category: z.string(),
  description: z.string(),
  technicalDetail: z.string(),
  recommendation: z.string(),
  affectedAssets: z.array(z.string()),
  references: z.array(z.string()),
});
export type Insight = z.infer<typeof Insight>;

export const RiskRating = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "minimal",
]);
export type RiskRating = z.infer<typeof RiskRating>;

export const PersonaAnalysis = z.object({
  persona: PersonaId,
  displayName: z.string(),
  perspective: z.string(),
  riskRating: RiskRating,
  executiveSummary: z.string(),
  insights: z.array(Insight),
  priorityActions: z.array(z.string()),
});
export type PersonaAnalysis = z.infer<typeof PersonaAnalysis>;

export const FullAnalysis = z.object({
  scanId: z.string(),
  timestamp: z.string(),
  analyses: z.array(PersonaAnalysis),
  consensusRating: z.string(),
  consensusActions: z.array(z.string()),
});
export type FullAnalysis = z.infer<typeof FullAnalysis>;

const RISK_ORDER: RiskRating[] = [
  "critical",
  "high",
  "medium",
  "low",
  "minimal",
];

/** Derive risk rating from the highest severity insight. */
export function riskFromInsights(insights: Insight[]): RiskRating {
  if (insights.length === 0) return "minimal";
  const severityToRisk: Record<Severity, RiskRating> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "minimal",
  };
  let worst: RiskRating = "minimal";
  for (const insight of insights) {
    const mapped = severityToRisk[insight.severity];
    if (RISK_ORDER.indexOf(mapped) < RISK_ORDER.indexOf(worst)) {
      worst = mapped;
    }
  }
  return worst;
}

/** Compute consensus rating (mode of ratings, ties broken toward higher severity). */
export function consensusRating(ratings: RiskRating[]): RiskRating {
  const counts = new Map<RiskRating, number>();
  for (const r of ratings) {
    counts.set(r, (counts.get(r) ?? 0) + 1);
  }
  let best: RiskRating = "minimal";
  let bestCount = 0;
  for (const rating of RISK_ORDER) {
    const count = counts.get(rating) ?? 0;
    if (count > bestCount || (count === bestCount && count > 0)) {
      best = rating;
      bestCount = count;
    }
  }
  return best;
}

/** Deduplicate and order actions by frequency across personas. */
export function consensusActions(allActions: string[][]): string[] {
  const freq = new Map<string, number>();
  for (const actions of allActions) {
    for (const action of actions) {
      const normalised = action.trim();
      freq.set(normalised, (freq.get(normalised) ?? 0) + 1);
    }
  }
  return [...freq.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([action]) => action);
}
