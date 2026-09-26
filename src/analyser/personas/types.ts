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
  consensusRating: RiskRating,
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
    // Strictly greater: RISK_ORDER runs most-severe first, so the first
    // rating to reach a tied count is the more severe one and keeps it.
    if (count > bestCount) {
      best = rating;
      bestCount = count;
    }
  }
  return best;
}

/**
 * A persona's priority action for one insight id. `key` names the underlying
 * remediation so consensus can merge different wordings of it across
 * personas; `text` defaults to the insight's own recommendation.
 */
export interface ActionDef {
  key: string;
  text?: string;
}
/** Insight id → action, in priority order. */
export type ActionMap = Record<string, ActionDef>;
export interface KeyedAction {
  key: string;
  text: string;
}

export interface PersonaSpec {
  persona: PersonaId;
  displayName: string;
  perspective: string;
  actions: ActionMap;
  /** When nothing maps, fall back to the most severe insight's recommendation. */
  fallback?: boolean;
}

const MAX_ACTIONS = 5;

/**
 * Priority actions for the insights a persona raised, in map order. Info
 * insights (passing checks) never produce an action.
 */
export function keyedActionsFor(insights: Insight[], spec: PersonaSpec): KeyedAction[] {
  const gaps = insights.filter((i) => i.severity !== "info");
  const byId = new Map(gaps.map((i) => [i.id, i]));
  const actions: KeyedAction[] = [];
  for (const [id, def] of Object.entries(spec.actions)) {
    const insight = byId.get(id);
    if (insight) actions.push({ key: def.key, text: def.text ?? insight.recommendation });
  }
  if (actions.length === 0 && spec.fallback && gaps.length > 0) {
    const top = Severity.options.map((s) => gaps.find((i) => i.severity === s)).find(Boolean)!;
    actions.push({ key: top.recommendation, text: top.recommendation });
  }
  return actions.slice(0, MAX_ACTIONS);
}

export function actionsFor(insights: Insight[], spec: PersonaSpec): string[] {
  return keyedActionsFor(insights, spec).map((a) => a.text);
}

export function buildPersonaAnalysis(
  spec: PersonaSpec,
  insights: Insight[],
  executiveSummary: string,
): PersonaAnalysis {
  return {
    persona: spec.persona,
    displayName: spec.displayName,
    perspective: spec.perspective,
    riskRating: riskFromInsights(insights),
    executiveSummary,
    insights,
    priorityActions: actionsFor(insights, spec),
  };
}

/**
 * Merge actions across personas on their canonical key, keeping the first
 * wording seen, ordered by how many personas recommend it.
 */
export function consensusActions(allActions: KeyedAction[][]): string[] {
  const byKey = new Map<string, { text: string; count: number }>();
  for (const actions of allActions) {
    for (const key of new Set(actions.map((a) => a.key))) {
      const entry = byKey.get(key);
      if (entry) entry.count++;
      else byKey.set(key, { text: actions.find((a) => a.key === key)!.text.trim(), count: 1 });
    }
  }
  return [...byKey.values()].sort((a, b) => b.count - a.count).map((e) => e.text);
}
