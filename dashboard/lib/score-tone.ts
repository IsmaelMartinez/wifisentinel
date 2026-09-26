// Shared colour bands for security scores (0–10) and compliance percentages.
// Security bands match the CLI reporters (>= 8 good, >= 5 fair); compliance
// bands follow the grade cut-offs (>= 80 is B or better, < 60 is F).

export type ScoreTone = "good" | "fair" | "poor";

const BANDS = {
  security: { good: 8, fair: 5 },
  compliance: { good: 80, fair: 60 },
} as const;

export function scoreTone(score: number, scale: keyof typeof BANDS = "security"): ScoreTone {
  const bands = BANDS[scale];
  if (score >= bands.good) return "good";
  if (score >= bands.fair) return "fair";
  return "poor";
}

// Full class names so Tailwind's content scan picks them up.
export const toneClasses: Record<ScoreTone, { text: string; stroke: string; strokeFaint: string; bg: string }> = {
  good: { text: "text-teal-400", stroke: "stroke-teal-400", strokeFaint: "stroke-teal-400/20", bg: "bg-teal-500" },
  fair: { text: "text-amber-400", stroke: "stroke-amber-400", strokeFaint: "stroke-amber-400/20", bg: "bg-amber-500" },
  poor: { text: "text-red-400", stroke: "stroke-red-400", strokeFaint: "stroke-red-400/20", bg: "bg-red-500" },
};
