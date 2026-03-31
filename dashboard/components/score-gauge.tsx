// dashboard/components/score-gauge.tsx
import { cn } from "@/lib/utils";

function scoreColor(score: number): string {
  if (score >= 8) return "text-green-500";
  if (score >= 5) return "text-yellow-500";
  return "text-red-500";
}

function scoreBgRing(score: number): string {
  if (score >= 8) return "stroke-green-500/20";
  if (score >= 5) return "stroke-yellow-500/20";
  return "stroke-red-500/20";
}

function scoreRing(score: number): string {
  if (score >= 8) return "stroke-green-500";
  if (score >= 5) return "stroke-yellow-500";
  return "stroke-red-500";
}

export function ScoreGauge({ score, size = 120 }: { score: number; size?: number }) {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 10) * circumference;

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" className="transform -rotate-90" style={{ width: size, height: size }}>
        <circle cx="50" cy="50" r={radius} fill="none" strokeWidth="8" className={scoreBgRing(score)} />
        <circle
          cx="50" cy="50" r={radius} fill="none" strokeWidth="8"
          className={scoreRing(score)}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn("text-3xl font-bold", scoreColor(score))}>{score.toFixed(1)}</span>
        <span className="text-xs text-muted-foreground">/10</span>
      </div>
    </div>
  );
}
