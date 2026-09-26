// dashboard/components/score-gauge.tsx
import { cn } from "@/lib/utils";
import { scoreTone, toneClasses } from "@/lib/score-tone";

export function ScoreGauge({ score, size = 120 }: { score: number; size?: number }) {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 10) * circumference;
  const tone = toneClasses[scoreTone(score)];

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" className="transform -rotate-90" style={{ width: size, height: size }}>
        <circle cx="50" cy="50" r={radius} fill="none" strokeWidth="8" className={tone.strokeFaint} />
        <circle
          cx="50" cy="50" r={radius} fill="none" strokeWidth="8"
          className={tone.stroke}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn("text-3xl font-bold", tone.text)}>{score.toFixed(1)}</span>
        <span className="text-xs text-muted-foreground">/10</span>
      </div>
    </div>
  );
}
