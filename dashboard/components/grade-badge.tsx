// dashboard/components/grade-badge.tsx
import { cn } from "@/lib/utils";

function gradeColor(grade: string): string {
  if (grade === "A" || grade === "B") return "text-green-400 border-green-400/30";
  if (grade === "C" || grade === "D") return "text-yellow-400 border-yellow-400/30";
  return "text-red-400 border-red-400/30";
}

export function GradeBadge({ grade, className }: { grade: string; className?: string }) {
  return (
    <span className={cn(
      "inline-flex items-center justify-center w-10 h-10 rounded-lg border-2 text-xl font-bold font-mono",
      gradeColor(grade),
      className,
    )}>
      {grade}
    </span>
  );
}
