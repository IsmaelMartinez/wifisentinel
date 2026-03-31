// dashboard/components/risk-badge.tsx
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const riskStyles: Record<string, string> = {
  critical: "bg-red-600 text-white hover:bg-red-600",
  high: "bg-red-500/20 text-red-400 hover:bg-red-500/20",
  medium: "bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/20",
  low: "bg-green-500/20 text-green-400 hover:bg-green-500/20",
  minimal: "bg-green-500/10 text-green-500 hover:bg-green-500/10",
};

export function RiskBadge({ risk, className }: { risk: string; className?: string }) {
  return (
    <Badge variant="secondary" className={cn(riskStyles[risk] ?? riskStyles.minimal, className)}>
      {risk.toUpperCase()}
    </Badge>
  );
}
