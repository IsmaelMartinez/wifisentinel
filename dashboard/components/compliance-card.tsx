import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { GradeBadge } from "@/components/grade-badge";

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  description: string;
  recommendation: string;
  evidence?: string;
}

interface StandardScore {
  standard: string;
  name: string;
  score: number;
  grade: string;
  findings: Finding[];
  summary: string;
}

const statusIcon: Record<string, string> = {
  pass: "text-green-400",
  fail: "text-red-400",
  partial: "text-yellow-400",
  "not-applicable": "text-muted-foreground",
};

const statusLabel: Record<string, string> = {
  pass: "\u2714",
  fail: "\u2718",
  partial: "\u25D0",
  "not-applicable": "\u2014",
};

export function ComplianceCard({ standard }: { standard: StandardScore }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <GradeBadge grade={standard.grade} className="w-8 h-8 text-base" />
            <div>
              <CardTitle className="text-base">{standard.name}</CardTitle>
              <p className="text-xs text-muted-foreground">{standard.summary}</p>
            </div>
          </div>
          <div className="text-right">
            <span className="text-2xl font-bold font-mono">{standard.score}%</span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="w-full bg-muted rounded-full h-2 mb-4">
          <div
            className={`h-2 rounded-full ${
              standard.score >= 80 ? "bg-green-500" : standard.score >= 60 ? "bg-yellow-500" : "bg-red-500"
            }`}
            style={{ width: `${standard.score}%` }}
          />
        </div>
        <div className="space-y-2">
          {standard.findings.map((f) => (
            <div key={f.id} className="flex items-start gap-2 text-sm">
              <span className={statusIcon[f.status] ?? ""}>{statusLabel[f.status] ?? "?"}</span>
              <div>
                <span className="text-muted-foreground">[{f.severity.toUpperCase()}]</span> {f.title}
                {f.status === "fail" && f.recommendation && (
                  <p className="text-xs text-primary mt-0.5">&rarr; {f.recommendation}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
