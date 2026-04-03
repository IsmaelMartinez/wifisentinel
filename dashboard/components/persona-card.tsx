"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { RiskBadge } from "@/components/risk-badge";
import { ChevronDown, ChevronRight } from "lucide-react";

interface Insight {
  id: string;
  title: string;
  severity: string;
  description: string;
  technicalDetail: string;
  recommendation: string;
  affectedAssets: string[];
}

interface PersonaAnalysis {
  persona: string;
  displayName: string;
  riskRating: string;
  executiveSummary: string;
  insights: Insight[];
  priorityActions: string[];
}

const severityColor: Record<string, string> = {
  critical: "text-red-500",
  high: "text-red-400",
  medium: "text-amber-400",
  low: "text-muted-foreground",
  info: "text-blue-400",
};

export function PersonaCard({ analysis }: { analysis: PersonaAnalysis }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardHeader
        className="cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-lg"
        role="button"
        tabIndex={0}
        onClick={() => setExpanded(!expanded)}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setExpanded(!expanded); } }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            <CardTitle className="text-base">{analysis.displayName}</CardTitle>
            <RiskBadge risk={analysis.riskRating} />
          </div>
          <span className="text-sm text-muted-foreground">
            {analysis.insights.length} finding{analysis.insights.length !== 1 ? "s" : ""}
          </span>
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-4">
          <p className="text-sm">{analysis.executiveSummary}</p>

          {analysis.priorityActions.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold mb-1">Priority Actions</h4>
              {analysis.priorityActions.map((a, i) => (
                <p key={i} className="text-sm text-muted-foreground ml-2">
                  &rarr; {a}
                </p>
              ))}
            </div>
          )}

          {analysis.insights.map((insight) => (
            <div key={insight.id} className="border-l-2 border-border pl-3 space-y-1">
              <p className="text-sm">
                <span className={severityColor[insight.severity] ?? ""}>[{insight.severity.toUpperCase()}]</span>{" "}
                {insight.title}
              </p>
              <p className="text-xs text-muted-foreground">{insight.description}</p>
              <p className="text-xs font-mono text-muted-foreground">{insight.technicalDetail}</p>
              <p className="text-xs text-primary">&rarr; {insight.recommendation}</p>
            </div>
          ))}
        </CardContent>
      )}
    </Card>
  );
}
