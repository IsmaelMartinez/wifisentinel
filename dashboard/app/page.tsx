// dashboard/app/page.tsx
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScoreGauge } from "@/components/score-gauge";
import { RiskBadge } from "@/components/risk-badge";
import { GradeBadge } from "@/components/grade-badge";
import { EmptyState } from "@/components/empty-state";
import { getScans, getScan } from "@/lib/store";

const personaNames: Record<string, string> = {
  "red-team": "Red Team",
  "blue-team": "Blue Team",
  "compliance": "Compliance",
  "net-engineer": "Net Engineer",
  "privacy": "Privacy",
};

export const revalidate = 60;

export default function OverviewPage() {
  const entries = getScans({ limit: 10 });

  if (entries.length === 0) {
    return <EmptyState />;
  }

  const latest = entries[0];
  let stored;
  try {
    stored = getScan(latest.scanId);
  } catch {
    return <EmptyState />;
  }

  const { scan, analysis, compliance } = stored;
  const rfSummary = stored.rfAnalysis;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold">Overview</h1>
          <p className="text-sm text-muted-foreground">
            {scan.wifi.ssid ?? "(hidden)"} &middot; {new Date(scan.meta.timestamp).toLocaleString()}
          </p>
        </div>
        <Link
          href={`/scans/${latest.scanId}`}
          className="text-sm text-primary underline underline-offset-4"
        >
          View Full Report
        </Link>
      </div>

      {/* Top metrics */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 lg:gap-4">
        <Card>
          <CardContent className="flex flex-col items-center pt-6">
            <ScoreGauge score={latest.securityScore} />
            <p className="mt-2 text-sm text-muted-foreground">Security Score</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-col items-center justify-center pt-6">
            <GradeBadge grade={latest.complianceGrade} />
            <p className="mt-3 text-sm text-muted-foreground">Compliance</p>
            <p className="text-xs text-muted-foreground">{compliance.overallScore}%</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-col items-center justify-center pt-6">
            <RiskBadge risk={latest.consensusRisk} className="text-lg px-4 py-1" />
            <p className="mt-3 text-sm text-muted-foreground">Consensus Risk</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-col items-center justify-center pt-6">
            <span className="text-3xl font-bold">{latest.hostCount}</span>
            <p className="mt-2 text-sm text-muted-foreground">Hosts</p>
          </CardContent>
        </Card>
      </div>

      {/* Persona badges */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Persona Risk Assessment</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3 sm:gap-4">
            {analysis.analyses.map((a) => (
              <div key={a.persona} className="flex flex-col items-center gap-1.5">
                <RiskBadge risk={a.riskRating} />
                <span className="text-xs text-muted-foreground">
                  {personaNames[a.persona] ?? a.persona}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Score trend + RF summary */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 sm:gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Score Trend</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-16">
              {[...entries].reverse().map((e) => {
                const height = Math.max(4, (e.securityScore / 10) * 64);
                const color = e.securityScore >= 8 ? "bg-teal-500" : e.securityScore >= 5 ? "bg-amber-500" : "bg-red-500";
                const label = `Score ${e.securityScore.toFixed(1)} on ${new Date(e.timestamp).toLocaleDateString()}`;
                return (
                  <div
                    key={e.scanId}
                    className={`${color} rounded-sm flex-1 min-w-1`}
                    style={{ height }}
                    role="img"
                    aria-label={label}
                    title={label}
                  />
                );
              })}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">RF Summary</CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-1">
            {rfSummary ? (
              <>
                <p>
                  Channel {rfSummary.channelMap.currentChannel} &middot;
                  Saturation: <span className={
                    rfSummary.channelMap.currentSaturation <= 30 ? "text-teal-400" :
                    rfSummary.channelMap.currentSaturation <= 60 ? "text-yellow-400" : "text-red-400"
                  }>{rfSummary.channelMap.currentSaturation}%</span>
                </p>
                {rfSummary.channelMap.recommendedChannel !== rfSummary.channelMap.currentChannel && (
                  <p className="text-yellow-400">
                    Consider channel {rfSummary.channelMap.recommendedChannel}
                  </p>
                )}
                <p>
                  Rogue APs: <span className={
                    rfSummary.rogueAPs.riskLevel === "clear" ? "text-teal-400" : "text-red-400"
                  }>{rfSummary.rogueAPs.riskLevel}</span>
                </p>
              </>
            ) : (
              <p className="text-muted-foreground">No RF data available</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Quick links */}
      <div className="flex flex-wrap gap-4">
        <Link href="/scans" className="text-sm text-primary underline underline-offset-4">
          View History
        </Link>
        <Link href="/trends" className="text-sm text-primary underline underline-offset-4">
          View Trends
        </Link>
      </div>
    </div>
  );
}
