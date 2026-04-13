// dashboard/app/mobile/page.tsx
import Link from "next/link";
import { Shield, Wifi, Server, Lock, Activity, ChevronRight, AlertTriangle } from "lucide-react";
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

export default function MobilePage() {
  const entries = getScans({ limit: 5 });

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
  const timestamp = new Date(scan.meta.timestamp);
  const timeAgo = getTimeAgo(timestamp);

  return (
    <div className="space-y-4 pb-8">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Shield className="h-5 w-5 text-teal-400" />
        <h1 className="text-lg font-bold">WiFi Sentinel</h1>
      </div>

      <p className="text-xs text-muted-foreground">
        Last scan: {timeAgo} &middot; {scan.wifi.ssid ?? "(hidden)"}
      </p>

      {/* Score hero */}
      <div className="flex items-center justify-between rounded-xl border border-border bg-card p-4">
        <div className="flex flex-col items-center">
          <ScoreGauge score={latest.securityScore} />
          <p className="mt-1 text-xs text-muted-foreground">Security</p>
        </div>
        <div className="flex flex-col items-center gap-1">
          <GradeBadge grade={latest.complianceGrade} />
          <p className="text-xs text-muted-foreground">Compliance</p>
          <p className="text-xs text-muted-foreground">{compliance.overallScore}%</p>
        </div>
        <div className="flex flex-col items-center gap-1">
          <RiskBadge risk={latest.consensusRisk} className="text-base px-3 py-0.5" />
          <p className="text-xs text-muted-foreground">Risk</p>
        </div>
        <div className="flex flex-col items-center gap-1">
          <span className="text-2xl font-bold">{latest.hostCount}</span>
          <p className="text-xs text-muted-foreground">Hosts</p>
        </div>
      </div>

      {/* Quick status cards */}
      <div className="grid grid-cols-2 gap-3">
        {/* WiFi */}
        <div className="rounded-xl border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 mb-2">
            <Wifi className="h-3.5 w-3.5 text-blue-400" />
            <span className="text-xs font-semibold">WiFi</span>
          </div>
          <div className="space-y-0.5 text-xs">
            <p>{scan.wifi.security}</p>
            <p className="text-muted-foreground">Ch {scan.wifi.channel} &middot; {scan.wifi.band}</p>
            <p className="text-muted-foreground">{scan.wifi.signal} dBm</p>
          </div>
        </div>

        {/* Network */}
        <div className="rounded-xl border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 mb-2">
            <Server className="h-3.5 w-3.5 text-purple-400" />
            <span className="text-xs font-semibold">Network</span>
          </div>
          <div className="space-y-0.5 text-xs">
            <p className="font-mono">{scan.network.ip}</p>
            <p className="text-muted-foreground font-mono">{scan.network.gateway.ip}</p>
            <p className="text-muted-foreground">{scan.network.hosts.length} devices</p>
          </div>
        </div>

        {/* Security */}
        <div className="rounded-xl border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 mb-2">
            <Lock className="h-3.5 w-3.5 text-teal-400" />
            <span className="text-xs font-semibold">Security</span>
          </div>
          <div className="space-y-0.5 text-xs">
            <p>Firewall: {scan.security.firewall.enabled ? "On" : "Off"}</p>
            <p>VPN: {scan.security.vpn.active ? "Active" : "Off"}</p>
            <p>IP Fwd: {scan.security.kernelParams.ipForwarding ? "On" : "Off"}</p>
          </div>
        </div>

        {/* Connections */}
        <div className="rounded-xl border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 mb-2">
            <Activity className="h-3.5 w-3.5 text-amber-400" />
            <span className="text-xs font-semibold">Connections</span>
          </div>
          <div className="space-y-0.5 text-xs">
            <p>{scan.connections.established} established</p>
            <p className="text-muted-foreground">{scan.connections.listening} listening</p>
            {scan.speed && <p className="text-muted-foreground">{scan.speed.download.speedMbps} Mbps</p>}
          </div>
        </div>
      </div>

      {/* Persona risks */}
      <div className="rounded-xl border border-border bg-card p-3">
        <p className="text-xs font-semibold mb-2">Risk by Persona</p>
        <div className="flex flex-wrap gap-2">
          {analysis.analyses.map((a) => (
            <div key={a.persona} className="flex items-center gap-1.5 rounded-full bg-muted px-2.5 py-1">
              <RiskBadge risk={a.riskRating} className="text-xs px-1.5 py-0" />
              <span className="text-xs text-muted-foreground">
                {personaNames[a.persona] ?? a.persona}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Priority actions */}
      {analysis.priorityActions.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 mb-2">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            <span className="text-xs font-semibold">Priority Actions</span>
          </div>
          <div className="space-y-1.5">
            {analysis.priorityActions.slice(0, 5).map((action, i) => (
              <p key={i} className="text-xs text-muted-foreground leading-relaxed">
                {i + 1}. {action}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* RF summary */}
      {rfSummary && (
        <div className="rounded-xl border border-border bg-card p-3">
          <p className="text-xs font-semibold mb-2">RF Summary</p>
          <div className="space-y-0.5 text-xs">
            <p>
              Channel {rfSummary.channelMap.currentChannel} &middot; Saturation:{" "}
              <span className={
                rfSummary.channelMap.currentSaturation <= 30 ? "text-teal-400" :
                rfSummary.channelMap.currentSaturation <= 60 ? "text-yellow-400" : "text-red-400"
              }>{rfSummary.channelMap.currentSaturation}%</span>
            </p>
            {rfSummary.channelMap.recommendedChannel !== rfSummary.channelMap.currentChannel && (
              <p className="text-yellow-400">Consider channel {rfSummary.channelMap.recommendedChannel}</p>
            )}
            <p>
              Rogue APs:{" "}
              <span className={rfSummary.rogueAPs.riskLevel === "clear" ? "text-teal-400" : "text-red-400"}>
                {rfSummary.rogueAPs.riskLevel}
              </span>
            </p>
          </div>
        </div>
      )}

      {/* Recent scans */}
      {entries.length > 1 && (
        <div className="rounded-xl border border-border bg-card p-3">
          <p className="text-xs font-semibold mb-2">Recent Scans</p>
          <div className="space-y-1">
            {entries.slice(1).map((e) => (
              <Link
                key={e.scanId}
                href={`/scans/${e.scanId}`}
                className="flex items-center justify-between rounded-lg px-2 py-1.5 text-xs hover:bg-accent active:bg-accent"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-muted-foreground">
                    {new Date(e.timestamp).toLocaleDateString("en-GB")}
                  </span>
                  <span>{e.ssid ?? "(hidden)"}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-mono">{e.securityScore.toFixed(1)}</span>
                  <ChevronRight className="h-3 w-3 text-muted-foreground" />
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Navigation links */}
      <div className="flex gap-3 pt-2">
        <Link href="/" className="text-xs text-primary underline underline-offset-4">
          Full Dashboard
        </Link>
        <Link href="/scans" className="text-xs text-primary underline underline-offset-4">
          All Scans
        </Link>
        <Link href="/trends" className="text-xs text-primary underline underline-offset-4">
          Trends
        </Link>
      </div>
    </div>
  );
}

function getTimeAgo(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
