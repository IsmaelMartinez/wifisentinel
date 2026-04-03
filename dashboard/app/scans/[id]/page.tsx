import { notFound } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScoreGauge } from "@/components/score-gauge";
import { RiskBadge } from "@/components/risk-badge";
import { GradeBadge } from "@/components/grade-badge";
import { PersonaCard } from "@/components/persona-card";
import { ComplianceCard } from "@/components/compliance-card";
import { ChannelChart } from "@/components/channel-chart";
import { getScan } from "@/lib/store";
import { computeSecurityScore } from "@wifisentinel/analyser/score.js";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  let stored;
  try {
    stored = getScan(id);
  } catch {
    notFound();
  }

  const { scan, compliance, analysis, rfAnalysis } = stored;
  const score = computeSecurityScore(scan);

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">
            Scan Report
          </h1>
          <a
            href={`/api/scans/${scan.meta.scanId}/export`}
            download
            className="text-sm text-primary underline underline-offset-4"
          >
            Export HTML
          </a>
        </div>
        <p className="text-sm text-muted-foreground">
          {scan.wifi.ssid ?? "(hidden)"} &middot; {new Date(scan.meta.timestamp).toLocaleString()} &middot;
          ID: <span className="font-mono">{scan.meta.scanId.slice(0, 8)}</span>
        </p>
      </div>

      <Tabs defaultValue="summary">
        <TabsList>
          <TabsTrigger value="summary">Summary</TabsTrigger>
          <TabsTrigger value="personas">Personas</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="rf">RF</TabsTrigger>
        </TabsList>

        {/* Summary Tab */}
        <TabsContent value="summary" className="space-y-4 mt-4">
          <div className="grid grid-cols-3 gap-4">
            <Card>
              <CardContent className="flex flex-col items-center pt-6">
                <ScoreGauge score={score} />
                <p className="mt-2 text-sm text-muted-foreground">Security Score</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">Network</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-1">
                <p>IP: <span className="font-mono">{scan.network.ip}</span></p>
                <p>Subnet: <span className="font-mono">{scan.network.subnet}</span></p>
                <p>Gateway: <span className="font-mono">{scan.network.gateway.ip}</span></p>
                {scan.network.gateway.vendor && <p className="text-muted-foreground">{scan.network.gateway.vendor}</p>}
                <p>Hosts: {scan.network.hosts.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">WiFi</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-1">
                <p>Protocol: {scan.wifi.protocol}</p>
                <p>Channel: {scan.wifi.channel} ({scan.wifi.band}, {scan.wifi.width})</p>
                <p>Security: {scan.wifi.security}</p>
                <p>Signal: {scan.wifi.signal} dBm / SNR: {scan.wifi.snr} dB</p>
                <p>TX Rate: {scan.wifi.txRate} Mbps</p>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-base">Security Posture</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-1">
                <p>Firewall: {scan.security.firewall.enabled ? "\u2714 Enabled" : "\u2718 Disabled"}
                  {scan.security.firewall.stealthMode ? " (stealth)" : ""}</p>
                <p>VPN: {scan.security.vpn.active ? "\u2714 Active" : "\u2718 Inactive"}
                  {scan.security.vpn.provider ? ` (${scan.security.vpn.provider})` : ""}</p>
                <p>Client Isolation: {scan.security.clientIsolation === true ? "\u2714" : scan.security.clientIsolation === false ? "\u2718" : "Unknown"}</p>
                <p>IP Forwarding: {scan.security.kernelParams.ipForwarding ? "\u2718 Enabled" : "\u2714 Disabled"}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">Connections</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-1">
                <p>Established: {scan.connections.established}</p>
                <p>Listening: {scan.connections.listening}</p>
                <p>TIME_WAIT: {scan.connections.timeWait}</p>
                {scan.speed && (
                  <>
                    <p className="mt-2">Download: {scan.speed.download.speedMbps} Mbps</p>
                    <p>Latency: {scan.speed.latency.internetMs} ms</p>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Personas Tab */}
        <TabsContent value="personas" className="space-y-4 mt-4">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm text-muted-foreground">Consensus:</span>
            <RiskBadge risk={analysis.consensusRating} />
          </div>
          {analysis.analyses.map((a) => (
            <PersonaCard key={a.persona} analysis={a} />
          ))}
        </TabsContent>

        {/* Compliance Tab */}
        <TabsContent value="compliance" className="space-y-4 mt-4">
          <div className="flex items-center gap-4 mb-2">
            <GradeBadge grade={compliance.overallGrade} />
            <div>
              <p className="font-semibold">Overall: {compliance.overallScore}%</p>
            </div>
          </div>
          {compliance.standards.map((s) => (
            <ComplianceCard key={s.standard} standard={s} />
          ))}
        </TabsContent>

        {/* RF Tab */}
        <TabsContent value="rf" className="space-y-4 mt-4">
          {rfAnalysis ? (
            <>
              <Card>
                <CardHeader><CardTitle className="text-base">Channel Saturation</CardTitle></CardHeader>
                <CardContent>
                  <ChannelChart
                    channels={rfAnalysis.channelMap.channels}
                    currentChannel={rfAnalysis.channelMap.currentChannel}
                  />
                  <p className="mt-2 text-sm text-muted-foreground">
                    {rfAnalysis.channelMap.recommendationReason}
                  </p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle className="text-base">Rogue AP Detection</CardTitle></CardHeader>
                <CardContent>
                  {rfAnalysis.rogueAPs.findings.length === 0 ? (
                    <p className="text-teal-400">No rogue APs detected.</p>
                  ) : (
                    <div className="space-y-2">
                      {rfAnalysis.rogueAPs.findings.map((f, i) => (
                        <div key={i} className="text-sm">
                          <span className={f.severity === "high" ? "text-red-400" : "text-amber-400"}>
                            [{f.severity.toUpperCase()}]
                          </span>{" "}
                          {f.description}
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          ) : (
            <p className="text-muted-foreground">No RF analysis data for this scan.</p>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
