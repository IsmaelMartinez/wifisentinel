// dashboard/app/trends/page.tsx
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TrendChart } from "@/components/trend-chart";
import { EmptyState } from "@/components/empty-state";
import { getScans, getScan } from "@/lib/store";

export const revalidate = 60;

export default function TrendsPage() {
  const entries = getScans({ limit: 20 });

  if (entries.length < 2) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Trends</h1>
        <EmptyState />
      </div>
    );
  }

  // Load full scans for detailed metrics (newest first, reverse for chronological)
  const chronological = [...entries].reverse();
  const scans = chronological.map((e) => {
    try {
      return getScan(e.scanId);
    } catch {
      return null;
    }
  }).filter(Boolean) as Exclude<ReturnType<typeof getScan>, null>[];

  const securityData = chronological.map((e) => ({
    date: e.timestamp,
    value: e.securityScore,
  }));

  const complianceData = scans.map((s) => ({
    date: s.scan.meta.timestamp,
    value: s.compliance.overallScore,
  }));

  const hostData = chronological.map((e) => ({
    date: e.timestamp,
    value: e.hostCount,
  }));

  const signalData = scans.map((s) => ({
    date: s.scan.meta.timestamp,
    value: s.scan.wifi.signal,
  }));

  const snrData = scans.map((s) => ({
    date: s.scan.meta.timestamp,
    value: s.scan.wifi.snr,
  }));

  const nearbyData = scans.map((s) => ({
    date: s.scan.meta.timestamp,
    value: s.scan.wifi.nearbyNetworks.length,
  }));

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Trends</h1>

      <div className="grid grid-cols-2 gap-4">
        <Card>
          <CardHeader><CardTitle className="text-base">Security Score</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={securityData} color="#22c55e" yDomain={[0, 10]} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Compliance Score</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={complianceData} color="#3b82f6" yDomain={[0, 100]} unit="%" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Host Count</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={hostData} color="#a855f7" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">WiFi Signal</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={signalData} color="#eab308" unit=" dBm" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Signal-to-Noise Ratio</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={snrData} color="#06b6d4" unit=" dB" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Nearby Networks</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={nearbyData} color="#f97316" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
