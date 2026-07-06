// dashboard/app/trends/page.tsx
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TrendChart } from "@/components/trend-chart";
import { EmptyState } from "@/components/empty-state";
import { getScans, getScan } from "@/lib/store";
import { isPartialSource, splitBySource } from "@wifisentinel/store/source.js";

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
  const loaded = chronological.flatMap((e) => {
    try {
      return [{ entry: e, stored: getScan(e.scanId) }];
    } catch {
      return [];
    }
  });

  // A partial import (Android companion) observes the network through a
  // weaker radio and caps nearby APs at 25, so blending sources makes every
  // series oscillate with the source rather than the network. Never blend:
  // plot the full CLI scans when there are enough to chart, otherwise the
  // partial imports on their own (an all-phone history is self-consistent).
  const { full, partial } = splitBySource(loaded, (p) => p.stored.scan.meta);
  const plotted = full.length >= 2 ? full : partial;
  const excluded = loaded.length - plotted.length;
  const showingPartial =
    plotted.length > 0 && isPartialSource(plotted[0].stored.scan.meta);
  const sourceNote =
    excluded > 0
      ? `${excluded} scan${excluded === 1 ? "" : "s"} from a different source excluded to keep the series comparable.`
      : showingPartial
        ? "Series are partial Android imports — points reflect the phone's limited view (weaker radio, nearby APs capped at 25)."
        : null;

  const securityData = plotted.map(({ entry }) => ({
    date: entry.timestamp,
    value: entry.securityScore,
  }));

  const complianceData = plotted.map(({ stored }) => ({
    date: stored.scan.meta.timestamp,
    value: stored.compliance.overallScore,
  }));

  const hostData = plotted.map(({ entry }) => ({
    date: entry.timestamp,
    value: entry.hostCount,
  }));

  const signalData = plotted.map(({ stored }) => ({
    date: stored.scan.meta.timestamp,
    value: stored.scan.wifi.signal,
  }));

  const snrData = plotted.map(({ stored }) => ({
    date: stored.scan.meta.timestamp,
    value: stored.scan.wifi.snr,
  }));

  const nearbyData = plotted.map(({ stored }) => ({
    date: stored.scan.meta.timestamp,
    value: stored.scan.wifi.nearbyNetworks.length,
  }));

  if (plotted.length < 2) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Trends</h1>
        <EmptyState />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Trends</h1>

      {sourceNote && (
        <p className="text-sm text-zinc-400">{sourceNote}</p>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 sm:gap-4">
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
