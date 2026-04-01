"use client";

import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useRouter } from "next/navigation";
import { NetworkTopology } from "./network-topology";

type ScanEvent = {
  type: string;
  scanner?: string;
  summary?: string;
  ip?: string;
  mac?: string;
  vendor?: string;
  port?: number;
  service?: string;
  scanId?: string;
  hostCount?: number;
  exitCode?: number;
  error?: string;
  gateway?: string;
};

interface ScanOptions {
  skipPorts: boolean;
  skipSpeed: boolean;
  skipTraffic: boolean;
}

export function ScanRunner() {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [options, setOptions] = useState<ScanOptions>({
    skipPorts: false,
    skipSpeed: false,
    skipTraffic: true,
  });
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  const toggle = (key: keyof ScanOptions) =>
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));

  const startScan = useCallback(async () => {
    setRunning(true);
    setEvents([]);
    setError(null);

    try {
      const response = await fetch("/api/scans/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(options),
      });

      if (!response.ok || !response.body) {
        setError(`Scan failed: ${response.statusText}`);
        setRunning(false);
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          const dataMatch = line.match(/^data: (.+)$/m);
          if (dataMatch) {
            try {
              const event = JSON.parse(dataMatch[1]) as ScanEvent;
              setEvents((prev) => [...prev, event]);

              if (event.type === "stream:end") {
                setRunning(false);
                setTimeout(() => router.refresh(), 500);
              }
              if (event.type === "stream:error") {
                setError(event.error ?? "Unknown error");
                setRunning(false);
              }
            } catch {
              // Ignore malformed JSON
            }
          }
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Connection failed");
      setRunning(false);
    }
  }, [options, router]);

  const completedScanners = events
    .filter((e) => e.type === "scanner:complete")
    .map((e) => ({ scanner: e.scanner!, summary: e.summary! }));

  const activeScanners = events
    .filter((e) => e.type === "scanner:start")
    .map((e) => e.scanner!)
    .filter((s) => !completedScanners.some((c) => c.scanner === s));

  const hosts = events.filter((e) => e.type === "host:found");

  const enrichedHosts = hosts.map((h) => {
    const enrichment = events.find((e) => e.type === "host:enriched" && e.ip === h.ip);
    const hostPorts = events
      .filter((e) => e.type === "port:found" && e.ip === h.ip)
      .map((e) => ({ port: e.port!, service: e.service! }));
    return {
      ip: h.ip!,
      mac: h.mac!,
      vendor: enrichment?.vendor,
      isCamera: false,
      ports: hostPorts,
    };
  });

  const gatewayEvent = events.find((e) => e.type === "bootstrap:complete");

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Run Scan</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <button
              onClick={startScan}
              disabled={running}
              className="px-4 py-2 bg-teal-400 text-black rounded font-semibold text-sm disabled:opacity-50"
            >
              {running ? "Scanning..." : "Start Scan"}
            </button>
            <label className="text-sm text-muted-foreground flex items-center gap-1">
              <input type="checkbox" checked={!options.skipPorts} onChange={() => toggle("skipPorts")} disabled={running} />
              Ports
            </label>
            <label className="text-sm text-muted-foreground flex items-center gap-1">
              <input type="checkbox" checked={!options.skipSpeed} onChange={() => toggle("skipSpeed")} disabled={running} />
              Speed
            </label>
            <label className="text-sm text-muted-foreground flex items-center gap-1">
              <input type="checkbox" checked={!options.skipTraffic} onChange={() => toggle("skipTraffic")} disabled={running} />
              Traffic
            </label>
          </div>

          {error && <p className="text-sm text-red-400">{error}</p>}

          {events.length > 0 && (
            <div className="text-sm space-y-1 font-mono">
              {completedScanners.map((s) => (
                <div key={s.scanner} className="text-teal-400">
                  ✔ {s.scanner} — {s.summary}
                </div>
              ))}
              {activeScanners.map((s) => (
                <div key={s} className="text-blue-400 animate-pulse">
                  ◐ {s}...
                </div>
              ))}
              {hosts.length > 0 && (
                <div className="mt-2 text-muted-foreground">
                  {hosts.length} host{hosts.length !== 1 ? "s" : ""} discovered
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {gatewayEvent && enrichedHosts.length > 0 && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle className="text-base">Network Topology</CardTitle>
          </CardHeader>
          <CardContent>
            <NetworkTopology
              gateway={(gatewayEvent as any).gateway}
              hosts={enrichedHosts}
            />
          </CardContent>
        </Card>
      )}
    </>
  );
}
