"use client";

import { useState, useCallback, useMemo, useRef } from "react";
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
  indicators?: string[];
  sessionId?: string;
  cycle?: number;
  changes?: number;
};

interface ScanOptions {
  skipPorts: boolean;
  skipSpeed: boolean;
  skipTraffic: boolean;
  stealth: boolean;
  watch: boolean;
  interval: number;
}

export function ScanRunner() {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [options, setOptions] = useState<ScanOptions>({
    skipPorts: false,
    skipSpeed: false,
    skipTraffic: true,
    stealth: false,
    watch: false,
    interval: 5,
  });
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [cycleCount, setCycleCount] = useState(0);
  const sessionIdRef = useRef<string | null>(null);
  const readerRef = useRef<ReadableStreamDefaultReader | null>(null);

  const toggleBool = (key: "skipPorts" | "skipSpeed" | "skipTraffic" | "stealth" | "watch") =>
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));

  const stopScan = useCallback(async () => {
    // Cancel the reader to trigger the stream's cancel() handler
    if (readerRef.current) {
      readerRef.current.cancel();
      readerRef.current = null;
    }
    // Also send DELETE to kill the server-side process
    if (sessionIdRef.current) {
      await fetch("/api/scans/run", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: sessionIdRef.current }),
      }).catch(() => {});
      sessionIdRef.current = null;
    }
    setRunning(false);
    setTimeout(() => router.refresh(), 500);
  }, [router]);

  const startScan = useCallback(async () => {
    setRunning(true);
    setEvents([]);
    setError(null);
    setCycleCount(0);

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
      readerRef.current = reader;
      const decoder = new TextDecoder();
      let buffer = "";

      try {
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

                if (event.type === "session:start") {
                  sessionIdRef.current = event.sessionId ?? null;
                  continue;
                }

                // For watch mode, reset scanner events each cycle
                if (event.type === "watch:cycle-start") {
                  setCycleCount(event.cycle ?? 0);
                  setEvents((prev) => prev.filter(
                    (e) => e.type === "host:found" || e.type === "host:enriched" ||
                           e.type === "host:camera-detected" || e.type === "port:found" ||
                           e.type === "bootstrap:complete" || e.type === "watch:alert"
                  ));
                  continue;
                }

                setEvents((prev) => [...prev, event]);

                if (event.type === "stream:end") {
                  setRunning(false);
                  readerRef.current = null;
                  sessionIdRef.current = null;
                  setTimeout(() => router.refresh(), 500);
                }
                if (event.type === "stream:error") {
                  setError(event.error ?? "Unknown error");
                  setRunning(false);
                  readerRef.current = null;
                  sessionIdRef.current = null;
                }
              } catch {
                // Ignore malformed JSON
              }
            }
          }
        }
      } catch {
        // Reader cancelled (user clicked stop)
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
  const alerts = events.filter((e) => e.type === "watch:alert");

  const enrichedHosts = useMemo(() => hosts.map((h) => {
    const enrichment = events.find((e) => e.type === "host:enriched" && e.ip === h.ip);
    const cameraEvent = events.find((e) => e.type === "host:camera-detected" && e.ip === h.ip);
    const hostPorts = events
      .filter((e) => e.type === "port:found" && e.ip === h.ip)
      .map((e) => ({ port: e.port!, service: e.service! }));
    return {
      ip: h.ip!,
      mac: h.mac!,
      vendor: enrichment?.vendor,
      isCamera: !!cameraEvent,
      ports: hostPorts,
    };
  }), [hosts, events]);

  const gatewayEvent = useMemo(
    () => events.find((e) => e.type === "bootstrap:complete"),
    [events],
  );

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {options.watch ? "Watch Mode" : "Run Scan"}
            {running && options.watch && cycleCount > 0 && (
              <span className="ml-2 text-sm font-normal text-muted-foreground">
                Cycle #{cycleCount}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4 flex-wrap">
            {running ? (
              <button
                onClick={stopScan}
                className="px-4 py-2 bg-red-400 text-black rounded font-semibold text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                Stop
              </button>
            ) : (
              <button
                onClick={startScan}
                className="px-4 py-2 bg-teal-400 text-black rounded font-semibold text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {options.watch ? "Start Watch" : "Start Scan"}
              </button>
            )}

            <div className="h-5 border-l border-border" />

            <label className="text-sm text-muted-foreground flex items-center gap-1">
              <input type="checkbox" checked={options.watch} onChange={() => toggleBool("watch")} disabled={running} />
              Watch
            </label>
            <label className="text-sm text-muted-foreground flex items-center gap-1">
              <input type="checkbox" checked={options.stealth} onChange={() => toggleBool("stealth")} disabled={running} />
              Stealth
            </label>

            <div className="h-5 border-l border-border" />

            <label className="text-sm text-muted-foreground flex items-center gap-1">
              <input type="checkbox" checked={!options.skipPorts} onChange={() => toggleBool("skipPorts")} disabled={running} />
              Ports
            </label>
            <label className="text-sm text-muted-foreground flex items-center gap-1">
              <input type="checkbox" checked={!options.skipSpeed} onChange={() => toggleBool("skipSpeed")} disabled={running} />
              Speed
            </label>
            <label className="text-sm text-muted-foreground flex items-center gap-1">
              <input type="checkbox" checked={!options.skipTraffic} onChange={() => toggleBool("skipTraffic")} disabled={running} />
              Traffic
            </label>

            {options.watch && (
              <>
                <div className="h-5 border-l border-border" />
                <label className="text-sm text-muted-foreground flex items-center gap-1">
                  <input
                    type="number"
                    min={1}
                    max={60}
                    value={options.interval}
                    onChange={(e) => setOptions((prev) => ({ ...prev, interval: parseInt(e.target.value) || 5 }))}
                    disabled={running}
                    className="w-12 bg-transparent border border-zinc-600 rounded px-1 text-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  />
                  min
                </label>
              </>
            )}
          </div>

          {options.stealth && !running && (
            <p className="text-xs text-muted-foreground">
              Stealth: passive discovery, randomised port timing, random DNS domains, no speed/traffic
            </p>
          )}

          {error && <p className="text-sm text-red-400">{error}</p>}

          {events.length > 0 && (
            <div className="text-sm space-y-1 font-mono">
              {completedScanners.map((s) => (
                <div key={s.scanner} className="text-teal-400">
                  ✔ {s.scanner} — {s.summary}
                </div>
              ))}
              {activeScanners.map((s) => (
                <div key={s} className="text-blue-400 animate-pulse motion-reduce:animate-none">
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

          {alerts.length > 0 && (
            <div className="text-sm space-y-1 font-mono mt-2 border-t border-border pt-2">
              <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Alerts</div>
              {alerts.map((a, i) => (
                <div key={i} className="text-amber-400">
                  ▲ {JSON.stringify((a as any).change)}
                </div>
              ))}
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
