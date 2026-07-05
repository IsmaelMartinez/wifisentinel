import type { LatencyMethod } from "./scan-result.js";

/**
 * Single owner of the latency-method semantics introduced alongside
 * `speed.latency.method`. Every consumer (terminal/HTML reporters, the
 * dashboard, the net-engineer persona) derives its behaviour from these
 * helpers so the "absent method means icmp-ping" backfill rule and the
 * per-method healthy bands can never drift apart between surfaces.
 */

/**
 * Whether the figures carry ICMP ping semantics. Absent means "icmp-ping" —
 * every record predating the field came from the CLI's ping path. Any
 * future non-ping method is treated as non-ping by construction.
 */
export function isPingLatency(method?: LatencyMethod): boolean {
  return (method ?? "icmp-ping") === "icmp-ping";
}

/**
 * Green/amber thresholds (ms) for a latency figure, keyed by how it was
 * measured. An HTTPS HEAD round-trip carries TCP+TLS handshakes on top of
 * the network path, so a healthy figure sits around 100–400 ms where an
 * ICMP ping would read ~15 ms.
 */
export function latencyBands(method?: LatencyMethod): { goodMs: number; warnMs: number } {
  return isPingLatency(method)
    ? { goodMs: 20, warnMs: 50 }
    : { goodMs: 400, warnMs: 1000 };
}

/** Human label for a non-ping latency method; undefined when no annotation is needed. */
export function latencyMethodLabel(method?: LatencyMethod): string | undefined {
  return method === "https-rtt" ? "HTTPS round-trip" : undefined;
}

/**
 * Full parenthetical (leading space included) for plain-text surfaces —
 * the HTML report and the dashboard append it verbatim after the figure.
 * Empty string for ping so callers can interpolate unconditionally.
 */
export function latencyMethodNote(method?: LatencyMethod): string {
  const label = latencyMethodLabel(method);
  if (!label) return "";
  const { goodMs } = latencyBands(method);
  return ` (${label} — healthy is ~100–${goodMs} ms)`;
}
