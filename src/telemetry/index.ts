export * from "./tracing.js";
export * from "./metrics.js";

import { initTracing, shutdownTracing } from "./tracing.js";
import { initMetrics, shutdownMetrics } from "./metrics.js";

export interface TelemetryOptions {
  tracing: "console" | "otlp" | "none";
  metrics: "console" | "none";
}

export function initTelemetry(options: TelemetryOptions): void {
  initTracing(options.tracing);
  initMetrics(options.metrics);
}

export async function shutdownTelemetry(): Promise<void> {
  await Promise.all([shutdownTracing(), shutdownMetrics()]);
}
