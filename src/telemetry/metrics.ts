import { MeterProvider, ConsoleMetricExporter, PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";
import { metrics, type Counter, type Histogram } from "@opentelemetry/api";

const SERVICE_NAME = "wifisentinel";
const SERVICE_VERSION = "0.1.0";

let meterProvider: MeterProvider | null = null;

let scanFindingsCounter: Counter;
let scanDurationHistogram: Histogram;
let toolResolutionCounter: Counter;

export function initMetrics(exportType: "console" | "none"): void {
  const resource = resourceFromAttributes({
    [ATTR_SERVICE_NAME]: SERVICE_NAME,
    [ATTR_SERVICE_VERSION]: SERVICE_VERSION,
  });

  const providerOptions: ConstructorParameters<typeof MeterProvider>[0] = { resource };

  if (exportType === "console") {
    providerOptions.readers = [
      new PeriodicExportingMetricReader({
        exporter: new ConsoleMetricExporter(),
        exportIntervalMillis: 60_000,
      }),
    ];
  }

  meterProvider = new MeterProvider(providerOptions);
  metrics.setGlobalMeterProvider(meterProvider);

  const meter = metrics.getMeter(SERVICE_NAME, SERVICE_VERSION);

  scanFindingsCounter = meter.createCounter("scan.findings", {
    description: "Number of findings detected, by severity and category",
  });

  scanDurationHistogram = meter.createHistogram("scan.duration_ms", {
    description: "Scan duration in milliseconds, by scanner name",
    unit: "ms",
  });

  toolResolutionCounter = meter.createCounter("tool.resolutions", {
    description: "Number of tool resolutions, by capability and tier",
  });
}

export function recordFinding(severity: string, category: string, persona: string): void {
  scanFindingsCounter?.add(1, { severity, category, persona });
}

export function recordScanDuration(scannerName: string, durationMs: number): void {
  scanDurationHistogram?.record(durationMs, { scanner: scannerName });
}

export function recordToolResolution(capability: string, tier: string): void {
  toolResolutionCounter?.add(1, { capability, tier });
}

export async function shutdownMetrics(): Promise<void> {
  if (meterProvider) {
    await meterProvider.shutdown();
    meterProvider = null;
  }
}
