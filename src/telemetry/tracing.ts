import { NodeSDK } from "@opentelemetry/sdk-node";
import { ConsoleSpanExporter } from "@opentelemetry/sdk-trace-base";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";
import {
  trace,
  SpanStatusCode,
  type Tracer,
  type SpanOptions,
} from "@opentelemetry/api";

import { SERVICE_NAME, SERVICE_VERSION } from "./service.js";

let sdk: NodeSDK | null = null;

export function initTracing(exportType: "console" | "otlp" | "none"): void {
  // "none": start no SDK at all. The API's no-op tracer is used, so nothing is exported
  // (an SDK without an exporter would fall back to its OTLP env default).
  if (exportType === "none") return;

  const resource = resourceFromAttributes({
    [ATTR_SERVICE_NAME]: SERVICE_NAME,
    [ATTR_SERVICE_VERSION]: SERVICE_VERSION,
  });

  sdk = new NodeSDK({
    resource,
    traceExporter: exportType === "console" ? new ConsoleSpanExporter() : new OTLPTraceExporter(),
  });
  sdk.start();
}

export function getTracer(): Tracer {
  return trace.getTracer(SERVICE_NAME, SERVICE_VERSION);
}

export async function shutdownTracing(): Promise<void> {
  if (sdk) {
    try {
      await sdk.shutdown();
    } catch {
      // Ignore OTLP connection errors on shutdown (no collector running)
    }
    sdk = null;
  }
}

export async function withSpan<T>(
  name: string,
  attributes: Record<string, string | number | boolean>,
  fn: () => Promise<T>
): Promise<T> {
  const tracer = getTracer();
  const spanOptions: SpanOptions = { attributes };

  return tracer.startActiveSpan(name, spanOptions, async (span) => {
    const startMs = Date.now();
    try {
      const result = await fn();
      span.setAttribute("duration_ms", Date.now() - startMs);
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (err) {
      span.setAttribute("duration_ms", Date.now() - startMs);
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: err instanceof Error ? err.message : String(err),
      });
      if (err instanceof Error) {
        span.recordException(err);
      }
      throw err;
    } finally {
      span.end();
    }
  });
}
