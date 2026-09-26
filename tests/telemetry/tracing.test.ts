import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { initTracing, shutdownTracing, withSpan } from "../../src/telemetry/tracing.js";
import { SERVICE_VERSION } from "../../src/telemetry/service.js";

const pkg = createRequire(import.meta.url)("../../package.json") as { version: string };

describe("initTracing('none')", () => {
  const calls: string[] = [];
  const originals = { fetch: globalThis.fetch, http: http.request, https: https.request };

  before(() => {
    globalThis.fetch = (async (input: unknown) => {
      calls.push(`fetch ${String(input)}`);
      throw new Error("network disabled in test");
    }) as typeof fetch;
    http.request = ((...args: unknown[]) => {
      calls.push(`http.request ${JSON.stringify(args[0])}`);
      throw new Error("network disabled in test");
    }) as typeof http.request;
    https.request = ((...args: unknown[]) => {
      calls.push(`https.request ${JSON.stringify(args[0])}`);
      throw new Error("network disabled in test");
    }) as typeof https.request;
    // The OTLP exporter reads `request` from the ESM namespace of node:http,
    // which only sees the patch once builtin ESM exports are re-synced.
    syncBuiltinESMExports();
  });

  after(() => {
    globalThis.fetch = originals.fetch;
    http.request = originals.http;
    https.request = originals.https;
    syncBuiltinESMExports();
  });

  it("makes no network request when spans are recorded and flushed", async () => {
    initTracing("none");
    const result = await withSpan("test-span", { "test.attr": 1 }, async () => 42);
    await shutdownTracing();
    assert.equal(result, 42);
    assert.deepEqual(calls, []);
  });
});

describe("SERVICE_VERSION", () => {
  it("matches package.json", () => {
    assert.equal(SERVICE_VERSION, pkg.version);
  });
});
