import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { reconCensys } from "../../../src/collector/recon/censys.recon.js";

describe("reconCensys", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns parsed services, AS, and location from search results", async () => {
    const mockResponse = {
      code: 200,
      status: "OK",
      result: {
        hits: [
          {
            services: [
              { port: 80, transport_protocol: "TCP", service_name: "HTTP" },
              { port: 443, transport_protocol: "TCP", service_name: "HTTPS" },
            ],
            matched_services: [{ certificate: "sha256:abc123" }],
            autonomous_system: { name: "AMAZON-02" },
            location: { country: "US", city: "Seattle" },
          },
        ],
      },
    };

    globalThis.fetch = async () => {
      return new Response(JSON.stringify(mockResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const result = await reconCensys("example.com", "test-id", "test-secret");

    assert.equal(result.services.length, 2);
    assert.equal(result.services[0].port, 80);
    assert.equal(result.services[0].serviceName, "HTTP");
    assert.equal(result.services[1].port, 443);
    assert.equal(result.services[1].serviceName, "HTTPS");
    assert.deepEqual(result.certificates, ["sha256:abc123"]);
    assert.equal(result.autonomousSystem, "AMAZON-02");
    assert.equal(result.location, "Seattle, US");
  });

  it("returns empty result when no hits found", async () => {
    const mockResponse = {
      code: 200,
      status: "OK",
      result: { hits: [] },
    };

    globalThis.fetch = async () => {
      return new Response(JSON.stringify(mockResponse), { status: 200 });
    };

    const result = await reconCensys("notfound.example", "test-id", "test-secret");

    assert.deepEqual(result.services, []);
    assert.deepEqual(result.certificates, []);
    assert.equal(result.autonomousSystem, null);
    assert.equal(result.location, null);
  });

  it("throws when API returns non-OK status", async () => {
    globalThis.fetch = async () => {
      return new Response(JSON.stringify({ code: 401, status: "Unauthorized" }), { status: 401 });
    };

    await assert.rejects(
      () => reconCensys("example.com", "bad-id", "bad-secret"),
      /Censys search failed: 401/,
    );
  });

  it("uses Basic auth header with base64-encoded credentials", async () => {
    let capturedHeaders: Headers | undefined;
    globalThis.fetch = async (_url: string | URL | Request, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers as Record<string, string>);
      return new Response(JSON.stringify({ result: { hits: [] } }), { status: 200 });
    };

    await reconCensys("example.com", "myid", "mysecret");

    assert.ok(capturedHeaders, "Headers should be captured");
    const auth = capturedHeaders!.get("Authorization");
    assert.ok(auth, "Authorization header should be present");
    assert.ok(auth!.startsWith("Basic "), "Should use Basic auth");

    const decoded = Buffer.from(auth!.replace("Basic ", ""), "base64").toString("utf-8");
    assert.equal(decoded, "myid:mysecret");
  });

  it("deduplicates certificates across multiple hits", async () => {
    const mockResponse = {
      result: {
        hits: [
          {
            services: [],
            matched_services: [{ certificate: "sha256:abc" }, { certificate: "sha256:def" }],
            autonomous_system: { name: "AS1" },
            location: { country: "DE" },
          },
          {
            services: [],
            matched_services: [{ certificate: "sha256:abc" }, { certificate: "sha256:ghi" }],
          },
        ],
      },
    };

    globalThis.fetch = async () => {
      return new Response(JSON.stringify(mockResponse), { status: 200 });
    };

    const result = await reconCensys("example.com", "id", "secret");

    // sha256:abc should appear only once
    assert.equal(result.certificates.filter((c) => c === "sha256:abc").length, 1);
    assert.equal(result.certificates.length, 3);
  });

  it("handles missing optional fields gracefully", async () => {
    const mockResponse = {
      result: {
        hits: [
          {
            services: [{ port: 22 }],
          },
        ],
      },
    };

    globalThis.fetch = async () => {
      return new Response(JSON.stringify(mockResponse), { status: 200 });
    };

    const result = await reconCensys("example.com", "id", "secret");

    assert.equal(result.services[0].port, 22);
    assert.equal(result.services[0].transportProtocol, "tcp");
    assert.equal(result.services[0].serviceName, "");
    assert.equal(result.autonomousSystem, null);
    assert.equal(result.location, null);
  });
});
