import { describe, it, mock, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { reconShodan } from "../../../src/collector/recon/shodan.recon.js";

describe("reconShodan", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    mock.restoreAll();
  });

  it("resolves domain to IP and returns host details", async () => {
    const mockResolveResponse = { "example.com": "93.184.216.34" };
    const mockHostResponse = {
      ip_str: "93.184.216.34",
      ports: [80, 443],
      data: [
        { port: 80, transport: "tcp", product: "Apache", version: "2.4" },
        { port: 443, transport: "tcp", product: "nginx", version: "1.18" },
      ],
      vulns: { "CVE-2021-44228": { verified: false } },
      last_update: "2024-01-15T10:00:00.000Z",
      isp: "Edgecast Inc.",
      os: null,
    };

    let callCount = 0;
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      callCount++;
      if (urlStr.includes("/dns/resolve")) {
        return new Response(JSON.stringify(mockResolveResponse), { status: 200 });
      }
      if (urlStr.includes("/shodan/host/")) {
        return new Response(JSON.stringify(mockHostResponse), { status: 200 });
      }
      throw new Error(`Unexpected URL: ${urlStr}`);
    };

    const result = await reconShodan("example.com", "test-api-key");

    assert.equal(callCount, 2);
    assert.equal(result.ip, "93.184.216.34");
    assert.deepEqual(result.openPorts, [80, 443]);
    assert.equal(result.services.length, 2);
    assert.equal(result.services[0].product, "Apache");
    assert.equal(result.services[1].product, "nginx");
    assert.deepEqual(result.vulns, ["CVE-2021-44228"]);
    assert.equal(result.lastScanDate, "2024-01-15T10:00:00.000Z");
    assert.equal(result.isp, "Edgecast Inc.");
    assert.equal(result.os, null);
  });

  it("returns empty result when domain cannot be resolved", async () => {
    globalThis.fetch = async () => {
      return new Response(JSON.stringify({}), { status: 200 });
    };

    const result = await reconShodan("notfound.example", "test-key");

    assert.equal(result.ip, "");
    assert.deepEqual(result.openPorts, []);
    assert.deepEqual(result.services, []);
    assert.deepEqual(result.vulns, []);
  });

  it("returns empty result when host lookup returns 404", async () => {
    const mockResolveResponse = { "unknown.example": "1.2.3.4" };

    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes("/dns/resolve")) {
        return new Response(JSON.stringify(mockResolveResponse), { status: 200 });
      }
      return new Response(JSON.stringify({ error: "No information available" }), { status: 404 });
    };

    const result = await reconShodan("unknown.example", "test-key");

    assert.equal(result.ip, "1.2.3.4");
    assert.deepEqual(result.openPorts, []);
    assert.deepEqual(result.vulns, []);
  });

  it("throws when DNS resolve request fails", async () => {
    globalThis.fetch = async () => {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    };

    await assert.rejects(
      () => reconShodan("example.com", "bad-key"),
      /Shodan DNS resolve failed: 401/,
    );
  });

  it("handles host with no vulns field", async () => {
    const mockResolveResponse = { "example.com": "1.1.1.1" };
    const mockHostResponse = {
      ip_str: "1.1.1.1",
      ports: [53],
      data: [],
      last_update: null,
      isp: "Cloudflare",
      os: "Linux",
    };

    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes("/dns/resolve")) {
        return new Response(JSON.stringify(mockResolveResponse), { status: 200 });
      }
      return new Response(JSON.stringify(mockHostResponse), { status: 200 });
    };

    const result = await reconShodan("example.com", "test-key");

    assert.deepEqual(result.vulns, []);
    assert.equal(result.os, "Linux");
    assert.equal(result.isp, "Cloudflare");
  });
});
