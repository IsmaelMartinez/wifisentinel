import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { measureUpload, uploadCurlArgs } from "../../src/collector/scanners/speed.scanner.js";

describe("upload speed test", () => {
  it("uses one bounded stdin body", () => {
    const args = uploadCurlArgs("https://example.test/upload");
    assert.equal(args.filter((arg) => arg === "--data-binary" || arg === "-d").length, 1);
    assert.equal(args[args.indexOf("--data-binary") + 1], "@-");
    assert.ok(!args.some((arg) => arg.includes("/dev/urandom")));
  });

  it("sends exactly 1 MB to a local endpoint", async () => {
    let receivedBytes = 0;
    const server = createServer((request, response) => {
      request.on("data", (chunk: Buffer) => { receivedBytes += chunk.length; });
      request.on("end", () => { response.writeHead(200).end(); });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const url = `http://127.0.0.1:${address.port}/upload`;

    try {
      const result = await measureUpload(url);
      assert.equal(receivedBytes, 1_000_000);
      assert.equal(result.bytesTransferred, 1_000_000);
      assert.equal(result.testUrl, url);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
