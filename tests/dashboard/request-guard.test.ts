import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkRequest, type GuardInput } from "../../dashboard/lib/request-guard.js";

const base: GuardInput = {
  method: "GET",
  pathname: "/api/scans/run",
  host: "127.0.0.1:3000",
  origin: null,
  contentType: null,
  port: "3000",
};

const post: GuardInput = {
  ...base,
  method: "POST",
  origin: "http://127.0.0.1:3000",
  contentType: "application/json",
};

describe("checkRequest host", () => {
  it("allows each localhost host on the configured port", () => {
    for (const host of ["localhost:3000", "127.0.0.1:3000", "[::1]:3000", "LOCALHOST:3000"]) {
      assert.deepEqual(checkRequest({ ...base, host }), { ok: true }, host);
    }
  });

  it("rejects non-localhost, wrong-port, look-alike and missing hosts", () => {
    for (const host of [
      "evil.example:3000",
      "localhost.evil.example:3000",
      "127.0.0.1.nip.io:3000",
      "192.168.1.10:3000",
      "localhost:3001",
      "localhost",
      null,
    ]) {
      assert.equal(checkRequest({ ...base, host }).ok, false, String(host));
    }
  });
});

describe("checkRequest origin", () => {
  it("allows a same-origin POST", () => {
    assert.deepEqual(checkRequest(post), { ok: true });
  });

  it("rejects non-GET requests with a mismatched, null or missing Origin", () => {
    for (const origin of ["http://evil.example", "null", "http://localhost:3000", "https://127.0.0.1:3000", null]) {
      assert.equal(checkRequest({ ...post, origin }).ok, false, String(origin));
      assert.equal(checkRequest({ ...post, method: "DELETE", origin }).ok, false, String(origin));
    }
  });

  it("does not require Origin on GET", () => {
    assert.deepEqual(checkRequest({ ...base, origin: "http://evil.example" }), { ok: true });
  });
});

describe("checkRequest content type", () => {
  it("accepts JSON with parameters", () => {
    assert.deepEqual(checkRequest({ ...post, contentType: "Application/JSON; charset=utf-8" }), { ok: true });
  });

  it("rejects non-JSON POSTs to /api/scans/run", () => {
    for (const contentType of ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", null]) {
      assert.equal(checkRequest({ ...post, contentType }).ok, false, String(contentType));
    }
  });

  it("does not constrain Content-Type on other paths", () => {
    assert.deepEqual(checkRequest({ ...post, pathname: "/", contentType: "text/plain" }), { ok: true });
  });
});
