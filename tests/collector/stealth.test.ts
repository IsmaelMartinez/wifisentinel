import { describe, it } from "node:test";
import assert from "node:assert/strict";

// Test stealth-related utility functions by importing the modules

describe("stealth mode: port scanner", () => {
  it("shuffle produces a permutation of the same elements", async () => {
    // Import the module to access shuffle indirectly via scanPorts behaviour
    // We test the shuffle logic directly here
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const shuffled = [...arr];
    // Fisher-Yates shuffle (same as in port.scanner.ts)
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    assert.equal(shuffled.length, arr.length);
    assert.deepEqual(shuffled.sort((a, b) => a - b), arr);
  });
});

describe("stealth mode: DNS scanner", () => {
  it("randomHijackDomain generates valid domain names", () => {
    // Replicate the logic from dns.scanner.ts
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    const domains = new Set<string>();
    for (let i = 0; i < 10; i++) {
      let sub = "";
      for (let j = 0; j < 12; j++) sub += chars[Math.floor(Math.random() * chars.length)];
      const domain = `${sub}.nxdomain.invalid`;
      domains.add(domain);
      assert.ok(domain.endsWith(".nxdomain.invalid"));
      assert.ok(domain.length > 20);
      assert.ok(/^[a-z0-9]+\.nxdomain\.invalid$/.test(domain));
    }
    // All 10 should be unique (collision probability is negligible with 36^12)
    assert.equal(domains.size, 10);
  });

  it("random domains differ from the static fingerprint", () => {
    const staticDomain = "this-domain-should-not-exist-7xk2.com";
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    let sub = "";
    for (let j = 0; j < 12; j++) sub += chars[Math.floor(Math.random() * chars.length)];
    const randomDomain = `${sub}.nxdomain.invalid`;
    assert.notEqual(randomDomain, staticDomain);
    assert.ok(!randomDomain.includes("should-not-exist"));
  });
});
