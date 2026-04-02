import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { shuffle } from "../../src/collector/scanners/port.scanner.js";
import { randomHijackDomain } from "../../src/collector/scanners/dns.scanner.js";

describe("stealth mode: shuffle", () => {
  it("produces a permutation of the same elements", () => {
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const shuffled = shuffle(arr);
    assert.equal(shuffled.length, arr.length);
    assert.deepEqual([...shuffled].sort((a, b) => a - b), arr);
  });

  it("does not mutate the original array", () => {
    const arr = [1, 2, 3];
    const original = [...arr];
    shuffle(arr);
    assert.deepEqual(arr, original);
  });
});

describe("stealth mode: randomHijackDomain", () => {
  it("generates valid domain names under .nxdomain.invalid", () => {
    const domain = randomHijackDomain();
    assert.ok(domain.endsWith(".nxdomain.invalid"));
    assert.ok(/^[a-z0-9]{12}\.nxdomain\.invalid$/.test(domain));
  });

  it("generates unique domains on each call", () => {
    const domains = new Set<string>();
    for (let i = 0; i < 10; i++) {
      domains.add(randomHijackDomain());
    }
    assert.equal(domains.size, 10);
  });

  it("differs from the static fingerprint domain", () => {
    const domain = randomHijackDomain();
    assert.notEqual(domain, "this-domain-should-not-exist-7xk2.com");
    assert.ok(!domain.includes("should-not-exist"));
  });
});
