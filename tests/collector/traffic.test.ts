import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseTsharkOutput,
  parseTcpdumpOutput,
} from "../../src/collector/scanners/traffic.scanner.js";

describe("parseTsharkOutput", () => {
  it("returns zero counts for empty output", () => {
    const result = parseTsharkOutput("");
    assert.equal(result.capturedPackets, 0);
    assert.deepEqual(result.protocols, {});
    assert.deepEqual(result.unencrypted, []);
    assert.deepEqual(result.dnsQueries, []);
    assert.deepEqual(result.mdnsLeaks, []);
  });

  it("counts packets and bucketises protocols by the deepest application layer", () => {
    const output = [
      // frame.protocols | ip.dst | tcp.dstport | udp.dstport | dns.qry.name | dns.flags.authenticated | mdns.qry.name
      "eth:ethertype:ip:tcp:http|93.184.216.34|80||||",
      "eth:ethertype:ip:tcp:tls|142.250.0.1|443||||",
      "eth:ethertype:ip:udp:dns|192.168.1.1||53|example.com|0|",
    ].join("\n");
    const result = parseTsharkOutput(output);
    assert.equal(result.capturedPackets, 3);
    assert.equal(result.protocols.http, 1);
    assert.equal(result.protocols.tls, 1);
    assert.equal(result.protocols.dns, 1);
  });

  it("flags unencrypted flows by well-known plaintext destination ports", () => {
    const output = [
      "eth:ip:tcp:http|10.0.0.5|80||||",
      "eth:ip:tcp:telnet|10.0.0.6|23||||",
      "eth:ip:tcp:ftp|10.0.0.7|21||||",
      "eth:ip:tcp:tls|10.0.0.8|443||||", // encrypted — should be ignored
    ].join("\n");
    const result = parseTsharkOutput(output);
    assert.equal(result.unencrypted.length, 3);
    const protocols = result.unencrypted.map((u) => u.protocol).sort();
    assert.deepEqual(protocols, ["ftp", "http", "telnet"]);
  });

  it("deduplicates unencrypted flows that share a dest/port", () => {
    const output = [
      "eth:ip:tcp:http|10.0.0.5|80||||",
      "eth:ip:tcp:http|10.0.0.5|80||||",
      "eth:ip:tcp:http|10.0.0.5|80||||",
    ].join("\n");
    const result = parseTsharkOutput(output);
    assert.equal(result.capturedPackets, 3);
    assert.equal(result.unencrypted.length, 1);
    assert.equal(result.unencrypted[0].dest, "10.0.0.5");
  });

  it("extracts DNS queries with DNSSEC authenticated flag", () => {
    const output = [
      "eth:ip:udp:dns|1.1.1.1||53|cloudflare.com|1|",
      "eth:ip:udp:dns|192.168.1.1||53|example.com|0|",
    ].join("\n");
    const result = parseTsharkOutput(output);
    assert.equal(result.dnsQueries.length, 2);
    const authed = result.dnsQueries.find((q) => q.domain === "cloudflare.com");
    const plain = result.dnsQueries.find((q) => q.domain === "example.com");
    assert.equal(authed?.dnssec, true);
    assert.equal(plain?.dnssec, false);
  });

  it("extracts mDNS leaks with service and host separation", () => {
    const output = [
      "eth:ip:udp:mdns|224.0.0.251||5353|||MacBook._ssh._tcp.local",
      "eth:ip:udp:mdns|224.0.0.251||5353|||_airplay._tcp.local",
    ].join("\n");
    const result = parseTsharkOutput(output);
    assert.equal(result.mdnsLeaks.length, 2);
    const ssh = result.mdnsLeaks.find((m) => m.service === "_ssh._tcp");
    assert.equal(ssh?.host, "MacBook");
    const airplay = result.mdnsLeaks.find((m) => m.service === "_airplay._tcp");
    assert.ok(airplay);
  });

  it("ignores ports outside the plaintext list", () => {
    const output = [
      "eth:ip:tcp:tls|10.0.0.5|443||||",
      "eth:ip:tcp:ssh|10.0.0.5|22||||",
    ].join("\n");
    const result = parseTsharkOutput(output);
    assert.equal(result.unencrypted.length, 0);
  });
});

describe("parseTcpdumpOutput", () => {
  it("returns zero counts for empty output", () => {
    const result = parseTcpdumpOutput("");
    assert.equal(result.capturedPackets, 0);
    assert.deepEqual(result.protocols, {});
    assert.deepEqual(result.unencrypted, []);
    assert.deepEqual(result.mdnsLeaks, []);
  });

  it("counts packets and protocols from -q format lines", () => {
    const output = [
      "2024-01-01 12:00:00.000000 IP 10.0.0.2.54321 > 10.0.0.1.80: tcp 512",
      "2024-01-01 12:00:00.100000 IP 10.0.0.2.54322 > 10.0.0.1.443: tcp 512",
      "2024-01-01 12:00:00.200000 IP 10.0.0.2.54323 > 10.0.0.3.53: UDP, length 64",
    ].join("\n");
    const result = parseTcpdumpOutput(output);
    assert.equal(result.capturedPackets, 3);
    assert.equal(result.protocols.tcp, 2);
    assert.ok(result.protocols.udp >= 1);
  });

  it("flags plaintext destination ports in tcpdump output", () => {
    const output = [
      "2024-01-01 12:00:00.000000 IP 10.0.0.2.12345 > 93.184.216.34.80: tcp 100",
      "2024-01-01 12:00:00.100000 IP 10.0.0.2.12346 > 93.184.216.34.23: tcp 100",
      "2024-01-01 12:00:00.200000 IP 10.0.0.2.12347 > 93.184.216.34.443: tcp 100",
    ].join("\n");
    const result = parseTcpdumpOutput(output);
    assert.equal(result.unencrypted.length, 2);
    const protocols = result.unencrypted.map((u) => u.protocol).sort();
    assert.deepEqual(protocols, ["http", "telnet"]);
  });

  it("captures mDNS traffic on port 5353", () => {
    const output = [
      "2024-01-01 12:00:00.000000 IP 10.0.0.2.5353 > 224.0.0.251.5353: UDP, length 80",
    ].join("\n");
    const result = parseTcpdumpOutput(output);
    assert.equal(result.mdnsLeaks.length, 1);
    assert.equal(result.mdnsLeaks[0].service, "mdns");
  });

  it("skips malformed lines without interfering with counts", () => {
    const output = [
      "tcpdump: verbose output suppressed, use -v for full protocol decode",
      "listening on en0, link-type EN10MB (Ethernet), snapshot length 262144 bytes",
      "2024-01-01 12:00:00.000000 IP 10.0.0.2.54321 > 10.0.0.1.80: tcp 512",
    ].join("\n");
    const result = parseTcpdumpOutput(output);
    // All non-empty lines are counted, but only the valid "IP" line contributes to protocols/unencrypted.
    assert.equal(result.capturedPackets, 3);
    assert.equal(result.protocols.tcp, 1);
    assert.equal(result.unencrypted.length, 1);
  });
});
