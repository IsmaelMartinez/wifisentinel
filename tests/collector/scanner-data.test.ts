import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isMulticastMac, isValidMac, normaliseMac } from "../../src/collector/mac.js";
import { lookupVendor } from "../../src/collector/oui-lookup.js";
import { parseArpOutput } from "../../src/collector/scanners/host-discovery.scanner.js";
import {
  detectArpAnomalies,
  parseArpTable,
} from "../../src/collector/scanners/intrusion-detection.scanner.js";
import { parseMacosLogs, parseTcpdumpOutput } from "../../src/collector/scanners/deauth.scanner.js";
import { openPortsOnly } from "../../src/collector/scanners/port.scanner.js";
import { hasAdFlag } from "../../src/collector/scanners/dns.scanner.js";
import { pickIsolationTarget } from "../../src/collector/scanners/security-posture.scanner.js";

// Captured from `arp -a` on macOS: leading zeros dropped, multicast and
// broadcast entries present alongside real hosts.
const MACOS_ARP = `vodafone.powerhub (192.168.1.1) at 60:d8:a4:37:7e:2e on en0 ifscope [ethernet]
? (192.168.1.23) at 0:1b:63:84:45:e6 on en0 ifscope [ethernet]
? (192.168.1.40) at 48:22:54:b:d0:90 on en0 ifscope [ethernet]
? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
mdns.mcast.net (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (239.255.255.250) at 1:0:5e:7f:ff:fa on en0 ifscope permanent [ethernet]
broadcasthost (255.255.255.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]`;

describe("normaliseMac", () => {
  it("zero-pads, lowercases and converts dashes", () => {
    assert.equal(normaliseMac("0:1B:63:84:45:E6"), "00:1b:63:84:45:e6");
    assert.equal(normaliseMac("48-22-54-B-D0-90"), "48:22:54:0b:d0:90");
    assert.equal(normaliseMac("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff");
  });

  it("leaves non-MAC values alone apart from case", () => {
    assert.equal(normaliseMac("unknown"), "unknown");
    assert.equal(normaliseMac("(incomplete)"), "(incomplete)");
    assert.equal(isValidMac("unknown"), false);
  });

  it("flags group (multicast/broadcast) MACs", () => {
    assert.equal(isMulticastMac("1:0:5e:0:0:fb"), true);
    assert.equal(isMulticastMac("33:33:0:0:0:1"), true);
    assert.equal(isMulticastMac("ff:ff:ff:ff:ff:ff"), true);
    assert.equal(isMulticastMac("60:d8:a4:37:7e:2e"), false);
    assert.equal(isMulticastMac("unknown"), false);
  });
});

describe("lookupVendor", () => {
  it("resolves vendors from the bundled OUI database", () => {
    assert.equal(lookupVendor("00:1b:63:84:45:e6"), "Apple, Inc.");
  });

  it("resolves macOS arp MACs with dropped leading zeros", () => {
    assert.equal(lookupVendor("0:1b:63:84:45:e6"), "Apple, Inc.");
    assert.equal(lookupVendor("48:22:54:b:d0:90"), "TP-Link Systems Inc");
  });

  it("returns undefined for placeholders", () => {
    assert.equal(lookupVendor("unknown"), undefined);
  });
});

describe("host-discovery parseArpOutput", () => {
  it("keeps unicast hosts with normalised MACs and skips multicast/broadcast", () => {
    const entries = parseArpOutput(MACOS_ARP);
    assert.deepEqual(
      entries.map((e) => [e.ip, e.mac]),
      [
        ["192.168.1.1", "60:d8:a4:37:7e:2e"],
        ["192.168.1.23", "00:1b:63:84:45:e6"],
        ["192.168.1.40", "48:22:54:0b:d0:90"],
      ],
    );
  });
});

describe("intrusion-detection", () => {
  it("parseArpTable normalises MACs and skips multicast entries", () => {
    const table = parseArpTable(MACOS_ARP);
    assert.equal(table.get("192.168.1.23"), "00:1b:63:84:45:e6");
    assert.equal(table.has("224.0.0.251"), false);
    assert.equal(table.has("192.168.1.255"), false);
  });

  it("does not raise gateway_mac_mismatch when the gateway MAC is unknown", () => {
    const snap = parseArpTable(MACOS_ARP);
    const anomalies = detectArpAnomalies(snap, snap, "192.168.1.1", "unknown");
    assert.deepEqual(anomalies, []);
  });

  it("matches the gateway MAC regardless of zero-padding", () => {
    const snap = parseArpTable("? (192.168.1.1) at 0:1b:63:84:45:e6 on en0 ifscope [ethernet]");
    assert.deepEqual(detectArpAnomalies(snap, snap, "192.168.1.1", "00:1B:63:84:45:E6"), []);
  });

  it("still flags a real gateway MAC mismatch", () => {
    const snap = parseArpTable(MACOS_ARP);
    const anomalies = detectArpAnomalies(snap, snap, "192.168.1.1", "aa:bb:cc:dd:ee:ff");
    assert.equal(anomalies.length, 1);
    assert.equal(anomalies[0].type, "gateway_mac_mismatch");
  });
});

describe("deauth MAC handling", () => {
  it("normalises source MACs and drops multicast", () => {
    const logs = `2024-01-01 12:00:00.000 com.apple.wifi Deauthentication from 0:11:22:33:44:55 to 1:0:5e:0:0:1 reason code: 3`;
    assert.deepEqual(parseMacosLogs(logs).sources, [{ mac: "00:11:22:33:44:55", count: 1 }]);
  });

  it("normalises tcpdump source MACs", () => {
    const out = `12:00:00.000000 0:11:22:33:44:55 > ff:ff:ff:ff:ff:ff: Deauthentication (reason: 3)`;
    assert.deepEqual(parseTcpdumpOutput(out).sources, [{ mac: "00:11:22:33:44:55", count: 1 }]);
  });
});

describe("port results", () => {
  it("keeps only open ports", () => {
    const results = [
      { port: 22, service: "SSH", state: "closed" },
      { port: 80, service: "HTTP", state: "open" },
      { port: 443, service: "HTTPS", state: "closed" },
    ];
    assert.deepEqual(openPortsOnly(results), [{ port: 80, service: "HTTP", state: "open" }]);
  });
});

describe("DNSSEC AD flag", () => {
  // Captured from `dig @1.1.1.1 cloudflare.com A +dnssec` (signed zone).
  const SIGNED = `; <<>> DiG 9.10.6 <<>> @1.1.1.1 cloudflare.com A +dnssec
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;cloudflare.com.			IN	A`;
  // Captured from `dig @1.1.1.1 google.com A +dnssec` (unsigned zone).
  const UNSIGNED = `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4243
;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232`;

  it("reports DNSSEC when the resolver sets AD", () => {
    assert.equal(hasAdFlag(SIGNED), true);
  });

  it("does not report DNSSEC without AD, even with several answer lines", () => {
    assert.equal(hasAdFlag(UNSIGNED), false);
    assert.equal(hasAdFlag("142.250.0.1\n142.250.0.2"), false);
  });
});

describe("client isolation target", () => {
  it("skips the gateway, this host and multicast entries", () => {
    assert.equal(pickIsolationTarget(MACOS_ARP, "192.168.1.1", "192.168.1.23"), "192.168.1.40");
  });

  it("returns undefined when only the gateway is known", () => {
    const arp = MACOS_ARP.split("\n").filter((l) => !l.includes("192.168.1.23") && !l.includes("192.168.1.40")).join("\n");
    assert.equal(pickIsolationTarget(arp, "192.168.1.1"), undefined);
  });
});
