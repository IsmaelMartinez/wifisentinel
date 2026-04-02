import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseMacosLogs,
  parseLinuxLogs,
  parseTcpdumpOutput,
} from "../../src/collector/scanners/deauth.scanner.js";

describe("parseMacosLogs", () => {
  it("returns no events when logs contain no deauth patterns", () => {
    const output = `
2024-01-01 12:00:00.000 com.apple.wifi WiFi connected to MyNetwork
2024-01-01 12:00:01.000 com.apple.wifi Signal strength: -55 dBm
    `.trim();
    const result = parseMacosLogs(output);
    assert.equal(result.detected, false);
    assert.equal(result.frameCount, 0);
    assert.deepEqual(result.sources, []);
  });

  it("detects deauthentication events and extracts MAC addresses", () => {
    const output = `
2024-01-01 12:00:00.000 com.apple.wifi Deauthentication from 00:11:22:33:44:55 reason code: 3
2024-01-01 12:00:01.000 com.apple.wifi deauth frame received from aa:bb:cc:dd:ee:ff
    `.trim();
    const result = parseMacosLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 2);
    assert.equal(result.sources.length, 2);
  });

  it("detects disassociation events", () => {
    const output = `
2024-01-01 12:00:00.000 com.apple.wifi Disassociation from 00:11:22:33:44:55
    `.trim();
    const result = parseMacosLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 1);
  });

  it("counts multiple events from same MAC and sorts by count descending", () => {
    const output = `
2024-01-01 12:00:00.000 com.apple.wifi Deauthentication from aa:bb:cc:dd:ee:ff reason code: 3
2024-01-01 12:00:01.000 com.apple.wifi Deauthentication from aa:bb:cc:dd:ee:ff reason code: 3
2024-01-01 12:00:02.000 com.apple.wifi deauth from 00:11:22:33:44:55
    `.trim();
    const result = parseMacosLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 3);
    assert.equal(result.sources[0].mac, "aa:bb:cc:dd:ee:ff");
    assert.equal(result.sources[0].count, 2);
    assert.equal(result.sources[1].mac, "00:11:22:33:44:55");
    assert.equal(result.sources[1].count, 1);
  });

  it("excludes broadcast MAC addresses", () => {
    const output = `
2024-01-01 12:00:00.000 com.apple.wifi Deauthentication from ff:ff:ff:ff:ff:ff reason code: 3
    `.trim();
    const result = parseMacosLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.sources.length, 0);
  });

  it("detects reason code patterns", () => {
    const output = `
2024-01-01 12:00:00.000 com.apple.wifi IEEE 802.11 frame reason code: 4
    `.trim();
    const result = parseMacosLogs(output);
    assert.equal(result.detected, true);
  });
});

describe("parseLinuxLogs", () => {
  it("returns no events when logs contain no deauth patterns", () => {
    const output = `
Jan  1 12:00:00 kernel: wlan0: associated
Jan  1 12:00:01 kernel: wlan0: DHCP lease obtained
    `.trim();
    const result = parseLinuxLogs(output);
    assert.equal(result.detected, false);
    assert.equal(result.frameCount, 0);
    assert.deepEqual(result.sources, []);
  });

  it("detects Linux deauthenticated events and extracts MAC", () => {
    const output = `
Jan  1 12:00:00 kernel: wlan0: deauthenticated from 00:11:22:33:44:55 (reason: 3)
    `.trim();
    const result = parseLinuxLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 1);
    assert.equal(result.sources.length, 1);
    assert.equal(result.sources[0].mac, "00:11:22:33:44:55");
  });

  it("detects disassociated events", () => {
    const output = `
Jan  1 12:00:00 kernel: wlan0: disassociated from aa:bb:cc:dd:ee:ff
    `.trim();
    const result = parseLinuxLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 1);
  });

  it("detects deauth from pattern", () => {
    const output = `
Jan  1 12:00:00 kernel: wlan0: deauth from 11:22:33:44:55:66
    `.trim();
    const result = parseLinuxLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 1);
  });

  it("handles multiple events and sorts sources by count", () => {
    const output = `
Jan  1 12:00:00 kernel: wlan0: deauthenticated from aa:bb:cc:dd:ee:ff (reason: 3)
Jan  1 12:00:01 kernel: wlan0: deauthenticated from aa:bb:cc:dd:ee:ff (reason: 3)
Jan  1 12:00:02 kernel: wlan0: disassociated from 00:11:22:33:44:55
    `.trim();
    const result = parseLinuxLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 3);
    assert.equal(result.sources[0].mac, "aa:bb:cc:dd:ee:ff");
    assert.equal(result.sources[0].count, 2);
  });

  it("excludes broadcast MAC", () => {
    const output = `
Jan  1 12:00:00 kernel: wlan0: deauthenticated from ff:ff:ff:ff:ff:ff
    `.trim();
    const result = parseLinuxLogs(output);
    assert.equal(result.detected, true);
    assert.equal(result.sources.length, 0);
  });
});

describe("parseTcpdumpOutput", () => {
  it("returns no events for empty output", () => {
    const result = parseTcpdumpOutput("");
    assert.equal(result.detected, false);
    assert.equal(result.frameCount, 0);
    assert.deepEqual(result.sources, []);
  });

  it("detects deauthentication frames in tcpdump output", () => {
    const output = `
12:00:00.000000 aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff: Deauthentication (reason: 3)
    `.trim();
    const result = parseTcpdumpOutput(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 1);
  });

  it("detects disassociation frames in tcpdump output", () => {
    const output = `
12:00:00.000000 11:22:33:44:55:66 > aa:bb:cc:dd:ee:ff: Disassociation (reason: 8)
    `.trim();
    const result = parseTcpdumpOutput(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 1);
  });

  it("accumulates counts per source MAC", () => {
    const output = `
12:00:00.000000 aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff: Deauthentication (reason: 3)
12:00:01.000000 aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff: Deauthentication (reason: 3)
12:00:02.000000 00:11:22:33:44:55 > ff:ff:ff:ff:ff:ff: Deauthentication (reason: 3)
    `.trim();
    const result = parseTcpdumpOutput(output);
    assert.equal(result.detected, true);
    assert.equal(result.frameCount, 3);
    assert.equal(result.sources[0].mac, "aa:bb:cc:dd:ee:ff");
    assert.equal(result.sources[0].count, 2);
    assert.equal(result.sources[1].mac, "00:11:22:33:44:55");
    assert.equal(result.sources[1].count, 1);
  });

  it("handles non-deauth lines without interference", () => {
    const output = `
12:00:00.000000 aa:bb:cc:dd:ee:ff > 00:11:22:33:44:55: Probe Request
12:00:01.000000 00:11:22:33:44:55 > ff:ff:ff:ff:ff:ff: Beacon
    `.trim();
    const result = parseTcpdumpOutput(output);
    assert.equal(result.detected, false);
    assert.equal(result.frameCount, 0);
  });
});
