import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArp } from "../../src/collector/platform/arp.js";
import { parseNetstat, splitNetstatAddr } from "../../src/collector/platform/netstat.js";
import { parsePingStats } from "../../src/collector/platform/ping.js";
import { parsePingOutput } from "../../src/collector/scanners/speed.scanner.js";
import { bin, broadcastPingArgs, singlePingArgs } from "../../src/collector/platform/commands.js";
import {
  parseIwDevInterface,
  parseLinuxDefaultRoute,
  parseWifiHardwarePort,
  subnetCidr,
} from "../../src/collector/platform/bootstrap.js";
import { countNetstat } from "../../src/collector/scanners/connection.scanner.js";
import { detectScanPatterns } from "../../src/collector/scanners/intrusion-detection.scanner.js";
import { resolveAllTools, resolveCapability, toolchainSummary } from "../../src/collector/tool-resolver.js";

const MACOS_ARP = `vodafone.powerhub (192.168.1.1) at 60:d8:a4:37:7e:2e on en0 ifscope [ethernet]
? (192.168.1.40) at 48:22:54:b:d0:90 on en0 ifscope [ethernet]
? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]
mdns.mcast.net (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]`;

const LINUX_ARP = `_gateway (192.168.1.1) at 60:d8:a4:37:7e:2e [ether] on wlp2s0
? (192.168.1.40) at 48:22:54:0b:d0:90 [ether] on wlp2s0
? (192.168.1.77) at <incomplete> on wlp2s0
? (192.168.1.2) at 48:22:54:0b:d0:91 [ether] PERM on wlp2s0
? (224.0.0.251) at 01:00:5e:00:00:fb [ether] PERM on wlp2s0`;

describe("platform/arp", () => {
  const expected = (iface: string) => [
    { ip: "192.168.1.1", mac: "60:d8:a4:37:7e:2e", iface },
    { ip: "192.168.1.40", mac: "48:22:54:0b:d0:90", iface },
  ];

  it("parses macOS arp -a", () => {
    assert.deepEqual(parseArp(MACOS_ARP), expected("en0"));
  });

  it("parses Linux arp -a, including permanent entries", () => {
    assert.deepEqual(parseArp(LINUX_ARP), [
      ...expected("wlp2s0"),
      { ip: "192.168.1.2", mac: "48:22:54:0b:d0:91", iface: "wlp2s0" },
    ]);
  });
});

// Captured from macOS `netstat -an` (dot-separated ports).
const MACOS_NETSTAT = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.93.64127     20.26.156.210.443      ESTABLISHED
tcp4       0      0  127.0.0.1.64126        127.0.0.1.4318         SYN_SENT
tcp6       0      0  2a0a:ef40:741:da.64099 2607:6bc0::10.443      ESTABLISHED
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  192.168.1.93.22        192.168.1.50.51000     SYN_RCVD
tcp4       0      0  192.168.1.93.64000     93.184.216.34.80       TIME_WAIT
udp6       0      0  2a0a:ef40:741:da.49989 2600:9000:272f:7.443
udp4       0      0  *.5353                 *.*`;

// Linux net-tools `netstat -an` (colon-separated ports).
const LINUX_NETSTAT = `Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.5:54321       20.26.156.210:443       ESTABLISHED
tcp        0      0 192.168.1.5:22          192.168.1.50:51000      SYN_RECV
tcp        0      0 192.168.1.5:54000       93.184.216.34:80        TIME_WAIT
tcp6       0      0 :::22                   :::*                    LISTEN
tcp6       0      0 ::1:631                 ::1:40000               ESTABLISHED
udp        0      0 0.0.0.0:68              0.0.0.0:*
Active UNIX domain sockets (servers and established)
unix  2      [ ACC ]     STREAM     LISTENING     12345    /run/systemd/private`;

describe("platform/netstat", () => {
  it("splits macOS and Linux endpoints", () => {
    assert.deepEqual(splitNetstatAddr("192.168.1.93.64127"), { addr: "192.168.1.93", port: "64127" });
    assert.deepEqual(splitNetstatAddr("2607:6bc0::10.443"), { addr: "2607:6bc0::10", port: "443" });
    assert.deepEqual(splitNetstatAddr("*.*"), { addr: "*", port: "*" });
    assert.deepEqual(splitNetstatAddr("192.168.1.5:54321"), { addr: "192.168.1.5", port: "54321" });
    assert.deepEqual(splitNetstatAddr(":::22"), { addr: "::", port: "22" });
    assert.deepEqual(splitNetstatAddr("0.0.0.0:*"), { addr: "0.0.0.0", port: "*" });
  });

  it("parses macOS netstat -an", () => {
    const entries = parseNetstat(MACOS_NETSTAT);
    assert.equal(entries.length, 8);
    assert.deepEqual(entries[0], {
      proto: "tcp4",
      localAddr: "192.168.1.93",
      localPort: "64127",
      remoteAddr: "20.26.156.210",
      remotePort: "443",
      state: "ESTABLISHED",
    });
    // macOS SYN_RCVD is normalised to the Linux spelling the detectors use
    assert.equal(entries[4].state, "SYN_RECV");
    assert.equal(entries[7].state, "");
  });

  it("parses Linux netstat -an and ignores unix sockets", () => {
    const entries = parseNetstat(LINUX_NETSTAT);
    assert.equal(entries.length, 7);
    assert.deepEqual(entries[1], {
      proto: "tcp",
      localAddr: "192.168.1.5",
      localPort: "54321",
      remoteAddr: "20.26.156.210",
      remotePort: "443",
      state: "ESTABLISHED",
    });
  });

  it("counts connections identically on both platforms", () => {
    const mac = countNetstat(parseNetstat(MACOS_NETSTAT));
    const linux = countNetstat(parseNetstat(LINUX_NETSTAT));
    assert.deepEqual(mac, { established: 2, listening: 1, timeWait: 1, establishedDestinations: ["20.26.156.210"] });
    assert.deepEqual(linux, { established: 2, listening: 2, timeWait: 1, establishedDestinations: ["20.26.156.210"] });
  });

  it("feeds half-open connections into scan detection on both platforms", () => {
    const synFlood = (fmt: (i: number) => string) =>
      parseNetstat(Array.from({ length: 5 }, (_, i) => fmt(i)).join("\n"));
    const mac = synFlood((i) => `tcp4 0 0 192.168.1.93.${22 + i} 10.0.0.9.5100${i} SYN_RCVD`);
    const linux = synFlood((i) => `tcp 0 0 192.168.1.5:${22 + i} 10.0.0.9:5100${i} SYN_RECV`);
    for (const entries of [mac, linux]) {
      const detections = detectScanPatterns(entries);
      assert.equal(detections.length, 1);
      assert.equal(detections[0].type, "inbound_scan");
      assert.equal(detections[0].source, "10.0.0.9");
    }
  });
});

describe("platform/ping", () => {
  it("parses macOS ping (stddev)", () => {
    const out = `--- 192.168.1.1 ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 9.621/10.047/10.474/0.427 ms`;
    assert.deepEqual(parsePingStats(out), { minMs: 9.621, avgMs: 10.047, maxMs: 10.474, jitterMs: 0.427, lossPercent: 0 });
  });

  it("parses Linux ping (mdev)", () => {
    const out = `--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 2.123/2.456/2.789/0.271 ms`;
    assert.deepEqual(parsePingStats(out), { minMs: 2.123, avgMs: 2.456, maxMs: 2.789, jitterMs: 0.271, lossPercent: 0 });
  });

  it("is the parser the speed test uses, so Linux mdev latency is read", () => {
    const out = `--- 1.1.1.1 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 9012ms
rtt min/avg/max/mdev = 11.204/12.873/15.990/1.338 ms`;
    assert.equal(parsePingOutput, parsePingStats);
    assert.deepEqual(parsePingOutput(out), { minMs: 11.204, avgMs: 12.873, maxMs: 15.99, jitterMs: 1.338, lossPercent: 0 });
  });

  it("reports total loss when there is no summary", () => {
    const out = `3 packets transmitted, 0 received, 100% packet loss, time 2040ms`;
    assert.equal(parsePingStats(out).lossPercent, 100);
    assert.equal(parsePingStats(out).avgMs, 0);
  });
});

describe("platform/commands", () => {
  it("uses fixed macOS paths and PATH lookup on Linux", () => {
    assert.equal(bin("arp", "darwin"), "/usr/sbin/arp");
    assert.equal(bin("lsof", "darwin"), "/usr/sbin/lsof");
    assert.equal(bin("arp", "linux"), "arp");
    assert.equal(bin("lsof", "linux"), "lsof");
    assert.equal(bin("system_profiler", "darwin"), "/usr/sbin/system_profiler");
  });

  it("builds ping args per platform", () => {
    assert.deepEqual(broadcastPingArgs("192.168.1.255", "darwin"), ["-c", "2", "-t", "1", "192.168.1.255"]);
    assert.deepEqual(broadcastPingArgs("192.168.1.255", "linux"), ["-b", "-c", "2", "-w", "1", "192.168.1.255"]);
    assert.deepEqual(singlePingArgs("192.168.1.40", "darwin"), ["-c", "1", "-W", "2000", "192.168.1.40"]);
    assert.deepEqual(singlePingArgs("192.168.1.40", "linux"), ["-c", "1", "-W", "2", "192.168.1.40"]);
  });
});

describe("platform/bootstrap parsers", () => {
  it("finds the Wi-Fi device in networksetup -listallhardwareports", () => {
    const out = `
Hardware Port: Ethernet Adapter (en3)
Device: en3
Ethernet Address: e2:ad:95:13:19:05

Hardware Port: Wi-Fi
Device: en1
Ethernet Address: fc:b2:14:8f:87:b9

VLAN Configurations
===================`;
    assert.deepEqual(parseWifiHardwarePort(out), { device: "en1", service: "Wi-Fi" });
    assert.equal(parseWifiHardwarePort("Hardware Port: Thunderbolt Bridge\nDevice: bridge0"), null);
  });

  it("computes the network address for any prefix length", () => {
    assert.equal(subnetCidr("192.168.1.93", 24), "192.168.1.0/24");
    assert.equal(subnetCidr("10.0.5.7", 16), "10.0.0.0/16");
    assert.equal(subnetCidr("172.20.130.4", 20), "172.20.128.0/20");
    assert.equal(subnetCidr("unknown", 24), "unknown/24");
  });

  it("parses the Linux default route and iw dev", () => {
    assert.deepEqual(
      parseLinuxDefaultRoute("default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600"),
      { gatewayIp: "192.168.1.1", iface: "wlp2s0" },
    );
    assert.equal(parseLinuxDefaultRoute(""), null);
    assert.equal(parseIwDevInterface("phy#0\n\tInterface wlp2s0\n\t\tifindex 3"), "wlp2s0");
  });
});

describe("tool-resolver", () => {
  function fakePath(bins: string[]): { dir: string; cleanup: () => void } {
    const dir = mkdtempSync(join(tmpdir(), "wifisentinel-bins-"));
    for (const name of bins) {
      const p = join(dir, name);
      writeFileSync(p, "#!/bin/sh\n");
      chmodSync(p, 0o755);
    }
    return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
  }

  it("picks the preferred tier when available", () => {
    const { dir, cleanup } = fakePath(["dig", "nslookup", "tshark", "tcpdump"]);
    try {
      const tools = resolveAllTools("linux", dir);
      assert.deepEqual(tools.get("dnsAudit"), { capability: "dnsAudit", name: "dig", path: join(dir, "dig"), tier: "preferred" });
      assert.equal(tools.get("packetAnalysis")?.name, "tshark");
    } finally {
      cleanup();
    }
  });

  it("falls back to the next tier", () => {
    const { dir, cleanup } = fakePath(["nslookup", "tcpdump", "iw"]);
    try {
      assert.equal(resolveCapability("dnsAudit", "linux", dir)?.tier, "fallback");
      assert.equal(resolveCapability("packetAnalysis", "linux", dir)?.name, "tcpdump");
      assert.equal(resolveCapability("wifiAnalysis", "linux", dir)?.name, "iw");
    } finally {
      cleanup();
    }
  });

  it("prefers iw for Linux Wi-Fi and reports nmcli alone as minimal", () => {
    const both = fakePath(["iw", "nmcli"]);
    const nmcliOnly = fakePath(["nmcli"]);
    try {
      assert.equal(resolveCapability("wifiAnalysis", "linux", both.dir)?.name, "iw");
      assert.deepEqual(
        [resolveCapability("wifiAnalysis", "linux", nmcliOnly.dir)?.name, resolveCapability("wifiAnalysis", "linux", nmcliOnly.dir)?.tier],
        ["nmcli", "minimal"],
      );
    } finally {
      both.cleanup();
      nmcliOnly.cleanup();
    }
  });

  it("reports none when no candidate exists", () => {
    const tools = resolveAllTools("linux", "");
    assert.deepEqual(tools.get("packetAnalysis"), { capability: "packetAnalysis", name: "none", path: "", tier: "minimal" });
    assert.equal(toolchainSummary(tools).packetAnalysis, null);
  });

  it("resolves macOS system tools at the fixed path the scanners execute, ignoring PATH", () => {
    const { dir, cleanup } = fakePath(["dig", "nc"]);
    try {
      const tools = resolveAllTools("darwin", dir);
      for (const [capability, name, path] of [
        ["dnsAudit", "dig", "/usr/bin/dig"],
        ["portScanning", "nc", "/usr/bin/nc"],
      ] as const) {
        const tool = tools.get(capability);
        // The fixed path is used when present, and a PATH copy never stands in for it.
        assert.ok(tool?.path === path || (tool?.name !== name && !existsSync(path)), `${capability}: ${JSON.stringify(tool)}`);
      }
    } finally {
      cleanup();
    }
  });

  it("only lists capabilities the scanners run", () => {
    assert.deepEqual(
      [...resolveAllTools("darwin", "").keys()].sort(),
      ["dnsAudit", "hostDiscovery", "packetAnalysis", "portScanning", "traceroute", "wifiAnalysis"],
    );
  });
});
