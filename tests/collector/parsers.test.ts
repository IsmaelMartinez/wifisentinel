import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseNetworksetup, parseSystemProfiler } from "../../src/collector/scanners/wifi.scanner.js";
import { parseNslookupServer, parseScutilDns } from "../../src/collector/scanners/dns.scanner.js";
import { parseTraceroute } from "../../src/collector/scanners/host-discovery.scanner.js";
import { parseLsofOutput } from "../../src/collector/scanners/port.scanner.js";
import {
  parseEnabled,
  parseNcList,
  parseSysctlBool,
  parseWebProxy,
} from "../../src/collector/scanners/security-posture.scanner.js";
import { detectSuspiciousHosts } from "../../src/collector/scanners/intrusion-detection.scanner.js";
import { scanHiddenDevices } from "../../src/collector/scanners/hidden-device.scanner.js";
import { countNetstat } from "../../src/collector/scanners/connection.scanner.js";
import { parseNetstat } from "../../src/collector/platform/netstat.js";

// All fixtures below are macOS tool output, captured and then anonymised.

describe("wifi: system_profiler SPAirPortDataType", () => {
  const output = readFileSync(new URL("./fixtures/system-profiler-airport.txt", import.meta.url), "utf-8");
  const wifi = parseSystemProfiler(output);

  it("reads the current connection", () => {
    assert.equal(wifi.ssid, "HomeNet");
    assert.equal(wifi.protocol, "802.11ax");
    assert.equal(wifi.channel, 100);
    assert.equal(wifi.band, "5GHz");
    assert.equal(wifi.width, "80MHz");
    assert.equal(wifi.security, "WPA2/WPA3 Personal");
    assert.equal(wifi.signal, -33);
    assert.equal(wifi.noise, -97);
    assert.equal(wifi.snr, 64);
    assert.equal(wifi.txRate, 1200);
    assert.equal(wifi.countryCode, "GB");
  });

  it("reads nearby networks, including redacted SSIDs", () => {
    assert.deepEqual(wifi.nearbyNetworks, [
      { ssid: "(hidden)", security: "WPA2 Personal", protocol: "802.11b/g/n", channel: 1, signal: -71, noise: -95 },
      { ssid: "CafeGuest", security: "Open", protocol: "802.11a/n/ac", channel: 36, signal: -80, noise: -96 },
    ]);
  });

  it("falls back to networksetup -getairportnetwork", () => {
    assert.deepEqual(parseNetworksetup("Current Wi-Fi Network: HomeNet"), { ssid: "HomeNet" });
    assert.deepEqual(parseNetworksetup("You are not associated with an AirPort network."), { ssid: null });
  });
});

describe("dns: scutil --dns and nslookup", () => {
  it("collects unique nameservers across resolvers", () => {
    const out = `DNS configuration

resolver #1
  search domain[0] : home
  nameserver[0] : 2a0a:ef40:741:da01::1
  nameserver[1] : 192.168.1.1
  if_index : 15 (en0)
  flags    : Request A records, Request AAAA records

resolver #2
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 15 (en0)`;
    assert.deepEqual(parseScutilDns(out), ["2a0a:ef40:741:da01::1", "192.168.1.1"]);
  });

  it("reads the server from nslookup", () => {
    const out = `Server:		192.168.1.1
Address:	192.168.1.1#53

Non-authoritative answer:
Name:	google.com
Address: 142.250.187.206`;
    assert.deepEqual(parseNslookupServer(out), ["192.168.1.1"]);
  });
});

describe("host-discovery: traceroute", () => {
  it("parses hops and skips timeouts", () => {
    const out = `traceroute to 8.8.8.8 (8.8.8.8), 5 hops max, 40 byte packets
 1  vodafone.powerhub (192.168.1.1)  3.210 ms
 2  10.0.0.1 (10.0.0.1)  9.875 ms
 3  *
 4  dns.google (8.8.8.8)  14.022 ms`;
    assert.deepEqual(parseTraceroute(out), [
      { ip: "192.168.1.1", hostname: "vodafone.powerhub", latencyMs: 3.21 },
      { ip: "10.0.0.1", hostname: undefined, latencyMs: 9.875 },
      { ip: "8.8.8.8", hostname: "dns.google", latencyMs: 14.022 },
    ]);
  });
});

describe("port: lsof -i -P -n", () => {
  it("keeps TCP listeners with their bind address", () => {
    const out = `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Spotify    1582 me   80u  IPv4 0xf86d4d7601b34935      0t0  TCP 127.0.0.1:7768 (LISTEN)
Spotify    1582 me   96u  IPv4 0x191b277df5ce7e3a      0t0  TCP *:57621 (LISTEN)
cupsd       411 root  5u  IPv6 0x1ee414d4602cf48f      0t0  TCP [::1]:631 (LISTEN)
Safari     2200 me   30u  IPv4 0x2ee414d4602cf48f      0t0  TCP 192.168.1.93:64127->20.26.156.210:443 (ESTABLISHED)
mDNSRespo   300 me   12u  IPv4 0x3ee414d4602cf48f      0t0  UDP *:5353`;
    assert.deepEqual(parseLsofOutput(out), [
      { port: 7768, process: "Spotify", bindAddress: "127.0.0.1" },
      { port: 57621, process: "Spotify", bindAddress: "*" },
      { port: 631, process: "cupsd", bindAddress: "[::1]" },
    ]);
  });
});

describe("security-posture: macOS tool output", () => {
  it("reads socketfilterfw state lines", () => {
    assert.equal(parseEnabled("Firewall is enabled. (State = 1)"), true);
    assert.equal(parseEnabled("Firewall is disabled. (State = 0)"), false);
    assert.equal(parseEnabled("Firewall stealth mode is on"), false);
    assert.equal(parseEnabled("Firewall stealth mode is off"), false);
    assert.equal(parseEnabled("Automatically allow built-in signed software ENABLED."), true);
  });

  it("reads sysctl booleans", () => {
    assert.equal(parseSysctlBool("net.inet.ip.forwarding: 0"), false);
    assert.equal(parseSysctlBool("net.inet.ip.forwarding: 1"), true);
    assert.equal(parseSysctlBool(""), false);
  });

  it("reads scutil --nc list", () => {
    assert.equal(parseNcList("Available network connection services in the current set (*=enabled):"), null);
    assert.deepEqual(
      parseNcList(`Available network connection services in the current set (*=enabled):
* (Connected)      3C1D2E4F-0000-4000-8000-000000000001 VPN (com.wireguard.macos) "Work VPN"   [VPN:com.wireguard.macos]`),
      { installed: true, active: true, provider: "Work VPN" },
    );
    assert.deepEqual(
      parseNcList(`* (Disconnected)   3C1D2E4F-0000-4000-8000-000000000002 PPP --> L2TP  "Old VPN"   [PPP:L2TP]`),
      { installed: true, active: false },
    );
  });

  it("reads networksetup -getwebproxy for a disabled proxy without swallowing the next line", () => {
    const out = `Enabled: No
Server:
Port: 0
Authenticated Proxy Enabled: 0`;
    assert.deepEqual(parseWebProxy(out), { enabled: false });
  });

  it("reads an enabled proxy", () => {
    const out = `Enabled: Yes
Server: proxy.example.com
Port: 8080
Authenticated Proxy Enabled: 0`;
    assert.deepEqual(parseWebProxy(out), { enabled: true, server: "proxy.example.com", port: 8080 });
  });
});

describe("connection: netstat -an counts", () => {
  it("counts macOS TCP states and public destinations", () => {
    const out = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.93.64127     20.26.156.210.443      ESTABLISHED
tcp4       0      0  192.168.1.93.64128     20.26.156.210.443      ESTABLISHED
tcp4       0      0  127.0.0.1.64126        127.0.0.1.4318         ESTABLISHED
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  192.168.1.93.64000     93.184.216.34.80       TIME_WAIT
udp4       0      0  *.5353                 *.*`;
    assert.deepEqual(countNetstat(parseNetstat(out)), {
      established: 3,
      listening: 1,
      timeWait: 1,
      establishedDestinations: ["20.26.156.210", "20.26.156.210"],
    });
  });
});

describe("intrusion-detection: suspicious host sweep", () => {
  it("flags several new sequential hosts between ARP snapshots", () => {
    const before = new Map([["192.168.1.1", "60:d8:a4:37:7e:2e"]]);
    const after = new Map([
      ...before,
      ["192.168.1.50", "aa:bb:cc:00:00:50"],
      ["192.168.1.51", "aa:bb:cc:00:00:51"],
      ["192.168.1.52", "aa:bb:cc:00:00:52"],
    ]);
    const suspicious = detectSuspiciousHosts(before, after);
    assert.equal(suspicious.length, 3);
    assert.ok(suspicious.every((h) => h.severity === "medium"));
  });

  it("ignores a single new host", () => {
    const before = new Map([["192.168.1.1", "60:d8:a4:37:7e:2e"]]);
    const after = new Map([...before, ["192.168.1.77", "aa:bb:cc:00:00:77"]]);
    assert.deepEqual(detectSuspiciousHosts(before, after), []);
  });
});

describe("hidden-device: camera scoring", () => {
  it("flags a camera-only vendor and an RTSP host, and lists unknown devices", async () => {
    const result = await scanHiddenDevices([
      { ip: "192.168.1.30", mac: "44:19:b6:00:00:01", vendor: "Hangzhou Hikvision Digital Technology Co.,Ltd." },
      { ip: "192.168.1.31", mac: "aa:bb:cc:00:00:31", vendor: "TP-Link Systems Inc", ports: [{ port: 554, service: "RTSP", state: "open" }] },
      { ip: "192.168.1.32", mac: "aa:bb:cc:00:00:32", ports: [{ port: 80, service: "HTTP", state: "open" }] },
      { ip: "192.168.1.33", mac: "00:1b:63:00:00:33", vendor: "Apple, Inc.", ports: [{ port: 22, service: "SSH", state: "open" }] },
    ]);
    assert.deepEqual(result.suspectedCameras.map((h) => h.ip), ["192.168.1.30", "192.168.1.31"]);
    assert.deepEqual(result.unknownDevices.map((h) => h.ip), ["192.168.1.32"]);
  });
});
