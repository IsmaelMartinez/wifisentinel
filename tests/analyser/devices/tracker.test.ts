import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildPresenceReport, normaliseMac } from "../../../src/analyser/devices/tracker.js";
import type { StoredScan } from "../../../src/store/types.js";

interface HostInput {
  ip: string;
  mac: string;
  hostname?: string;
  vendor?: string;
  deviceType?: string;
  isCamera?: boolean;
}

function makeScan(id: string, timestamp: string, hosts: HostInput[], ssid = "TestNet"): StoredScan {
  // We only use a subset of the shape — cast to any then StoredScan for test brevity.
  return {
    scan: {
      meta: { scanId: id, timestamp },
      wifi: { ssid },
      network: { hosts },
    },
  } as unknown as StoredScan;
}

describe("normaliseMac", () => {
  it("lowercases and normalises dashes to colons", () => {
    assert.equal(normaliseMac("AA-BB-CC-DD-EE-01"), "aa:bb:cc:dd:ee:01");
    assert.equal(normaliseMac("AA:BB:CC:DD:EE:01"), "aa:bb:cc:dd:ee:01");
    assert.equal(normaliseMac("aa:bb:cc:dd:ee:01"), "aa:bb:cc:dd:ee:01");
  });
});

describe("buildPresenceReport", () => {
  it("returns empty report when no scans are provided", () => {
    const report = buildPresenceReport([]);
    assert.equal(report.totalScans, 0);
    assert.equal(report.devices.length, 0);
    assert.equal(report.windowStart, "");
    assert.equal(report.windowEnd, "");
  });

  it("tracks a device present in every scan as one continuous session", () => {
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [
        { ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:01", vendor: "Acme" },
      ]),
      makeScan("s2", "2025-01-01T11:00:00Z", [
        { ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:01", vendor: "Acme" },
      ]),
      makeScan("s3", "2025-01-01T12:00:00Z", [
        { ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:01", vendor: "Acme" },
      ]),
    ];
    const report = buildPresenceReport(scans);
    assert.equal(report.totalScans, 3);
    assert.equal(report.devices.length, 1);

    const d = report.devices[0];
    assert.equal(d.mac, "aa:bb:cc:dd:ee:01");
    assert.equal(d.scanCount, 3);
    assert.equal(d.presenceRatio, 1);
    assert.equal(d.currentlyPresent, true);
    assert.equal(d.sessions.length, 1);
    assert.equal(d.sessions[0].start, "2025-01-01T10:00:00Z");
    assert.equal(d.sessions[0].end, "2025-01-01T12:00:00Z");
    assert.equal(d.sessions[0].scanCount, 3);
  });

  it("splits sessions when a device is missing from an intermediate scan", () => {
    const mac = "aa:bb:cc:dd:ee:02";
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [{ ip: "192.168.1.11", mac }]),
      makeScan("s2", "2025-01-01T11:00:00Z", []), // device absent
      makeScan("s3", "2025-01-01T12:00:00Z", [{ ip: "192.168.1.11", mac }]),
      makeScan("s4", "2025-01-01T13:00:00Z", [{ ip: "192.168.1.11", mac }]),
    ];
    const report = buildPresenceReport(scans);
    const d = report.devices.find((x) => x.mac === mac);
    assert.ok(d, "device should be tracked");
    assert.equal(d.scanCount, 3);
    assert.equal(d.sessions.length, 2);
    assert.equal(d.sessions[0].scanCount, 1);
    assert.equal(d.sessions[0].start, "2025-01-01T10:00:00Z");
    assert.equal(d.sessions[1].scanCount, 2);
    assert.equal(d.sessions[1].start, "2025-01-01T12:00:00Z");
    assert.equal(d.sessions[1].end, "2025-01-01T13:00:00Z");
    assert.equal(d.currentlyPresent, true);
  });

  it("marks a device absent in the final scan as not currently present", () => {
    const mac = "aa:bb:cc:dd:ee:03";
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [{ ip: "192.168.1.12", mac }]),
      makeScan("s2", "2025-01-01T11:00:00Z", [{ ip: "192.168.1.12", mac }]),
      makeScan("s3", "2025-01-01T12:00:00Z", []), // device left
    ];
    const report = buildPresenceReport(scans);
    const d = report.devices.find((x) => x.mac === mac);
    assert.ok(d);
    assert.equal(d.currentlyPresent, false);
    assert.equal(d.sessions.length, 1);
    assert.equal(d.sessions[0].scanCount, 2);
  });

  it("marks a new device appearing only in the last scan as currently present", () => {
    const newMac = "aa:bb:cc:dd:ee:04";
    const existing = "aa:bb:cc:dd:ee:05";
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [{ ip: "192.168.1.13", mac: existing }]),
      makeScan("s2", "2025-01-01T11:00:00Z", [{ ip: "192.168.1.13", mac: existing }]),
      makeScan("s3", "2025-01-01T12:00:00Z", [
        { ip: "192.168.1.13", mac: existing },
        { ip: "192.168.1.99", mac: newMac, vendor: "NewCo" },
      ]),
    ];
    const report = buildPresenceReport(scans);
    const newDevice = report.devices.find((x) => x.mac === newMac);
    assert.ok(newDevice);
    assert.equal(newDevice.currentlyPresent, true);
    assert.equal(newDevice.scanCount, 1);
    assert.equal(newDevice.firstSeen, "2025-01-01T12:00:00Z");
    assert.equal(newDevice.lastSeen, "2025-01-01T12:00:00Z");
    assert.equal(newDevice.vendors[0], "NewCo");
  });

  it("aggregates metadata across scans (hostnames, vendors, IPs, device types)", () => {
    const mac = "aa:bb:cc:dd:ee:06";
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [
        { ip: "192.168.1.20", mac, hostname: "laptop", vendor: "Apple", deviceType: "computer" },
      ]),
      makeScan("s2", "2025-01-01T11:00:00Z", [
        { ip: "192.168.1.21", mac, hostname: "laptop-2", vendor: "Apple", deviceType: "computer" },
      ]),
      makeScan("s3", "2025-01-01T12:00:00Z", [
        { ip: "192.168.1.21", mac, hostname: "laptop-2", vendor: "Apple Inc.", deviceType: "computer" },
      ]),
    ];
    const report = buildPresenceReport(scans);
    const d = report.devices.find((x) => x.mac === mac);
    assert.ok(d);
    assert.deepEqual(d.hostnames.sort(), ["laptop", "laptop-2"]);
    assert.deepEqual(d.vendors.sort(), ["Apple", "Apple Inc."]);
    assert.deepEqual(d.ips.sort(), ["192.168.1.20", "192.168.1.21"]);
    assert.deepEqual(d.deviceTypes, ["computer"]);
  });

  it("flags a device as camera if any scan marks it so", () => {
    const mac = "aa:bb:cc:dd:ee:07";
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [{ ip: "192.168.1.30", mac }]),
      makeScan("s2", "2025-01-01T11:00:00Z", [{ ip: "192.168.1.30", mac, isCamera: true }]),
      makeScan("s3", "2025-01-01T12:00:00Z", [{ ip: "192.168.1.30", mac }]),
    ];
    const report = buildPresenceReport(scans);
    const d = report.devices.find((x) => x.mac === mac);
    assert.ok(d);
    assert.equal(d.isCamera, true);
  });

  it("normalises MAC case and separators so the same device is not tracked twice", () => {
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [
        { ip: "192.168.1.40", mac: "AA:BB:CC:DD:EE:08" },
      ]),
      makeScan("s2", "2025-01-01T11:00:00Z", [
        { ip: "192.168.1.40", mac: "aa-bb-cc-dd-ee-08" },
      ]),
    ];
    const report = buildPresenceReport(scans);
    assert.equal(report.devices.length, 1);
    assert.equal(report.devices[0].mac, "aa:bb:cc:dd:ee:08");
    assert.equal(report.devices[0].scanCount, 2);
  });

  it("filters by SSID when an ssid option is supplied", () => {
    const mac = "aa:bb:cc:dd:ee:09";
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [{ ip: "192.168.1.50", mac }], "Home"),
      makeScan("s2", "2025-01-01T11:00:00Z", [{ ip: "192.168.1.50", mac }], "Cafe"),
      makeScan("s3", "2025-01-01T12:00:00Z", [{ ip: "192.168.1.50", mac }], "Home"),
    ];
    const report = buildPresenceReport(scans, { ssid: "Home" });
    assert.equal(report.totalScans, 2);
    assert.equal(report.ssidFilter, "Home");
    const d = report.devices.find((x) => x.mac === mac);
    assert.ok(d);
    assert.equal(d.scanCount, 2);
  });

  it("sorts scans chronologically regardless of input order", () => {
    const mac = "aa:bb:cc:dd:ee:10";
    const scans = [
      makeScan("s2", "2025-01-01T11:00:00Z", [{ ip: "192.168.1.60", mac }]),
      makeScan("s1", "2025-01-01T10:00:00Z", [{ ip: "192.168.1.60", mac }]),
      makeScan("s3", "2025-01-01T12:00:00Z", [{ ip: "192.168.1.60", mac }]),
    ];
    const report = buildPresenceReport(scans);
    assert.equal(report.windowStart, "2025-01-01T10:00:00Z");
    assert.equal(report.windowEnd, "2025-01-01T12:00:00Z");
    const d = report.devices.find((x) => x.mac === mac);
    assert.ok(d);
    assert.equal(d.sessions.length, 1);
    assert.equal(d.firstSeen, "2025-01-01T10:00:00Z");
    assert.equal(d.lastSeen, "2025-01-01T12:00:00Z");
  });

  it("sorts devices by most recently seen first", () => {
    const scans = [
      makeScan("s1", "2025-01-01T10:00:00Z", [
        { ip: "192.168.1.70", mac: "aa:bb:cc:dd:ee:11" },
        { ip: "192.168.1.71", mac: "aa:bb:cc:dd:ee:12" },
      ]),
      makeScan("s2", "2025-01-01T11:00:00Z", [
        { ip: "192.168.1.71", mac: "aa:bb:cc:dd:ee:12" },
      ]),
    ];
    const report = buildPresenceReport(scans);
    assert.equal(report.devices[0].mac, "aa:bb:cc:dd:ee:12");
    assert.equal(report.devices[1].mac, "aa:bb:cc:dd:ee:11");
  });
});
