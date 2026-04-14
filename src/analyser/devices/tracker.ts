// src/analyser/devices/tracker.ts — Build device presence timelines from scan history
import type { StoredScan } from "../../store/types.js";
import type { DeviceSession, DeviceTimeline, PresenceReport } from "./types.js";

/** Normalise MAC addresses to lowercase colon-separated form for stable keys. */
export function normaliseMac(mac: string): string {
  return mac.toLowerCase().replace(/-/g, ":").trim();
}

interface DeviceAccumulator {
  mac: string;
  firstSeen: string;
  lastSeen: string;
  scanCount: number;
  currentlyPresent: boolean;
  sessions: DeviceSession[];
  openSession: DeviceSession | null;
  hostnames: Set<string>;
  vendors: Set<string>;
  ips: Set<string>;
  deviceTypes: Set<string>;
  isCamera: boolean;
}

export interface BuildPresenceOptions {
  /** Restrict consideration to scans with this SSID */
  ssid?: string;
}

/**
 * Walk a list of stored scans (in any order) and build per-device presence timelines.
 *
 * A "session" is a run of consecutive scans where the device was observed;
 * the session ends the first time the device is absent from a subsequent scan.
 * A new session starts when the device reappears after being absent.
 */
export function buildPresenceReport(
  scans: StoredScan[],
  opts: BuildPresenceOptions = {},
): PresenceReport {
  let filtered = scans;
  if (opts.ssid !== undefined) {
    filtered = filtered.filter((s) => s.scan.wifi.ssid === opts.ssid);
  }

  const chronological = [...filtered].sort((a, b) =>
    a.scan.meta.timestamp.localeCompare(b.scan.meta.timestamp),
  );

  const totalScans = chronological.length;

  if (totalScans === 0) {
    return {
      windowStart: "",
      windowEnd: "",
      totalScans: 0,
      ssidFilter: opts.ssid,
      devices: [],
    };
  }

  const deviceMap = new Map<string, DeviceAccumulator>();
  const lastIndex = chronological.length - 1;

  for (let i = 0; i < chronological.length; i++) {
    const stored = chronological[i];
    const ts = stored.scan.meta.timestamp;
    const isLatest = i === lastIndex;

    const presentMacs = new Set<string>();
    for (const host of stored.scan.network.hosts) {
      if (!host.mac) continue;
      const mac = normaliseMac(host.mac);
      if (!mac) continue;
      presentMacs.add(mac);

      let device = deviceMap.get(mac);
      if (!device) {
        device = {
          mac,
          firstSeen: ts,
          lastSeen: ts,
          scanCount: 0,
          currentlyPresent: false,
          sessions: [],
          openSession: null,
          hostnames: new Set(),
          vendors: new Set(),
          ips: new Set(),
          deviceTypes: new Set(),
          isCamera: false,
        };
        deviceMap.set(mac, device);
      }

      device.lastSeen = ts;
      device.scanCount++;
      if (host.hostname) device.hostnames.add(host.hostname);
      if (host.vendor) device.vendors.add(host.vendor);
      if (host.ip) device.ips.add(host.ip);
      if (host.deviceType) device.deviceTypes.add(host.deviceType);
      if (host.isCamera) device.isCamera = true;
      if (isLatest) device.currentlyPresent = true;

      if (device.openSession) {
        device.openSession.end = ts;
        device.openSession.scanCount++;
      } else {
        device.openSession = { start: ts, end: ts, scanCount: 1 };
      }
    }

    // Close sessions for any device that did not appear in this scan
    for (const [mac, device] of deviceMap) {
      if (!presentMacs.has(mac) && device.openSession) {
        device.sessions.push(device.openSession);
        device.openSession = null;
      }
    }
  }

  // Flush any sessions still open at the end of the window
  for (const device of deviceMap.values()) {
    if (device.openSession) {
      device.sessions.push(device.openSession);
      device.openSession = null;
    }
  }

  const devices: DeviceTimeline[] = Array.from(deviceMap.values()).map((d) => ({
    mac: d.mac,
    firstSeen: d.firstSeen,
    lastSeen: d.lastSeen,
    scanCount: d.scanCount,
    totalScans,
    presenceRatio: d.scanCount / totalScans,
    currentlyPresent: d.currentlyPresent,
    sessions: d.sessions,
    hostnames: Array.from(d.hostnames),
    vendors: Array.from(d.vendors),
    ips: Array.from(d.ips),
    deviceTypes: Array.from(d.deviceTypes),
    isCamera: d.isCamera,
  }));

  // Most recently seen first; within ties, stable by MAC for determinism
  devices.sort((a, b) => {
    const cmp = b.lastSeen.localeCompare(a.lastSeen);
    return cmp !== 0 ? cmp : a.mac.localeCompare(b.mac);
  });

  return {
    windowStart: chronological[0].scan.meta.timestamp,
    windowEnd: chronological[lastIndex].scan.meta.timestamp,
    totalScans,
    ssidFilter: opts.ssid,
    devices,
  };
}
