// src/analyser/devices/types.ts — Device presence tracking types
export interface DeviceSession {
  /** ISO timestamp of the first scan in this session */
  start: string;
  /** ISO timestamp of the last scan in this session */
  end: string;
  /** Number of consecutive scans the device was present in */
  scanCount: number;
}

export interface DeviceTimeline {
  /** Normalised MAC address (lowercase, colon-separated) */
  mac: string;
  /** First timestamp the device ever appeared in the window */
  firstSeen: string;
  /** Most recent timestamp the device appeared in the window */
  lastSeen: string;
  /** Number of scans in the window where the device was present */
  scanCount: number;
  /** Total scans in the window (for ratio calculation) */
  totalScans: number;
  /** scanCount / totalScans, in range [0, 1] */
  presenceRatio: number;
  /** Whether the device was present in the most recent scan */
  currentlyPresent: boolean;
  /** Presence sessions (consecutive scan runs where the device was observed) */
  sessions: DeviceSession[];
  /** Unique hostnames observed for this MAC */
  hostnames: string[];
  /** Unique vendors observed for this MAC */
  vendors: string[];
  /** Unique IPs observed for this MAC (useful for spotting DHCP reassignments) */
  ips: string[];
  /** Unique deviceType strings observed */
  deviceTypes: string[];
  /** True if the device was flagged as a suspected camera in any scan */
  isCamera: boolean;
}

export interface PresenceReport {
  /** Earliest scan timestamp in the window */
  windowStart: string;
  /** Latest scan timestamp in the window */
  windowEnd: string;
  /** Number of scans considered */
  totalScans: number;
  /** SSID filter applied, if any */
  ssidFilter?: string;
  /** Device timelines, sorted by most recently seen first */
  devices: DeviceTimeline[];
}
