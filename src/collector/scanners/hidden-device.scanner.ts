import type { NetworkScanResult } from "../schema/scan-result.js";

type HiddenDevicesResult = NonNullable<NetworkScanResult["hiddenDevices"]>;
type Host = NetworkScanResult["network"]["hosts"][number];

interface InputHost {
  ip: string;
  mac: string;
  vendor?: string;
  ports?: Array<{ port: number; service: string; state: string }>;
}

// Vendors that ONLY make cameras/surveillance — high confidence
const CAMERA_ONLY_VENDORS = [
  "Hikvision", "Dahua", "Reolink", "Amcrest", "Arlo",
  "Axis Communications", "Vivotek", "Hanwha", "FLIR",
  "Lorex", "Swann", "Annke", "Foscam", "Wansview",
  "YI Technology",
];

// Vendors that make cameras AND other devices — only flag if combined with camera ports
const MIXED_VENDORS = [
  "TP-Link", "Xiaomi", "Ring", "Nest", "Eufy", "Wyze",
  "Ubiquiti", "Blink",
];

const RTSP_PORTS = new Set([554, 8554]);
const ONVIF_PORT = 3702;
const HTTP_PORTS = new Set([80, 443, 8080]);
const TYPICAL_SERVER_PORTS = new Set([21, 22, 25, 53, 110, 143, 389, 445, 465, 587, 636, 993, 995, 1433, 3306, 5432, 6379, 27017]);

function isCameraOnlyVendor(vendor: string): boolean {
  const lower = vendor.toLowerCase();
  return CAMERA_ONLY_VENDORS.some((v) => lower.includes(v.toLowerCase()));
}

function isMixedVendor(vendor: string): boolean {
  const lower = vendor.toLowerCase();
  return MIXED_VENDORS.some((v) => lower.includes(v.toLowerCase()));
}

function scoreHost(host: InputHost): { score: number; indicators: string[] } {
  let score = 0;
  const indicators: string[] = [];
  const openPorts = (host.ports ?? []).filter((p) => p.state === "open").map((p) => p.port);
  const portSet = new Set(openPorts);

  if (host.vendor && isCameraOnlyVendor(host.vendor)) {
    score += 50;
    indicators.push(`Camera-only vendor: ${host.vendor}`);
  } else if (host.vendor && isMixedVendor(host.vendor)) {
    // Mixed vendors (TP-Link, Xiaomi, etc.) only get points if camera ports are also open
    const hasCameraPorts = openPorts.some((p) => RTSP_PORTS.has(p) || p === ONVIF_PORT);
    if (hasCameraPorts) {
      score += 30;
      indicators.push(`Mixed vendor with camera ports: ${host.vendor}`);
    }
  }

  const hasRtsp = openPorts.some((p) => RTSP_PORTS.has(p));
  if (hasRtsp) {
    score += 40;
    const rtspPort = openPorts.find((p) => RTSP_PORTS.has(p));
    indicators.push(`RTSP streaming port open (${rtspPort})`);
  }

  if (portSet.has(ONVIF_PORT)) {
    score += 30;
    indicators.push("ONVIF camera discovery port open (3702)");
  }

  const hasHttp = openPorts.some((p) => HTTP_PORTS.has(p));
  const hasTypicalServer = openPorts.some((p) => TYPICAL_SERVER_PORTS.has(p));
  if (hasHttp && !hasTypicalServer && !hasRtsp) {
    score += 10;
    indicators.push("HTTP interface with no typical server ports");
  }

  return { score, indicators };
}

export async function scanHiddenDevices(hosts: InputHost[]): Promise<HiddenDevicesResult> {
  const suspectedCameras: Host[] = [];
  const unknownDevices: Host[] = [];
  const globalIndicators: string[] = [];

  for (const host of hosts) {
    const { score, indicators } = scoreHost(host);
    const openPorts = (host.ports ?? []).filter((p) => p.state === "open");

    if (score >= 40) {
      suspectedCameras.push({
        ip: host.ip,
        mac: host.mac,
        vendor: host.vendor,
        ports: host.ports,
        isCamera: true,
        cameraIndicators: indicators,
      });
      globalIndicators.push(`${host.ip} (${host.vendor ?? "unknown vendor"}): suspected camera — ${indicators.join(", ")}`);
    } else if (!host.vendor && openPorts.length > 0) {
      unknownDevices.push({
        ip: host.ip,
        mac: host.mac,
        ports: host.ports,
        deviceType: "unknown",
      });
      globalIndicators.push(`${host.ip}: unidentified device with ${openPorts.length} open port(s), no vendor info`);
    }
  }

  return {
    suspectedCameras,
    unknownDevices,
    indicators: globalIndicators,
  };
}
