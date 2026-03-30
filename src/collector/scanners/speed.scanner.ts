import { run, runAsync } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";

type SpeedResult = NonNullable<NetworkScanResult["speed"]>;

// Test endpoints — use well-known CDN files for download speed
// These are public speed test files hosted on major CDNs
const DOWNLOAD_URLS = [
  "https://speed.cloudflare.com/__down?bytes=10000000", // 10MB from Cloudflare
  "https://proof.ovh.net/files/1Mb.dat",                // 1MB from OVH
  "http://speedtest.tele2.net/1MB.zip",                  // 1MB from Tele2
];

const UPLOAD_URL = "https://speed.cloudflare.com/__up";

const PING_COUNT = 10;
const PING_TARGETS = {
  gateway: "", // filled at runtime
  internet: "1.1.1.1",
};

interface PingStats {
  avgMs: number;
  minMs: number;
  maxMs: number;
  jitterMs: number;
  lossPercent: number;
}

function parsePingOutput(output: string): PingStats {
  const defaults: PingStats = { avgMs: 0, minMs: 0, maxMs: 0, jitterMs: 0, lossPercent: 100 };

  // Parse packet loss: "X packets transmitted, Y packets received, Z% packet loss"
  const lossMatch = output.match(/([\d.]+)% packet loss/);
  const lossPercent = lossMatch ? parseFloat(lossMatch[1]) : 100;

  // Parse round-trip: "round-trip min/avg/max/stddev = 1.234/5.678/9.012/3.456 ms"
  const rttMatch = output.match(/min\/avg\/max\/stddev\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)/);
  if (!rttMatch) return { ...defaults, lossPercent };

  const minMs = parseFloat(rttMatch[1]);
  const avgMs = parseFloat(rttMatch[2]);
  const maxMs = parseFloat(rttMatch[3]);
  const jitterMs = parseFloat(rttMatch[4]); // stddev is a good jitter approximation

  return { avgMs, minMs, maxMs, jitterMs, lossPercent };
}

async function pingTarget(target: string, count: number): Promise<PingStats> {
  const result = await runAsync("ping", ["-c", String(count), "-W", "2", target], 30_000);
  if (result.exitCode !== 0 && !result.stdout.includes("packet loss")) {
    return { avgMs: 0, minMs: 0, maxMs: 0, jitterMs: 0, lossPercent: 100 };
  }
  return parsePingOutput(result.stdout);
}

async function measureDnsResolution(): Promise<number> {
  const start = Date.now();
  // Resolve a domain that's unlikely to be cached
  const random = Math.random().toString(36).substring(2, 8);
  run("dig", [`${random}.example.com`, "+short", "+time=3"], 5_000);
  // Also measure a real domain
  const start2 = Date.now();
  run("dig", ["cloudflare.com", "+short", "+time=3"], 5_000);
  return Date.now() - start2;
}

interface DownloadResult {
  speedMbps: number;
  bytesTransferred: number;
  durationMs: number;
  testUrl: string;
}

async function measureDownload(): Promise<DownloadResult> {
  // Try each URL until one works
  for (const url of DOWNLOAD_URLS) {
    const result = await runAsync(
      "curl",
      [
        "-s", "-o", "/dev/null",
        "-w", "%{size_download} %{time_total} %{speed_download}",
        "--max-time", "15",
        "-L", // follow redirects
        url,
      ],
      20_000
    );

    if (result.exitCode !== 0) continue;

    const parts = result.stdout.trim().split(/\s+/);
    if (parts.length < 3) continue;

    const bytesTransferred = parseInt(parts[0], 10);
    const timeTotal = parseFloat(parts[1]);
    const speedBytesPerSec = parseFloat(parts[2]);

    if (bytesTransferred < 1000 || timeTotal <= 0) continue;

    return {
      speedMbps: Math.round((speedBytesPerSec * 8 / 1_000_000) * 100) / 100,
      bytesTransferred,
      durationMs: Math.round(timeTotal * 1000),
      testUrl: url,
    };
  }

  return { speedMbps: 0, bytesTransferred: 0, durationMs: 0, testUrl: "none" };
}

async function measureUpload(): Promise<DownloadResult> {
  // Generate 1MB of random-ish data and POST it to Cloudflare's speed test endpoint
  const size = 1_000_000;
  const result = await runAsync(
    "curl",
    [
      "-s", "-o", "/dev/null",
      "-w", "%{size_upload} %{time_total} %{speed_upload}",
      "--max-time", "15",
      "-X", "POST",
      "-H", "Content-Type: application/octet-stream",
      "--data-binary", "@/dev/urandom",
      "--limit-rate", "0",
      "-d", "x".repeat(Math.min(size, 100000)), // 100KB test payload
      UPLOAD_URL,
    ],
    20_000
  );

  if (result.exitCode !== 0 || !result.stdout.trim()) {
    return { speedMbps: 0, bytesTransferred: 0, durationMs: 0, testUrl: UPLOAD_URL };
  }

  const parts = result.stdout.trim().split(/\s+/);
  if (parts.length < 3) {
    return { speedMbps: 0, bytesTransferred: 0, durationMs: 0, testUrl: UPLOAD_URL };
  }

  const bytesTransferred = parseInt(parts[0], 10);
  const timeTotal = parseFloat(parts[1]);
  const speedBytesPerSec = parseFloat(parts[2]);

  return {
    speedMbps: Math.round((speedBytesPerSec * 8 / 1_000_000) * 100) / 100,
    bytesTransferred,
    durationMs: Math.round(timeTotal * 1000),
    testUrl: UPLOAD_URL,
  };
}

function rateSpeed(downloadMbps: number, latencyMs: number): SpeedResult["rating"] {
  if (downloadMbps >= 100 && latencyMs < 20) return "excellent";
  if (downloadMbps >= 50 && latencyMs < 50) return "good";
  if (downloadMbps >= 10 && latencyMs < 100) return "fair";
  if (downloadMbps >= 1) return "poor";
  return "unusable";
}

export async function scanSpeed(
  gatewayIp: string,
  wifiLinkRate: number
): Promise<SpeedResult> {
  // Run latency tests in parallel
  const [gatewayPing, internetPing, dnsMs] = await Promise.all([
    pingTarget(gatewayIp, PING_COUNT),
    pingTarget(PING_TARGETS.internet, PING_COUNT),
    measureDnsResolution(),
  ]);

  // Run throughput tests sequentially (they compete for bandwidth)
  const download = await measureDownload();
  const upload = await measureUpload();

  // Calculate WiFi utilisation (actual speed vs link rate)
  const effectiveUtilisation =
    wifiLinkRate > 0
      ? Math.round((download.speedMbps / wifiLinkRate) * 100 * 10) / 10
      : 0;

  const rating = rateSpeed(download.speedMbps, internetPing.avgMs);

  return {
    latency: {
      gatewayMs: Math.round(gatewayPing.avgMs * 100) / 100,
      internetMs: Math.round(internetPing.avgMs * 100) / 100,
      dnsResolutionMs: dnsMs,
    },
    jitter: {
      gatewayMs: Math.round(gatewayPing.jitterMs * 100) / 100,
      internetMs: Math.round(internetPing.jitterMs * 100) / 100,
    },
    download,
    upload,
    packetLoss: {
      gatewayPercent: gatewayPing.lossPercent,
      internetPercent: internetPing.lossPercent,
    },
    wifiLinkRate,
    effectiveUtilisation,
    rating,
  };
}
