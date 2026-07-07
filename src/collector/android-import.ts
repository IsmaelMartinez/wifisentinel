import { z } from "zod";
import type { NetworkScanResult } from "./schema/scan-result.js";
import { normaliseSecurity } from "./schema/security.js";

// A nearby AP as the phone exports it. `band` is phone-only colour — the CLI
// `NearbyNetwork` shape has no band field, so the adapter drops it.
const NearbyNetworkImport = z.object({
  ssid: z.string().nullable().optional(),
  bssid: z.string().nullable().optional(),
  security: z.string().optional(),
  channel: z.number().optional(),
  band: z.string().optional(),
  signal: z.number().optional(),
});

/**
 * Relaxed schema for the JSON the Android companion app exports. It mirrors
 * the Kotlin `LocalScanResult` data class
 * (`android/app/src/main/kotlin/.../scan/LocalScanResult.kt`): field names and
 * value shapes line up so the export is a drop-in for this import path.
 *
 * Everything the phone cannot observe is absent rather than zero-filled, so
 * most sections are optional here. The adapter below expands this subset into
 * a full `NetworkScanResult` with honest sentinels for the missing fields, and
 * flags `meta.partial = true` so downstream consumers know not to read the
 * absent sections as real measurements.
 */
export const AndroidScanImport = z.object({
  meta: z.object({
    scanId: z.string(),
    timestamp: z.string(),
    platform: z.literal("android"),
    partial: z.boolean().optional(),
    appVersion: z.string().optional(),
  }),
  wifi: z
    .object({
      ssid: z.string().nullable().optional(),
      bssid: z.string().nullable().optional(),
      security: z.string().optional(),
      channel: z.number().optional(),
      band: z.string().optional(),
      signal: z.number().optional(),
      txRate: z.number().optional(),
      // Legacy location for the nearby list — exports from app versions before
      // the capture was decoupled nested it under `wifi`. Still accepted so
      // those exports round-trip; the adapter prefers the top-level field
      // below when both are present. See docs/android-companion.md §10.
      nearbyNetworks: z.array(NearbyNetworkImport).nullable().optional(),
    })
    .nullable()
    .optional(),
  // Nearby APs observed by the phone's WifiManager scan (deduped by BSSID and
  // capped on-device), decoupled from the connected-AP capture so a survey
  // taken while disconnected — or with `wifi` redacted/absent — still carries
  // the RF neighbourhood. Null means "not collected": either the scan
  // permission was absent (the scanner returns null) or the export predates
  // the field (a pre-upgrade Room record deserialises to the default null).
  nearbyNetworks: z.array(NearbyNetworkImport).nullable().optional(),
  network: z
    .object({
      ip: z.string().nullable().optional(),
      gatewayIp: z.string().nullable().optional(),
      dnsServers: z.array(z.string()).optional(),
      vpnActive: z.boolean().optional(),
    })
    .nullable()
    .optional(),
  hosts: z
    .array(
      z.object({
        ip: z.string(),
        hostname: z.string().nullable().optional(),
        serviceType: z.string().nullable().optional(),
        openPorts: z.array(z.number()).optional(),
      })
    )
    .optional(),
  latencyMs: z.number().nullable().optional(),
  // Opt-in download speed test. The `.catch(undefined)` keeps the schema's
  // "relaxed" promise: a trimmed or drifted speed section degrades to absent
  // instead of rejecting the whole scan.
  speed: z
    .object({
      download: z.object({
        speedMbps: z.number(),
        bytesTransferred: z.number(),
        durationMs: z.number(),
        testUrl: z.string(),
      }),
    })
    .nullable()
    .optional()
    .catch(undefined),
});

export type AndroidScanImport = z.infer<typeof AndroidScanImport>;

/**
 * Expand an Android companion export into a full `NetworkScanResult`. Fields the
 * phone cannot measure are set to explicit sentinels ("unknown", 0, false, or
 * an empty collection) and the optional deep-scan sections (traffic, hidden
 * devices, intrusion, deauth) are omitted entirely. The always-on latency
 * probe and the opt-in speed test are carried across as a partial `speed`
 * section (`latency.internetMs` and/or `download`). `meta.partial` is set so
 * history/diff/trend/devices can render the record without treating the
 * sentinels as genuine findings.
 */
export function androidImportToScanResult(
  input: AndroidScanImport
): NetworkScanResult {
  const wifi = input.wifi ?? undefined;
  const network = input.network ?? undefined;

  // Nearby capture is decoupled from the connected AP, so it may arrive at the
  // top level even when `wifi` is null (a survey taken while disconnected).
  // Prefer the top-level field; fall back to the legacy `wifi.nearbyNetworks`
  // location for exports that predate the decoupling.
  const nearbyNetworks = input.nearbyNetworks ?? wifi?.nearbyNetworks ?? [];

  // Always-on latency probe + opt-in download → a partial `speed` section
  // (see the docblock above for the degrade-to-absent rationale). The phone's
  // probe is an HTTPS HEAD round-trip, not an ICMP ping — a healthy figure is
  // ~100–400 ms, not ~15 ms — so stamp the method to keep consumers from
  // reading it against ping thresholds.
  const speed: NetworkScanResult["speed"] = {
    ...(typeof input.latencyMs === "number"
      ? { latency: { internetMs: input.latencyMs, method: "https-rtt" as const } }
      : {}),
    ...(input.speed?.download ? { download: input.speed.download } : {}),
  };
  const hasSpeed = Object.keys(speed).length > 0;

  return {
    meta: {
      scanId: input.meta.scanId,
      timestamp: input.meta.timestamp,
      duration: 0,
      hostname: input.meta.appVersion
        ? `android (${input.meta.appVersion})`
        : "android",
      platform: "android",
      partial: true,
      toolchain: {},
    },
    wifi: {
      ssid: wifi?.ssid ?? null,
      bssid: wifi?.bssid ?? "unknown",
      protocol: "unknown",
      channel: wifi?.channel ?? 0,
      band: wifi?.band ?? "unknown",
      width: "unknown",
      // The phone's coarse labels ("Open", "WPA2", …) are folded into the
      // same canonical vocabulary the CLI scanner emits so cross-source
      // comparisons (rogue-AP weaker-security, rf --compare) work — see
      // schema/security.ts. The "unknown" sentinel passes through unchanged.
      security: normaliseSecurity(wifi?.security ?? "unknown"),
      signal: wifi?.signal ?? 0,
      noise: 0,
      snr: 0,
      txRate: wifi?.txRate ?? 0,
      // Not observable from an unprivileged Android app — see
      // docs/android-companion.md §3.
      macRandomised: false,
      countryCode: "",
      // `protocol` and `noise` aren't in the phone's scan results — the same
      // sentinels ("unknown", 0) as the connected-AP fields above. Feeding
      // these through lets the net-engineer channel-congestion insight work
      // on imported scans. Entries missing bssid/channel/signal are dropped
      // (the phone always emits all three — they're non-nullable in
      // `LocalScanResult.NearbyNetwork`): sentinel-filling would misrepresent
      // observable data, e.g. 0 dBm reads as the strongest possible signal.
      // Channel 0 (the phone's own unknown-frequency sentinel) is dropped
      // too — RF consumers place channels numerically, so 0 would count as
      // 2.4 GHz overlap for channels 1–2 and fabricate congestion.
      nearbyNetworks: nearbyNetworks.flatMap((n) =>
        n.bssid && n.channel !== undefined && n.channel > 0 && n.signal !== undefined
          ? [
              {
                ssid: n.ssid ?? null,
                bssid: n.bssid.toLowerCase(),
                security: normaliseSecurity(n.security ?? "unknown"),
                protocol: "unknown",
                channel: n.channel,
                signal: n.signal,
                noise: 0,
              },
            ]
          : []
      ),
    },
    network: {
      interface: "wlan0",
      ip: network?.ip ?? "unknown",
      subnet: "unknown",
      gateway: {
        ip: network?.gatewayIp ?? "unknown",
        mac: "unknown",
      },
      topology: { doubleNat: false, hops: [] },
      dns: {
        servers: network?.dnsServers ?? [],
        anomalies: [],
        dnssecSupported: false,
        dohDotEnabled: false,
        hijackTestResult: "unknown",
      },
      hosts: (input.hosts ?? []).map((h) => ({
        ip: h.ip,
        mac: "unknown",
        ...(h.hostname ? { hostname: h.hostname } : {}),
        ports: (h.openPorts ?? []).map((port) => ({
          port,
          service: "unknown",
          state: "open",
        })),
      })),
    },
    localServices: [],
    security: {
      firewall: {
        enabled: false,
        stealthMode: false,
        autoAllowSigned: false,
        autoAllowDownloaded: false,
      },
      vpn: {
        installed: network?.vpnActive ?? false,
        active: network?.vpnActive ?? false,
      },
      proxy: { enabled: false },
      kernelParams: { ipForwarding: false, icmpRedirects: false },
      clientIsolation: null,
    },
    connections: {
      established: 0,
      listening: 0,
      timeWait: 0,
      topDestinations: [],
    },
    ...(hasSpeed ? { speed } : {}),
  };
}
