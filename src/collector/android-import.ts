import { z } from "zod";
import type { NetworkScanResult } from "./schema/scan-result.js";

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
    })
    .nullable()
    .optional(),
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
});

export type AndroidScanImport = z.infer<typeof AndroidScanImport>;

/**
 * Expand an Android companion export into a full `NetworkScanResult`. Fields the
 * phone cannot measure are set to explicit sentinels ("unknown", 0, false, or
 * an empty collection) and the optional deep-scan sections (traffic, hidden
 * devices, intrusion, deauth, speed) are omitted entirely. `meta.partial` is
 * set so history/diff/trend/devices can render the record without treating the
 * sentinels as genuine findings.
 */
export function androidImportToScanResult(
  input: AndroidScanImport
): NetworkScanResult {
  const wifi = input.wifi ?? undefined;
  const network = input.network ?? undefined;

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
      security: wifi?.security ?? "unknown",
      signal: wifi?.signal ?? 0,
      noise: 0,
      snr: 0,
      txRate: wifi?.txRate ?? 0,
      // Not observable from an unprivileged Android app — see
      // docs/android-companion.md §3.
      macRandomised: false,
      countryCode: "",
      nearbyNetworks: [],
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
  };
}
