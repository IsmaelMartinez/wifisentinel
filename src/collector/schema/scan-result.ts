import { z } from "zod";

export const ToolTier = z.enum(["preferred", "fallback", "minimal"]);
export type ToolTier = z.infer<typeof ToolTier>;

export const ResolvedTool = z.object({
  name: z.string(),
  path: z.string(),
  tier: ToolTier,
});
export type ResolvedTool = z.infer<typeof ResolvedTool>;

const NearbyNetwork = z.object({
  ssid: z.string().nullable(),
  bssid: z.string().optional(),
  security: z.string(),
  protocol: z.string(),
  channel: z.number(),
  signal: z.number(),
  noise: z.number(),
});

const Host = z.object({
  ip: z.string(),
  mac: z.string(),
  vendor: z.string().optional(),
  hostname: z.string().optional(),
  ports: z
    .array(
      z.object({
        port: z.number(),
        service: z.string(),
        state: z.string(),
      })
    )
    .optional(),
  deviceType: z.string().optional(),
  isCamera: z.boolean().optional(),
  cameraIndicators: z.array(z.string()).optional(),
});

const LocalService = z.object({
  port: z.number(),
  process: z.string(),
  bindAddress: z.string(),
  exposedToNetwork: z.boolean(),
});

const TopDestination = z.object({
  ip: z.string(),
  count: z.number(),
  reverseDns: z.string().optional(),
});

export const NetworkScanResult = z.object({
  meta: z.object({
    scanId: z.string(),
    timestamp: z.string(),
    duration: z.number(),
    hostname: z.string(),
    platform: z.enum(["darwin", "linux", "win32"]),
    toolchain: z.record(z.string(), z.string().nullable()),
  }),

  wifi: z.object({
    ssid: z.string().nullable(),
    bssid: z.string(),
    protocol: z.string(),
    channel: z.number(),
    band: z.string(),
    width: z.string(),
    security: z.string(),
    signal: z.number(),
    noise: z.number(),
    snr: z.number(),
    txRate: z.number(),
    macRandomised: z.boolean(),
    countryCode: z.string(),
    nearbyNetworks: z.array(NearbyNetwork),
  }),

  network: z.object({
    interface: z.string(),
    ip: z.string(),
    subnet: z.string(),
    gateway: z.object({
      ip: z.string(),
      mac: z.string(),
      vendor: z.string().optional(),
    }),
    topology: z.object({
      doubleNat: z.boolean(),
      hops: z.array(
        z.object({
          ip: z.string(),
          hostname: z.string().optional(),
          latencyMs: z.number(),
        })
      ),
    }),
    dns: z.object({
      servers: z.array(z.string()),
      anomalies: z.array(z.string()),
      dnssecSupported: z.boolean(),
      dohDotEnabled: z.boolean(),
      hijackTestResult: z.enum(["clean", "intercepted", "unknown"]),
    }),
    hosts: z.array(Host),
  }),

  localServices: z.array(LocalService),

  security: z.object({
    firewall: z.object({
      enabled: z.boolean(),
      stealthMode: z.boolean(),
      autoAllowSigned: z.boolean(),
      autoAllowDownloaded: z.boolean(),
    }),
    vpn: z.object({
      installed: z.boolean(),
      active: z.boolean(),
      provider: z.string().optional(),
    }),
    proxy: z.object({
      enabled: z.boolean(),
      server: z.string().optional(),
      port: z.number().optional(),
    }),
    kernelParams: z.object({
      ipForwarding: z.boolean(),
      icmpRedirects: z.boolean(),
    }),
    clientIsolation: z.boolean().nullable(),
  }),

  traffic: z
    .object({
      capturedPackets: z.number(),
      durationSeconds: z.number(),
      protocols: z.record(z.string(), z.number()),
      unencrypted: z.array(
        z.object({ dest: z.string(), port: z.number(), protocol: z.string() })
      ),
      dnsQueries: z.array(
        z.object({
          domain: z.string(),
          server: z.string(),
          dnssec: z.boolean(),
        })
      ),
      mdnsLeaks: z.array(
        z.object({ service: z.string(), host: z.string() })
      ),
    })
    .optional(),

  connections: z.object({
    established: z.number(),
    listening: z.number(),
    timeWait: z.number(),
    topDestinations: z.array(TopDestination),
  }),

  hiddenDevices: z
    .object({
      suspectedCameras: z.array(Host),
      unknownDevices: z.array(Host),
      indicators: z.array(z.string()),
    })
    .optional(),

  intrusionIndicators: z
    .object({
      arpAnomalies: z.array(
        z.object({
          type: z.string(),
          detail: z.string(),
          severity: z.enum(["high", "medium", "low"]),
        })
      ),
      suspiciousHosts: z.array(
        z.object({
          ip: z.string(),
          mac: z.string(),
          reason: z.string(),
          severity: z.enum(["high", "medium", "low"]),
        })
      ),
      scanDetection: z.array(
        z.object({
          source: z.string(),
          type: z.string(),
          detail: z.string(),
        })
      ),
    })
    .optional(),

  speed: z
    .object({
      latency: z.object({
        gatewayMs: z.number(),
        internetMs: z.number(),
        dnsResolutionMs: z.number(),
      }),
      jitter: z.object({
        gatewayMs: z.number(),
        internetMs: z.number(),
      }),
      download: z.object({
        speedMbps: z.number(),
        bytesTransferred: z.number(),
        durationMs: z.number(),
        testUrl: z.string(),
      }),
      upload: z.object({
        speedMbps: z.number(),
        bytesTransferred: z.number(),
        durationMs: z.number(),
        testUrl: z.string(),
      }),
      packetLoss: z.object({
        gatewayPercent: z.number(),
        internetPercent: z.number(),
      }),
      wifiLinkRate: z.number(),
      effectiveUtilisation: z.number(),
      rating: z.enum(["excellent", "good", "fair", "poor", "unusable"]),
    })
    .optional(),
});

export type NetworkScanResult = z.infer<typeof NetworkScanResult>;
export type Host = z.infer<typeof Host>;
export type NearbyNetwork = z.infer<typeof NearbyNetwork>;
