import type { NetworkScanResult } from "../../src/collector/schema/scan-result.js";
import type { ReconResult } from "../../src/collector/recon/schema.js";

/** A hardened scan: every persona and standard check should come out clean. */
export function cleanScan(): NetworkScanResult {
  return {
    meta: {
      scanId: "scan-clean",
      timestamp: "2026-01-01T12:00:00Z",
      duration: 30000,
      hostname: "testhost",
      platform: "darwin",
      toolchain: { packetAnalysis: "tshark", hostDiscovery: "nmap" },
    },
    wifi: {
      ssid: "HomeNet",
      bssid: "AA:BB:CC:DD:EE:FF",
      protocol: "802.11ax",
      channel: 36,
      band: "5GHz",
      width: "80MHz",
      security: "WPA3 Personal",
      signal: -50,
      noise: -95,
      snr: 45,
      txRate: 866,
      macRandomised: true,
      countryCode: "GB",
      nearbyNetworks: [],
    },
    network: {
      interface: "en0",
      ip: "192.168.1.10",
      subnet: "192.168.1.0/24",
      gateway: { ip: "192.168.1.1", mac: "00:11:22:33:44:55", vendor: "Acme" },
      topology: { doubleNat: false, hops: [] },
      dns: {
        servers: ["1.1.1.1"],
        anomalies: [],
        dnssecSupported: true,
        dohDotEnabled: true,
        hijackTestResult: "clean",
      },
      hosts: [],
    },
    localServices: [],
    security: {
      firewall: {
        enabled: true,
        stealthMode: true,
        autoAllowSigned: false,
        autoAllowDownloaded: false,
      },
      vpn: { installed: true, active: true },
      proxy: { enabled: false },
      kernelParams: { ipForwarding: false, icmpRedirects: false },
      clientIsolation: true,
    },
    traffic: {
      capturedPackets: 100,
      durationSeconds: 10,
      protocols: {},
      unencrypted: [],
      dnsQueries: [],
      mdnsLeaks: [],
    },
    connections: { established: 1, listening: 1, timeWait: 0, topDestinations: [] },
    hiddenDevices: { suspectedCameras: [], unknownDevices: [], indicators: [] },
    intrusionIndicators: { arpAnomalies: [], suspiciousHosts: [], scanDetection: [] },
  };
}

/** A scan that trips most persona insights and standards failures. */
export function noisyScan(): NetworkScanResult {
  const scan = cleanScan();
  scan.meta.scanId = "scan-noisy";
  scan.meta.toolchain = { packetAnalysis: null };
  const camera = {
    ip: "192.168.1.50",
    mac: "11:22:33:44:55:66",
    vendor: "Hikvision",
    ports: [{ port: 554, service: "rtsp", state: "open" }],
    isCamera: true,
    cameraIndicators: ["rtsp"],
  };
  const unknown = { ip: "192.168.1.60", mac: "22:33:44:55:66:77" };
  scan.wifi = {
    ...scan.wifi,
    ssid: "netgear",
    protocol: "802.11g",
    channel: 3,
    band: "2.4GHz",
    width: "40MHz",
    security: "WEP",
    signal: -82,
    noise: -90,
    snr: 8,
    txRate: 24,
    macRandomised: false,
    countryCode: "",
    nearbyNetworks: [
      { ssid: "Cafe", bssid: "01:01:01:01:01:01", security: "Open", protocol: "802.11n", channel: 3, signal: -60, noise: -90 },
      { ssid: null, bssid: "02:02:02:02:02:02", security: "WPA2 Personal", protocol: "802.11n", channel: 3, signal: -70, noise: -90 },
      { ssid: "Other", bssid: "03:03:03:03:03:03", security: "WPA2 Personal", protocol: "802.11n", channel: 3, signal: -75, noise: -90 },
    ],
  };
  scan.network.topology = {
    doubleNat: true,
    hops: [
      { ip: "192.168.1.1", latencyMs: 2 },
      { ip: "10.0.0.1", latencyMs: 5 },
    ],
  };
  scan.network.dns = {
    servers: ["192.168.1.1"],
    anomalies: ["resolver answered NXDOMAIN with an IP"],
    dnssecSupported: false,
    dohDotEnabled: false,
    hijackTestResult: "intercepted",
  };
  scan.network.hosts = [
    {
      ip: "192.168.1.20",
      mac: "33:44:55:66:77:88",
      ports: [
        { port: 23, service: "telnet", state: "open" },
        { port: 80, service: "http", state: "open" },
      ],
    },
    camera,
    unknown,
  ];
  scan.localServices = [
    { port: 8080, process: "node", bindAddress: "0.0.0.0", exposedToNetwork: true },
  ];
  scan.security = {
    firewall: { enabled: false, stealthMode: false, autoAllowSigned: true, autoAllowDownloaded: true },
    vpn: { installed: false, active: false },
    proxy: { enabled: false },
    kernelParams: { ipForwarding: true, icmpRedirects: true },
    clientIsolation: false,
  };
  scan.traffic = {
    capturedPackets: 500,
    durationSeconds: 10,
    protocols: { http: 10 },
    unencrypted: [{ dest: "203.0.113.5", port: 80, protocol: "HTTP" }],
    dnsQueries: [{ domain: "example.com", server: "192.168.1.1", dnssec: false }],
    mdnsLeaks: [{ service: "_airplay._tcp", host: "tv.local" }],
  };
  scan.hiddenDevices = { suspectedCameras: [camera], unknownDevices: [unknown], indicators: [] };
  scan.intrusionIndicators = {
    arpAnomalies: [{ type: "duplicate-mac", detail: "192.168.1.1 and 192.168.1.20", severity: "high" }],
    suspiciousHosts: [{ ip: "192.168.1.20", mac: "33:44:55:66:77:88", reason: "telnet open", severity: "medium" }],
    scanDetection: [],
  };
  scan.speed = {
    latency: { gatewayMs: 60, internetMs: 120, dnsResolutionMs: 150, method: "icmp-ping" },
    jitter: { gatewayMs: 10, internetMs: 40 },
    download: { speedMbps: 2, bytesTransferred: 1000, durationMs: 1000, testUrl: "https://example.com" },
    upload: { speedMbps: 1, bytesTransferred: 1000, durationMs: 1000, testUrl: "https://example.com" },
    packetLoss: { gatewayPercent: 6, internetPercent: 12 },
    wifiLinkRate: 54,
    effectiveUtilisation: 4,
    rating: "poor",
  };
  return scan;
}

function header(name: string, status: "pass" | "fail" | "missing", value: string | null = null) {
  return { header: name, present: status !== "missing", value, status, detail: `${name}: ${status}` };
}

/** A recon result that fails every recon persona check. */
export function weakRecon(): ReconResult {
  return {
    meta: { reconId: "recon-weak", timestamp: "2026-01-01T12:00:00Z", duration: 1000, domain: "example.com" },
    dns: {
      domain: "example.com",
      records: [
        { type: "A", name: "example.com", value: "203.0.113.1", ttl: 60 },
        { type: "AAAA", name: "www.example.com", value: "2001:db8::1", ttl: 172800 },
        { type: "TXT", name: "example.com", value: "hello", ttl: 3600 },
      ],
      subdomains: [],
      zoneTransfer: { attempted: true, vulnerable: true, server: "ns1.example.com" },
      nameservers: ["ns1.example.com"],
    },
    tls: {
      domain: "example.com",
      protocol: "TLSv1.0",
      cipher: "RC4-SHA",
      certificate: {
        issuer: "example.com",
        subject: "example.com",
        validFrom: "2025-01-01",
        validTo: "2026-01-20",
        daysUntilExpiry: 19,
        selfSigned: true,
        sans: [],
      },
      chainDepth: 1,
      grade: "F",
      issues: ["TLS 1.0 enabled"],
    },
    headers: {
      domain: "example.com",
      url: "https://example.com",
      statusCode: 200,
      headers: [
        header("Strict-Transport-Security", "missing"),
        header("Content-Security-Policy", "fail", "default-src *"),
        header("Referrer-Policy", "missing"),
        header("Permissions-Policy", "missing"),
        header("X-Frame-Options", "pass", "DENY"),
        header("Server", "fail", "Apache/2.4.1"),
      ],
      score: 20,
      grade: "D",
    },
    whois: {
      domain: "example.com",
      registrar: "Registrar Inc",
      createdDate: null,
      expiryDate: null,
      updatedDate: null,
      nameservers: ["ns1.example.com"],
      dnssec: false,
      registrant: "Jane Doe",
    },
    crt: {
      domain: "example.com",
      entries: [],
      uniqueSubdomains: ["www.example.com", "staging.example.com", "admin.example.com"],
    },
  };
}

/** A recon result that passes every recon persona check. */
export function strongRecon(): ReconResult {
  const r = weakRecon();
  r.meta.reconId = "recon-strong";
  r.dns.records = [
    { type: "A", name: "example.com", value: "203.0.113.1", ttl: 3600 },
    { type: "MX", name: "example.com", value: "10 mail.example.com", ttl: 3600 },
    { type: "TXT", name: "example.com", value: "v=spf1 -all", ttl: 3600 },
  ];
  r.dns.zoneTransfer = { attempted: true, vulnerable: false };
  r.dns.nameservers = ["ns1.example.com", "ns2.example.com"];
  r.tls = {
    ...r.tls,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    certificate: { ...r.tls.certificate, issuer: "Let's Encrypt", daysUntilExpiry: 80, selfSigned: false },
    grade: "A",
    issues: [],
  };
  r.headers.headers = r.headers.headers.map((h) =>
    h.header === "Server" ? header("Server", "pass") : header(h.header, "pass", "set"),
  );
  r.headers.grade = "A";
  r.whois.dnssec = true;
  r.whois.registrant = "REDACTED FOR PRIVACY";
  r.crt.uniqueSubdomains = ["www.example.com"];
  return r;
}
