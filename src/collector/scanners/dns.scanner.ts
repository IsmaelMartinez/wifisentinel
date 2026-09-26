import { runAsync } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";
import { isPrivateIp } from "../util.js";
import { bin } from "../platform/commands.js";
import { resolveCapability } from "../tool-resolver.js";

type DnsResult = NetworkScanResult["network"]["dns"];

const HIJACK_TEST_DOMAIN = "this-domain-should-not-exist-7xk2.com";

/** Generate a random NXDOMAIN test domain that won't appear in DNS logs as a fingerprint */
export function randomHijackDomain(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let sub = "";
  for (let i = 0; i < 12; i++) sub += chars[Math.floor(Math.random() * chars.length)];
  return `${sub}.nxdomain.invalid`;
}
const CLOUDFLARE_DNS = "1.1.1.1";
const TEST_DOMAIN = "google.com";
/** A DNSSEC-signed zone: a validating resolver sets the AD flag on answers for it. */
const DNSSEC_SIGNED_DOMAIN = "cloudflare.com";

/**
 * Parse DNS server IPs from `scutil --dns` output.
 * Looks for lines like: "  nameserver[0] : 192.168.1.1"
 */
function parseScutilDns(output: string): string[] {
  const servers: string[] = [];
  const re = /nameserver\[\d+\]\s*:\s*([\d.:a-fA-F]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(output)) !== null) {
    const ip = m[1].trim();
    if (!servers.includes(ip)) {
      servers.push(ip);
    }
  }
  return servers;
}

/**
 * Returns true if the value looks like a valid IP address (hijack detected).
 */
function isIpAddress(value: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value.trim()) ||
    (/^[0-9a-fA-F:]+$/.test(value.trim()) && value.includes(":"));
}

/**
 * Run a dig query and return trimmed stdout.
 * Uses: dig @server domain type +short [extraFlags...]
 */
async function digShort(server: string, domain: string, type: string, extraFlags: string[] = []): Promise<string> {
  const result = await runAsync(bin("dig"), ["@" + server, domain, type, "+short", ...extraFlags]);
  return result.stdout.trim();
}

/**
 * True when dig's header shows the AD (authenticated data) flag, i.e. the
 * resolver validated the answer with DNSSEC.
 * Header line: ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, ..."
 */
export function hasAdFlag(digOutput: string): boolean {
  const flags = /^;; flags:([^;\n]*);/m.exec(digOutput);
  if (!flags) return false;
  return flags[1].trim().split(/\s+/).includes("ad");
}

/**
 * Test DNSSEC: query a signed zone with +dnssec and check the resolver sets
 * the AD flag. An unsigned zone such as google.com never gets AD, so it
 * cannot be used for this check.
 */
async function testDnssec(server: string): Promise<boolean> {
  const result = await runAsync(bin("dig"), ["@" + server, DNSSEC_SIGNED_DOMAIN, "A", "+dnssec"]);
  if (result.exitCode !== 0) return false;
  return hasAdFlag(result.stdout);
}

/**
 * Hijack test: resolve a domain that should never exist.
 * If we get back an IP, the DNS resolver is intercepting/hijacking queries.
 */
async function testHijack(server: string, stealth = false): Promise<"clean" | "intercepted" | "unknown"> {
  const domain = stealth ? randomHijackDomain() : HIJACK_TEST_DOMAIN;
  const result = await runAsync(bin("dig"), ["@" + server, domain, "A", "+short"]);
  if (result.exitCode !== 0) return "unknown";
  const out = result.stdout.trim();
  if (!out) return "clean";
  const lines = out.split("\n").filter((l) => l.trim().length > 0);
  for (const line of lines) {
    if (isIpAddress(line)) return "intercepted";
  }
  return "clean";
}

/**
 * Detect DNS-over-HTTPS or DNS-over-TLS by checking if the resolver
 * is a known DoH/DoT provider.
 */
function detectDohDot(servers: string[]): boolean {
  const dohDotProviders = new Set([
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "94.140.14.14", "94.140.15.15",
    "185.228.168.9", "185.228.169.9",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
  ]);
  return servers.some((s) => dohDotProviders.has(s));
}

/**
 * DNS leak test: compare resolution results from the gateway DNS vs Cloudflare 1.1.1.1.
 * Only flags genuine anomalies — different IPs for CDN-served domains like google.com
 * are normal (geo-routing). We check for truly suspicious patterns instead.
 */
async function detectDnsLeakAnomalies(gatewayServers: string[], gateway: string): Promise<string[]> {
  const anomalies: string[] = [];
  if (gatewayServers.length === 0) return anomalies;

  for (const server of gatewayServers) {
    if (server === CLOUDFLARE_DNS || server === "8.8.8.8" || server === "8.8.4.4") continue;

    // Check if the server is on a different subnet than the gateway (suspicious)
    const serverParts = server.split(".");
    const gatewayParts = gateway.split(".");
    if (
      serverParts.length === 4 &&
      gatewayParts.length === 4 &&
      isPrivateIp(server) &&
      isPrivateIp(gateway) &&
      (serverParts[0] !== gatewayParts[0] || serverParts[1] !== gatewayParts[1] || serverParts[2] !== gatewayParts[2])
    ) {
      anomalies.push(
        `DNS server ${server} is on a different subnet than gateway ${gateway} — may indicate double NAT or rogue resolver`
      );
    }

    // Check if the server resolves the NX test domain (hijack already caught above,
    // but some resolvers hijack only popular domains)
    const gwResult = await digShort(server, TEST_DOMAIN, "A");
    const gwIps = gwResult.split("\n").filter((l) => l.trim() && isIpAddress(l));
    if (gwIps.length === 0) {
      anomalies.push(`DNS server ${server} returned no results for ${TEST_DOMAIN} — possible filtering or failure`);
    }
  }

  return anomalies;
}

/**
 * Parse nslookup output for DNS server info.
 */
function parseNslookupServer(output: string): string[] {
  const servers: string[] = [];
  const re = /^Server:\s*([\d.:a-fA-F]+)/im;
  const m = output.match(re);
  if (m) servers.push(m[1].trim());
  return servers;
}

export interface DnsScanOptions {
  stealth?: boolean;
  /** Resolved dnsAudit tool name ("dig", "nslookup" or "none"). */
  tool?: string;
}

export async function scanDns(gateway: string, options: DnsScanOptions = {}): Promise<DnsResult> {
  const defaults: DnsResult = {
    servers: [],
    anomalies: [],
    dnssecSupported: false,
    dohDotEnabled: false,
    hijackTestResult: "unknown",
  };

  // Step 1: Get DNS servers from scutil --dns
  let servers: string[] = [];
  const scutilResult = await runAsync(bin("scutil"), ["--dns"]);
  if (scutilResult.exitCode === 0 && scutilResult.stdout.length > 0) {
    servers = parseScutilDns(scutilResult.stdout);
  }

  // Fallback: try resolv.conf
  if (servers.length === 0) {
    const resolvResult = await runAsync("/bin/cat", ["/etc/resolv.conf"]);
    if (resolvResult.exitCode === 0) {
      const re = /^nameserver\s+([\d.:a-fA-F]+)/gim;
      let m: RegExpExecArray | null;
      while ((m = re.exec(resolvResult.stdout)) !== null) {
        const ip = m[1].trim();
        if (!servers.includes(ip)) servers.push(ip);
      }
    }
  }

  const dohDotEnabled = detectDohDot(servers);

  // Step 2: Which DNS tool is available (resolved once by the tool resolver)
  const tool = options.tool ?? resolveCapability("dnsAudit")?.name ?? "none";
  const hasDig = tool === "dig";
  const hasNslookup = tool === "nslookup";

  if (!hasDig && !hasNslookup) {
    // Minimal: scutil --dns only
    return { ...defaults, servers, dohDotEnabled };
  }

  // Step 3: If no servers found yet and we have nslookup, try to get server from it
  if (servers.length === 0 && hasNslookup) {
    const nsResult = await runAsync(bin("nslookup"), [TEST_DOMAIN]);
    if (nsResult.exitCode === 0 || nsResult.stdout.length > 0) {
      servers = parseNslookupServer(nsResult.stdout);
    }
  }

  const testServers = servers.length > 0 ? servers : [gateway];

  // Step 4: Run checks using dig (preferred) or nslookup (fallback)
  let dnssecSupported = false;
  let hijackTestResult: "clean" | "intercepted" | "unknown" = "unknown";
  const anomalies: string[] = [];

  if (hasDig) {
    const primaryServer = testServers[0];

    try {
      dnssecSupported = await testDnssec(primaryServer);
    } catch {
      dnssecSupported = false;
    }

    try {
      hijackTestResult = await testHijack(primaryServer, options.stealth);
      if (hijackTestResult === "intercepted") {
        const domain = options.stealth ? "random NXDOMAIN test" : HIJACK_TEST_DOMAIN;
        anomalies.push(`DNS hijacking detected: ${domain} resolved to an IP via ${primaryServer}`);
      }
    } catch {
      hijackTestResult = "unknown";
    }

    try {
      const leakAnomalies = await detectDnsLeakAnomalies(testServers, gateway);
      anomalies.push(...leakAnomalies);
    } catch {
      // ignore leak detection failures
    }
  } else if (hasNslookup) {
    // Minimal hijack check with nslookup
    const hijackResult = await runAsync(bin("nslookup"), [HIJACK_TEST_DOMAIN]);
    if (hijackResult.exitCode === 0 || hijackResult.stdout.length > 0) {
      const lines = hijackResult.stdout.split("\n");
      // Skip server/address header lines — only look at the answer section
      const answerStart = lines.findIndex((l) => l.trim() === "" || l.startsWith("Non-authoritative"));
      const answerSection = answerStart >= 0 ? lines.slice(answerStart).join("\n") : hijackResult.stdout;
      const addressMatch = /^Address:\s*([\d.]+)/m.exec(answerSection);
      if (addressMatch && isIpAddress(addressMatch[1])) {
        hijackTestResult = "intercepted";
        anomalies.push(`DNS hijacking detected: ${HIJACK_TEST_DOMAIN} resolved via nslookup`);
      } else {
        hijackTestResult = "clean";
      }
    }
  }

  return { servers, anomalies, dnssecSupported, dohDotEnabled, hijackTestResult };
}
