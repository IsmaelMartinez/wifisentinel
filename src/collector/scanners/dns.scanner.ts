import { run } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";

type DnsResult = NetworkScanResult["network"]["dns"];

const HIJACK_TEST_DOMAIN = "this-domain-should-not-exist-7xk2.com";
const CLOUDFLARE_DNS = "1.1.1.1";
const TEST_DOMAIN = "google.com";

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
function digShort(server: string, domain: string, type: string, extraFlags: string[] = []): string {
  const result = run("dig", ["@" + server, domain, type, "+short", ...extraFlags]);
  return result.stdout.trim();
}

/**
 * Test DNSSEC: dig @server google.com A +dnssec +short
 * DNSSEC is considered supported if RRSIG records appear in the response.
 */
function testDnssec(server: string): boolean {
  const result = run("dig", ["@" + server, TEST_DOMAIN, "A", "+dnssec", "+short"]);
  if (result.exitCode !== 0) return false;
  const lines = result.stdout.split("\n").filter((l) => l.trim().length > 0);
  return lines.some((l) => /^A\s|RRSIG|^\S+\s+\d+\s+IN\s+RRSIG/i.test(l)) || lines.length > 1;
}

/**
 * Hijack test: resolve a domain that should never exist.
 * If we get back an IP, the DNS resolver is intercepting/hijacking queries.
 */
function testHijack(server: string): "clean" | "intercepted" | "unknown" {
  const result = run("dig", ["@" + server, HIJACK_TEST_DOMAIN, "A", "+short"]);
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
function detectDnsLeakAnomalies(gatewayServers: string[], gateway: string): string[] {
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
    const gwResult = digShort(server, TEST_DOMAIN, "A");
    const gwIps = gwResult.split("\n").filter((l) => l.trim() && isIpAddress(l));
    if (gwIps.length === 0) {
      anomalies.push(`DNS server ${server} returned no results for ${TEST_DOMAIN} — possible filtering or failure`);
    }
  }

  return anomalies;
}

function isPrivateIp(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
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

export async function scanDns(gateway: string): Promise<DnsResult> {
  const defaults: DnsResult = {
    servers: [],
    anomalies: [],
    dnssecSupported: false,
    dohDotEnabled: false,
    hijackTestResult: "unknown",
  };

  // Step 1: Get DNS servers from scutil --dns
  let servers: string[] = [];
  const scutilResult = run("scutil", ["--dns"]);
  if (scutilResult.exitCode === 0 && scutilResult.stdout.length > 0) {
    servers = parseScutilDns(scutilResult.stdout);
  }

  // Fallback: try resolv.conf
  if (servers.length === 0) {
    const resolvResult = run("/bin/cat", ["/etc/resolv.conf"]);
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

  // Step 2: Determine which DNS tool is available
  const digCheck = run("dig", ["-v"]);
  const hasDig = digCheck.exitCode === 0 || digCheck.stderr.includes("DiG") || digCheck.stdout.includes("DiG");

  const nslookupCheck = run("nslookup", ["-version"]);
  const hasNslookup = nslookupCheck.exitCode === 0 || nslookupCheck.stderr.length > 0;

  if (!hasDig && !hasNslookup) {
    // Minimal: scutil --dns only
    return { ...defaults, servers, dohDotEnabled };
  }

  // Step 3: If no servers found yet and we have nslookup, try to get server from it
  if (servers.length === 0 && hasNslookup) {
    const nsResult = run("nslookup", [TEST_DOMAIN]);
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
      dnssecSupported = testDnssec(primaryServer);
    } catch {
      dnssecSupported = false;
    }

    try {
      hijackTestResult = testHijack(primaryServer);
      if (hijackTestResult === "intercepted") {
        anomalies.push(`DNS hijacking detected: ${HIJACK_TEST_DOMAIN} resolved to an IP via ${primaryServer}`);
      }
    } catch {
      hijackTestResult = "unknown";
    }

    try {
      const leakAnomalies = detectDnsLeakAnomalies(testServers, gateway);
      anomalies.push(...leakAnomalies);
    } catch {
      // ignore leak detection failures
    }
  } else if (hasNslookup) {
    // Minimal hijack check with nslookup
    const hijackResult = run("nslookup", [HIJACK_TEST_DOMAIN]);
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
