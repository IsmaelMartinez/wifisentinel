import { runAsync } from "../exec.js";
import type { DnsRecon, DnsRecord } from "./schema.js";
import { mapLimit } from "../util.js";

const DOMAIN_REGEX = /^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?)*\.?$/;
const HOSTNAME_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$/;

const RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"] as const;

const DIG_CONCURRENCY = 8;

const SUBDOMAIN_PREFIXES = [
  "www",
  "mail",
  "ftp",
  "api",
  "dev",
  "staging",
  "admin",
  "vpn",
  "remote",
  "cdn",
  "app",
  "test",
  "blog",
  "shop",
  "portal",
];

function parseDigRecords(output: string, type: string): DnsRecord[] {
  const records: DnsRecord[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    // Skip comments, blank lines, and non-record lines
    if (!trimmed || trimmed.startsWith(";") || trimmed.startsWith(";;")) continue;

    // Standard dig output format: name TTL IN TYPE value
    const match = trimmed.match(/^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.+)$/);
    if (match && match[3] === type) {
      records.push({
        type,
        name: match[1],
        value: match[4].trim(),
        ttl: parseInt(match[2], 10),
      });
    }
  }
  return records;
}

async function queryRecords(domain: string, type: string): Promise<DnsRecord[]> {
  const result = await runAsync("dig", ["+noall", "+answer", domain, type], 10_000);
  if (result.exitCode !== 0) return [];
  return parseDigRecords(result.stdout, type);
}

async function discoverSubdomains(
  domain: string
): Promise<Array<{ name: string; ips: string[] }>> {
  const results = await mapLimit(SUBDOMAIN_PREFIXES, DIG_CONCURRENCY, async (prefix) => {
    const fqdn = `${prefix}.${domain}`;
    const result = await runAsync("dig", ["+short", fqdn, "A"], 5_000);
    if (result.exitCode !== 0 || !result.stdout) return null;

    const ips = result.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith(";") && /^[\d.]+$/.test(l));

    return ips.length > 0 ? { name: fqdn, ips } : null;
  });
  return results.filter((r): r is { name: string; ips: string[] } => r !== null);
}

async function attemptZoneTransfer(
  domain: string,
  nameservers: string[]
): Promise<{ attempted: boolean; vulnerable: boolean; server?: string }> {
  if (nameservers.length === 0) {
    return { attempted: false, vulnerable: false };
  }

  for (const ns of nameservers) {
    // Strip trailing dot from NS record value
    const server = ns.replace(/\.$/, "");
    if (!HOSTNAME_REGEX.test(server)) continue;
    const result = await runAsync("dig", ["axfr", `@${server}`, domain], 15_000);

    // A successful zone transfer contains record lines (not just SOA or error)
    if (result.exitCode === 0 && result.stdout) {
      const lines = result.stdout.split("\n").filter(
        (l) => l.trim() && !l.startsWith(";") && !l.startsWith(";;")
      );
      // A real zone transfer has multiple records beyond the two SOA bookends
      if (lines.length > 2) {
        return { attempted: true, vulnerable: true, server };
      }
    }
  }

  return { attempted: true, vulnerable: false };
}

export async function scanDns(domain: string, options?: { zoneTransfer?: boolean }): Promise<DnsRecon> {
  if (!DOMAIN_REGEX.test(domain)) {
    return { domain, records: [], subdomains: [], zoneTransfer: { attempted: false, vulnerable: false }, nameservers: [] };
  }

  const records: DnsRecord[] = (
    await Promise.all(RECORD_TYPES.map((type) => queryRecords(domain, type)))
  ).flat();

  const nameservers = records
    .filter((r) => r.type === "NS")
    .map((r) => r.value);

  const [subdomains, zoneTransfer] = await Promise.all([
    discoverSubdomains(domain),
    options?.zoneTransfer
      ? attemptZoneTransfer(domain, nameservers)
      : { attempted: false, vulnerable: false },
  ]);

  return {
    domain,
    records,
    subdomains,
    zoneTransfer,
    nameservers: nameservers.map((ns) => ns.replace(/\.$/, "")),
  };
}
