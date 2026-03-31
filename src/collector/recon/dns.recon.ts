import { run } from "../exec.js";
import type { DnsRecon, DnsRecord } from "./schema.js";

const RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"] as const;

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

function parseDigRecords(output: string, type: string, domain: string): DnsRecord[] {
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

function queryRecords(domain: string, type: string): DnsRecord[] {
  const result = run("dig", ["+noall", "+answer", domain, type], 10_000);
  if (result.exitCode !== 0) return [];
  return parseDigRecords(result.stdout, type, domain);
}

function discoverSubdomains(
  domain: string
): Array<{ name: string; ips: string[] }> {
  const found: Array<{ name: string; ips: string[] }> = [];
  for (const prefix of SUBDOMAIN_PREFIXES) {
    const fqdn = `${prefix}.${domain}`;
    const result = run("dig", ["+short", fqdn, "A"], 5_000);
    if (result.exitCode !== 0 || !result.stdout) continue;

    const ips = result.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith(";") && /^[\d.]+$/.test(l));

    if (ips.length > 0) {
      found.push({ name: fqdn, ips });
    }
  }
  return found;
}

function attemptZoneTransfer(
  domain: string,
  nameservers: string[]
): { attempted: boolean; vulnerable: boolean; server?: string } {
  if (nameservers.length === 0) {
    return { attempted: false, vulnerable: false };
  }

  for (const ns of nameservers) {
    // Strip trailing dot from NS record value
    const server = ns.replace(/\.$/, "");
    const result = run("dig", ["axfr", `@${server}`, domain], 15_000);

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

export function scanDns(domain: string): DnsRecon {
  const records: DnsRecord[] = [];

  for (const type of RECORD_TYPES) {
    records.push(...queryRecords(domain, type));
  }

  const nameservers = records
    .filter((r) => r.type === "NS")
    .map((r) => r.value);

  const subdomains = discoverSubdomains(domain);
  const zoneTransfer = attemptZoneTransfer(domain, nameservers);

  return {
    domain,
    records,
    subdomains,
    zoneTransfer,
    nameservers: nameservers.map((ns) => ns.replace(/\.$/, "")),
  };
}
