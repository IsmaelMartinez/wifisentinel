import { run } from "../exec.js";
import type { WhoisRecon } from "./schema.js";

function firstMatch(output: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = output.match(pattern);
    if (match?.[1]?.trim()) return match[1].trim();
  }
  return null;
}

function parseNameservers(output: string): string[] {
  const servers: string[] = [];
  const regex = /(?:Name\s*Server|nserver|nameserver)\s*[:.]?\s*(\S+)/gi;
  let match;
  while ((match = regex.exec(output)) !== null) {
    const ns = match[1].toLowerCase().replace(/\.$/, "");
    if (ns && !servers.includes(ns)) servers.push(ns);
  }
  return servers;
}

function parseDnssec(output: string): boolean {
  const dnssecLine = firstMatch(output, [
    /DNSSEC\s*:\s*(.+)/i,
    /dnssec\s*:\s*(.+)/i,
  ]);
  if (!dnssecLine) return false;
  const lower = dnssecLine.toLowerCase();
  return lower.includes("signed") || lower === "yes" || lower === "true";
}

export function scanWhois(domain: string): WhoisRecon {
  const result = run("whois", [domain], 20_000);

  if (result.exitCode !== 0 && !result.stdout) {
    return {
      domain,
      registrar: null,
      createdDate: null,
      expiryDate: null,
      updatedDate: null,
      nameservers: [],
      dnssec: false,
      registrant: null,
    };
  }

  const output = result.stdout;

  const registrar = firstMatch(output, [
    /Registrar\s*:\s*(.+)/i,
    /registrar name\s*:\s*(.+)/i,
    /Sponsoring Registrar\s*:\s*(.+)/i,
  ]);

  const createdDate = firstMatch(output, [
    /Creation Date\s*:\s*(.+)/i,
    /Created\s*:\s*(.+)/i,
    /Registration Date\s*:\s*(.+)/i,
    /created\s*:\s*(.+)/i,
    /Registered on\s*:\s*(.+)/i,
  ]);

  const expiryDate = firstMatch(output, [
    /Registry Expiry Date\s*:\s*(.+)/i,
    /Expir(?:y|ation) Date\s*:\s*(.+)/i,
    /Expiry date\s*:\s*(.+)/i,
    /paid-till\s*:\s*(.+)/i,
    /Expiry\s*:\s*(.+)/i,
  ]);

  const updatedDate = firstMatch(output, [
    /Updated Date\s*:\s*(.+)/i,
    /Last Modified\s*:\s*(.+)/i,
    /Last Updated\s*:\s*(.+)/i,
    /last-modified\s*:\s*(.+)/i,
    /changed\s*:\s*(.+)/i,
  ]);

  const nameservers = parseNameservers(output);
  const dnssec = parseDnssec(output);

  const registrant = firstMatch(output, [
    /Registrant Organi[sz]ation\s*:\s*(.+)/i,
    /Registrant Name\s*:\s*(.+)/i,
    /Registrant\s*:\s*(.+)/i,
    /org-name\s*:\s*(.+)/i,
  ]);

  return {
    domain,
    registrar,
    createdDate,
    expiryDate,
    updatedDate,
    nameservers,
    dnssec,
    registrant,
  };
}
