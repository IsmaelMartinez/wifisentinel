# Phase 5: External Reconnaissance — Design Spec

## Overview

Phase 5 adds external attack surface mapping via a `wifisentinel recon <domain>` command. It analyses a domain's DNS records, subdomains (via cert transparency), TLS/SSL configuration, HTTP security headers, and WHOIS data, then runs the five persona agents against the findings. All tools are standard macOS/Linux CLI utilities (dig, curl, openssl, whois) — no new dependencies.

Shodan/Censys integration is deferred to keep the phase dependency-free.

## Recon Scanner Module

### Location: `src/collector/recon/`

Follows the same pattern as existing network scanners: each sub-scanner runs a CLI tool, parses its output, and returns typed results.

### `dns.recon.ts` — DNS enumeration

Queries the target domain using `dig`:
- Standard record types: A, AAAA, MX, NS, TXT, SOA, CNAME.
- Subdomain discovery: queries a list of common prefixes (www, mail, ftp, api, dev, staging, admin, vpn, remote, cdn, app, test, blog, shop, portal — 15 prefixes) prepended to the domain.
- Zone transfer attempt: `dig axfr @<ns> <domain>` against each NS record. Reports success/failure.

Output type:

```ts
interface DnsRecord {
  type: string;       // A, AAAA, MX, NS, TXT, SOA, CNAME
  name: string;
  value: string;
  ttl: number;
}

interface DnsRecon {
  domain: string;
  records: DnsRecord[];
  subdomains: Array<{ name: string; ips: string[] }>;
  zoneTransfer: { attempted: boolean; vulnerable: boolean; server?: string };
  nameservers: string[];
}
```

### `tls.recon.ts` — TLS/SSL grading

Connects via `openssl s_client` and parses the certificate and connection:
- Protocol version (TLS 1.2, 1.3).
- Cipher suite.
- Certificate issuer, subject, validity dates, days until expiry.
- Certificate chain depth.
- Whether the cert is self-signed.
- SAN (Subject Alternative Names) extraction.

Computes a grade: A (TLS 1.3, valid cert, >30 days), B (TLS 1.2, valid), C (TLS 1.2, weak cipher or <30 days), D (TLS 1.1 or expired cert), F (TLS 1.0, SSL, self-signed, or connection failure).

```ts
interface TlsRecon {
  domain: string;
  protocol: string;
  cipher: string;
  certificate: {
    issuer: string;
    subject: string;
    validFrom: string;
    validTo: string;
    daysUntilExpiry: number;
    selfSigned: boolean;
    sans: string[];
  };
  chainDepth: number;
  grade: "A" | "B" | "C" | "D" | "F";
  issues: string[];
}
```

### `headers.recon.ts` — HTTP security headers

Fetches headers via `curl -sI https://<domain>` and checks for:
- Strict-Transport-Security (HSTS): present, max-age value, includeSubDomains.
- Content-Security-Policy (CSP): present, directives.
- X-Frame-Options: present, value.
- X-Content-Type-Options: present (should be "nosniff").
- Referrer-Policy: present, value.
- Permissions-Policy: present.
- Server header: present (information leak if detailed).

Each header gets a pass/fail/missing status.

```ts
interface HeaderCheck {
  header: string;
  present: boolean;
  value: string | null;
  status: "pass" | "fail" | "missing";
  detail: string;
}

interface HeadersRecon {
  domain: string;
  url: string;
  statusCode: number;
  headers: HeaderCheck[];
  score: number;        // 0-100 based on headers present
  grade: "A" | "B" | "C" | "D" | "F";
}
```

### `whois.recon.ts` — WHOIS lookup

Runs `whois <domain>` and extracts:
- Registrar name.
- Creation date, expiry date, updated date.
- Name servers.
- DNSSEC status.
- Registrant organisation (if not redacted).

```ts
interface WhoisRecon {
  domain: string;
  registrar: string | null;
  createdDate: string | null;
  expiryDate: string | null;
  updatedDate: string | null;
  nameservers: string[];
  dnssec: boolean;
  registrant: string | null;
}
```

### `crt.recon.ts` — Certificate transparency

Queries `https://crt.sh/?q=<domain>&output=json` via curl to discover subdomains from CT logs. Deduplicates and returns unique names.

```ts
interface CrtEntry {
  commonName: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
}

interface CrtRecon {
  domain: string;
  entries: CrtEntry[];
  uniqueSubdomains: string[];
}
```

### `schema.ts` — Combined recon result

```ts
interface ReconResult {
  meta: {
    reconId: string;
    timestamp: string;
    duration: number;
    domain: string;
  };
  dns: DnsRecon;
  tls: TlsRecon;
  headers: HeadersRecon;
  whois: WhoisRecon;
  crt: CrtRecon;
}
```

### `index.ts` — Orchestrator

`collectRecon(domain, options?)` runs all five sub-scanners in parallel, assembles the `ReconResult`, and returns it. Options: `verbose` for progress logging to stderr.

## Persona Analysis

### `src/analyser/recon-personas.ts`

Reuses the persona types from Phase 1b (PersonaAnalysis, Insight, RiskRating). A function `analyseReconAllPersonas(result: ReconResult): FullReconAnalysis` runs analysis logic for each persona:

- Red Team: looks for zone transfer vulnerability, weak TLS, missing security headers, exposed subdomains (dev, staging, admin), short cert expiry.
- Blue Team: checks HSTS, CSP, DNSSEC, certificate chain validity, header completeness.
- Compliance: grades against common frameworks — checks for HSTS (PCI-DSS), TLS 1.2+ (PCI-DSS), security headers (OWASP).
- Net Engineer: checks DNS configuration quality — MX records, SPF/DKIM in TXT, NS redundancy, TTL values.
- Privacy: checks server header information leak, referrer policy, permissions policy, WHOIS privacy.

Uses the same insight/severity/risk types, so the terminal and HTML reporters can render them identically to network scan personas.

```ts
interface FullReconAnalysis {
  reconId: string;
  timestamp: string;
  domain: string;
  analyses: PersonaAnalysis[];
  consensusRating: string;
  consensusActions: string[];
  overallGrade: string;  // A-F based on TLS + headers + DNS
}
```

## CLI Command

### `wifisentinel recon <domain>`

Options:
- `-o, --output <format>`: terminal (default) or json.
- `-f, --file <path>`: write output to file.
- `--analyse`: include persona analysis (like the scan command).
- `--no-save`: skip saving to history.
- `-v, --verbose`: progress output to stderr.

### Reporter

`src/reporter/recon.reporter.ts` — terminal output with the same box-drawing style as the scan report:

- Header: domain, timestamp, duration.
- DNS section: records table, subdomains found, zone transfer status.
- TLS section: grade, protocol, cipher, cert details, issues.
- Headers section: per-header pass/fail table, overall grade.
- WHOIS section: registrar, dates, DNSSEC.
- CT section: subdomain count, notable entries.
- Scorecard: overall grade combining TLS + headers + DNS.

When `--analyse` is used, appends persona analysis sections (same format as network scan analysis).

`src/reporter/recon-json.reporter.ts` — JSON output combining recon result and analysis.

## Store Integration

Recon results saved to `~/.wifisentinel/recons/` as JSON (separate from network scans). An `index.json` manifest in the same directory with entries:

```ts
interface ReconIndexEntry {
  reconId: string;
  timestamp: string;
  domain: string;
  tlsGrade: string;
  headersGrade: string;
  overallGrade: string;
  subdomainCount: number;
  filename: string;
}
```

A `wifisentinel recon-history` command lists past recons.

### Store module: `src/store/recon-store.ts`

Functions: `saveRecon`, `listRecons`, `loadRecon`. Same pattern as the scan store but in a separate directory and with its own index.

## File Structure

New files:

```
src/
  collector/recon/
    schema.ts             — ReconResult, DnsRecon, TlsRecon, etc.
    dns.recon.ts          — DNS enumeration via dig
    tls.recon.ts          — TLS grading via openssl
    headers.recon.ts      — HTTP security headers via curl
    whois.recon.ts        — WHOIS lookup
    crt.recon.ts          — Certificate transparency via crt.sh
    index.ts              — collectRecon orchestrator
  analyser/
    recon-personas.ts     — persona analysis for recon results
  reporter/
    recon.reporter.ts     — terminal output for recon
    recon-json.reporter.ts — JSON output for recon
  store/
    recon-store.ts        — persistence for recon results
  commands/
    recon.ts              — recon CLI command
    recon-history.ts      — recon-history CLI command
```

Modified files:

```
src/cli.ts  — register recon and recon-history commands
```

## Dependencies

No new dependencies. Uses existing dig, curl, openssl, whois CLI tools. All existing patterns (Zod, chalk, commander, exec helper) are reused.

## Out of Scope

- Shodan/Censys integration (requires API keys, deferred).
- Active port scanning of external hosts (legal/ethical concerns).
- Subdomain brute-forcing beyond the 15 common prefixes and CT log results.
- Dashboard integration for recon results (can be added later).
