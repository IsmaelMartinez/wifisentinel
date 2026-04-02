import { z } from "zod";

// --- DNS ---

export const DnsRecord = z.object({
  type: z.string(),
  name: z.string(),
  value: z.string(),
  ttl: z.number(),
});
export type DnsRecord = z.infer<typeof DnsRecord>;

export const DnsRecon = z.object({
  domain: z.string(),
  records: z.array(DnsRecord),
  subdomains: z.array(
    z.object({ name: z.string(), ips: z.array(z.string()) })
  ),
  zoneTransfer: z.object({
    attempted: z.boolean(),
    vulnerable: z.boolean(),
    server: z.string().optional(),
  }),
  nameservers: z.array(z.string()),
});
export type DnsRecon = z.infer<typeof DnsRecon>;

// --- TLS ---

export const TlsRecon = z.object({
  domain: z.string(),
  protocol: z.string(),
  cipher: z.string(),
  certificate: z.object({
    issuer: z.string(),
    subject: z.string(),
    validFrom: z.string(),
    validTo: z.string(),
    daysUntilExpiry: z.number(),
    selfSigned: z.boolean(),
    sans: z.array(z.string()),
  }),
  chainDepth: z.number(),
  grade: z.enum(["A", "B", "C", "D", "F"]),
  issues: z.array(z.string()),
});
export type TlsRecon = z.infer<typeof TlsRecon>;

// --- Headers ---

export const HeaderCheck = z.object({
  header: z.string(),
  present: z.boolean(),
  value: z.union([z.string(), z.null()]),
  status: z.enum(["pass", "fail", "missing"]),
  detail: z.string(),
});
export type HeaderCheck = z.infer<typeof HeaderCheck>;

export const HeadersRecon = z.object({
  domain: z.string(),
  url: z.string(),
  statusCode: z.number(),
  headers: z.array(HeaderCheck),
  score: z.number(),
  grade: z.enum(["A", "B", "C", "D", "F"]),
});
export type HeadersRecon = z.infer<typeof HeadersRecon>;

// --- WHOIS ---

export const WhoisRecon = z.object({
  domain: z.string(),
  registrar: z.union([z.string(), z.null()]),
  createdDate: z.union([z.string(), z.null()]),
  expiryDate: z.union([z.string(), z.null()]),
  updatedDate: z.union([z.string(), z.null()]),
  nameservers: z.array(z.string()),
  dnssec: z.boolean(),
  registrant: z.union([z.string(), z.null()]),
});
export type WhoisRecon = z.infer<typeof WhoisRecon>;

// --- Shodan ---

export const ShodanService = z.object({
  port: z.number(),
  transport: z.string(),
  product: z.string(),
  version: z.string(),
});
export type ShodanService = z.infer<typeof ShodanService>;

export const ShodanRecon = z.object({
  ip: z.string(),
  openPorts: z.array(z.number()),
  services: z.array(ShodanService),
  vulns: z.array(z.string()),
  lastScanDate: z.union([z.string(), z.null()]),
  isp: z.union([z.string(), z.null()]),
  os: z.union([z.string(), z.null()]),
});
export type ShodanRecon = z.infer<typeof ShodanRecon>;

// --- Censys ---

export const CensysService = z.object({
  port: z.number(),
  transportProtocol: z.string(),
  serviceName: z.string(),
});
export type CensysService = z.infer<typeof CensysService>;

export const CensysRecon = z.object({
  services: z.array(CensysService),
  certificates: z.array(z.string()),
  autonomousSystem: z.union([z.string(), z.null()]),
  location: z.union([z.string(), z.null()]),
});
export type CensysRecon = z.infer<typeof CensysRecon>;

// --- Certificate Transparency ---

export const CrtEntry = z.object({
  commonName: z.string(),
  issuer: z.string(),
  notBefore: z.string(),
  notAfter: z.string(),
});
export type CrtEntry = z.infer<typeof CrtEntry>;

export const CrtRecon = z.object({
  domain: z.string(),
  entries: z.array(CrtEntry),
  uniqueSubdomains: z.array(z.string()),
});
export type CrtRecon = z.infer<typeof CrtRecon>;

// --- Combined Result ---

export const ReconResult = z.object({
  meta: z.object({
    reconId: z.string(),
    timestamp: z.string(),
    duration: z.number(),
    domain: z.string(),
  }),
  dns: DnsRecon,
  tls: TlsRecon,
  headers: HeadersRecon,
  whois: WhoisRecon,
  crt: CrtRecon,
  shodan: ShodanRecon.optional(),
  censys: CensysRecon.optional(),
});
export type ReconResult = z.infer<typeof ReconResult>;
