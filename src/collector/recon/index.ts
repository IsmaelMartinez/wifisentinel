import { randomUUID } from "node:crypto";
import type { ReconResult } from "./schema.js";
import { scanDns } from "./dns.recon.js";
import { scanTls } from "./tls.recon.js";
import { scanHeaders } from "./headers.recon.js";
import { scanWhois } from "./whois.recon.js";
import { scanCrt } from "./crt.recon.js";

export type { ReconResult } from "./schema.js";

export interface ReconOptions {
  verbose?: boolean;
  zoneTransfer?: boolean;
}

export async function collectRecon(domain: string, options: ReconOptions = {}): Promise<ReconResult> {
  const reconId = randomUUID();
  const startTime = Date.now();
  const log = options.verbose ? (msg: string) => console.error(`[recon] ${msg}`) : () => {};

  log(`Starting reconnaissance for ${domain}...`);

  // Run all scanners in parallel
  const [dns, tls, headers, whois, crt] = await Promise.all([
    Promise.resolve().then(() => { log("DNS enumeration..."); return scanDns(domain, { zoneTransfer: options.zoneTransfer }); }),
    Promise.resolve().then(() => { log("TLS/SSL grading..."); return scanTls(domain); }),
    Promise.resolve().then(() => { log("HTTP headers analysis..."); return scanHeaders(domain); }),
    Promise.resolve().then(() => { log("WHOIS lookup..."); return scanWhois(domain); }),
    Promise.resolve().then(() => { log("Certificate transparency..."); return scanCrt(domain); }),
  ]);

  const duration = Date.now() - startTime;
  log(`Recon complete in ${duration}ms`);

  return {
    meta: { reconId, timestamp: new Date().toISOString(), duration, domain },
    dns, tls, headers, whois, crt,
  };
}
