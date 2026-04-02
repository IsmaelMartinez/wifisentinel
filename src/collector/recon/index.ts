import { randomUUID } from "node:crypto";
import type { ReconResult } from "./schema.js";
import { scanDns } from "./dns.recon.js";
import { scanTls } from "./tls.recon.js";
import { scanHeaders } from "./headers.recon.js";
import { scanWhois } from "./whois.recon.js";
import { scanCrt } from "./crt.recon.js";
import { reconShodan } from "./shodan.recon.js";
import { reconCensys } from "./censys.recon.js";

export type { ReconResult } from "./schema.js";

export interface ReconOptions {
  verbose?: boolean;
  zoneTransfer?: boolean;
  shodanKey?: string;
  censysId?: string;
  censysSecret?: string;
}

export async function collectRecon(domain: string, options: ReconOptions = {}): Promise<ReconResult> {
  const reconId = randomUUID();
  const startTime = Date.now();
  const log = options.verbose ? (msg: string) => console.error(`[recon] ${msg}`) : () => {};

  log(`Starting reconnaissance for ${domain}...`);

  const shodanKey = options.shodanKey ?? process.env["SHODAN_API_KEY"];
  const censysId = options.censysId ?? process.env["CENSYS_API_ID"];
  const censysSecret = options.censysSecret ?? process.env["CENSYS_API_SECRET"];

  if (!shodanKey) {
    process.stderr.write("Shodan: skipped (SHODAN_API_KEY not set)\n");
  }
  if (!censysId || !censysSecret) {
    process.stderr.write("Censys: skipped (CENSYS_API_ID/CENSYS_API_SECRET not set)\n");
  }

  // Run all scanners in parallel
  const [dns, tls, headers, whois, crt] = await Promise.all([
    Promise.resolve().then(() => { log("DNS enumeration..."); return scanDns(domain, { zoneTransfer: options.zoneTransfer }); }),
    Promise.resolve().then(() => { log("TLS/SSL grading..."); return scanTls(domain); }),
    Promise.resolve().then(() => { log("HTTP headers analysis..."); return scanHeaders(domain); }),
    Promise.resolve().then(() => { log("WHOIS lookup..."); return scanWhois(domain); }),
    Promise.resolve().then(() => { log("Certificate transparency..."); return scanCrt(domain); }),
  ]);

  // Optional enrichment — run conditionally in parallel
  const shodanPromise = shodanKey
    ? (log("Shodan host lookup..."), reconShodan(domain, shodanKey).catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`Shodan: error — ${msg}\n`);
        return undefined;
      }))
    : Promise.resolve(undefined);

  const censysPromise = (censysId && censysSecret)
    ? (log("Censys search..."), reconCensys(domain, censysId, censysSecret).catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`Censys: error — ${msg}\n`);
        return undefined;
      }))
    : Promise.resolve(undefined);

  const [shodan, censys] = await Promise.all([shodanPromise, censysPromise]);

  const duration = Date.now() - startTime;
  log(`Recon complete in ${duration}ms`);

  return {
    meta: { reconId, timestamp: new Date().toISOString(), duration, domain },
    dns, tls, headers, whois, crt,
    ...(shodan !== undefined ? { shodan } : {}),
    ...(censys !== undefined ? { censys } : {}),
  };
}
