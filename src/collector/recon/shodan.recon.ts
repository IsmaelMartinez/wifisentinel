import type { ShodanRecon } from "./schema.js";

interface ShodanHostResponse {
  ip_str?: string;
  ports?: number[];
  data?: Array<{
    port?: number;
    transport?: string;
    product?: string;
    version?: string;
  }>;
  vulns?: Record<string, unknown>;
  last_update?: string;
  isp?: string;
  os?: string | null;
}

export async function reconShodan(domain: string, apiKey: string): Promise<ShodanRecon> {
  // Step 1: resolve domain to IP
  const resolveUrl = `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(domain)}&key=${apiKey}`;
  const resolveRes = await fetch(resolveUrl);
  if (!resolveRes.ok) {
    throw new Error(`Shodan DNS resolve failed: ${resolveRes.status} ${resolveRes.statusText}`);
  }
  const resolveData = await resolveRes.json() as Record<string, string>;
  const ip = resolveData[domain];
  if (!ip) {
    return { ip: "", openPorts: [], services: [], vulns: [], lastScanDate: null, isp: null, os: null };
  }

  // Step 2: fetch host details
  const hostUrl = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`;
  const hostRes = await fetch(hostUrl);
  if (!hostRes.ok) {
    // 404 means no data for this IP
    if (hostRes.status === 404) {
      return { ip, openPorts: [], services: [], vulns: [], lastScanDate: null, isp: null, os: null };
    }
    throw new Error(`Shodan host lookup failed: ${hostRes.status} ${hostRes.statusText}`);
  }

  const host = await hostRes.json() as ShodanHostResponse;

  const openPorts = host.ports ?? [];
  const services = (host.data ?? []).map((d) => ({
    port: d.port ?? 0,
    transport: d.transport ?? "tcp",
    product: d.product ?? "",
    version: d.version ?? "",
  }));
  const vulns = host.vulns ? Object.keys(host.vulns) : [];

  return {
    ip,
    openPorts,
    services,
    vulns,
    lastScanDate: host.last_update ?? null,
    isp: host.isp ?? null,
    os: host.os ?? null,
  };
}
