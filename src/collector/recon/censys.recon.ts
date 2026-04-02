import type { CensysRecon, CensysService } from "./schema.js";

interface CensysHit {
  services?: Array<{
    port?: number;
    transport_protocol?: string;
    service_name?: string;
  }>;
  autonomous_system?: { name?: string };
  location?: { country?: string; city?: string };
  matched_services?: Array<{ certificate?: string }>;
}

interface CensysSearchResponse {
  code?: number;
  status?: string;
  result?: {
    hits?: CensysHit[];
  };
}

export async function reconCensys(domain: string, apiId: string, apiSecret: string): Promise<CensysRecon> {
  const credentials = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
  const url = `https://search.censys.io/api/v2/hosts/search?q=${encodeURIComponent(domain)}`;

  const res = await fetch(url, {
    headers: {
      Authorization: `Basic ${credentials}`,
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    throw new Error(`Censys search failed: ${res.status} ${res.statusText}`);
  }

  const data = await res.json() as CensysSearchResponse;
  const hits = data.result?.hits ?? [];

  if (hits.length === 0) {
    return { services: [], certificates: [], autonomousSystem: null, location: null };
  }

  // Aggregate from all hits
  const services: CensysService[] = [];
  const certSet = new Set<string>();
  let autonomousSystem: string | null = null;
  let location: string | null = null;

  for (const hit of hits) {
    for (const svc of hit.services ?? []) {
      services.push({
        port: svc.port ?? 0,
        transportProtocol: svc.transport_protocol ?? "tcp",
        serviceName: svc.service_name ?? "",
      });
    }

    for (const msvc of hit.matched_services ?? []) {
      if (msvc.certificate) certSet.add(msvc.certificate);
    }

    if (!autonomousSystem && hit.autonomous_system?.name) {
      autonomousSystem = hit.autonomous_system.name;
    }

    if (!location && hit.location) {
      const parts = [hit.location.city, hit.location.country].filter(Boolean);
      if (parts.length > 0) location = parts.join(", ");
    }
  }

  return {
    services,
    certificates: [...certSet],
    autonomousSystem,
    location,
  };
}
