import { run } from "../exec.js";
import type { CrtRecon, CrtEntry } from "./schema.js";

interface CrtShEntry {
  common_name?: string;
  name_value?: string;
  issuer_name?: string;
  not_before?: string;
  not_after?: string;
}

function extractSubdomains(entries: CrtShEntry[], domain: string): string[] {
  const seen = new Set<string>();
  for (const entry of entries) {
    for (const field of [entry.common_name, entry.name_value]) {
      if (!field) continue;
      // name_value can contain newline-separated entries
      for (const name of field.split("\n")) {
        const trimmed = name.trim().toLowerCase();
        if (
          trimmed &&
          trimmed.endsWith(domain.toLowerCase()) &&
          !trimmed.startsWith("*")
        ) {
          seen.add(trimmed);
        }
      }
    }
  }
  return [...seen].sort();
}

export function scanCrt(domain: string): CrtRecon {
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
  const result = run("curl", ["-s", "--max-time", "15", url], 20_000);

  if (result.exitCode !== 0 || !result.stdout) {
    return { domain, entries: [], uniqueSubdomains: [] };
  }

  let raw: CrtShEntry[];
  try {
    raw = JSON.parse(result.stdout) as CrtShEntry[];
  } catch {
    return { domain, entries: [], uniqueSubdomains: [] };
  }

  if (!Array.isArray(raw)) {
    return { domain, entries: [], uniqueSubdomains: [] };
  }

  const entries: CrtEntry[] = raw.map((e) => ({
    commonName: e.common_name ?? "",
    issuer: e.issuer_name ?? "",
    notBefore: e.not_before ?? "",
    notAfter: e.not_after ?? "",
  }));

  const uniqueSubdomains = extractSubdomains(raw, domain);

  return { domain, entries, uniqueSubdomains };
}
