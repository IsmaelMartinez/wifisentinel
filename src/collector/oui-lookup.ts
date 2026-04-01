import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

let ouiDb: Record<string, string> | null = null;

function loadDb(): Record<string, string> {
  if (ouiDb) return ouiDb;
  try {
    const require = createRequire(import.meta.url);
    const dbPath = require.resolve("oui-data/index.json");
    ouiDb = JSON.parse(readFileSync(dbPath, "utf-8"));
    return ouiDb!;
  } catch {
    ouiDb = {};
    return ouiDb;
  }
}

/** Look up a MAC address vendor from the local OUI database. Returns the vendor name or undefined. */
export function lookupVendor(mac: string): string | undefined {
  const db = loadDb();
  const prefix = mac.replace(/[^0-9a-f]/gi, "").toUpperCase().substring(0, 6);
  if (prefix.length < 6) return undefined;
  const entry = db[prefix];
  if (!entry) return undefined;
  // The entry contains the full address block — extract just the first line (company name)
  return entry.split("\n")[0].trim();
}
