import { createRequire } from "node:module";
import { normaliseMac, isValidMac } from "./mac.js";

let ouiDb: Record<string, string> | null = null;

function loadDb(): Record<string, string> {
  if (ouiDb) return ouiDb;
  try {
    // oui-data only exports its root entry (index.json), so resolve the
    // package itself rather than a subpath.
    const require = createRequire(import.meta.url);
    ouiDb = require("oui-data") as Record<string, string>;
  } catch {
    ouiDb = {};
  }
  return ouiDb;
}

/** Look up a MAC address vendor from the local OUI database. Returns the vendor name or undefined. */
export function lookupVendor(mac: string): string | undefined {
  if (!isValidMac(mac)) return undefined;
  const prefix = normaliseMac(mac).replace(/:/g, "").toUpperCase().substring(0, 6);
  const entry = loadDb()[prefix];
  if (!entry) return undefined;
  // The entry contains the full address block — extract just the first line (company name)
  return entry.split("\n")[0].trim();
}
