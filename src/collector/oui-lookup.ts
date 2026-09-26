import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { normaliseMac, isValidMac } from "./mac.js";

let dbText: Promise<string> | null = null;

/**
 * Read oui-data's index.json as text, once and asynchronously. Parsing the
 * whole 5.6 MB file with JSON.parse blocks the event loop for hundreds of
 * milliseconds, so lookups search the text for the single entry instead.
 */
function loadDbText(): Promise<string> {
  dbText ??= (async () => {
    try {
      // oui-data only exports its root entry (index.json), so resolve the
      // package itself rather than a subpath.
      const require = createRequire(import.meta.url);
      return await readFile(require.resolve("oui-data"), "utf-8");
    } catch {
      return "";
    }
  })();
  return dbText;
}

/** Look up a MAC address vendor from the local OUI database. Returns the vendor name or undefined. */
export async function lookupVendor(mac: string): Promise<string | undefined> {
  if (!isValidMac(mac)) return undefined;
  const prefix = normaliseMac(mac).replace(/:/g, "").toUpperCase().substring(0, 6);
  const text = await loadDbText();

  // index.json holds one entry per line: ` "001B63": "Apple, Inc.\n1 Infinite Loop…",`
  const at = text.indexOf(`\n "${prefix}": `);
  if (at < 0) return undefined;
  const end = text.indexOf("\n", at + 1);
  let line = text.slice(at + 1, end < 0 ? undefined : end).trimEnd();
  if (line.endsWith(",")) line = line.slice(0, -1);
  try {
    const entry: unknown = Object.values(JSON.parse(`{${line}}`))[0];
    // The entry contains the full address block — keep just the first line (company name)
    return typeof entry === "string" ? entry.split("\n")[0].trim() : undefined;
  } catch {
    return undefined;
  }
}
