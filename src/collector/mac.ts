const OCTET = /^[0-9a-f]{1,2}$/;

/**
 * Normalise a MAC address to lowercase, colon-separated, zero-padded form
 * (`0:1B:63:a-…` → `00:1b:63:0a:…`). macOS `arp` drops leading zeros, so
 * every collector path that keys or looks up a MAC goes through this.
 * Values that are not six hex octets (e.g. "unknown") are returned lowercased.
 */
export function normaliseMac(mac: string): string {
  const lower = mac.trim().toLowerCase();
  const octets = lower.split(/[:-]/);
  if (octets.length !== 6 || !octets.every((o) => OCTET.test(o))) return lower;
  return octets.map((o) => o.padStart(2, "0")).join(":");
}

/** True for a well-formed six-octet MAC address (after normalisation). */
export function isValidMac(mac: string): boolean {
  return /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/.test(normaliseMac(mac));
}

/**
 * True for group (multicast or broadcast) MACs: the least-significant bit of
 * the first octet is set, e.g. `01:00:5e:…` (IPv4 multicast), `33:33:…`
 * (IPv6 multicast) and `ff:ff:ff:ff:ff:ff`.
 */
export function isMulticastMac(mac: string): boolean {
  if (!isValidMac(mac)) return false;
  return (parseInt(normaliseMac(mac).slice(0, 2), 16) & 1) === 1;
}
