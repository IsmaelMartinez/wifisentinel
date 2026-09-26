import {
  isWeakerSecurity,
  securityChanged,
  securityFamily,
  securityMode,
  securityStrength,
  type SecurityFamily,
  type SecurityMode,
} from "../collector/schema/security.js";

/**
 * Where a label sits against the standards' "WPA3, else at least WPA2" bar.
 * Mixed modes count for the newer protocol they offer (WPA2/WPA3 → wpa3,
 * WPA/WPA2 → wpa2); "unknown" means the label was never measured.
 */
export type WpaTier = "wpa3" | "wpa2" | "below" | "unknown";

export interface SecurityClassification {
  family: SecurityFamily;
  mode: SecurityMode | undefined;
  /** Ordered strength: 0 (open) to 7 (WPA3); -1 when unknown. */
  level: number;
  /** Open, WEP or WPA1-only — the personas' critical weak-encryption bar. */
  weak: boolean;
  /** Open or WEP — no meaningful encryption at all. */
  unencrypted: boolean;
  wpaTier: WpaTier;
}

/**
 * The analyser's single Wi-Fi security classification. Every persona,
 * standard and RF check reads the level from here; parsing of the raw
 * macOS / nmcli / iw / Android vocabularies stays in the collector taxonomy.
 */
export function classifySecurity(raw: string): SecurityClassification {
  const family = securityFamily(raw);
  let wpaTier: WpaTier;
  if (family === "unknown") wpaTier = "unknown";
  else if (family === "wpa3" || family === "wpa2/wpa3") wpaTier = "wpa3";
  else if (family === "wpa2" || family === "wpa/wpa2") wpaTier = "wpa2";
  else wpaTier = "below";

  return {
    family,
    mode: securityMode(raw),
    level: securityStrength(raw),
    weak: family === "open" || family === "wep" || family === "wpa",
    unencrypted: family === "open" || family === "wep",
    wpaTier,
  };
}

/**
 * Whether moving from `from` to `to` lowers the security level, or drops
 * Enterprise to Personal. Unknown on either side is never a downgrade.
 */
export function isSecurityDowngrade(from: string, to: string): boolean {
  return isWeakerSecurity(to, from);
}

export { securityChanged };
