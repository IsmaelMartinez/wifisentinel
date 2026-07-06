/**
 * Single owner of the WiFi security taxonomy. Every source emits a different
 * vocabulary for the same protocols — macOS system_profiler says
 * "WPA2 Personal", nmcli says "WPA2" or "WPA1 WPA2", the iw fallback says
 * "WPA/WPA2", and the Android companion exports coarse labels like "Open" or
 * "WPA2" (a `ScanResult.capabilities` string carries no Personal/Enterprise
 * distinction). Comparing those raw strings breaks every cross-source
 * consumer: the rogue-AP weaker-security rule can never fire on imported
 * scans, and `rf --compare` against an imported baseline reports a spurious
 * security change for every AP both sources see.
 *
 * The fix is one canonical vocabulary: `normaliseSecurity` is applied at the
 * collection/import boundary (CLI wifi scanner, Android importer), and the
 * comparison helpers here (`securityFamily`, `isWeakerSecurity`,
 * `securityChanged`) parse any vocabulary — canonical or legacy — so
 * consumers also behave on scans stored before normalisation existed.
 */

/**
 * Protocol family, the strength-relevant part of a security label. Ordered
 * weakest to strongest in `FAMILY_STRENGTH`. Mixed-mode networks
 * ("WPA/WPA2", "WPA2/WPA3") rank below the pure newer protocol because the
 * weaker handshake stays negotiable.
 */
export type SecurityFamily =
  | "open"
  | "wep"
  | "owe"
  | "wpa"
  | "wpa/wpa2"
  | "wpa2"
  | "wpa2/wpa3"
  | "wpa3"
  | "unknown";

/** Authentication mode when the label carries one. */
export type SecurityMode = "Personal" | "Enterprise";

const FAMILY_STRENGTH: Record<Exclude<SecurityFamily, "unknown">, number> = {
  open: 0,
  wep: 1,
  owe: 2,
  wpa: 3,
  "wpa/wpa2": 4,
  wpa2: 5,
  "wpa2/wpa3": 6,
  wpa3: 7,
};

const FAMILY_LABEL: Record<Exclude<SecurityFamily, "unknown">, string> = {
  open: "Open",
  wep: "WEP",
  owe: "Enhanced Open",
  wpa: "WPA",
  "wpa/wpa2": "WPA/WPA2",
  wpa2: "WPA2",
  "wpa2/wpa3": "WPA2/WPA3",
  wpa3: "WPA3",
};

/**
 * Classify any source's security string into a protocol family.
 * Unrecognised strings (including the "unknown"/"Unknown" sentinels) map to
 * "unknown" so consumers can refuse to compare rather than guess.
 */
export function securityFamily(raw: string): SecurityFamily {
  const lower = raw.trim().toLowerCase();

  // WEP first, before the WPA families: a mixed transition label like
  // "WPA2 WEP" keeps the WEP handshake negotiable, so weakest-link
  // classification is the honest reading (same rationale as ranking
  // mixed WPA modes below the pure newer protocol).
  if (lower.includes("wep")) return "wep";

  const hasWpa3 = lower.includes("wpa3");
  const hasWpa2 = lower.includes("wpa2");
  // WPA1 in any spelling: "wpa", "wpa1", "wpa personal", "wpa/wpa2",
  // "wpa1 wpa2" — i.e. "wpa" not immediately followed by a 2 or 3.
  const hasWpa1 = /wpa(?![23])/.test(lower);

  if (hasWpa3) {
    // macOS labels WPA2/WPA3 mixed mode "WPA3 Transitional".
    if (hasWpa2 || hasWpa1 || lower.includes("transitional")) return "wpa2/wpa3";
    return "wpa3";
  }
  if (hasWpa2) return hasWpa1 ? "wpa/wpa2" : "wpa2";
  if (hasWpa1) return "wpa";
  // OWE before plain open — "Enhanced Open" contains "open".
  if (lower.includes("enhanced open") || /\bowe\b/.test(lower)) return "owe";
  // Word-prefix rather than exact match so qualified labels from vendor
  // tools or hand-fed scans ("Open System", "None (no encryption)") still
  // classify; "--" is nmcli's table-mode spelling for no security.
  if (/^(open|none)\b/.test(lower) || lower === "--") return "open";
  return "unknown";
}

/**
 * Authentication mode when the label states one; undefined otherwise.
 * Coarse sources (the Android companion, nmcli's plain "WPA2") never state
 * a mode, so consumers must treat undefined as "could be either" rather
 * than defaulting.
 */
export function securityMode(raw: string): SecurityMode | undefined {
  const lower = raw.toLowerCase();
  if (
    lower.includes("enterprise") ||
    lower.includes("802.1x") ||
    lower.includes("eap")
  ) {
    return "Enterprise";
  }
  if (
    lower.includes("personal") ||
    lower.includes("psk") ||
    lower.includes("sae")
  ) {
    return "Personal";
  }
  return undefined;
}

/**
 * Canonical display label: family label plus the mode when known
 * ("WPA2 Personal", "WPA2", "Open"). Unrecognised strings pass through
 * trimmed but otherwise untouched — collapsing a future vendor label to
 * "unknown" would destroy information the raw string still carries.
 */
export function normaliseSecurity(raw: string): string {
  const family = securityFamily(raw);
  if (family === "unknown") {
    // Never emit a blank label into stored scans; a whitespace-only input
    // becomes the same sentinel the Android importer uses.
    const trimmed = raw.trim();
    return trimmed === "" ? "unknown" : trimmed;
  }
  const mode = securityMode(raw);
  const label = FAMILY_LABEL[family];
  // Mode is only meaningful for the WPA families.
  if (mode && family.startsWith("wpa")) {
    return `${label} ${mode}`;
  }
  return label;
}

/**
 * Numeric strength for ordering comparisons; -1 when the family is unknown
 * (callers must treat that as "not comparable", never as weakest).
 */
export function securityStrength(raw: string): number {
  const family = securityFamily(raw);
  return family === "unknown" ? -1 : FAMILY_STRENGTH[family];
}

/**
 * Whether `suspect` is genuinely weaker than `current`, across vocabularies.
 * Weaker means a lower family strength, or an Enterprise → Personal mode
 * downgrade in any family combination — a PSK evil twin of an 802.1X
 * network dodges server-certificate validation even when its protocol
 * family is newer (a "WPA3 Personal" twin of a "WPA2 Enterprise" corporate
 * SSID is still a credential-harvest setup). A missing mode on either side
 * is never treated as a downgrade — coarse sources simply don't know it.
 */
export function isWeakerSecurity(suspect: string, current: string): boolean {
  const ss = securityStrength(suspect);
  const cs = securityStrength(current);
  if (ss < 0 || cs < 0) return false;
  if (ss < cs) return true;
  return securityMode(suspect) === "Personal" && securityMode(current) === "Enterprise";
}

/**
 * Whether a label is weak enough for the personas' critical-severity
 * weak-encryption insights: open, WEP, or WPA1-only. Mixed WPA/WPA2 and
 * unknown labels don't qualify — the former is downgraded-but-encrypted,
 * the latter is unmeasured.
 */
export function isWeakSecurity(raw: string): boolean {
  const family = securityFamily(raw);
  return family === "open" || family === "wep" || family === "wpa";
}

/**
 * Whether a label offers no meaningful encryption at all (open or WEP) —
 * the "legacy/insecure" set the standards checks score as failing outright.
 * OWE doesn't qualify: open-auth but encrypted.
 */
export function isUnencrypted(raw: string): boolean {
  const family = securityFamily(raw);
  return family === "open" || family === "wep";
}

/**
 * Whether a label satisfies a "requires WPA3" check. Mixed WPA2/WPA3
 * counts: the network offers WPA3 even though the WPA2 handshake stays
 * negotiable (which is why `securityStrength` still ranks it lower).
 */
export function supportsWpa3(raw: string): boolean {
  const family = securityFamily(raw);
  return family === "wpa3" || family === "wpa2/wpa3";
}

/**
 * Whether a label satisfies a "requires at least WPA2" check when
 * `supportsWpa3` already failed. Mixed WPA/WPA2 counts for the same
 * offers-the-protocol reason as `supportsWpa3`.
 */
export function supportsWpa2(raw: string): boolean {
  const family = securityFamily(raw);
  return family === "wpa2" || family === "wpa/wpa2";
}

/**
 * Whether two labels describe a genuinely different configuration, compared
 * at the coarsest granularity both sides can support: family must be known
 * on both sides; modes only count as a change when both sides state one.
 * This keeps `rf --compare` quiet when a phone-imported "WPA2" baseline
 * meets a macOS "WPA2 Personal" reading of the same AP.
 */
export function securityChanged(a: string, b: string): boolean {
  const fa = securityFamily(a);
  const fb = securityFamily(b);
  if (fa === "unknown" || fb === "unknown") return false;
  if (fa !== fb) return true;
  const ma = securityMode(a);
  const mb = securityMode(b);
  return ma !== undefined && mb !== undefined && ma !== mb;
}
