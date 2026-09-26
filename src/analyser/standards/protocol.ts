/**
 * Wi-Fi generation (the Wi-Fi Alliance number) for each 802.11 amendment
 * suffix. 802.11a/b/g predate the numbering; they are ranked as the legacy
 * generations 1–3.
 */
const GENERATION = new Map<string, number>([
  ["b", 1],
  ["a", 2],
  ["g", 3],
  ["n", 4],
  ["ac", 5],
  ["ax", 6],
  ["be", 7],
]);

/**
 * Parse a PHY-mode string ("802.11ax", "802.11a/b/g/n/ac", "Wi-Fi 6E") into
 * its highest Wi-Fi generation, or undefined when it names none (the
 * "Unknown" sentinel, or an empty value from a partial import). Suffixes are
 * matched as whole tokens so "802.11ac" is never read as "802.11a".
 */
export function wifiGeneration(protocol: string): number | undefined {
  const lower = protocol.toLowerCase();
  let best: number | undefined;
  const consider = (gen: number | undefined) => {
    if (gen !== undefined && (best === undefined || gen > best)) best = gen;
  };

  const amendment = /802\.11([a-z/]+)/.exec(lower);
  if (amendment) {
    for (const suffix of amendment[1].split("/")) consider(GENERATION.get(suffix));
  }
  const marketing = /wi-?fi ?(\d)/.exec(lower);
  if (marketing) consider(Number(marketing[1]));

  return best;
}
