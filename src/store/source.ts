// src/store/source.ts — Scan-source helpers shared by trend consumers (CLI and dashboard).

export interface ScanSource {
  platform?: string;
  partial?: boolean;
}

/**
 * True when the scan carries only a subset of the full CLI shape — e.g. an
 * Android companion import (`meta.partial`).
 */
export function isPartialSource(source: ScanSource): boolean {
  return source.partial === true;
}

/**
 * True when the scan carries source provenance — i.e. it was indexed after the
 * `platform`/`partial` fields were added. Pre-source index entries have neither
 * field, so their source is genuinely unknown: they could be full CLI scans or
 * partial imports written before the fields existed. Trend summaries gate these
 * out when any sourced entries are present, rather than assume "full" and risk
 * folding a phone import's weaker radio back into the maths (that assumption is
 * what {@link splitBySource} would otherwise make, since a missing `partial` is
 * not `true`). `wifisentinel` backfills the fields when the index is rebuilt.
 */
export function isKnownSource(source: ScanSource): boolean {
  return source.platform !== undefined;
}

/**
 * Compact source cell for the CLI trend tables: the bare platform, with a
 * trailing `*` marking a partial import (footnoted by {@link partialTrendNote}).
 * `-` when the scan predates the source fields in the index.
 */
export function sourceCell(source: ScanSource): string {
  const platform = source.platform ?? "-";
  return isPartialSource(source) ? `${platform}*` : platform;
}

/**
 * Footnote for a trend summary of a mixed history — the `*`-marked rows
 * explained. `fullCount`/`partialCount` are the two halves from
 * {@link splitBySource}: with full scans present the summary ran over them
 * and the partials were excluded; an all-partial history keeps its own
 * (self-consistent) summary flagged as the phone's limited view. Returns
 * null when there are no partials to footnote.
 */
export function partialTrendNote(fullCount: number, partialCount: number): string | null {
  if (partialCount === 0) return null;
  if (fullCount > 0) {
    return `* partial scan (imported) — ${partialCount} excluded from the summary above`;
  }
  return "* partial scan (imported) — summary reflects the phone's limited view";
}

/**
 * Partition a series into full-scan and partial-import halves. Order-agnostic:
 * each half preserves the input order (the CLI passes newest-first arrays).
 * Trend maths should run on one side only: a phone import caps nearby APs at
 * 25 and observes them through a weaker radio, so a mixed series oscillates
 * with the source rather than the network. Convention: use `full` when it is
 * non-empty, otherwise fall back to `partial` (an all-phone history is still
 * self-consistent).
 */
export function splitBySource<T>(
  items: T[],
  getSource: (item: T) => ScanSource,
): { full: T[]; partial: T[] } {
  const full: T[] = [];
  const partial: T[] = [];
  for (const item of items) {
    (isPartialSource(getSource(item)) ? partial : full).push(item);
  }
  return { full, partial };
}
