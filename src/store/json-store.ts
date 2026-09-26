// src/store/json-store.ts — shared file-per-record store with a JSON index,
// used by both the scan store and the recon store.
import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, renameSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { z } from "zod";

const SAFE_FILENAME = /^[\w.-]+\.json$/;

export interface JsonStoreConfig<E, S> {
  /** Resolves the store root lazily so XDG/env changes are honoured. */
  root: () => string;
  /** Sub-directory holding one JSON file per record. */
  dataDir: string;
  /** Index file name inside the store root. */
  indexFile: string;
  indexSchema: z.ZodType<E[]>;
  /** Human noun used in error messages, e.g. "Scan". */
  noun: string;
  /** CLI command that lists records, for not-found hints. */
  listCommand: string;
  /** CLI command that rebuilds the index, for missing-file hints. */
  reindexCommand: string;
  idOf: (entry: E) => string;
  timestampOf: (entry: E) => string;
  filenameOf: (entry: E) => string;
  /** Builds the index entry for a stored record written to `filename`. */
  toEntry: (stored: S, filename: string) => E;
  /** Record id and timestamp, used to name the file on save. */
  keyOf: (stored: S) => { id: string; timestamp: string };
}

export interface JsonStore<E, S> {
  save(stored: S): E;
  /** Index entries, newest first; self-heals a missing, corrupt or stale index. */
  list(): E[];
  load(id: string): S;
  /** Loads the records for already-listed entries without re-reading the index. */
  loadMany(entries: E[]): S[];
  rebuildIndex(): E[];
}

/** Write via a sibling temp file plus rename so readers never see a partial file. */
export function writeFileAtomic(path: string, data: string): void {
  const tmp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(tmp, data, { encoding: "utf-8", mode: 0o600 });
  renameSync(tmp, path);
}

export function makeFilename(timestamp: string, id: string): string {
  const datePart = timestamp.replace(/:/g, "-").replace(/\.\d+Z$/, "");
  return `${datePart}_${id.slice(0, 8)}.json`;
}

export function createJsonStore<E, S>(config: JsonStoreConfig<E, S>): JsonStore<E, S> {
  const dataPath = () => join(config.root(), config.dataDir);
  const indexPath = () => join(config.root(), config.indexFile);
  const sortNewestFirst = (entries: E[]) =>
    entries.sort((a, b) => config.timestampOf(b).localeCompare(config.timestampOf(a)));

  function ensureDirs(): void {
    mkdirSync(dataPath(), { recursive: true, mode: 0o700 });
  }

  function dataFiles(): string[] {
    if (!existsSync(dataPath())) return [];
    return readdirSync(dataPath()).filter(f => SAFE_FILENAME.test(f));
  }

  /** Returns null when the index is missing or unreadable, so callers can rebuild. */
  function readIndex(): E[] | null {
    if (!existsSync(indexPath())) return null;
    try {
      return config.indexSchema.parse(JSON.parse(readFileSync(indexPath(), "utf-8")));
    } catch {
      return null;
    }
  }

  function writeIndex(entries: E[]): void {
    writeFileAtomic(indexPath(), JSON.stringify(entries, null, 2));
  }

  function rebuildIndex(): E[] {
    ensureDirs();
    const entries: E[] = [];
    for (const filename of dataFiles()) {
      try {
        const stored = JSON.parse(readFileSync(join(dataPath(), filename), "utf-8")) as S;
        entries.push(config.toEntry(stored, filename));
      } catch {
        // skip corrupt files
      }
    }
    sortNewestFirst(entries);
    writeIndex(entries);
    return entries;
  }

  function save(stored: S): E {
    ensureDirs();
    const { id, timestamp } = config.keyOf(stored);
    const filename = makeFilename(timestamp, id);
    writeFileAtomic(join(dataPath(), filename), JSON.stringify(stored, null, 2));
    const entry = config.toEntry(stored, filename);

    const index = readIndex();
    if (index === null) {
      // A corrupt index would otherwise be overwritten with this one entry,
      // orphaning every earlier record; rebuild from the data files instead.
      rebuildIndex();
      return entry;
    }
    const withoutDup = index.filter(e => config.filenameOf(e) !== filename);
    withoutDup.push(entry);
    writeIndex(sortNewestFirst(withoutDup));
    return entry;
  }

  function list(): E[] {
    const index = readIndex();
    // A concurrent writer can drop another's entry between read and rename, so
    // treat a count mismatch with the data directory as a stale index.
    if (index === null || index.length !== dataFiles().length) return rebuildIndex();
    return index;
  }

  function fileFor(entry: E): string {
    const filename = config.filenameOf(entry);
    if (!SAFE_FILENAME.test(filename)) {
      throw new Error(`Invalid filename in index: ${filename}`);
    }
    const filePath = join(dataPath(), filename);
    if (!existsSync(filePath)) {
      throw new Error(
        `${config.noun} file missing: ${filename}. Run "${config.reindexCommand}" to repair the index.`,
      );
    }
    return filePath;
  }

  function loadMany(entries: E[]): S[] {
    return entries.map(e => JSON.parse(readFileSync(fileFor(e), "utf-8")) as S);
  }

  function load(id: string): S {
    const entry = list().find(e => config.idOf(e) === id || config.idOf(e).startsWith(id));
    if (!entry) {
      throw new Error(
        `${config.noun} "${id}" not found. Run "${config.listCommand}" to list available records.`,
      );
    }
    return loadMany([entry])[0];
  }

  return { save, list, load, loadMany, rebuildIndex };
}
