import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, unlinkSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  saveScan,
  listScans,
  loadScans,
  rebuildIndex,
  getStorePath,
} from "../../src/store/index.js";
import {
  AndroidScanImport,
  androidImportToScanResult,
} from "../../src/collector/android-import.js";
import { scoreAllStandards } from "../../src/analyser/standards/index.js";
import { analyseAllPersonas } from "../../src/analyser/personas/index.js";
import type { NetworkScanResult } from "../../src/collector/schema/scan-result.js";

// `getStorePath` honours XDG_DATA_HOME only on Linux, so pin the platform for
// the duration of these tests — otherwise a macOS dev run would write into
// the real ~/.wifisentinel store.
const realPlatform = Object.getOwnPropertyDescriptor(process, "platform")!;
let storeDir: string;

function makeScan(overrides: {
  scanId: string;
  timestamp: string;
  platform?: NetworkScanResult["meta"]["platform"];
  partial?: boolean;
}): NetworkScanResult {
  const imported = AndroidScanImport.parse({
    meta: {
      scanId: overrides.scanId,
      timestamp: overrides.timestamp,
      platform: "android",
    },
    wifi: { ssid: "TestNet", bssid: "aa:bb:cc:dd:ee:ff", security: "WPA2", signal: -50 },
    hosts: [{ ip: "192.168.1.10" }],
  });
  const result = androidImportToScanResult(imported);
  if (overrides.platform) result.meta.platform = overrides.platform;
  if (overrides.partial === undefined) {
    delete result.meta.partial;
  } else {
    result.meta.partial = overrides.partial;
  }
  return result;
}

function save(result: NetworkScanResult): void {
  saveScan(result, scoreAllStandards(result), analyseAllPersonas(result));
}

describe("scan index source fields", () => {
  beforeEach(() => {
    storeDir = mkdtempSync(join(tmpdir(), "wifisentinel-store-test-"));
    Object.defineProperty(process, "platform", { value: "linux" });
    process.env.XDG_DATA_HOME = storeDir;
  });

  afterEach(() => {
    Object.defineProperty(process, "platform", realPlatform);
    delete process.env.XDG_DATA_HOME;
    rmSync(storeDir, { recursive: true, force: true });
  });

  it("records platform and partial in the index on save", () => {
    save(makeScan({ scanId: "aaaaaaaa-1111", timestamp: "2026-07-01T10:00:00.000Z", partial: true }));
    save(makeScan({ scanId: "bbbbbbbb-2222", timestamp: "2026-07-01T11:00:00.000Z", platform: "darwin" }));

    const entries = listScans();
    assert.equal(entries.length, 2);

    // Newest first
    assert.equal(entries[0].scanId, "bbbbbbbb-2222");
    assert.equal(entries[0].platform, "darwin");
    assert.equal(entries[0].partial, undefined);

    assert.equal(entries[1].scanId, "aaaaaaaa-1111");
    assert.equal(entries[1].platform, "android");
    assert.equal(entries[1].partial, true);
  });

  it("recovers every scan after the index is truncated", () => {
    save(makeScan({ scanId: "11111111-a", timestamp: "2026-07-02T10:00:00.000Z" }));
    save(makeScan({ scanId: "22222222-b", timestamp: "2026-07-02T11:00:00.000Z" }));
    save(makeScan({ scanId: "33333333-c", timestamp: "2026-07-02T12:00:00.000Z" }));
    const indexPath = join(getStorePath(), "index.json");
    const raw = readFileSync(indexPath, "utf-8");
    writeFileSync(indexPath, raw.slice(0, raw.length / 2));

    save(makeScan({ scanId: "44444444-d", timestamp: "2026-07-02T13:00:00.000Z" }));

    const entries = listScans();
    assert.equal(entries.length, 4);
    assert.deepEqual(
      entries.map(e => e.scanId),
      ["44444444-d", "33333333-c", "22222222-b", "11111111-a"],
    );
  });

  it("rebuilds a stale index that is missing an entry", () => {
    save(makeScan({ scanId: "55555555-e", timestamp: "2026-07-03T10:00:00.000Z" }));
    save(makeScan({ scanId: "66666666-f", timestamp: "2026-07-03T11:00:00.000Z" }));
    const indexPath = join(getStorePath(), "index.json");
    const index = JSON.parse(readFileSync(indexPath, "utf-8"));
    writeFileSync(indexPath, JSON.stringify(index.slice(0, 1)));

    assert.equal(listScans().length, 2);
  });

  it("rebuilds a same-size index that names a phantom file", () => {
    save(makeScan({ scanId: "5a5a5a5a-e", timestamp: "2026-07-03T12:00:00.000Z" }));
    save(makeScan({ scanId: "6b6b6b6b-f", timestamp: "2026-07-03T13:00:00.000Z" }));
    const indexPath = join(getStorePath(), "index.json");
    const index = JSON.parse(readFileSync(indexPath, "utf-8"));
    index[0].filename = "2026-01-01T00-00-00_deadbeef.json";
    writeFileSync(indexPath, JSON.stringify(index));

    const entries = listScans();
    assert.equal(entries.length, 2);
    assert.doesNotThrow(() => loadScans(entries));
  });

  it("writes atomically, leaving no temp files behind", () => {
    save(makeScan({ scanId: "77777777-g", timestamp: "2026-07-04T10:00:00.000Z" }));
    const stray = [
      ...readdirSync(getStorePath()),
      ...readdirSync(join(getStorePath(), "scans")),
    ].filter(f => f.endsWith(".tmp"));
    assert.deepEqual(stray, []);
  });

  it("bulk-loads listed scans without re-reading the index", () => {
    save(makeScan({ scanId: "88888888-h", timestamp: "2026-07-05T10:00:00.000Z" }));
    save(makeScan({ scanId: "99999999-i", timestamp: "2026-07-05T11:00:00.000Z" }));
    const entries = listScans();
    // Corrupt the index after listing: a per-entry index lookup would now fail.
    writeFileSync(join(getStorePath(), "index.json"), "{");
    const stored = loadScans(entries);
    assert.deepEqual(stored.map(s => s.scan.meta.scanId), ["99999999-i", "88888888-h"]);
  });

  it("names a real recovery command when a scan file is missing", () => {
    save(makeScan({ scanId: "aaaa0000-j", timestamp: "2026-07-06T10:00:00.000Z" }));
    const [entry] = listScans();
    unlinkSync(join(getStorePath(), "scans", entry.filename));
    assert.throws(() => loadScans([entry]), /wifisentinel history --reindex/);
  });

  it("backfills platform and partial on rebuild", () => {
    save(makeScan({ scanId: "cccccccc-3333", timestamp: "2026-07-01T12:00:00.000Z", partial: true }));
    // Simulate a pre-source index: drop it and rebuild from the scan files.
    unlinkSync(join(getStorePath(), "index.json"));

    const entries = rebuildIndex();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].platform, "android");
    assert.equal(entries[0].partial, true);
  });
});
