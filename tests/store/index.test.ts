import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  saveScan,
  listScans,
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
