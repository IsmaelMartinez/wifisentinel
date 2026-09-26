import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getStorePath } from "../../src/store/index.js";
import { saveRecon, listRecons, loadRecon } from "../../src/store/recon-store.js";
import type { ReconResult } from "../../src/collector/recon/schema.js";
import type { FullReconAnalysis } from "../../src/analyser/recon-personas.js";

const realPlatform = Object.getOwnPropertyDescriptor(process, "platform")!;
let storeDir: string;

// Only the fields the recon index reads are populated.
function makeRecon(reconId: string, timestamp: string): ReconResult {
  return {
    meta: { reconId, timestamp, domain: "example.com" },
    tls: { grade: "A" },
    headers: { grade: "C" },
    crt: { uniqueSubdomains: ["a.example.com", "b.example.com"] },
  } as unknown as ReconResult;
}

const analysis = { overallGrade: "B" } as unknown as FullReconAnalysis;

describe("recon store", () => {
  beforeEach(() => {
    storeDir = mkdtempSync(join(tmpdir(), "wifisentinel-recon-test-"));
    Object.defineProperty(process, "platform", { value: "linux" });
    process.env.XDG_DATA_HOME = storeDir;
  });

  afterEach(() => {
    Object.defineProperty(process, "platform", realPlatform);
    delete process.env.XDG_DATA_HOME;
    rmSync(storeDir, { recursive: true, force: true });
  });

  it("indexes the analyser's overall grade and recovers from a corrupt index", () => {
    saveRecon(makeRecon("r1111111-x", "2026-07-01T10:00:00.000Z"), analysis);
    writeFileSync(join(getStorePath(), "recon-index.json"), "[{");
    saveRecon(makeRecon("r2222222-y", "2026-07-01T11:00:00.000Z"), analysis);

    const entries = listRecons();
    assert.deepEqual(entries.map(e => e.reconId), ["r2222222-y", "r1111111-x"]);
    assert.equal(entries[0].overallGrade, "B");
    assert.equal(entries[0].subdomainCount, 2);
    assert.equal(loadRecon("r1111111").recon.meta.reconId, "r1111111-x");
  });
});
