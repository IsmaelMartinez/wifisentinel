import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  isPartialSource,
  partialTrendNote,
  sourceCell,
  splitBySource,
} from "../../src/store/source.js";

describe("isPartialSource", () => {
  it("is true only when partial is explicitly set", () => {
    assert.equal(isPartialSource({ platform: "android", partial: true }), true);
    assert.equal(isPartialSource({ platform: "darwin", partial: false }), false);
    assert.equal(isPartialSource({ platform: "darwin" }), false);
    // Pre-source index entries have neither field — treated as full scans.
    assert.equal(isPartialSource({}), false);
  });
});

describe("sourceCell", () => {
  it("labels full scans with the bare platform", () => {
    assert.equal(sourceCell({ platform: "darwin" }), "darwin");
    assert.equal(sourceCell({ platform: "linux", partial: false }), "linux");
  });

  it("marks partial imports with a trailing asterisk", () => {
    assert.equal(sourceCell({ platform: "android", partial: true }), "android*");
  });

  it("falls back to a dash when platform is absent (pre-source index entry)", () => {
    assert.equal(sourceCell({}), "-");
    assert.equal(sourceCell({ partial: true }), "-*");
  });
});

describe("partialTrendNote", () => {
  it("returns null when there are no partial scans", () => {
    assert.equal(partialTrendNote(5, 0), null);
    assert.equal(partialTrendNote(0, 0), null);
  });

  it("reports the excluded count when full scans carry the summary", () => {
    assert.match(partialTrendNote(3, 2)!, /2 excluded/);
  });

  it("flags the phone's limited view for an all-partial history", () => {
    assert.match(partialTrendNote(0, 4)!, /phone's limited view/);
  });
});

describe("splitBySource", () => {
  const items = [
    { id: "mac1", platform: "darwin" },
    { id: "phone1", platform: "android", partial: true },
    { id: "mac2", platform: "darwin", partial: false },
    { id: "phone2", platform: "android", partial: true },
  ];

  it("partitions items preserving order", () => {
    const { full, partial } = splitBySource(items, (i) => i);
    assert.deepEqual(full.map((i) => i.id), ["mac1", "mac2"]);
    assert.deepEqual(partial.map((i) => i.id), ["phone1", "phone2"]);
  });

  it("returns empty halves for empty input", () => {
    const { full, partial } = splitBySource([], () => ({}));
    assert.deepEqual(full, []);
    assert.deepEqual(partial, []);
  });
});
