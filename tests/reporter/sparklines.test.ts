import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { renderSparkline, renderScoreTrend, renderSignalTrend } from "../../src/reporter/sparklines.js";

describe("renderSparkline", () => {
  it("renders sparkline characters for data points", () => {
    const result = renderSparkline([1, 3, 5, 7, 9]);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.length >= 5);
    assert.ok(/[▁▂▃▄▅▆▇█]/.test(plain));
  });

  it("returns empty string for empty data", () => {
    const result = renderSparkline([]);
    assert.equal(result, "");
  });
});

describe("renderScoreTrend", () => {
  it("shows improving trend", () => {
    const result = renderScoreTrend([6.0, 6.5, 7.0, 7.5, 8.0]);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("improving"));
  });

  it("shows degrading trend", () => {
    const result = renderScoreTrend([8.0, 7.5, 7.0, 6.5, 6.0]);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("degrading"));
  });

  it("shows stable trend", () => {
    const result = renderScoreTrend([7.0, 7.0, 7.0]);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("stable"));
  });
});

describe("renderSignalTrend", () => {
  it("returns empty for single data point", () => {
    assert.equal(renderSignalTrend([-45]), "");
  });

  it("renders sparkline with average for multiple points", () => {
    const result = renderSignalTrend([-50, -45, -40]);
    const plain = result.replace(/\x1B\[[0-9;]*m/g, "");
    assert.ok(plain.includes("dBm"));
    assert.ok(plain.includes("avg"));
  });
});
