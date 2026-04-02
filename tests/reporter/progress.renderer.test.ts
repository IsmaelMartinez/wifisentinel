import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createScanTasks } from "../../src/reporter/progress.renderer.js";

describe("createScanTasks", () => {
  it("returns a task list with expected scanner names", () => {
    const tasks = createScanTasks({});
    const titles = tasks.map(t => t.title);
    assert.ok(titles.includes("WiFi environment"));
    assert.ok(titles.includes("DNS audit"));
    assert.ok(titles.includes("Security posture"));
    assert.ok(titles.includes("Active connections"));
    assert.ok(titles.includes("Host discovery"));
  });

  it("excludes port scanning when skipPorts is true", () => {
    const tasks = createScanTasks({ skipPorts: true });
    const titles = tasks.map(t => t.title);
    assert.ok(!titles.includes("Port scanning"));
  });

  it("excludes speed test when skipSpeed is true", () => {
    const tasks = createScanTasks({ skipSpeed: true });
    const titles = tasks.map(t => t.title);
    assert.ok(!titles.includes("Speed test"));
  });
});
