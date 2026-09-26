import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runAsync } from "../../src/collector/exec.js";
import { mapLimit, sleep } from "../../src/collector/util.js";

describe("runAsync", () => {
  it("returns stdout and a zero exit code", async () => {
    const r = await runAsync(process.execPath, ["-e", "process.stdout.write('ok\\n')"]);
    assert.deepEqual(r, { stdout: "ok", stderr: "", exitCode: 0 });
  });

  it("reports the numeric exit status of a failing command", async () => {
    const r = await runAsync(process.execPath, ["-e", "process.exit(3)"]);
    assert.equal(r.exitCode, 3);
  });

  it("reports exit code 1 when the binary cannot be spawned", async () => {
    const r = await runAsync("/nonexistent/wifisentinel-no-such-binary");
    assert.equal(r.exitCode, 1);
  });

  it("feeds input on stdin and closes it", async () => {
    const echo = "process.stdin.pipe(process.stdout)";
    assert.equal((await runAsync(process.execPath, ["-e", echo], 5_000, "hello")).stdout, "hello");
    // With no input stdin is closed at once, so a reader does not hang.
    assert.equal((await runAsync(process.execPath, ["-e", echo], 5_000)).exitCode, 0);
  });
});

describe("mapLimit", () => {
  it("never exceeds the limit and preserves order", async () => {
    let inFlight = 0;
    let peak = 0;
    const items = Array.from({ length: 50 }, (_, i) => i);
    const out = await mapLimit(items, 4, async (n) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await sleep(n % 3);
      inFlight--;
      return n * 2;
    });
    assert.equal(peak, 4);
    assert.deepEqual(out, items.map((n) => n * 2));
  });

  it("runs sequentially with a limit of 1 and handles empty input", async () => {
    const order: number[] = [];
    await mapLimit([3, 1, 2], 1, async (n) => {
      await sleep(n);
      order.push(n);
    });
    assert.deepEqual(order, [3, 1, 2]);
    assert.deepEqual(await mapLimit([], 8, async (n: number) => n), []);
  });
});
