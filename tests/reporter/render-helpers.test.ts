import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  statusIcon,
  severityColor,
  scoreBar,
  boolStatus,
  signalBar,
  snrLabel,
} from "../../src/reporter/render-helpers.js";

// Strip ANSI escape codes for plain-text assertions
function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1B\[[0-9;]*m/g, "");
}

describe("statusIcon", () => {
  it("pass: contains tick icon and 'Pass' label", () => {
    const plain = stripAnsi(statusIcon("pass"));
    assert.ok(plain.includes("✔") || plain.includes("√") || plain.includes("v"), `expected tick in: ${plain}`);
    assert.ok(plain.toLowerCase().includes("pass"), `expected 'pass' in: ${plain}`);
  });

  it("fail: contains cross icon and 'Fail' label", () => {
    const plain = stripAnsi(statusIcon("fail"));
    assert.ok(plain.includes("✘") || plain.includes("x") || plain.includes("X"), `expected cross in: ${plain}`);
    assert.ok(plain.toLowerCase().includes("fail"), `expected 'fail' in: ${plain}`);
  });

  it("warn: contains warning icon and 'Warn' label", () => {
    const plain = stripAnsi(statusIcon("warn"));
    assert.ok(
      plain.includes("⚠") || plain.includes("!") || plain.includes("‼"),
      `expected warning symbol in: ${plain}`
    );
    assert.ok(plain.toLowerCase().includes("warn"), `expected 'warn' in: ${plain}`);
  });

  it("info: contains info icon and 'Info' label", () => {
    const plain = stripAnsi(statusIcon("info"));
    assert.ok(plain.includes("ℹ") || plain.includes("ⓘ") || plain.includes("·"), `expected info symbol in: ${plain}`);
    assert.ok(plain.toLowerCase().includes("info"), `expected 'info' in: ${plain}`);
  });

  it("n/a: contains n/a label", () => {
    const plain = stripAnsi(statusIcon("n/a"));
    assert.ok(plain.toLowerCase().includes("n/a"), `expected 'n/a' in: ${plain}`);
  });
});

describe("boolStatus", () => {
  it("good=true: contains checkmark (teal, not plain green)", () => {
    const result = boolStatus(true, true);
    const plain = stripAnsi(result);
    // Must contain a checkmark
    assert.ok(plain.includes("✔") || plain.includes("√"), `expected checkmark in: ${plain}`);
    // ANSI should reference hex colour for teal (#4ec9b0), not plain chalk.green (32m)
    assert.ok(!result.includes("\x1B[32m"), "should not use plain chalk.green (32m) for teal");
  });

  it("good=false: contains cross (red)", () => {
    const result = boolStatus(true, false);
    const plain = stripAnsi(result);
    assert.ok(plain.includes("✘") || plain.includes("x") || plain.includes("X"), `expected cross in: ${plain}`);
    // Should not use plain chalk.red (31m)
    assert.ok(!result.includes("\x1B[31m"), "should not use plain chalk.red (31m) for red");
  });

  it("goodWhenTrue=false inverts logic", () => {
    const good = stripAnsi(boolStatus(false, false));
    const bad = stripAnsi(boolStatus(true, false));
    assert.ok(good.includes("✔") || good.includes("√"), `expected checkmark for inverted good: ${good}`);
    assert.ok(bad.includes("✘") || bad.includes("x") || bad.includes("X"), `expected cross for inverted bad: ${bad}`);
  });
});

describe("scoreBar", () => {
  it("score=10 produces 10 filled squares", () => {
    const plain = stripAnsi(scoreBar(10));
    assert.equal((plain.match(/■/g) ?? []).length, 10);
    assert.equal((plain.match(/□/g) ?? []).length, 0);
  });

  it("score=0 produces 0 filled squares", () => {
    const plain = stripAnsi(scoreBar(0));
    assert.equal((plain.match(/■/g) ?? []).length, 0);
    assert.equal((plain.match(/□/g) ?? []).length, 10);
  });

  it("score=5 produces 5 filled and 5 empty squares", () => {
    const plain = stripAnsi(scoreBar(5));
    assert.equal((plain.match(/■/g) ?? []).length, 5);
    assert.equal((plain.match(/□/g) ?? []).length, 5);
  });

  it("score>=7 does not use plain chalk.green (32m)", () => {
    const result = scoreBar(8);
    assert.ok(!result.includes("\x1B[32m"), "score>=7 should use TEAL hex, not plain chalk.green");
  });

  it("score<4 does not use plain chalk.red (31m)", () => {
    const result = scoreBar(2);
    assert.ok(!result.includes("\x1B[31m"), "score<4 should use RED hex, not plain chalk.red");
  });
});

describe("signalBar", () => {
  it("returns a string containing dBm", () => {
    const plain = stripAnsi(signalBar(-60));
    assert.ok(plain.includes("dBm"), `expected dBm in: ${plain}`);
  });

  it("contains filled and empty bar characters", () => {
    const plain = stripAnsi(signalBar(-60));
    assert.ok(plain.includes("█"), `expected filled bar chars in: ${plain}`);
    assert.ok(plain.includes("░"), `expected empty bar chars in: ${plain}`);
  });
});

describe("snrLabel", () => {
  it(">=25 returns Excellent", () => {
    const plain = stripAnsi(snrLabel(30));
    assert.equal(plain, "Excellent");
  });

  it(">=15 returns Good", () => {
    const plain = stripAnsi(snrLabel(20));
    assert.equal(plain, "Good");
  });

  it(">=10 returns Fair", () => {
    const plain = stripAnsi(snrLabel(12));
    assert.equal(plain, "Fair");
  });

  it("<10 returns Poor", () => {
    const plain = stripAnsi(snrLabel(5));
    assert.equal(plain, "Poor");
  });
});

describe("severityColor", () => {
  it("critical returns a chalk instance (bold)", () => {
    const color = severityColor("critical");
    assert.ok(typeof color === "function", "severityColor('critical') should return a chalk function");
    const out = color("test");
    assert.ok(typeof out === "string");
  });

  it("high returns a chalk instance", () => {
    const color = severityColor("high");
    assert.ok(typeof color === "function");
  });

  it("medium returns a chalk instance", () => {
    const color = severityColor("medium");
    assert.ok(typeof color === "function");
  });

  it("low returns a chalk instance", () => {
    const color = severityColor("low");
    assert.ok(typeof color === "function");
  });
});
