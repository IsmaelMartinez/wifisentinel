import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  buildCronLine,
  buildPlist,
  getBinaryPath,
  shellQuote,
  type ScheduleTarget,
} from "../../src/commands/schedule.js";

const awkward: ScheduleTarget = {
  nodePath: "/opt/node dir/bin/node",
  binaryPath: "/Users/Tom & Jerry's/wifisentinel/dist/cli.js",
  logPath: "/Users/Tom & Jerry's/.wifisentinel/schedule.log",
  intervalHours: 6,
};

describe("schedule", () => {
  it("resolves the package's own dist/cli.js, not the working directory", () => {
    assert.equal(
      getBinaryPath("file:///pkg/src/commands/schedule.ts"),
      "/pkg/dist/cli.js",
    );
    assert.equal(
      getBinaryPath("file:///pkg%20dir/dist/commands/schedule.js"),
      "/pkg dir/dist/cli.js",
    );
  });

  it("XML-escapes plist paths containing a space and an ampersand", () => {
    const plist = buildPlist(awkward);
    assert.ok(plist.includes("<string>/Users/Tom &amp; Jerry&apos;s/wifisentinel/dist/cli.js</string>"));
    assert.ok(plist.includes("<string>/opt/node dir/bin/node</string>"));
    assert.ok(plist.includes("<integer>21600</integer>"));
    assert.ok(!/&(?!amp;|apos;|lt;|gt;|quot;)/.test(plist), "no bare ampersand in plist");
  });

  it("shell-quotes cron paths so a space and an ampersand survive", () => {
    const line = buildCronLine(awkward);
    assert.ok(line.startsWith("0 */6 * * * "));
    // Round-trip the command portion through a real POSIX shell.
    const argv = execFileSync(
      "sh",
      ["-c", `printf '%s\\n' ${shellQuote(awkward.nodePath)} ${shellQuote(awkward.binaryPath)}`],
      { encoding: "utf-8" },
    ).trimEnd().split("\n");
    assert.deepEqual(argv, [awkward.nodePath, awkward.binaryPath]);
    assert.ok(line.includes(`2>> ${shellQuote(awkward.logPath)}`));
  });

  it("rejects cron intervals that do not divide 24", () => {
    for (const n of [5, 7, 25, 48]) {
      assert.throws(() => buildCronLine({ ...awkward, intervalHours: n }), /does not divide 24/);
    }
    assert.ok(buildCronLine({ ...awkward, intervalHours: 24 }).startsWith("0 0 * * * "));
    assert.ok(buildCronLine({ ...awkward, intervalHours: 8 }).startsWith("0 */8 * * * "));
  });
});
