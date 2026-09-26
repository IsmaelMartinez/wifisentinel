import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  buildCronLine,
  buildPlist,
  cronQuote,
  getBinaryPath,
  shellQuote,
  type ScheduleTarget,
} from "../../src/commands/schedule.js";

/**
 * Mirrors Vixie cron's command preprocessing (do_command.c): `\%` becomes
 * `%`, a backslash before anything else is kept along with that character,
 * and the first unescaped `%` ends the command.
 */
function cronCommand(line: string): { command: string; split: boolean } {
  let out = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "\\" && i + 1 < line.length) {
      out += line[i + 1] === "%" ? "%" : ch + line[i + 1];
      i++;
    } else if (ch === "%") {
      return { command: out, split: true };
    } else {
      out += ch;
    }
  }
  return { command: out, split: false };
}

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
    assert.ok(
      line.includes(`${shellQuote(awkward.nodePath)} ${shellQuote(awkward.binaryPath)} scan --analyse`),
      "node and binary paths are quoted in the command",
    );
    assert.ok(line.includes(`2>> ${shellQuote(awkward.logPath)}`));
  });

  it("rejects paths containing line breaks", () => {
    for (const key of ["nodePath", "binaryPath", "logPath"] as const) {
      for (const br of ["\n", "\r"]) {
        assert.throws(
          () => buildCronLine({ ...awkward, [key]: `/a${br}* * * * * evil` }),
          /line break/,
        );
      }
    }
  });

  it("survives cron's % handling and the shell for %, backslash and quote paths", () => {
    for (const path of ["/home/a%b/cli.js", "/x\\%y/cli.js", "/p\\q'r%/s\\\\", "/end\\"]) {
      const cmd = cronCommand(`printf '%s\\n' ${cronQuote(path)}`.replace("'%s", "'\\%s"));
      assert.ok(!cmd.split, `cron split the command for ${path}`);
      const out = execFileSync("sh", ["-c", cmd.command], { encoding: "utf-8" });
      assert.equal(out, path + "\n");
    }
  });

  it("rejects cron intervals that do not divide 24", () => {
    for (const n of [5, 7, 25, 48]) {
      assert.throws(() => buildCronLine({ ...awkward, intervalHours: n }), /does not divide 24/);
    }
    assert.ok(buildCronLine({ ...awkward, intervalHours: 24 }).startsWith("0 0 * * * "));
    assert.ok(buildCronLine({ ...awkward, intervalHours: 8 }).startsWith("0 */8 * * * "));
  });
});
