import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildUploadArgs, UPLOAD_URL } from "../../src/collector/scanners/speed.scanner.js";

const DATA_FLAGS = new Set([
  "-d", "--data", "--data-binary", "--data-raw", "--data-ascii", "--data-urlencode",
  "-F", "--form", "-T", "--upload-file",
]);

describe("buildUploadArgs", () => {
  const args = buildUploadArgs("/tmp/payload.bin");

  it("never reads from /dev/urandom", () => {
    assert.ok(!args.some((a) => a.includes("/dev/urandom")));
  });

  it("passes exactly one data flag, pointing at the bounded payload file", () => {
    const dataFlags = args.filter((a) => DATA_FLAGS.has(a));
    assert.deepEqual(dataFlags, ["--data-binary"]);
    assert.equal(args[args.indexOf("--data-binary") + 1], "@/tmp/payload.bin");
  });

  it("posts to the upload endpoint", () => {
    assert.equal(args.at(-1), UPLOAD_URL);
  });
});
