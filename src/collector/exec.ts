import { execFileSync, execFile as execFileCb } from "node:child_process";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a command safely using execFile (no shell injection risk).
 * Pass the binary and args separately. Blocks the event loop — prefer
 * runAsync on the scan path.
 */
export function run(
  binary: string,
  args: string[] = [],
  timeoutMs = 30_000
): ExecResult {
  try {
    const stdout = execFileSync(binary, args, {
      encoding: "utf-8",
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout: stdout.trim(), stderr: "", exitCode: 0 };
  } catch (err: any) {
    return {
      stdout: (err.stdout ?? "").toString().trim(),
      stderr: (err.stderr ?? "").toString().trim(),
      exitCode: err.status ?? 1,
    };
  }
}

/**
 * Async version of run using execFile (no shell). stdin receives `input`
 * (or nothing) and is then closed, so tools such as `openssl s_client` do
 * not wait for more.
 */
export function runAsync(
  binary: string,
  args: string[] = [],
  timeoutMs = 30_000,
  input = "",
): Promise<ExecResult> {
  return new Promise((resolve) => {
    const child = execFileCb(
      binary,
      args,
      { encoding: "utf-8", timeout: timeoutMs },
      (error, stdout, stderr) => {
        // error.code is the exit status for a non-zero exit, but a string
        // (e.g. "ENOENT") when the binary could not be spawned.
        const code = (error as { code?: unknown } | null)?.code;
        resolve({
          stdout: (stdout ?? "").trim(),
          stderr: (stderr ?? "").trim(),
          exitCode: error ? (typeof code === "number" ? code : 1) : 0,
        });
      }
    );
    child.stdin?.on("error", () => {
      // The child may exit before reading stdin (EPIPE); the callback reports the result.
    });
    child.stdin?.end(input);
  });
}
