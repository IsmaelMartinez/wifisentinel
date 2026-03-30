import { execFileSync, execFile as execFileCb } from "node:child_process";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a command safely using execFile (no shell injection risk).
 * Pass the binary and args separately.
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
 * Async version of run using execFile (no shell).
 */
export function runAsync(
  binary: string,
  args: string[] = [],
  timeoutMs = 30_000
): Promise<ExecResult> {
  return new Promise((resolve) => {
    execFileCb(
      binary,
      args,
      { encoding: "utf-8", timeout: timeoutMs },
      (error, stdout, stderr) => {
        resolve({
          stdout: (stdout ?? "").trim(),
          stderr: (stderr ?? "").trim(),
          exitCode: error ? (error as any).code ?? 1 : 0,
        });
      }
    );
  });
}
