import { NextRequest } from "next/server";
import { spawn, type ChildProcess } from "node:child_process";
import { resolve } from "node:path";

export const dynamic = "force-dynamic";

// Track running scan processes so they can be stopped, and so we can
// enforce a single concurrent scan per server.
const activeProcesses = new Map<string, ChildProcess>();

// Keep the last N lines of stderr so we can forward a useful error
// message to the client if the child exits non-zero.
const STDERR_TAIL_LINES = 20;

// Watch interval is clamped to [1, 1440] minutes (1 minute to 24 hours).
const MIN_INTERVAL_MINUTES = 1;
const MAX_INTERVAL_MINUTES = 1440;

function clampInterval(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return 5;
  return Math.min(MAX_INTERVAL_MINUTES, Math.max(MIN_INTERVAL_MINUTES, value));
}

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));

  // Enforce one active scan per server. Parallel network scans would
  // interfere with each other and blow up resource usage.
  if (activeProcesses.size > 0) {
    return new Response(
      JSON.stringify({
        error: "A scan is already running. Stop it before starting another.",
      }),
      {
        status: 409,
        headers: { "Content-Type": "application/json" },
      },
    );
  }

  const skipPorts = body.skipPorts === true;
  const skipSpeed = body.skipSpeed === true;
  const skipTraffic = body.skipTraffic === true;
  const stealth = body.stealth === true;
  const watch = body.watch === true;
  const interval = clampInterval(body.interval);

  const command = watch ? "watch" : "scan";
  const args = ["src/cli.ts", command, "--events"];

  if (!watch) args.push("--no-save");

  if (skipPorts) args.push("--skip-ports");
  if (skipSpeed || stealth) args.push("--skip-speed");
  if (skipTraffic || stealth) args.push("--skip-traffic");
  if (stealth) args.push("--stealth");
  if (watch) args.push("--interval", String(interval));

  const cliDir = process.env.CLI_ROOT_DIR ?? resolve(process.cwd(), "..");
  const sessionId = crypto.randomUUID();

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      // Once the stream is torn down (client cancel, child close, error),
      // guard further enqueue/close calls to avoid throwing on a closed
      // controller.
      let closed = false;
      const safeEnqueue = (payload: string) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(payload));
        } catch {
          closed = true;
        }
      };
      const safeClose = () => {
        if (closed) return;
        closed = true;
        try {
          controller.close();
        } catch {
          // already closed
        }
      };

      const child = spawn("npx", ["tsx", ...args], {
        cwd: cliDir,
        stdio: ["ignore", "pipe", "pipe"],
      });

      activeProcesses.set(sessionId, child);

      // Send session ID so client can stop it
      safeEnqueue(`data: ${JSON.stringify({ type: "session:start", sessionId })}\n\n`);

      let stdoutBuffer = "";
      child.stdout.on("data", (chunk: Buffer) => {
        stdoutBuffer += chunk.toString();
        const lines = stdoutBuffer.split("\n");
        stdoutBuffer = lines.pop() ?? "";
        for (const line of lines) {
          if (line.trim()) {
            safeEnqueue(`data: ${line}\n\n`);
          }
        }
      });

      // Capture a rolling tail of stderr so we can surface a helpful error
      // if the child exits non-zero (e.g. tsx can't resolve a module).
      const stderrTail: string[] = [];
      let stderrCarry = "";
      child.stderr.on("data", (chunk: Buffer) => {
        const text = stderrCarry + chunk.toString();
        const lines = text.split("\n");
        stderrCarry = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          console.error(`[scan-runner] ${line}`);
          stderrTail.push(line);
          if (stderrTail.length > STDERR_TAIL_LINES) {
            stderrTail.shift();
          }
        }
      });

      child.on("close", (code) => {
        activeProcesses.delete(sessionId);

        // Flush any trailing, non-newline-terminated data
        if (stdoutBuffer.trim()) {
          safeEnqueue(`data: ${stdoutBuffer.trim()}\n\n`);
          stdoutBuffer = "";
        }
        if (stderrCarry.trim()) {
          console.error(`[scan-runner] ${stderrCarry.trim()}`);
          stderrTail.push(stderrCarry.trim());
          stderrCarry = "";
        }

        const exitCode = code ?? 0;

        // If the child failed, surface the stderr tail so the UI isn't silent.
        if (exitCode !== 0 && stderrTail.length > 0) {
          const message = stderrTail.join("\n");
          safeEnqueue(
            `data: ${JSON.stringify({ type: "stream:error", error: message, exitCode })}\n\n`,
          );
        }

        safeEnqueue(
          `data: ${JSON.stringify({ type: "stream:end", exitCode })}\n\n`,
        );
        safeClose();
      });

      child.on("error", (err) => {
        activeProcesses.delete(sessionId);
        safeEnqueue(
          `data: ${JSON.stringify({ type: "stream:error", error: err.message })}\n\n`,
        );
        safeClose();
      });
    },
    cancel() {
      const child = activeProcesses.get(sessionId);
      if (child) {
        child.kill("SIGINT");
        activeProcesses.delete(sessionId);
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export async function DELETE(request: NextRequest) {
  const { sessionId } = await request.json().catch(() => ({ sessionId: "" }));
  const child = activeProcesses.get(sessionId);
  if (child) {
    child.kill("SIGINT");
    activeProcesses.delete(sessionId);
    return new Response(JSON.stringify({ stopped: true }), { status: 200 });
  }
  return new Response(JSON.stringify({ stopped: false, error: "Session not found" }), { status: 404 });
}
