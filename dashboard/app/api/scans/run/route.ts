import { NextRequest } from "next/server";
import { spawn, type ChildProcess } from "node:child_process";
import { resolve } from "node:path";

export const dynamic = "force-dynamic";

// Track running watch processes so they can be stopped
const activeProcesses = new Map<string, ChildProcess>();

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const skipPorts = body.skipPorts === true;
  const skipSpeed = body.skipSpeed === true;
  const skipTraffic = body.skipTraffic === true;
  const stealth = body.stealth === true;
  const watch = body.watch === true;
  const interval = typeof body.interval === "number" ? Math.max(1, body.interval) : 5;

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
      const child = spawn("npx", ["tsx", ...args], {
        cwd: cliDir,
        stdio: ["ignore", "pipe", "pipe"],
      });

      activeProcesses.set(sessionId, child);

      // Send session ID so client can stop it
      const meta = JSON.stringify({ type: "session:start", sessionId });
      controller.enqueue(encoder.encode(`data: ${meta}\n\n`));

      let buffer = "";
      child.stdout.on("data", (chunk: Buffer) => {
        buffer += chunk.toString();
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (line.trim()) {
            controller.enqueue(encoder.encode(`data: ${line}\n\n`));
          }
        }
      });

      child.stderr.on("data", (chunk: Buffer) => {
        console.error(`[scan-runner] ${chunk.toString().trim()}`);
      });

      child.on("close", (code) => {
        activeProcesses.delete(sessionId);
        const payload = JSON.stringify({ type: "stream:end", exitCode: code ?? 0 });
        controller.enqueue(encoder.encode(`data: ${payload}\n\n`));
        controller.close();
      });

      child.on("error", (err) => {
        activeProcesses.delete(sessionId);
        const payload = JSON.stringify({ type: "stream:error", error: err.message });
        controller.enqueue(encoder.encode(`data: ${payload}\n\n`));
        controller.close();
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
