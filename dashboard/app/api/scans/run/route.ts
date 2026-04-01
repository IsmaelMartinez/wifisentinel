import { NextRequest } from "next/server";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const skipPorts = body.skipPorts === true;
  const skipSpeed = body.skipSpeed === true;
  const skipTraffic = body.skipTraffic === true;
  const args = ["src/cli.ts", "scan", "--events", "--no-save"];

  if (skipPorts) args.push("--skip-ports");
  if (skipSpeed) args.push("--skip-speed");
  if (skipTraffic) args.push("--skip-traffic");

  const cliDir = process.env.CLI_ROOT_DIR ?? resolve(process.cwd(), "..");

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const child = spawn("npx", ["tsx", ...args], {
        cwd: cliDir,
        stdio: ["ignore", "pipe", "pipe"],
      });

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
        const payload = JSON.stringify({ type: "stream:end", exitCode: code ?? 0 });
        controller.enqueue(encoder.encode(`data: ${payload}\n\n`));
        controller.close();
      });

      child.on("error", (err) => {
        const payload = JSON.stringify({ type: "stream:error", error: err.message });
        controller.enqueue(encoder.encode(`data: ${payload}\n\n`));
        controller.close();
      });
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
