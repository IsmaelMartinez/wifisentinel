import { NextRequest } from "next/server";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const args = ["src/cli.ts", "scan", "--events", "--no-save"];

  if (body.skipPorts) args.push("--skip-ports");
  if (body.skipSpeed) args.push("--skip-speed");
  if (body.skipTraffic) args.push("--skip-traffic");

  const cliDir = resolve(process.cwd(), "..");

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const child = spawn("npx", ["tsx", ...args], {
        cwd: cliDir,
        stdio: ["ignore", "pipe", "pipe"],
      });

      child.stdout.on("data", (chunk: Buffer) => {
        const lines = chunk.toString().split("\n").filter(Boolean);
        for (const line of lines) {
          controller.enqueue(encoder.encode(`data: ${line}\n\n`));
        }
      });

      child.stderr.on("data", (chunk: Buffer) => {
        console.error(`[scan-runner] ${chunk.toString().trim()}`);
      });

      child.on("close", (code) => {
        controller.enqueue(encoder.encode(`data: {"type":"stream:end","exitCode":${code ?? 0}}\n\n`));
        controller.close();
      });

      child.on("error", (err) => {
        controller.enqueue(encoder.encode(`data: {"type":"stream:error","error":"${err.message}"}\n\n`));
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
