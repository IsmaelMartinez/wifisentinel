import { Listr } from "listr2";
import type { ScanEvent } from "../collector/scan-events.js";
import { ScanEventEmitter } from "../collector/scan-events.js";
import { collectNetworkScan, type ScanOptions } from "../collector/index.js";
import type { NetworkScanResult } from "../collector/schema/scan-result.js";

interface TaskDef {
  title: string;
  scanner: string;
}

export function createScanTasks(opts: { skipPorts?: boolean; skipSpeed?: boolean; skipTraffic?: boolean }): TaskDef[] {
  const tasks: TaskDef[] = [
    { title: "WiFi environment", scanner: "wifi" },
    { title: "DNS audit", scanner: "dns" },
    { title: "Security posture", scanner: "security" },
    { title: "Active connections", scanner: "connections" },
    { title: "Host discovery", scanner: "host-discovery" },
  ];

  if (!opts.skipPorts) {
    tasks.push({ title: "Port scanning", scanner: "ports" });
  }

  tasks.push({ title: "Deep analysis", scanner: "deep-analysis" });

  if (!opts.skipSpeed) {
    tasks.push({ title: "Speed test", scanner: "speed" });
  }

  return tasks;
}

export async function runScanWithProgress(scanOptions: ScanOptions): Promise<NetworkScanResult> {
  const emitter = new ScanEventEmitter();
  const taskDefs = createScanTasks({
    skipPorts: scanOptions.skipPortScan,
    skipSpeed: scanOptions.skipSpeed,
    skipTraffic: scanOptions.skipTraffic,
  });
  const completed = new Map<string, string>();

  emitter.on("event", (event: ScanEvent) => {
    if (event.type === "scanner:complete") {
      completed.set(event.scanner, event.summary);
    }
  });

  const listrTasks = new Listr(
    taskDefs.map((def) => ({
      title: def.title,
      task: async (_ctx: unknown, task: { title: string }) => {
        await new Promise<void>((resolve) => {
          if (completed.has(def.scanner)) {
            task.title = `${def.title} — ${completed.get(def.scanner)}`;
            resolve();
            return;
          }
          const handler = (event: ScanEvent) => {
            if (event.type === "scanner:complete" && event.scanner === def.scanner) {
              task.title = `${def.title} — ${event.summary}`;
              emitter.off("event", handler);
              resolve();
            }
          };
          emitter.on("event", handler);
        });
      },
    })),
    { concurrent: true, rendererOptions: { collapseSubtasks: false } }
  );

  const [scanResult] = await Promise.all([
    collectNetworkScan({ ...scanOptions, emitter }),
    listrTasks.run(),
  ]);

  return scanResult;
}
