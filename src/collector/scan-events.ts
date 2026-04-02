import { EventEmitter } from "node:events";
import type { NetworkChange } from "../analyser/diff.js";

export type ScanEvent =
  | { type: "scan:start"; scanId: string; timestamp: string }
  | { type: "scanner:start"; scanner: string; timestamp: string }
  | { type: "scanner:complete"; scanner: string; summary: string; timestamp: string }
  | { type: "scanner:error"; scanner: string; error: string; timestamp: string }
  | { type: "host:found"; ip: string; mac: string; timestamp: string }
  | { type: "host:enriched"; ip: string; vendor: string; timestamp: string }
  | { type: "port:found"; ip: string; port: number; service: string; timestamp: string }
  | { type: "scan:complete"; scanId: string; hostCount: number; timestamp: string }
  | { type: "scan:score"; score: number; timestamp: string }
  | { type: "bootstrap:complete"; gateway: string; ip: string; subnet: string; timestamp: string }
  | { type: "host:camera-detected"; ip: string; indicators: string[]; timestamp: string }
  | { type: "watch:cycle-start"; cycle: number; timestamp: string }
  | { type: "watch:cycle-complete"; cycle: number; changes: number; timestamp: string }
  | { type: "watch:alert"; change: NetworkChange; timestamp: string };

export class ScanEventEmitter extends EventEmitter {
  private ts(): string {
    return new Date().toISOString();
  }

  scanStart(scanId: string): void {
    this.emit("event", { type: "scan:start", scanId, timestamp: this.ts() } satisfies ScanEvent);
  }

  scannerStart(scanner: string): void {
    this.emit("event", { type: "scanner:start", scanner, timestamp: this.ts() } satisfies ScanEvent);
  }

  scannerComplete(scanner: string, summary: string): void {
    this.emit("event", { type: "scanner:complete", scanner, summary, timestamp: this.ts() } satisfies ScanEvent);
  }

  scannerError(scanner: string, error: string): void {
    this.emit("event", { type: "scanner:error", scanner, error, timestamp: this.ts() } satisfies ScanEvent);
  }

  hostFound(ip: string, mac: string): void {
    this.emit("event", { type: "host:found", ip, mac, timestamp: this.ts() } satisfies ScanEvent);
  }

  hostEnriched(ip: string, vendor: string): void {
    this.emit("event", { type: "host:enriched", ip, vendor, timestamp: this.ts() } satisfies ScanEvent);
  }

  portFound(ip: string, port: number, service: string): void {
    this.emit("event", { type: "port:found", ip, port, service, timestamp: this.ts() } satisfies ScanEvent);
  }

  scanComplete(scanId: string, hostCount: number): void {
    this.emit("event", { type: "scan:complete", scanId, hostCount, timestamp: this.ts() } satisfies ScanEvent);
  }

  scanScore(score: number): void {
    this.emit("event", { type: "scan:score", score, timestamp: this.ts() } satisfies ScanEvent);
  }

  bootstrapComplete(gateway: string, ip: string, subnet: string): void {
    this.emit("event", { type: "bootstrap:complete", gateway, ip, subnet, timestamp: this.ts() } satisfies ScanEvent);
  }

  hostCameraDetected(ip: string, indicators: string[]): void {
    this.emit("event", { type: "host:camera-detected", ip, indicators, timestamp: this.ts() } satisfies ScanEvent);
  }

  watchCycleStart(cycle: number): void {
    this.emit("event", { type: "watch:cycle-start", cycle, timestamp: this.ts() } satisfies ScanEvent);
  }

  watchCycleComplete(cycle: number, changes: number): void {
    this.emit("event", { type: "watch:cycle-complete", cycle, changes, timestamp: this.ts() } satisfies ScanEvent);
  }

  watchAlert(change: NetworkChange): void {
    this.emit("event", { type: "watch:alert", change, timestamp: this.ts() } satisfies ScanEvent);
  }

  toJSON(event: ScanEvent): string {
    return JSON.stringify(event);
  }
}
