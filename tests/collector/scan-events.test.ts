import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ScanEventEmitter } from "../../src/collector/scan-events.js";
import type { ScanEvent } from "../../src/collector/scan-events.js";

describe("ScanEventEmitter", () => {
  it("emits scan:start event", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));
    emitter.scanStart("test-id");
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "scan:start");
    assert.equal((events[0] as any).scanId, "test-id");
  });

  it("emits scanner lifecycle events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));
    emitter.scannerStart("wifi");
    emitter.scannerComplete("wifi", "802.11ax, 5GHz");
    assert.equal(events.length, 2);
    assert.equal(events[0].type, "scanner:start");
    assert.equal(events[1].type, "scanner:complete");
    assert.equal((events[1] as any).summary, "802.11ax, 5GHz");
  });

  it("emits host:found events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));
    emitter.hostFound("192.168.1.100", "aa:bb:cc:dd:ee:ff");
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "host:found");
    assert.equal((events[0] as any).ip, "192.168.1.100");
  });

  it("emits host:enriched events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));
    emitter.hostEnriched("192.168.1.100", "Apple Inc");
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "host:enriched");
    assert.equal((events[0] as any).vendor, "Apple Inc");
  });

  it("emits port:found events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));
    emitter.portFound("192.168.1.100", 22, "ssh");
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "port:found");
  });

  it("emits host:camera-detected events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("event", (e) => events.push(e));
    emitter.hostCameraDetected("192.168.1.50", ["rtsp port open", "camera vendor"]);
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "host:camera-detected");
    assert.equal((events[0] as any).ip, "192.168.1.50");
  });

  it("serialises events as NDJSON", () => {
    const emitter = new ScanEventEmitter();
    const lines: string[] = [];
    emitter.on("event", (e) => lines.push(emitter.toJSON(e)));
    emitter.scanStart("test-id");
    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.type, "scan:start");
    assert.equal(parsed.scanId, "test-id");
    assert.ok(parsed.timestamp);
  });
});
