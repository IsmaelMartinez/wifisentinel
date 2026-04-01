import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NetworkTreeRenderer } from "../../src/reporter/network-tree.js";

// Strip ANSI escape codes for plain-text assertions
function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1B\[[0-9;]*m/g, "");
}

describe("NetworkTreeRenderer", () => {
  it("renders gateway as root node", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    const output = stripAnsi(tree.render());
    assert.ok(output.includes("192.168.1.1"));
    assert.ok(output.includes("gateway"));
  });

  it("adds hosts progressively", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    tree.addHost("192.168.1.100", "aa:bb:cc:dd:ee:ff");
    const output = stripAnsi(tree.render());
    assert.ok(output.includes("192.168.1.100"));
  });

  it("enriches hosts with vendor info", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    tree.addHost("192.168.1.100", "aa:bb:cc:dd:ee:ff");
    tree.enrichHost("192.168.1.100", "Apple Inc");
    const output = stripAnsi(tree.render());
    assert.ok(output.includes("Apple Inc"));
  });

  it("adds ports to hosts", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    tree.addHost("192.168.1.100", "aa:bb:cc:dd:ee:ff");
    tree.addPort("192.168.1.100", 22, "ssh");
    const output = stripAnsi(tree.render());
    assert.ok(output.includes("22/ssh"));
  });

  it("shows host count in header", () => {
    const tree = new NetworkTreeRenderer();
    tree.setGateway("192.168.1.1");
    tree.addHost("192.168.1.100", "aa:bb:cc:dd:ee:ff");
    tree.addHost("192.168.1.105", "bb:cc:dd:ee:ff:00");
    const output = stripAnsi(tree.render());
    assert.ok(output.includes("2 hosts"));
  });
});
