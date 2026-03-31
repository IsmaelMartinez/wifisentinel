import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildChannelMap } from "../../../src/analyser/rf/channel-map.js";

function baseWifi(overrides: any = {}): any {
  return {
    ssid: "TestNetwork",
    signal: -50,
    security: "WPA3 Personal",
    channel: 6,
    nearbyNetworks: [],
    ...overrides,
  };
}

describe("buildChannelMap", () => {
  it("returns channel map with only current network when no nearby networks", () => {
    const result = buildChannelMap(baseWifi());
    assert.equal(result.currentChannel, 6);
    assert.equal(result.currentBand, "2.4GHz");
    // 14 channels for 2.4 GHz
    assert.equal(result.channels.length, 14);
    // Channel 6 should have 1 network (the current one)
    const ch6 = result.channels.find(c => c.channel === 6)!;
    assert.equal(ch6.networkCount, 1);
  });

  it("detects 2.4 GHz overlap: network on channel 6 overlaps channels 4-8", () => {
    const wifi = baseWifi({
      nearbyNetworks: [
        { ssid: "Neighbor", signal: -60, security: "WPA2 Personal", channel: 6 },
      ],
    });
    const result = buildChannelMap(wifi);

    // Channel 6 direct: current + neighbor = 2 networks
    const ch6 = result.channels.find(c => c.channel === 6)!;
    assert.equal(ch6.networkCount, 2);

    // Channels 4,5,7,8 should have overlap from the two channel-6 networks
    for (const ch of [4, 5, 7, 8]) {
      const info = result.channels.find(c => c.channel === ch)!;
      assert.ok(info.overlapCount >= 2, `Channel ${ch} should show overlap from ch6 networks`);
    }

    // Channel 1 should have no overlap from channel 6 (distance is 5)
    const ch1 = result.channels.find(c => c.channel === 1)!;
    assert.equal(ch1.overlapCount, 0);
  });

  it("recommends a non-overlapping channel (1, 6, or 11) with lowest saturation", () => {
    // Load channel 6 heavily
    const wifi = baseWifi({
      nearbyNetworks: [
        { ssid: "A", signal: -40, security: "WPA2 Personal", channel: 6 },
        { ssid: "B", signal: -45, security: "WPA2 Personal", channel: 6 },
        { ssid: "C", signal: -50, security: "WPA2 Personal", channel: 6 },
      ],
    });
    const result = buildChannelMap(wifi);

    // Recommended channel should be 1 or 11, not 6 since 6 is congested
    assert.ok(
      [1, 11].includes(result.recommendedChannel),
      `Expected recommended channel to be 1 or 11, got ${result.recommendedChannel}`,
    );
    assert.ok(result.recommendationReason.includes("saturation"));
  });

  it("identifies current channel correctly", () => {
    const wifi = baseWifi({ channel: 11 });
    const result = buildChannelMap(wifi);
    assert.equal(result.currentChannel, 11);
  });

  it("5 GHz channels have no overlap", () => {
    const wifi = baseWifi({
      channel: 36,
      nearbyNetworks: [
        { ssid: "Neighbor5", signal: -55, security: "WPA3 Personal", channel: 40 },
      ],
    });
    const result = buildChannelMap(wifi);
    assert.equal(result.currentBand, "5GHz");

    // No channel should have overlapCount > 0 in 5 GHz
    for (const ch of result.channels) {
      assert.equal(ch.overlapCount, 0, `5 GHz channel ${ch.channel} should have 0 overlap`);
    }
  });

  it("recommends current channel when already optimal", () => {
    // Load channels 1, 6, and 11 equally so current channel wins the tie
    const wifi = baseWifi({
      channel: 1,
      nearbyNetworks: [
        { ssid: "A", signal: -50, security: "WPA2 Personal", channel: 6 },
        { ssid: "B", signal: -50, security: "WPA2 Personal", channel: 11 },
      ],
    });
    const result = buildChannelMap(wifi);
    // All three non-overlapping channels have similar load; reduce picks first <= so ch1 wins
    assert.equal(result.recommendedChannel, 1);
    assert.ok(result.recommendationReason.includes("already optimal"));
  });
});
