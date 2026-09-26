export interface PingStats {
  avgMs: number;
  minMs: number;
  maxMs: number;
  jitterMs: number;
  lossPercent: number;
}

/**
 * Parse ping summary output from macOS or Linux.
 * macOS: round-trip min/avg/max/stddev = 9.621/10.047/10.474/0.427 ms
 * Linux: rtt min/avg/max/mdev = 2.123/2.456/2.789/0.271 ms
 * The last field (stddev or mdev) is used as the jitter estimate.
 */
export function parsePingStats(output: string): PingStats {
  const lossMatch = /([\d.]+)% packet loss/.exec(output);
  const lossPercent = lossMatch ? parseFloat(lossMatch[1]) : 100;

  const rtt = /min\/avg\/max\/(?:stddev|mdev) = ([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)/.exec(output);
  if (!rtt) return { avgMs: 0, minMs: 0, maxMs: 0, jitterMs: 0, lossPercent };

  return {
    minMs: parseFloat(rtt[1]),
    avgMs: parseFloat(rtt[2]),
    maxMs: parseFloat(rtt[3]),
    jitterMs: parseFloat(rtt[4]),
    lossPercent,
  };
}
