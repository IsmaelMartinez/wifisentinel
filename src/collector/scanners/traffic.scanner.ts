import { run, runAsync } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";

type TrafficResult = NonNullable<NetworkScanResult["traffic"]>;

export interface TrafficScanOptions {
  interface: string;
  duration?: number;
  tool?: "tshark" | "tcpdump";
}

// Well-known plaintext-by-default destination ports.
const UNENCRYPTED_PORTS: Record<number, string> = {
  21: "ftp",
  23: "telnet",
  25: "smtp",
  69: "tftp",
  80: "http",
  110: "pop3",
  143: "imap",
  161: "snmp",
  389: "ldap",
  512: "rexec",
  513: "rlogin",
  514: "rsh",
  873: "rsync",
  3306: "mysql",
  5432: "postgres",
  5900: "vnc",
  6667: "irc",
};

// Fields flow-aligned with tsharkArgs below. Separator `|` is unambiguous for IPs and hostnames.
const TSHARK_SEPARATOR = "|";

function tsharkArgs(iface: string, duration: number): string[] {
  return [
    "-i",
    iface,
    "-a",
    `duration:${duration}`,
    "-n",
    "-Q",
    "-l",
    "-T",
    "fields",
    "-E",
    `separator=${TSHARK_SEPARATOR}`,
    "-e",
    "frame.protocols",
    "-e",
    "ip.dst",
    "-e",
    "tcp.dstport",
    "-e",
    "udp.dstport",
    "-e",
    "dns.qry.name",
    "-e",
    "dns.flags.authenticated",
    "-e",
    "mdns.qry.name",
  ];
}

function extractAppProtocol(frameProtocols: string): string {
  const parts = frameProtocols.split(":").filter(Boolean);
  const skip = new Set([
    "eth",
    "ethertype",
    "ethtype",
    "ip",
    "ipv6",
    "tcp",
    "udp",
    "data",
    "sll",
    "vlan",
  ]);
  for (let i = parts.length - 1; i >= 0; i--) {
    if (!skip.has(parts[i])) return parts[i];
  }
  return parts[parts.length - 1] ?? "unknown";
}

function parseMdnsName(qryName: string): { service: string; host: string } | null {
  const trimmed = qryName.replace(/\.$/, "");
  if (!trimmed.endsWith(".local")) return null;
  const pre = trimmed.slice(0, -".local".length);
  // Patterns like "hostname._ssh._tcp" or "_airplay._tcp".
  const match = pre.match(/^(?:(.+?)\.)?(_[A-Za-z0-9-]+\._(?:tcp|udp))(?:\.(.+))?$/);
  if (!match) return { service: trimmed, host: trimmed };
  const host = (match[1] ?? match[3] ?? "").replace(/\.$/, "");
  return { service: match[2], host: host || trimmed };
}

export function parseTsharkOutput(output: string): Omit<TrafficResult, "durationSeconds"> {
  const protocols: Record<string, number> = {};
  const unencrypted = new Map<string, TrafficResult["unencrypted"][number]>();
  const dnsQueries = new Map<string, TrafficResult["dnsQueries"][number]>();
  const mdnsLeaks = new Map<string, TrafficResult["mdnsLeaks"][number]>();
  let capturedPackets = 0;

  for (const rawLine of output.split("\n")) {
    const line = rawLine.replace(/\r$/, "");
    if (!line.trim()) continue;
    capturedPackets++;

    const cols = line.split(TSHARK_SEPARATOR);
    const frameProtocols = cols[0] ?? "";
    const ipDst = cols[1] ?? "";
    const tcpDst = cols[2] ?? "";
    const udpDst = cols[3] ?? "";
    const dnsQryName = cols[4] ?? "";
    const dnsDnssec = cols[5] ?? "";
    const mdnsQryName = cols[6] ?? "";

    if (frameProtocols) {
      const proto = extractAppProtocol(frameProtocols);
      protocols[proto] = (protocols[proto] ?? 0) + 1;
    }

    const tcpPort = tcpDst ? parseInt(tcpDst, 10) : NaN;
    const udpPort = udpDst ? parseInt(udpDst, 10) : NaN;
    const dstPort = !Number.isNaN(tcpPort)
      ? tcpPort
      : !Number.isNaN(udpPort)
        ? udpPort
        : NaN;
    const protoFamily = !Number.isNaN(tcpPort) ? "tcp" : "udp";

    if (!Number.isNaN(dstPort) && UNENCRYPTED_PORTS[dstPort] && ipDst) {
      const key = `${ipDst}:${dstPort}:${protoFamily}`;
      if (!unencrypted.has(key)) {
        unencrypted.set(key, {
          dest: ipDst,
          port: dstPort,
          protocol: UNENCRYPTED_PORTS[dstPort],
        });
      }
    }

    if (dnsQryName && ipDst && dstPort === 53) {
      const key = `${dnsQryName}|${ipDst}`;
      if (!dnsQueries.has(key)) {
        dnsQueries.set(key, {
          domain: dnsQryName.replace(/\.$/, ""),
          server: ipDst,
          dnssec: dnsDnssec === "1" || /true/i.test(dnsDnssec),
        });
      }
    }

    if (mdnsQryName) {
      const parsed = parseMdnsName(mdnsQryName);
      if (parsed) {
        const key = `${parsed.service}|${parsed.host}`;
        if (!mdnsLeaks.has(key)) {
          mdnsLeaks.set(key, parsed);
        }
      }
    }
  }

  return {
    capturedPackets,
    protocols,
    unencrypted: [...unencrypted.values()],
    dnsQueries: [...dnsQueries.values()],
    mdnsLeaks: [...mdnsLeaks.values()],
  };
}

function tcpdumpArgs(iface: string, count: number): string[] {
  return [
    "-i",
    iface,
    "-n",
    "-q",
    "-l",
    "-tttt",
    "-c",
    String(count),
  ];
}

export function parseTcpdumpOutput(output: string): Omit<TrafficResult, "durationSeconds"> {
  const protocols: Record<string, number> = {};
  const unencrypted = new Map<string, TrafficResult["unencrypted"][number]>();
  const mdnsLeaks = new Map<string, TrafficResult["mdnsLeaks"][number]>();
  let capturedPackets = 0;

  // tcpdump -q lines look like:
  //   2024-01-01 12:00:00.000000 IP 10.0.0.2.54321 > 10.0.0.1.80: tcp 123
  //   2024-01-01 12:00:00.000000 IP6 fe80::1.5353 > ff02::fb.5353: UDP, length 80
  // With -v we'd see more, but we stick to -q to keep parsing narrow.
  const lineRe = /IP6?\s+(\S+)\s+>\s+(\S+):\s*(\S+)/;

  for (const rawLine of output.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    capturedPackets++;

    const m = line.match(lineRe);
    if (!m) continue;

    const dstAddr = m[2];
    const proto = m[3].replace(/[,:]$/, "").toLowerCase();
    protocols[proto] = (protocols[proto] ?? 0) + 1;

    const dotIdx = dstAddr.lastIndexOf(".");
    if (dotIdx <= 0) continue;
    const ip = dstAddr.slice(0, dotIdx);
    const port = parseInt(dstAddr.slice(dotIdx + 1), 10);
    if (Number.isNaN(port)) continue;

    const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
    if (isIpv4 && UNENCRYPTED_PORTS[port]) {
      const key = `${ip}:${port}`;
      if (!unencrypted.has(key)) {
        unencrypted.set(key, {
          dest: ip,
          port,
          protocol: UNENCRYPTED_PORTS[port],
        });
      }
    }

    if (port === 5353) {
      const host = isIpv4 ? ip : dstAddr;
      const key = `mdns|${host}`;
      if (!mdnsLeaks.has(key)) {
        mdnsLeaks.set(key, { service: "mdns", host });
      }
    }
  }

  return {
    capturedPackets,
    protocols,
    unencrypted: [...unencrypted.values()],
    dnsQueries: [],
    mdnsLeaks: [...mdnsLeaks.values()],
  };
}

function detectTool(override?: "tshark" | "tcpdump"): "tshark" | "tcpdump" | null {
  const probe = (bin: string) => {
    const r = run(bin, ["-v"]);
    return (
      r.exitCode === 0 ||
      /tshark|tcpdump/i.test(r.stderr) ||
      /tshark|tcpdump/i.test(r.stdout)
    );
  };
  if (override) {
    return probe(override) ? override : null;
  }
  if (probe("tshark")) return "tshark";
  if (probe("tcpdump")) return "tcpdump";
  return null;
}

export async function scanTraffic(
  options: TrafficScanOptions
): Promise<TrafficResult | undefined> {
  const duration = Math.max(1, options.duration ?? 8);
  const tool = detectTool(options.tool);
  if (!tool) return undefined;

  const started = Date.now();

  if (tool === "tshark") {
    const result = await runAsync(
      "tshark",
      tsharkArgs(options.interface, duration),
      (duration + 5) * 1000
    );
    // Permission / interface errors: no usable stdout -> treat as unavailable.
    if (!result.stdout.trim()) return undefined;
    const parsed = parseTsharkOutput(result.stdout);
    return {
      ...parsed,
      durationSeconds: Math.max(1, Math.round((Date.now() - started) / 1000)),
    };
  }

  // tcpdump fallback: bound by packet count and timeout. Duration is best-effort.
  const packetBudget = Math.max(50, duration * 50);
  const result = await runAsync(
    "tcpdump",
    tcpdumpArgs(options.interface, packetBudget),
    (duration + 2) * 1000
  );
  if (!result.stdout.trim()) return undefined;
  const parsed = parseTcpdumpOutput(result.stdout);
  return {
    ...parsed,
    durationSeconds: Math.max(1, Math.round((Date.now() - started) / 1000)),
  };
}
