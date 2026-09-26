export interface NetstatEntry {
  proto: string;
  localAddr: string;
  localPort: string;
  remoteAddr: string;
  remotePort: string;
  state: string;
}

/**
 * Split a netstat endpoint into address and port.
 * macOS separates the port with a dot (`1.2.3.4.443`, `fe80::1.5353`, `*.*`);
 * Linux uses a colon (`1.2.3.4:443`, `:::22`, `0.0.0.0:*`). A macOS token's
 * text after its last colon always contains the dot-port, so a purely numeric
 * (or `*`) suffix after the last colon identifies the Linux form.
 */
export function splitNetstatAddr(token: string): { addr: string; port: string } | null {
  const colon = token.lastIndexOf(":");
  if (colon >= 0) {
    const port = token.slice(colon + 1);
    if (port === "*" || /^\d+$/.test(port)) {
      return { addr: token.slice(0, colon), port };
    }
  }
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return null;
  return { addr: token.slice(0, dot), port: token.slice(dot + 1) };
}

/**
 * Parse `netstat -an` TCP/UDP rows from macOS or Linux.
 * macOS: tcp4  0  0  192.168.1.93.64127  20.26.156.210.443  ESTABLISHED
 * Linux: tcp   0  0  192.168.1.5:54321   93.184.216.34:443  ESTABLISHED
 * States are upper-cased and macOS's SYN_RCVD is reported as SYN_RECV.
 */
export function parseNetstat(output: string): NetstatEntry[] {
  const entries: NetstatEntry[] = [];
  for (const line of output.split("\n")) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 5 || !/^(?:tcp|udp)[46]?$/i.test(cols[0])) continue;
    const local = splitNetstatAddr(cols[3]);
    const remote = splitNetstatAddr(cols[4]);
    if (!local || !remote) continue;
    const state = (cols[5] ?? "").toUpperCase();
    entries.push({
      proto: cols[0].toLowerCase(),
      localAddr: local.addr,
      localPort: local.port,
      remoteAddr: remote.addr,
      remotePort: remote.port,
      state: state === "SYN_RCVD" ? "SYN_RECV" : state,
    });
  }
  return entries;
}
