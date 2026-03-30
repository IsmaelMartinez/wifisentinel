import { run } from "../exec.js";
import type { NetworkScanResult } from "../schema/scan-result.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseEnabled(output: string): boolean {
  return /enabled/i.test(output);
}

function parseSysctlBool(output: string): boolean {
  // e.g. "net.inet.ip.forwarding: 0"  or  "net.inet.ip.forwarding: 1"
  const match = output.match(/:\s*(\d+)/);
  return match ? match[1] !== "0" : false;
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

function scanFirewall(): NetworkScanResult["security"]["firewall"] {
  const base = "/usr/libexec/ApplicationFirewall/socketfilterfw";

  const globalState = run(base, ["--getglobalstate"]).stdout;
  const stealthOut = run(base, ["--getstealthmode"]).stdout;
  const allowSigned = run(base, ["--getallowsigned"]).stdout;
  const allowDownloaded = run(base, ["--getallowsignedapp"]).stdout;

  return {
    enabled: parseEnabled(globalState),
    stealthMode: parseEnabled(stealthOut),
    autoAllowSigned: parseEnabled(allowSigned),
    autoAllowDownloaded: parseEnabled(allowDownloaded),
  };
}

// ---------------------------------------------------------------------------
// VPN
// ---------------------------------------------------------------------------

function scanVpn(): NetworkScanResult["security"]["vpn"] {
  // scutil --nc list shows configured VPN connections and their state
  const ncList = run("/usr/sbin/scutil", ["--nc", "list"]).stdout;

  // A connected entry looks like:
  //   * (Connected)    <UUID>  "My VPN"   [VPNType]
  const connectedMatch = ncList.match(/\(Connected\)[^\n]*"([^"]+)"/i);
  if (connectedMatch) {
    return { installed: true, active: true, provider: connectedMatch[1] };
  }

  // Any entry (connected or not) means VPN is installed
  const hasAny = /\(Connected\)|\(Disconnected\)|\(Connecting\)/i.test(ncList);
  if (hasAny) {
    return { installed: true, active: false };
  }

  // Also check networksetup for VPN-named services as a fallback
  const services = run("/usr/sbin/networksetup", [
    "-listallnetworkservices",
  ]).stdout;
  const vpnService = services
    .split("\n")
    .find((line) => /vpn|wireguard|tunnel/i.test(line));

  if (vpnService) {
    return { installed: true, active: false, provider: vpnService.trim() };
  }

  return { installed: false, active: false };
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

function scanProxy(): NetworkScanResult["security"]["proxy"] {
  const out = run("/usr/sbin/networksetup", ["-getwebproxy", "Wi-Fi"]).stdout;

  // Output format:
  //   Enabled: Yes
  //   Server: proxy.example.com
  //   Port: 8080
  const enabledMatch = out.match(/^Enabled:\s*(\S+)/im);
  const serverMatch = out.match(/^Server:\s*(\S+)/im);
  const portMatch = out.match(/^Port:\s*(\d+)/im);

  const enabled =
    enabledMatch ? /yes/i.test(enabledMatch[1]) : false;
  const server = serverMatch ? serverMatch[1] : undefined;
  const port = portMatch ? parseInt(portMatch[1], 10) : undefined;

  return {
    enabled,
    ...(server ? { server } : {}),
    ...(port !== undefined && !isNaN(port) ? { port } : {}),
  };
}

// ---------------------------------------------------------------------------
// Kernel params
// ---------------------------------------------------------------------------

function scanKernelParams(): NetworkScanResult["security"]["kernelParams"] {
  const forwarding = run("/usr/sbin/sysctl", ["net.inet.ip.forwarding"]).stdout;
  const redirect = run("/usr/sbin/sysctl", ["net.inet.ip.redirect"]).stdout;

  return {
    ipForwarding: parseSysctlBool(forwarding),
    icmpRedirects: parseSysctlBool(redirect),
  };
}

// ---------------------------------------------------------------------------
// Client isolation
// ---------------------------------------------------------------------------

function scanClientIsolation(knownHostIp?: string): boolean | null {
  // If no known host IP was supplied, try to find one from the ARP table
  let targetIp = knownHostIp;

  if (!targetIp) {
    const arpOut = run("/usr/sbin/arp", ["-a"]).stdout;
    // Lines look like:  hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff ...
    const arpMatch = arpOut.match(/\((\d{1,3}(?:\.\d{1,3}){3})\)/);
    if (arpMatch) {
      targetIp = arpMatch[1];
    }
  }

  if (!targetIp) {
    // Cannot determine isolation without a peer to ping
    return null;
  }

  // ping -c 1 -W 2000 (2 s timeout, 1 packet)
  const pingResult = run("/sbin/ping", [
    "-c",
    "1",
    "-W",
    "2000",
    targetIp,
  ]);

  // If ping succeeds (exit 0) the host is reachable → no client isolation
  // If ping fails the host is unreachable → client isolation may be active
  return pingResult.exitCode !== 0;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function scanSecurityPosture(
  knownHostIp?: string
): Promise<NetworkScanResult["security"]> {
  const firewall = scanFirewall();
  const vpn = scanVpn();
  const proxy = scanProxy();
  const kernelParams = scanKernelParams();
  const clientIsolation = scanClientIsolation(knownHostIp);

  return { firewall, vpn, proxy, kernelParams, clientIsolation };
}
