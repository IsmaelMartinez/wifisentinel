import { runAsync } from "../exec.js";
import { bin, currentPlatform, type Platform } from "./commands.js";

export interface NetworkBootstrap {
  interface: string;
  /** macOS network service name for networksetup (e.g. "Wi-Fi"); undefined on Linux. */
  service?: string;
  ip: string;
  subnet: string;
  gatewayIp: string;
  broadcastAddr: string;
}

/** Network address in CIDR form, e.g. 10.0.5.7 + 16 -> "10.0.0.0/16". */
export function subnetCidr(ip: string, cidrBits: number): string {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return `${ip}/${cidrBits}`;
  }
  const ipNum = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = cidrBits <= 0 ? 0 : (0xffffffff << (32 - Math.min(cidrBits, 32))) >>> 0;
  const net = (ipNum & mask) >>> 0;
  return `${net >>> 24}.${(net >>> 16) & 0xff}.${(net >>> 8) & 0xff}.${net & 0xff}/${cidrBits}`;
}

/**
 * Find the Wi-Fi port in `networksetup -listallhardwareports` output:
 *   Hardware Port: Wi-Fi
 *   Device: en0
 */
export function parseWifiHardwarePort(output: string): { device: string; service: string } | null {
  const blocks = output.split(/\n{2,}/);
  for (const block of blocks) {
    const port = /^Hardware Port:\s*(.+)$/m.exec(block)?.[1]?.trim();
    const device = /^Device:\s*(\S+)/m.exec(block)?.[1];
    if (port && device && /^(?:Wi-Fi|AirPort)$/i.test(port)) {
      return { device, service: port };
    }
  }
  return null;
}

/** Parse `ip route show default`: "default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600". */
export function parseLinuxDefaultRoute(output: string): { gatewayIp: string; iface: string } | null {
  const m = /default via (\d+\.\d+\.\d+\.\d+) dev (\S+)/.exec(output);
  return m ? { gatewayIp: m[1], iface: m[2] } : null;
}

/** First interface listed by `iw dev`. */
export function parseIwDevInterface(output: string): string | null {
  return /Interface\s+(\S+)/.exec(output)?.[1] ?? null;
}

/** The wireless interface to scan: the Wi-Fi hardware port on macOS, the default-route (or first iw) interface on Linux. */
export async function detectWifiInterface(
  platform: Platform = currentPlatform(),
): Promise<{ iface: string; service?: string }> {
  if (platform === "darwin") {
    const port = parseWifiHardwarePort((await runAsync(bin("networksetup", platform), ["-listallhardwareports"])).stdout);
    return port ? { iface: port.device, service: port.service } : { iface: "en0", service: "Wi-Fi" };
  }
  const route = parseLinuxDefaultRoute((await runAsync("ip", ["route", "show", "default"])).stdout);
  if (route) return { iface: route.iface };
  return { iface: parseIwDevInterface((await runAsync("iw", ["dev"])).stdout) ?? "wlan0" };
}

async function detectNetworkDarwin(): Promise<NetworkBootstrap> {
  const { iface, service } = await detectWifiInterface("darwin");
  const ifconfigResult = await runAsync(bin("ifconfig", "darwin"), [iface]);
  const inetMatch = ifconfigResult.stdout.match(
    /inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+) broadcast (\d+\.\d+\.\d+\.\d+)/
  );
  const ip = inetMatch?.[1] ?? "unknown";
  const broadcastAddr = inetMatch?.[3] ?? "255.255.255.255";

  const maskHex = inetMatch?.[2] ?? "0xffffff00";
  const maskNum = parseInt(maskHex, 16);
  const cidrBits = maskNum.toString(2).split("1").length - 1;
  const subnet = subnetCidr(ip, cidrBits);

  // Use networksetup for reliable gateway detection (works even with VPN active)
  let gatewayIp = "unknown";
  const nsInfo = await runAsync(bin("networksetup", "darwin"), ["-getinfo", service ?? "Wi-Fi"]);
  const routerMatch = nsInfo.stdout.match(/Router:\s+(\d+\.\d+\.\d+\.\d+)/);
  if (routerMatch) {
    gatewayIp = routerMatch[1];
  } else {
    // Fallback: the default route bound to this interface
    const routeResult = await runAsync(bin("netstat", "darwin"), ["-rn"]);
    const ifaceDefault = routeResult.stdout
      .split("\n")
      .find((l) => l.startsWith("default") && l.trim().split(/\s+/).includes(iface));
    const gwMatch = ifaceDefault?.match(/default\s+(\d+\.\d+\.\d+\.\d+)/);
    if (gwMatch) gatewayIp = gwMatch[1];
  }

  return { interface: iface, service, ip, subnet, gatewayIp, broadcastAddr };
}

async function detectNetworkLinux(): Promise<NetworkBootstrap> {
  const route = parseLinuxDefaultRoute((await runAsync("ip", ["route", "show", "default"])).stdout);
  const iface = route?.iface ?? (await detectWifiInterface("linux")).iface;
  const gatewayIp = route?.gatewayIp ?? "unknown";

  // Get IP and CIDR from ip addr
  const addrResult = await runAsync("ip", ["-o", "-4", "addr", "show", iface]);
  let ip = "unknown";
  let cidrBits = 24;
  const addrMatch = addrResult.stdout.match(/inet (\d+\.\d+\.\d+\.\d+)\/(\d+)/);
  if (addrMatch) {
    ip = addrMatch[1];
    cidrBits = parseInt(addrMatch[2], 10);
  }

  const subnet = subnetCidr(ip, cidrBits);

  // Compute broadcast from IP and CIDR
  const ipParts = ip.split(".").map(Number);
  const hostBits = 32 - cidrBits;
  const ipNum =
    ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
  const broadcastNum = (ipNum | ((1 << hostBits) - 1)) >>> 0;
  const broadcastAddr = ip === "unknown"
    ? "255.255.255.255"
    : `${(broadcastNum >>> 24) & 0xff}.${(broadcastNum >>> 16) & 0xff}.${(broadcastNum >>> 8) & 0xff}.${broadcastNum & 0xff}`;

  return { interface: iface, ip, subnet, gatewayIp, broadcastAddr };
}

export function detectNetwork(platform: Platform = currentPlatform()): Promise<NetworkBootstrap> {
  return platform === "linux" ? detectNetworkLinux() : detectNetworkDarwin();
}
