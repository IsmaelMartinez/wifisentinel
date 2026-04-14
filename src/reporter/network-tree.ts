import chalk from "chalk";

const RED = chalk.hex("#f44747");
const AMBER = chalk.hex("#cca700");

interface HostNode {
  ip: string;
  mac: string;
  vendor?: string;
  ports: Array<{ port: number; service: string }>;
  isCamera?: boolean;
}

export class NetworkTreeRenderer {
  private gateway = "";
  private hosts: Map<string, HostNode> = new Map();

  setGateway(ip: string): void {
    this.gateway = ip;
  }

  addHost(ip: string, mac: string): void {
    if (!this.hosts.has(ip)) {
      this.hosts.set(ip, { ip, mac, ports: [] });
    }
  }

  enrichHost(ip: string, vendor: string, isCamera?: boolean): void {
    const host = this.hosts.get(ip);
    if (host) {
      host.vendor = vendor;
      if (isCamera !== undefined) host.isCamera = isCamera;
    }
  }

  addPort(ip: string, port: number, service: string): void {
    const host = this.hosts.get(ip);
    if (host) host.ports.push({ port, service });
  }

  render(): string {
    const serviceCount = Array.from(this.hosts.values()).reduce(
      (sum, h) => sum + h.ports.length,
      0
    );
    const hostCount = this.hosts.size;
    const header = chalk.dim(
      `NETWORK MAP (${hostCount} hosts${serviceCount > 0 ? ` · ${serviceCount} services` : ""})`
    );
    const lines: string[] = [header];
    lines.push(`${chalk.dim("┌─")} ${AMBER(this.gateway)} ${chalk.dim("gateway")}`);
    const hostList = Array.from(this.hosts.values());
    hostList.forEach((host, idx) => {
      const isLast = idx === hostList.length - 1;
      const connector = isLast ? "└─" : "├─";
      const vendorStr = host.vendor ? chalk.dim(` ${host.vendor}`) : "";
      const cameraFlag = host.isCamera ? RED(" ✘ CAM") : "";
      const ipColor = host.isCamera ? RED : (s: string) => s;
      lines.push(`${chalk.dim(connector)} ${ipColor(host.ip)}${vendorStr}${cameraFlag}`);
      if (host.ports.length > 0) {
        const prefix = isLast ? " " : "│";
        const portStr = host.ports.map((p) => `${p.port}/${p.service}`).join(" ");
        lines.push(`${chalk.dim(prefix)}  ${chalk.dim(portStr)}`);
      }
    });
    return lines.join("\n");
  }
}
