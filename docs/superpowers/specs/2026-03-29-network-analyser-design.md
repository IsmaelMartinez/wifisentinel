# Network/WiFi Security Analyser — Design Spec

## Overview

A multi-persona network security analyser delivered as a layered TypeScript pipeline with a Claude Code skill wrapper. The tool scans WiFi networks (targeting Airbnb-style shared environments), then runs five AI persona agents in parallel to produce audience-adaptive reports grounded in real scan data and scored against industry standards.

## Architecture — Layered Pipeline (Approach B)

Three independent layers, each usable standalone, with OTEL instrumentation throughout.

### Layer 1: Collector (TypeScript CLI)

Seven independent scanner modules that resolve the best available tool on the host, execute the scan, and return their slice of a typed `NetworkScanResult` schema.

Scanner modules:

- `wifi.scanner` — SSID, BSSID, protocol, channel, band, security, signal/noise, SNR, nearby networks. Tool chain: `airport` → `system_profiler` → `networksetup`.
- `host-discovery.scanner` — ARP table, broadcast ping, MAC vendor resolution. Tool chain: `nmap -sn` → `arp-scan` → `arp -a` + ping sweep.
- `port.scanner` — Open ports on discovered hosts and local machine, service identification, bind address audit. Tool chain: `nmap -sV` → `masscan` → `netstat` + `nc` per-port + `lsof`.
- `dns.scanner` — Resolver list, DNSSEC validation, hijack detection (NX domain test), DNS leak test, reverse DNS on infrastructure. Tool chain: `dig` → `nslookup` → `scutil --dns`.
- `traffic.scanner` — Protocol distribution, unencrypted traffic detection, DNS query capture, mDNS leak detection. Tool chain: `tshark` → `tcpdump` → `netstat -s` (stats only). Optional — only runs if packet capture tools are available.
- `security-posture.scanner` — Firewall state and config, VPN status, proxy settings, ICMP redirect acceptance, IP forwarding, kernel network params. Tool chain: native macOS commands (`socketfilterfw`, `sysctl`, `networksetup`, `scutil`).
- `connection.scanner` — Active connection count by state, top destinations with reverse DNS, IPv6 status. Tool chain: `netstat` + `dig -x`.

The collector also performs a bootstrap phase to detect the active interface, IP, gateway, subnet, and route topology (including double NAT detection via traceroute).

Tool resolution follows a three-tier chain per capability: preferred (richest output) → fallback (good enough) → minimal (always works on macOS). The resolved tool name and tier are recorded in scan metadata and OTEL span attributes.

Parsers are isolated per external tool (one file per tool output format) so format changes are localised.

Execution flow:

1. Resolve tools (parallel, all capabilities)
2. Network bootstrap (detect interface, IP, gateway, subnet, traceroute)
3. Parallel scan (wifi, dns, traffic, security, connections — all concurrent, each in own OTEL span)
4. Host discovery (depends on subnet from step 2)
5. Port scan (optional, depends on hosts from step 4)
6. Assemble into `NetworkScanResult`, validate with zod
7. Output JSON to stdout or file, flush OTEL traces

### Layer 2: Analyser (AI Persona Agents)

Five expert personas that each receive the full `NetworkScanResult` and produce findings from their perspective. All five run in parallel as Claude Code subagents.

Personas:

- Red Team Operator — "What can I exploit?" Assesses attack surface: lateral movement, exposed services, ARP spoofing feasibility, IoT pivot points, router admin exposure, credential interception vectors.
- Blue Team Defender — "What's exposed and how do I harden it?" Evaluates defensive posture: firewall config, VPN status, service binding, kernel params, stealth mode, auto-allow policies. Produces prioritised hardening checklist.
- Compliance Auditor — "Does this meet standards?" Scores against CIS Benchmarks (wireless), NIST SP 800-153, IEEE 802.11, OWASP network layer. Pluggable modules for ISO 27001 Annex A.13, PCI DSS wireless, GDPR Article 32, NIST CSF 2.0, WPA3 SAE spec. Each standard produces a control-by-control pass/fail/warn table.
- Network Engineer — "Is the infra sound and performant?" Analyses topology (NAT layers, subnet sizing), WiFi performance (SNR, MCS, channel contention), DNS architecture, IPv6 readiness, gateway service footprint.
- Privacy Advocate — "What data is leaking and who sees it?" Maps observer-to-visibility (other guests, host, ISP, manufacturer). Identifies DNS plaintext exposure, mDNS broadcasts, service discovery protocols, connection metadata leakage.

Each persona produces a structured `PersonaReport` containing: persona name, severity-rated findings (with evidence), an overall rating (1-10), and actionable recommendations.

### Layer 3: Reporter (Audience-Adaptive Output)

Takes the array of `PersonaReport` objects and renders them for the target audience:

- Personal (terminal) — Colour-coded ASCII summary with consolidated scorecard, top findings, and immediate action list. Default output.
- Host (PDF/HTML) — Property-owner-friendly report: plain language, no jargon, actionable recommendations for the router/network config. Generated via headless rendering.
- Security Team (JSON + OTEL) — Full machine-readable output: all findings as structured JSON, OTEL traces with span-per-scanner and span-per-persona, compliance scores as metrics, exportable to Jaeger/Grafana.

### Skill Wrapper

A Claude Code skill (`/network-audit`) that orchestrates the full pipeline:

1. Invokes the CLI collector
2. Dispatches five persona subagents in parallel with the scan result
3. Assembles reports
4. Renders output for the requested audience

## Data Schema — NetworkScanResult

```typescript
interface NetworkScanResult {
  meta: {
    scanId: string                    // uuid
    timestamp: string                 // ISO-8601
    duration: number                  // ms
    hostname: string
    platform: "darwin" | "linux" | "win32"
    toolchain: {
      hostDiscovery: "nmap" | "arp-scan" | "arp"
      portScanning: "nmap" | "masscan" | "netstat"
      wifiAnalysis: "airport" | "system_profiler" | "networksetup"
      dnsAudit: "dig" | "nslookup" | "scutil"
      packetAnalysis: "tshark" | "tcpdump" | "netstat-stats" | null
      tlsVerify: "testssl" | "openssl" | "curl" | null
      mitmDetection: "bettercap" | "arp-monitor" | "arp-check" | null
    }
  }

  wifi: {
    ssid: string | null
    bssid: string
    protocol: "ax" | "ac" | "n" | "g" | "b" | "a"
    channel: number
    band: "2.4GHz" | "5GHz" | "6GHz"
    width: "20MHz" | "40MHz" | "80MHz" | "160MHz"
    security: "WPA3" | "WPA2/WPA3" | "WPA2" | "WEP" | "Open"
    signal: number                    // dBm
    noise: number                     // dBm
    snr: number                       // dB (computed)
    txRate: number                    // Mbps
    macRandomised: boolean
    countryCode: string
    nearbyNetworks: Array<{
      ssid: string | null
      bssid: string
      security: string
      protocol: string
      channel: number
      signal: number
      noise: number
    }>
  }

  network: {
    interface: string
    ip: string
    subnet: string                    // CIDR
    gateway: { ip: string; mac: string; vendor?: string }
    topology: {
      doubleNat: boolean
      hops: Array<{ ip: string; hostname?: string; latencyMs: number }>
    }
    dns: {
      servers: string[]
      anomalies: string[]
      dnssecSupported: boolean
      dohDotEnabled: boolean
      hijackTestResult: "clean" | "intercepted" | "unknown"
    }
    hosts: Array<{
      ip: string
      mac: string
      vendor?: string
      hostname?: string
      ports?: Array<{ port: number; service: string; state: string }>
    }>
  }

  localServices: Array<{
    port: number
    process: string
    bindAddress: string
    exposedToNetwork: boolean
  }>

  security: {
    firewall: {
      enabled: boolean
      stealthMode: boolean
      autoAllowSigned: boolean
      autoAllowDownloaded: boolean
    }
    vpn: { installed: boolean; active: boolean; provider?: string }
    proxy: { enabled: boolean; server?: string; port?: number }
    kernelParams: {
      ipForwarding: boolean
      icmpRedirects: boolean
    }
    clientIsolation: boolean | null
  }

  traffic?: {
    capturedPackets: number
    durationSeconds: number
    protocols: Record<string, number>
    unencrypted: Array<{ dest: string; port: number; protocol: string }>
    dnsQueries: Array<{ domain: string; server: string; dnssec: boolean }>
    mdnsLeaks: Array<{ service: string; host: string }>
  }

  connections: {
    established: number
    listening: number
    timeWait: number
    topDestinations: Array<{ ip: string; count: number; reverseDns?: string }>
  }
}
```

## Standards Framework

Core (always scored):

- CIS Benchmarks — wireless hardening baselines
- NIST SP 800-153 — WiFi security guidelines
- IEEE 802.11 — protocol-level compliance
- OWASP — network layer attack surfaces

Pluggable modules (loaded on demand):

- ISO 27001 Annex A.13 — network security management
- PCI DSS (wireless) — payment system network requirements
- GDPR Article 32 — privacy on shared networks
- NIST CSF 2.0 — broader risk framework
- WPA3 SAE specification — protocol compliance

Each standard module exports a `score(scanResult: NetworkScanResult): ComplianceResult` function that returns control-by-control pass/fail/warn with evidence references back into the scan data.

## OTEL Instrumentation

Trace structure (one scan):

```
[root] network-scan
  ├── [span] tool-resolution
  ├── [span] network-bootstrap
  ├── [span] wifi-scan              { tool: "system_profiler", tier: "fallback" }
  ├── [span] dns-audit              { tool: "dig", tier: "preferred" }
  ├── [span] traffic-monitor        { tool: "tcpdump", tier: "fallback" }
  ├── [span] security-posture       { tool: "native", tier: "minimal" }
  ├── [span] connections            { tool: "netstat", tier: "minimal" }
  ├── [span] host-discovery         { tool: "arp", tier: "minimal" }
  │   └── [span] port-scan          { tool: "nc", tier: "minimal" }
  ├── [span] persona/red-team
  ├── [span] persona/blue-team
  ├── [span] persona/compliance
  ├── [span] persona/net-engineer
  ├── [span] persona/privacy
  └── [span] report-generation
```

Metrics (counters and histograms):

- `scan.findings.total` — by severity, category, persona
- `scan.duration` — by scanner name
- `scan.tool.resolution` — by capability, resolved tier
- `compliance.score` — by standard name

Export targets: stdout (default), OTLP endpoint, JSON file, Jaeger, Grafana.

## Phased Delivery

Phase 1 (now): CLI scanner + Claude Code skill + 5 persona agents + terminal output + OTEL traces. This is the MVP — scan, analyse, report in the terminal.

Phase 2: OTEL pipeline with persistent export, scan history (JSON files or SQLite), trend comparison between scans, scheduled scanning via cron.

Phase 3: Next.js dashboard with shadcn/ui, real-time persona perspectives, historical trends, compliance tracking over time, PDF/HTML report generation.

## Project Structure

```
network-analyser/
├── src/
│   ├── collector/
│   │   ├── index.ts                 # orchestrator
│   │   ├── tool-resolver.ts         # which/command-v chain
│   │   ├── scanners/
│   │   │   ├── wifi.scanner.ts
│   │   │   ├── host-discovery.scanner.ts
│   │   │   ├── port.scanner.ts
│   │   │   ├── dns.scanner.ts
│   │   │   ├── traffic.scanner.ts
│   │   │   ├── security-posture.scanner.ts
│   │   │   └── connection.scanner.ts
│   │   ├── parsers/
│   │   │   ├── nmap.parser.ts
│   │   │   ├── airport.parser.ts
│   │   │   ├── arp.parser.ts
│   │   │   ├── netstat.parser.ts
│   │   │   ├── system-profiler.parser.ts
│   │   │   └── dig.parser.ts
│   │   └── schema/
│   │       ├── scan-result.ts       # zod schema + TS types
│   │       └── finding.ts           # Finding type
│   ├── analyser/
│   │   ├── index.ts                 # persona orchestrator
│   │   ├── personas/
│   │   │   ├── red-team.persona.ts
│   │   │   ├── blue-team.persona.ts
│   │   │   ├── compliance.persona.ts
│   │   │   ├── net-engineer.persona.ts
│   │   │   └── privacy.persona.ts
│   │   └── standards/
│   │       ├── cis-wireless.ts
│   │       ├── nist-800-153.ts
│   │       ├── ieee-80211.ts
│   │       └── owasp-network.ts
│   ├── reporter/
│   │   ├── index.ts
│   │   ├── terminal.reporter.ts     # ASCII colour output
│   │   ├── json.reporter.ts         # machine-readable
│   │   └── html.reporter.ts         # PDF/HTML (Phase 3)
│   ├── telemetry/
│   │   ├── tracing.ts
│   │   ├── metrics.ts
│   │   └── exporters.ts
│   └── cli.ts                       # entry point
├── skill/
│   └── network-audit/
│       └── SKILL.md                 # Claude Code skill definition
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-03-29-network-analyser-design.md
├── package.json
├── tsconfig.json
└── README.md
```

## Investigation Spike Findings (2026-03-29)

Ran against a live Airbnb-style WiFi network in Amsterdam, Netherlands. ISP: Odido (AS50266) via Glasoperator FTTH. Router: TP-Link Deco mesh system.

Key discoveries that informed the design:

- Double NAT topology (Deco → ISP router → Internet) — the tool must detect and report NAT layers via traceroute.
- DNS "anomaly" was explained by the double NAT — primary DNS 192.168.1.1 is the ISP router behind the Deco. The tool must correlate DNS servers with route topology before flagging anomalies.
- Flat /22 subnet with 8 active hosts (5 Sonos, 1 Apple device, 1 iRobot, 1 user). No client isolation. The tool must detect L2 adjacency and broadcast reachability.
- Three local services bound to 0.0.0.0 (node:3000, Spotify:57621, Spotify:62952) — the tool must audit local service bind addresses.
- Gateway admin panel on self-signed cert from 2010 (tplinkdeco.net) — the tool must audit gateway TLS.
- Firewall enabled but stealth mode off and auto-allow too permissive — the tool must evaluate firewall policy, not just on/off state.
- No VPN active, no encrypted DNS, no DNSSEC — full metadata exposure to network operator and ISP.
- Tool availability was minimal tier (no nmap, no tshark, no bettercap) — the graceful fallback strategy produced a comprehensive analysis regardless.
- Overall score: 3.7/10 across all personas. Typical for consumer Airbnb setup but unsafe for professional work.
