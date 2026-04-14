# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev             # Run CLI in development (via tsx): tsx src/cli.ts
npm run scan            # Quick scan shortcut: tsx src/cli.ts scan
npm run build           # Compile TypeScript to dist/
npm run typecheck       # Type-check without emitting: tsc --noEmit
npm test                # Run tests (Node built-in test runner via tsx)
npm run lint            # Run ESLint on src/ and tests/
```

Scan with options:
```bash
npm run dev -- scan --skip-ports --skip-speed --skip-traffic   # fast scan
npm run dev -- scan --analyse -v                               # full analysis with verbose output
npm run dev -- scan -o json -f report.json                     # JSON output to file
npm run dev -- scan --otel otlp                                # enable OTEL tracing
npm run dev -- analyse -v                                      # dedicated analysis command
npm run dev -- watch --interval 10m                            # continuous monitoring with alerting
npm run dev -- devices                                         # per-MAC presence timelines from history
npm run dev -- recon example.com --analyse                     # external attack surface recon
```

Tests are in `tests/` and run with `npm test` (Node built-in test runner via tsx). ESLint is configured in `eslint.config.js` and run with `npm run lint`.

## Architecture

WiFi Sentinel is a CLI tool (macOS-first, with a Linux path) that scans the local network and produces multi-persona security reports. It runs system commands (nmap, arp, ifconfig, ip, iw, nmcli, etc.) and parses their output to build a structured `NetworkScanResult`.

The pipeline flows: CLI (commander) -> Collector -> Scanners -> Analyser -> Reporter.

### `src/collector/` — Data collection layer

The collector orchestrates all scanning. `tool-resolver.ts` implements a three-tier fallback chain (preferred -> fallback -> minimal) for each capability (e.g. nmap -> arp-scan -> arp for host discovery). `exec.ts` provides safe command execution via `execFileSync`/`execFile` (no shell, avoiding injection). Ten scanners in `scanners/` each parse output from system tools into typed data (wifi, dns, host-discovery, port, security-posture, connection, hidden-device, intrusion-detection, deauth, speed). `schema/scan-result.ts` is the central Zod-validated schema — the `NetworkScanResult` type flows through everything. The `traffic` field in the schema is reserved for a future traffic-capture scanner; it is currently not populated (see ROADMAP Phase 1).

Network detection branches by platform: macOS uses `ifconfig en0` + `networksetup`; Linux uses `ip route` + `ip addr` to pick the default wireless interface. The scan runs in stages: parallel independent scans first (wifi, dns, security, connections), then host discovery, then deep analysis (ports, hidden devices, intrusion detection, deauth detection), and finally speed test last to avoid skewing results.

### `src/analyser/` — AI persona and standards scoring

Two sub-modules produce the analysis layer. `personas/` contains five analysis functions (red-team, blue-team, compliance, net-engineer, privacy) that each take a `NetworkScanResult` and return a `PersonaAnalysis` with insights, risk ratings, and priority actions. `standards/` scores against four frameworks (CIS Wireless, NIST 800-153, IEEE 802.11, OWASP IoT) producing letter grades and findings. Consensus rating and actions are computed across all personas.

### `src/reporter/` — Output formatting

Core reporters: `terminal.reporter.ts` produces coloured ASCII output with a scorecard, `analysis.reporter.ts` adds persona perspectives and standards scoring, `json.reporter.ts` emits structured JSON with both scan data and analysis, `html.reporter.ts` renders a shareable HTML export. Specialised reporters cover RF (`rf.reporter.ts`), recon (`recon.reporter.ts`, `recon-json.reporter.ts`), watch-mode events (`watch.reporter.ts`), and the live progress renderer (`progress.renderer.ts`). `render-helpers.ts` has shared chalk-based formatting utilities.

### `src/commands/` — Additional CLI commands

Beyond `scan` / `analyse` (registered directly in `cli.ts`), each file in `src/commands/` registers one sub-command on the Commander program: `history`, `diff`, `trend`, `schedule`, `rf`, `export`, `recon`, `recon-history`, `watch` (continuous monitoring), `devices` (per-MAC presence timelines aggregated from scan history).

### `src/store/` — Scan persistence

`src/store/index.ts` persists scans to `~/.wifisentinel/scans/` as JSON files with a validated index. `recon-store.ts` does the same for recon results. `diff.ts` computes structural deltas between two stored scans.

### `src/telemetry/` — OpenTelemetry instrumentation

Tracing wraps scan phases in spans via `withSpan()`. Metrics record tool resolution tiers and scan durations. Supports console, OTLP, or no-op exporters.

## Conventions

The project uses UK English spelling (e.g. `analyser`, `analyse`, `normalised`). All schemas use Zod for validation and type inference. ESM modules throughout (`"type": "module"` in package.json, `.js` extensions in imports). The TypeScript target is ES2022 with Node16 module resolution.

## Repo Butler

This repo is monitored by [Repo Butler](https://github.com/IsmaelMartinez/repo-butler), a portfolio health agent that observes repo health daily and generates dashboards, governance proposals, and tier classifications.

**Your report:** https://ismaelmartinez.github.io/repo-butler/wifisentinel.html
**Portfolio dashboard:** https://ismaelmartinez.github.io/repo-butler/
**Consumer guide:** https://github.com/IsmaelMartinez/repo-butler/blob/main/docs/consumer-guide.md

### Querying Reginald (the butler MCP server)

To query your repo's health tier, governance findings, and portfolio data from any Claude Code session, add the MCP server once (adjust the path to your local repo-butler checkout):

```bash
claude mcp add repo-butler node /path/to/repo-butler/src/mcp.js
```

Available tools: `get_health_tier`, `get_campaign_status`, `query_portfolio`, `get_snapshot_diff`, `get_governance_findings`.

When working on health improvements, check the per-repo report for the current tier checklist and use the consumer guide for fix instructions.
