# WiFi Sentinel

Multi-persona WiFi and network security analyser with compliance scoring, RF intelligence, and external reconnaissance.

## Features

**CLI Scanner** — scans the local network using system tools (nmap, arp, ifconfig, airport) with a three-tier fallback chain. Produces a structured `NetworkScanResult` covering WiFi info, DNS, host discovery, open ports, security posture, hidden devices, and intrusion indicators.

**Multi-persona analysis** — five AI-style analyst lenses (red team, blue team, compliance, network engineer, privacy) each produce independent insights, risk ratings, and priority actions. A consensus rating and action list is computed across all five.

**Compliance scoring** — automated scoring against CIS Wireless Controls, NIST 800-153, IEEE 802.11, and OWASP IoT Top 10. Each framework produces a letter grade and a list of findings.

**RF intelligence** — channel utilisation map for 2.4 GHz and 5 GHz, co-channel interference scoring, optimal channel recommendations, rogue AP / evil twin detection, and WiFi environment change detection between scans.

**External reconnaissance** — `recon <domain>` maps the external attack surface of a domain: DNS enumeration (brute + certificate transparency), WHOIS, TLS/SSL grading, and HTTP security header analysis. Results are scored and analysed through the same persona layer.

**Scan history and observability** — scans are persisted to `~/.wifisentinel/scans/`. `history`, `trend`, and `diff` commands let you review past scans, track compliance over time, and compare two scan snapshots. Scheduled scanning via launchd/cron is available through the `schedule` command.

**Dashboard** — Next.js app (dark theme, shadcn/ui) showing scan details, real-time persona perspectives, historical trends, and compliance tracking. HTML report export from both CLI and dashboard.

**OTEL instrumentation** — optional OpenTelemetry tracing and metrics for each scan phase, exportable to console or an OTLP endpoint.

## Requirements

- Node.js >= 20
- macOS or Linux (WiFi scanning uses platform-native tools)

Optional system tools (used when available, gracefully degraded otherwise):

- `nmap` — host and port discovery
- `dig` — DNS enumeration (recon command)
- `openssl` — TLS/SSL grading (recon command)
- `whois` — registrar lookup (recon command)
- `iw` / `nmcli` — WiFi scanning on Linux
- `ip` — network interface detection on Linux

## Installation

```bash
git clone https://github.com/IsmaelMartinez/wifisentinel.git
cd wifisentinel
npm install
npm run build
```

To use as a global command after building:

```bash
npm link
```

Or run directly via `tsx` without building:

```bash
npm run dev -- <command>
```

## Quick Start

```bash
# Basic network scan
wifisentinel scan

# Full scan with multi-persona analysis and compliance scoring
wifisentinel analyse -v

# Fast scan (skip ports, speed test, and traffic analysis)
wifisentinel scan --skip-ports --skip-speed --skip-traffic

# Save scan to history with JSON output
wifisentinel scan --analyse -o json -f report.json

# RF channel intelligence
wifisentinel rf

# External recon on a domain
wifisentinel recon example.com
```

## CLI Commands

| Command | Description |
|---|---|
| `scan` | Scan the current network and produce a security report |
| `analyse` | Scan + full multi-persona analysis and compliance scoring |
| `rf` | RF channel map, saturation scores, rogue AP detection |
| `recon <domain>` | External attack surface mapping for a domain |
| `export` | Export a past scan as an HTML report |
| `history` | List saved scans |
| `trend` | Compliance score trends across saved scans |
| `diff <id1> <id2>` | Compare two saved scans |
| `schedule` | Configure scheduled scanning via launchd/cron |
| `recon-history` | List saved recon results |

### `scan` / `analyse` options

```text
-o, --output <format>   Output format: terminal, json  (default: terminal)
-f, --file <path>       Write output to file instead of stdout
--skip-ports            Skip port scanning
--skip-traffic          Skip traffic analysis
--skip-speed            Skip speed test
--otel <exporter>       OTEL exporter: console, otlp, none  (default: none)
-v, --verbose           Verbose output
--no-save               Skip saving scan to history
```

## Dashboard

Start the Next.js dashboard from the repo root:

```bash
npm run dashboard
# Opens on http://localhost:3000
```

The dashboard shows scan history with per-scan detail pages (raw data, persona perspectives, compliance tab), a trends page tracking compliance scores over time, and a download button to export any scan as an HTML report.

## Architecture

The pipeline flows: **CLI** (commander) → **Collector** → **Analyser** → **Reporter**.

`src/collector/` orchestrates all scanning. `src/collector/tool-resolver.ts` implements the three-tier fallback chain (preferred → fallback → minimal) for each capability. Nine scanner modules in `src/collector/scanners/` each parse system tool output into typed data. All data is validated against the central Zod schema in `src/collector/schema/scan-result.ts` — the `NetworkScanResult` type flows through everything.

`src/analyser/` contains two sub-modules: `src/analyser/personas/` (five analysis functions producing `PersonaAnalysis` with insights and risk ratings) and `src/analyser/standards/` (scoring against CIS, NIST, IEEE, and OWASP frameworks). The RF analyser in `src/analyser/rf/` reads both live scan data and historical scans from the store.

`src/reporter/` provides three formatters: `terminal.reporter.ts` (coloured ASCII scorecard), `analysis.reporter.ts` (adds persona and standards output), and `json.reporter.ts` (structured JSON including analysis).

`src/store/` persists scans to `~/.wifisentinel/scans/` as JSON files, indexed for history and trend queries.

`src/telemetry/` wraps scan phases in OTEL spans via `withSpan()` and records tool resolution tier metrics.

## Claude Code Integration

WiFi Sentinel ships with a `/network-audit` skill for Claude Code. If you use Claude Code (claude.ai/code), you can run a full network security audit directly from a conversation:

```
/network-audit
```

This runs a scan, analyses the results through all five personas, and presents findings conversationally. You can ask follow-up questions like "what should I fix first?" or "explain the red team findings" and Claude will work with the live scan data.

To set up the skill, add the `network-audit` skill definition to your `.claude/skills/` directory. The skill should invoke the built CLI (`node /path/to/wifisentinel/dist/cli.js analyse`) or use tsx for development (`npx tsx /path/to/wifisentinel/src/cli.ts analyse`).

## Usage Examples

The simplest way to check your network:

```bash
# Just scan — takes about 30-60 seconds
wifisentinel scan

# Want the full picture with persona analysis? Add --analyse
wifisentinel analyse -v

# Quick check without the slow bits (ports, speed test)
wifisentinel scan --skip-ports --skip-speed

# Check your WiFi channel congestion
wifisentinel rf

# Investigate a domain's external security
wifisentinel recon yourdomain.com --analyse

# Export a past scan as a shareable HTML report
wifisentinel export <scan-id>

# See how your network has changed over time
wifisentinel trend

# Compare two scans side by side
wifisentinel diff <id1> <id2>

# Set up automatic scanning every 6 hours
wifisentinel schedule enable
```

If you haven't run `npm link`, use `npm run dev -- <command>` instead.

All scan data is stored locally in `~/.wifisentinel/` — nothing is sent to any external service.

## Contributing

Contributions are welcome. The project follows a standard fork-and-PR workflow.

### Getting started

```bash
git clone https://github.com/IsmaelMartinez/wifisentinel.git
cd wifisentinel
npm install
npm test        # run unit tests
npm run lint    # ESLint with typescript-eslint
npm run build   # compile TypeScript
```

### Development workflow

Run the CLI in development mode (no build step needed):

```bash
npm run dev -- scan --skip-speed
```

Start the dashboard:

```bash
npm run dashboard
```

### Branch conventions

All work goes through feature branches and pull requests — direct pushes to `main` are not accepted. Branch naming: `feature/<description>` for new work, `fix/<description>` for bug fixes.

### Code conventions

The project uses UK English spelling throughout (analyser, analyse, normalised, etc.). TypeScript is strict-mode with ESM modules and `.js` extensions in all imports. Schemas use Zod for validation and type inference. Terminal output uses chalk with the existing box-drawing style from `render-helpers.ts`.

### Running tests

```bash
npm test                    # run all tests
npm run typecheck           # tsc --noEmit
npm run lint                # eslint
```

CI runs typecheck, build, lint, and tests on Node 20 and 22, plus a dashboard build, on every PR.

### Areas for contribution

There are several areas where contributions would be particularly valuable: adding Linux support (the WiFi scanner currently targets macOS `system_profiler` and `en0`), expanding the test suite, improving error messages when system tools are missing, adding Shodan/Censys integration to the recon command, and building Phase 6 (continuous monitoring with `wifisentinel watch`).

## Licence

MIT