# WiFi Sentinel — Roadmap

## Phase 1: CLI Scanner (NEAR COMPLETE)

- [x] Design spec and investigation spike
- [x] Core schema (NetworkScanResult + zod validation)
- [x] Tool resolver with three-tier fallback chains
- [x] 10 scanner modules: wifi, dns, host-discovery, port, security-posture, connection, hidden-device, intrusion-detection, deauth, speed
- [ ] Traffic analysis scanner (schema and `--skip-traffic` flag wired up, implementation pending)
- [x] OTEL tracing and metrics layer
- [x] Terminal reporter with ASCII output and scorecard
- [x] CLI entry point (scan command)
- [x] Tuning: gateway detection, DNS false positives, camera detection, WiFi parsing
- [x] Tested on two live networks (Airbnb Amsterdam 8.2/10, home UK 8.7/10)

## Phase 1b: AI Persona Layer (COMPLETE)

- [x] Five persona agents (red team, blue team, compliance, net engineer, privacy)
- [x] Claude Code skill wrapper (`/network-audit` command)
- [x] Standards scoring modules (CIS wireless, NIST 800-153, IEEE 802.11, OWASP)
- [x] Audience-adaptive reporter (personal terminal, JSON+OTEL, analysis command)

## Phase 2: Observability Pipeline (COMPLETE)

- [x] Persistent scan export (JSON files in ~/.wifisentinel/scans/)
- [x] Scan history and trend comparison (history, trend commands)
- [x] Scheduled scanning via launchd/cron (schedule command)
- [x] Diff reports between scans (diff command)

## Phase 3: Dashboard (COMPLETE)

- [x] Next.js app with shadcn/ui (dark theme, sidebar nav, Geist fonts)
- [x] Real-time persona perspectives (scan detail personas tab)
- [x] Historical trends and compliance tracking (trends page, compliance tab)
- [x] HTML report generation (CLI export command + dashboard download button)

## Phase 4: WiFi RF Intelligence (COMPLETE)

- [x] Channel utilisation map: 2.4 GHz and 5 GHz channel occupancy from nearby networks
- [x] Channel saturation scoring: overlap calculation, co-channel interference count, signal-weighted penalty
- [x] Optimal channel recommendation engine based on local RF environment
- [x] Signal strength trends over time (rf --trend, reads from scan history)
- [x] Rogue AP / evil twin detection: nearby APs matching SSID with different BSSID or weaker security
- [x] Deauth flood detection: system log analysis (default) + monitor mode capture (opt-in via --monitor-interface)
- [x] WiFi environment change detection: new APs, signal anomalies, security downgrades between scans

## Phase 5: External Reconnaissance (COMPLETE)

- [x] `wifisentinel recon <domain>` command for external attack surface mapping
- [x] DNS enumeration (subdomains via brute + CT, zone transfers, 7 record types via dig)
- [x] Certificate transparency log queries (crt.sh)
- [x] WHOIS and registrar data lookup
- [x] TLS/SSL grading (protocol versions, cipher suites, cert chain via openssl s_client)
- [x] HTTP security headers analysis (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [x] External risk scoring with persona analysis (reuses Phase 1b persona types)
- [x] Shodan/Censys integration (configurable via API keys / env vars)

## Security Hardening (COMPLETE)

### Critical

- [x] Fix command injection in `tls.recon.ts` — domain arg interpolated into `bash -c` shell string. Replace with direct `execFile("openssl", [...])` using `input` option for stdin
- [x] Fix command injection in `dns.recon.ts` — NS record values from DNS responses used unsanitised in `dig axfr @${server}`. Validate server values against strict hostname/IP regex

### High

- [x] Replace `execSync` in `schedule.ts` with `execFileSync("which", [...])` to avoid unnecessary shell spawning
- [x] Add path traversal protection in store — validate `filename` from index.json matches `/^[\w\-]+\.json$/` before `join()`. Apply Zod parsing to `recon-store.ts` index reads
- [x] Add security headers to dashboard HTML export route — `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`, `Cache-Control: no-store`

### Medium

- [x] Add `--no-vendor-lookup` flag — MAC OUI lookups are sent to api.macvendors.com and can now be skipped
- [x] Bundle a local OUI database to avoid external MAC vendor lookups entirely (nice-to-have)
- [x] Bind dashboard to localhost only — add `--hostname 127.0.0.1` to `next dev` invocation
- [x] Bounds-check `limit` query param in dashboard API (clamp to max 200, treat NaN as default)

### Low

- [x] Add `--zone-transfer` flag to gate AXFR attempts behind explicit opt-in (may trigger security alerts)
- [x] Pin CI actions to commit SHAs instead of mutable tags (`actions/checkout@v4` -> SHA)

### Infrastructure

- [x] Add `npm audit` step to CI pipeline
- [x] Add domain validation regex for `recon` command input
- [x] Add SECURITY.md with responsible disclosure policy
- [x] Restrict file permissions on `~/.wifisentinel/` (mode 0700)

## Dependency Updates (COMPLETE)

- [x] Upgrade OpenTelemetry packages to v2/v0.214 (`@opentelemetry/resources`, `sdk-metrics`, `sdk-trace-base` → 2.x; `sdk-node`, `exporter-trace-otlp-http` → 0.214.x) — replaced `new Resource()` with `resourceFromAttributes()`
- [x] Upgrade Zod from 3.x to 4.x — no code changes required (existing patterns compatible)
- [x] Upgrade Commander from 13.x to 14.x — drop-in replacement, no code changes
- [x] Upgrade TypeScript from 5.x to 6.x — added `"types": ["node"]` to tsconfig.json
- [x] Upgrade `@types/node` from 22.x to 25.x

## Phase 6: Mobile & Browser Support (IN PROGRESS)

- [x] Responsive dashboard: collapsible sidebar, adaptive grids, mobile-friendly scan history cards
- [x] Lightweight `/mobile` page: compact card-based summary for quick phone glances
- [x] Viewport meta tag and touch-friendly tap targets
- [ ] Browser-based network scan: gather what the browser can see without system commands
  - [ ] Connection quality via Network Information API (`navigator.connection` — RTT, downlink, effectiveType)
  - [ ] Speed test via fetch (download/upload blob timing)
  - [ ] DNS resolution timing via Resource Timing API
  - [ ] Public IP detection and geolocation (via external API)
  - [ ] Local IP discovery via WebRTC (where browser permits)
  - [ ] DNS security checks via DNS-over-HTTPS (DoH) queries
  - [ ] TLS and security header analysis of user-specified URLs (via server-side proxy)
  - [ ] Latency measurement (ping-like round-trip timing via fetch)
- [ ] Browser scan results integrated into the same dashboard and history store
- [ ] Progressive Web App (PWA) support for offline access to past scan results
- [x] Remote scan trigger: start a full CLI scan on the Mac from the mobile browser (API route + ScanRunner UI with live progress)

## Phase 7: Continuous Monitoring (IN PROGRESS)

- [x] `wifisentinel watch` mode: continuous scanning at configurable intervals
- [x] Real-time alerting on network changes (new hosts, dropped hosts, security changes)
- [x] Event stream output (NDJSON) for piping into external SIEM/monitoring tools
- [ ] Anomaly detection: baseline normal network behaviour, flag deviations
- [x] Device tracking: `wifisentinel devices` aggregates scan history into per-MAC presence timelines with join/leave sessions, ratio, and metadata (hostnames, vendors, IPs, device types, camera flag)
- [ ] Signal quality trending: extend `rf --trend` (SNR done) to also track latency, jitter, and packet loss over time
- [ ] Threat correlation: cross-reference nearby network changes with intrusion indicators

## Deferred / Side Quests

These are exploratory ideas that are on-hold — no implementation has landed and they are not on the active roadmap.

- [ ] LG webOS TV controller (SSAP over `wss://…:3001`) — discovered via the scanner's host discovery, originally planned as a scriptable remote. No code in the repo.
- [ ] Curated UK IPTV playlist — `public/uk-freeview-plus.m3u` is checked in, but no CLI command consumes it.
