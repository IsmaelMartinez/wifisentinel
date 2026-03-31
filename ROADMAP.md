# WiFi Sentinel — Roadmap

## Phase 1: CLI Scanner (COMPLETE)

- [x] Design spec and investigation spike
- [x] Core schema (NetworkScanResult + zod validation)
- [x] Tool resolver with three-tier fallback chains
- [x] 10 scanner modules: wifi, dns, host-discovery, port, security-posture, connection, hidden-device, intrusion-detection, speed, traffic
- [x] OTEL tracing and metrics layer
- [x] Terminal reporter with ASCII output and scorecard
- [x] CLI entry point (scan, tv commands)
- [x] Tuning: gateway detection, DNS false positives, camera detection, WiFi parsing
- [x] Tested on two live networks (Airbnb Amsterdam 8.2/10, home UK 8.7/10)
- [x] LG webOS TV controller (SSAP over wss://3001) — side quest
- [x] Curated UK IPTV playlist (33 channels)

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
- [ ] Deauth flood detection via frame counters (deferred — requires monitor mode)
- [x] WiFi environment change detection: new APs, signal anomalies, security downgrades between scans

## Phase 5: External Reconnaissance (COMPLETE)

- [x] `wifisentinel recon <domain>` command for external attack surface mapping
- [x] DNS enumeration (subdomains via brute + CT, zone transfers, 7 record types via dig)
- [x] Certificate transparency log queries (crt.sh)
- [x] WHOIS and registrar data lookup
- [x] TLS/SSL grading (protocol versions, cipher suites, cert chain via openssl s_client)
- [x] HTTP security headers analysis (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [x] External risk scoring with persona analysis (reuses Phase 1b persona types)
- [ ] Shodan/Censys integration (deferred — requires API keys)

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
- [ ] Bundle a local OUI database to avoid external MAC vendor lookups entirely (nice-to-have)
- [x] Bind dashboard to localhost only — add `--hostname 127.0.0.1` to `next dev` invocation
- [x] Bounds-check `limit` query param in dashboard API (clamp to max 200, treat NaN as default)

### Low

- [x] Add `--zone-transfer` flag to gate AXFR attempts behind explicit opt-in (may trigger security alerts)
- [x] Pin CI actions to commit SHAs instead of mutable tags (`actions/checkout@v4` -> SHA)

### Infrastructure

- [x] Add `npm audit` step to CI pipeline
- [x] Add domain validation regex for `recon` command input
- [x] Add SECURITY.md with responsible disclosure policy
- [ ] Restrict file permissions on `~/.wifisentinel/` (mode 0700)

## Phase 6: Continuous Monitoring (NOT STARTED)

- [ ] `wifisentinel watch` mode: continuous scanning at configurable intervals
- [ ] Real-time alerting on network changes (new hosts, dropped hosts, security changes)
- [ ] Anomaly detection: baseline normal network behaviour, flag deviations
- [ ] Device tracking: log when devices join/leave, build presence timeline
- [ ] Signal quality trending: track WiFi SNR, latency, packet loss over time
- [ ] Threat correlation: cross-reference nearby network changes with intrusion indicators
- [ ] Event stream output (NDJSON) for piping into external SIEM/monitoring tools
