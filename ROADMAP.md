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

## Phase 3: Dashboard (NOT STARTED)

- [ ] Next.js app with shadcn/ui
- [ ] Real-time persona perspectives
- [ ] Historical trends and compliance tracking
- [ ] PDF/HTML report generation

## Phase 4: WiFi RF Intelligence (COMPLETE)

- [x] Channel utilisation map: 2.4 GHz and 5 GHz channel occupancy from nearby networks
- [x] Channel saturation scoring: overlap calculation, co-channel interference count, signal-weighted penalty
- [x] Optimal channel recommendation engine based on local RF environment
- [x] Signal strength trends over time (rf --trend, reads from scan history)
- [x] Rogue AP / evil twin detection: nearby APs matching SSID with different BSSID or weaker security
- [ ] Deauth flood detection via frame counters (deferred — requires monitor mode)
- [x] WiFi environment change detection: new APs, signal anomalies, security downgrades between scans

## Phase 5: External Reconnaissance (NOT STARTED)

- [ ] `wifisentinel recon <domain>` command for external attack surface mapping
- [ ] DNS enumeration (subdomains, zone transfers, record types via dig)
- [ ] Certificate transparency log queries (crt.sh)
- [ ] WHOIS and registrar data lookup
- [ ] TLS/SSL grading (protocol versions, cipher suites, cert chain via openssl s_client)
- [ ] HTTP security headers analysis (HSTS, CSP, X-Frame-Options via curl)
- [ ] External risk scoring with persona analysis (reuse Phase 1b personas)
- [ ] Shodan/Censys integration for exposed service discovery (API key optional)

## Phase 6: Continuous Monitoring (NOT STARTED)

- [ ] `wifisentinel watch` mode: continuous scanning at configurable intervals
- [ ] Real-time alerting on network changes (new hosts, dropped hosts, security changes)
- [ ] Anomaly detection: baseline normal network behaviour, flag deviations
- [ ] Device tracking: log when devices join/leave, build presence timeline
- [ ] Signal quality trending: track WiFi SNR, latency, packet loss over time
- [ ] Threat correlation: cross-reference nearby network changes with intrusion indicators
- [ ] Event stream output (NDJSON) for piping into external SIEM/monitoring tools
