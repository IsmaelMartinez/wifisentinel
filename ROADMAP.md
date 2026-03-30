# Network Analyser — Roadmap

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

## Phase 1b: AI Persona Layer (NOT STARTED)

- [ ] Five persona agents (red team, blue team, compliance, net engineer, privacy)
- [ ] Claude Code skill wrapper (`/network-audit` command)
- [ ] Standards scoring modules (CIS wireless, NIST 800-153, IEEE 802.11, OWASP)
- [ ] Audience-adaptive reporter (personal terminal, host PDF, team JSON+OTEL)

## Phase 2: Observability Pipeline (NOT STARTED)

- [ ] Persistent OTEL export (JSON files or SQLite)
- [ ] Scan history and trend comparison
- [ ] Scheduled scanning via cron
- [ ] Diff reports between scans

## Phase 3: Dashboard (NOT STARTED)

- [ ] Next.js app with shadcn/ui
- [ ] Real-time persona perspectives
- [ ] Historical trends and compliance tracking
- [ ] PDF/HTML report generation
