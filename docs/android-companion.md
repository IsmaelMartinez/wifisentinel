# Android companion app — investigation and design

**Status:** Investigation / design-stage. Prototype skeleton lives under `android/`.
**Branch:** `claude/android-companion-app-Q5Q06`
**Related roadmap entry:** Phase 6 — Mobile & Browser Support.

## 1. Goal

Provide a standalone Android app that can scan whatever network the phone is
currently connected to and produce a lightweight security summary — **without
needing to reach the Mac CLI or dashboard**. The app should be useful on the
move (hotel WiFi, coffee-shop hotspots, a relative's home network) where the
CLI host is not available.

Non-goals for this investigation:

- Remote control of the Mac CLI over LAN.
- Full parity with the CLI's `NetworkScanResult` schema.
- Push notifications / backgrounded watch mode (explicit follow-up).

## 2. Constraints

Three constraints bound the design:

1. **No LAN-accessible server.** The Next.js dashboard stays bound to
   `127.0.0.1` per the Phase 5 security hardening. The Android app therefore
   cannot call `/api/scans/run` or read the scan store over the wire.
2. **Android's platform limits.** Since Android 9, WiFi scanning is throttled
   (4 scans per 2 min) and requires `ACCESS_FINE_LOCATION` plus location
   services. Monitor mode, raw packet capture, and ARP sweeps are unavailable
   without root. Android 13 added `NEARBY_WIFI_DEVICES` as an alternative to
   `ACCESS_FINE_LOCATION` for scan results.
3. **UK English and existing conventions.** Docs and user-facing strings
   follow the repo's UK English convention (`analyser`, `colour`, etc.).
   Schemas remain Zod-first on the Node side; the Kotlin side mirrors the
   subset it can populate.

## 3. What the Android side can and can't measure

The schema below is a subset of `NetworkScanResult` (see
`src/collector/schema/scan-result.ts`). Fields the phone cannot observe are
either omitted or set to a documented sentinel.

| Field | Source | Notes |
|---|---|---|
| `wifi.ssid`, `bssid`, `signal`, `band`, `channel`, `txRate` | `NetworkCapabilities.transportInfo as WifiInfo` (API 29+) | `ssid`/`bssid` require the runtime scan permission; redacted otherwise |
| `wifi.security` | Matched `ScanResult.capabilities` for the current BSSID | Requires a fresh `startScan()` — we trigger and await the broadcast |
| `wifi.nearbyNetworks` | `WifiManager.getScanResults()` | Throttled to 4 per 2 min; same permission gate |
| `wifi.macRandomised` | — | **Not observable.** `WifiInfo.getMacAddress()` returns the sanitised `02:00:00:00:00:00` for all non-system callers; the real per-SSID randomisation flag lives in `WifiConfiguration.macRandomizationSetting` which requires a system permission. Omitted from the Android schema. |
| `network.ip`, `subnet`, `gateway.ip`, `dns.servers` | `DhcpInfo` / `LinkProperties` | Available without extra permissions |
| `network.gateway.mac` | ARP via `/proc/net/arp` | **Blocked** on modern Android; leave undefined |
| `network.hosts` | TCP connect sweep + `NsdManager` (mDNS) | Lightweight; no OS fingerprint, no nmap-grade detail |
| `connections.*`, `localServices` | — | **Not observable** from an unprivileged app; omit |
| `security.firewall`, `security.vpn` | `ConnectivityManager` link capabilities (`NET_CAPABILITY_*`) | Can detect an active VPN; no firewall introspection |
| `traffic.*` | — | **Not observable** without VpnService interception; explicit follow-up |
| `deauthDetection` | — | **Requires monitor mode**; not viable |
| `intrusionIndicators` | Partial — gateway change detection, duplicate-BSSID heuristics | Weak; useful as a trend signal only |
| `speed.latency.internetMs` | HTTP `HEAD` to a known host | Reasonable; no need to hit a CDN speed test for MVP |
| `speed.download.speedMbps` | HTTP `GET` of a sized blob | Optional — off by default to spare mobile data |

## 4. Architecture

```
┌────────────────────────────────────────────────────────────┐
│ Android app (Kotlin + Jetpack Compose)                     │
│                                                            │
│  UI layer (Compose)                                        │
│    ├─ ScanScreen           (trigger + live progress)       │
│    ├─ ResultScreen         (scorecard + details)           │
│    ├─ HistoryScreen        (local timeline)                │
│    └─ SettingsScreen       (permissions, export)           │
│                                                            │
│  Domain                                                    │
│    ├─ LocalScanner         (orchestrates stages)           │
│    ├─ WifiProbe            (WifiManager + DhcpInfo)        │
│    ├─ HostProbe            (NSD + TCP connect sweep)       │
│    ├─ LatencyProbe         (HEAD request timing)           │
│    └─ LocalAnalyser        (subset of persona logic)       │
│                                                            │
│  Storage                                                   │
│    └─ ScanStore            (Room — JSON-blob per scan)     │
│                                                            │
│  Export                                                    │
│    └─ JsonExporter         (emits CLI-compatible subset)   │
└────────────────────────────────────────────────────────────┘
```

The app does not embed a persona LLM. The `LocalAnalyser` implements a
rule-based subset of the existing CIS/NIST/OWASP rules that **can be
evaluated from the Android-visible fields** — primarily WiFi security
(Open / WEP / WPA / WPA2 / WPA3), MAC randomisation, VPN state, and
plaintext reachability of the gateway. Results are tagged `partial: true`
so the user is not misled into thinking the phone gave them a full audit.

### Data model

`LocalScanResult` is a superset-friendly *subset* of `NetworkScanResult`: same
field names where they apply (`signal`, `txRate`, `band`, `channel`, `bssid`,
`ssid`, `security`), same value shapes, missing fields omitted. This keeps
the JSON export drop-in for the CLI's future import path.

### Scan pipeline (parallel where safe)

1. **Permissions gate** — check `ACCESS_FINE_LOCATION` (or
   `NEARBY_WIFI_DEVICES` on API 33+); prompt with a rationale dialog, remember
   the result across button taps within the same process.
2. **WiFi stage** — `startScan()` → await `SCAN_RESULTS_AVAILABLE_ACTION`
   broadcast (5 s timeout, fall back to cache) → `WifiInfo` via
   `NetworkCapabilities.transportInfo` (the non-deprecated path on API 29+).
3. **Network stage** — `DhcpInfo`, `LinkProperties`, VPN state.
4. **Host discovery** — `NsdManager` service-type sweep (configurable list:
   `_http._tcp`, `_ipp._tcp`, `_airplay._tcp`, `_homekit._tcp`, `_ssh._tcp`,
   `_printer._tcp`, `_googlecast._tcp`); TCP connect sweep to common ports
   (22, 80, 443, 53, 8080, 8443, 554) with a 300 ms timeout and a 32-way
   concurrency cap.
5. **Latency stage** — single `HEAD` to `https://www.cloudflare.com/cdn-cgi/trace`.
6. **Analyse stage** — rule-based local analyser.

## 5. Permissions

Manifest-declared (normal):
- `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`,
  `CHANGE_WIFI_STATE` (for `startScan()`).

Runtime (must be prompted):
- `ACCESS_FINE_LOCATION` — up to Android 12.
- `NEARBY_WIFI_DEVICES` — Android 13+, paired with
  `android:usesPermissionFlags="neverForLocation"`.

The UX shows a rationale dialog (Material3 `AlertDialog`) on the first tap
and after any denial, explaining why the scan permission is required before
the system dialog appears. This is implemented in `MainActivity.ScanApp()`.

## 6. Sync story (no LAN)

Because the dashboard is not LAN-reachable, v1 sync is **manual, file-based**:

- **Export.** Android writes a `LocalScanResult` JSON file to the device's
  Downloads folder (or shares it via Android's Share intent).
- **Import (CLI, future).** A new `wifisentinel import <file>` command
  validates the JSON against a relaxed variant of `NetworkScanResult`
  (missing optional sections allowed, `meta.platform: "android"`) and writes
  it into `~/.wifisentinel/scans/` so it shows up in history/trend/diff.

Explicit follow-ups we are **not** doing in the first pass:

- No LAN HTTP server on the Mac.
- No cloud sync.
- No direct USB/adb import helper.

## 7. Security and privacy

- No telemetry. No external network calls beyond the optional latency probe
  and (opt-in) speed test.
- All scan data lives in app-private storage (`Context.filesDir` / Room db).
  The backup rules opt out of auto-backup for the scans table.
- Exported JSON is written via `ActivityResultContracts.CreateDocument` so
  the user explicitly chooses the location — we never silently drop files in
  shared storage.
- Location permission is requested with a clear rationale and not retained
  beyond what Android requires.

## 8. Tech choices (with rationale)

| Choice | Rationale |
|---|---|
| Kotlin 2.x + Jetpack Compose | Default for new Android work. Avoids the fragmentation of Flutter/RN. |
| `compileSdk 35`, `minSdk 29`, `targetSdk 35` | API 29 (Android 10) was when the modern scan-result model stabilised; cuts ~5% of devices but avoids a large legacy WiFi-API branch. |
| Room for local history | Structured querying, migrations, testable. Overkill for a single table, but the second table (exports) arrives quickly. |
| `kotlinx.serialization` for JSON | Works nicely with Kotlin data classes; avoids Moshi codegen setup. |
| No DI framework in MVP | Manual constructor wiring; introduce Hilt only when we grow past two screens with dependencies. |
| No analytics / crash-reporting SDK | Matches the rest of the project's no-telemetry stance. |

## 9. Prototype scope (what's in `android/`)

The skeleton under `android/` is a spike, not a feature-complete app. It ships:

- A buildable Gradle project (AGP 8.7, Kotlin 2.0).
- Manifest with the permissions listed above.
- A single `MainActivity` + Compose scaffold, with a rationale dialog and
  a "permission denied" state.
- A `LocalScanner` with the WiFi and network stages implemented — including
  `startScan()` + broadcast-await so `security` is derived from fresh data
  rather than a stale cache — and the host-discovery / latency stages
  stubbed with empty-list placeholders.
- A `LocalScanResult` data class that matches the schema subset in §3.

It deliberately does **not** include:

- Room storage (the schema still needs a round of review).
- The TCP sweep or NSD host probe (both want their own tests).
- Any UI beyond a single "Scan now" button and a JSON dump.

## 10. Open questions

1. **Package name.** Default in the skeleton is
   `io.github.ismaelmartinez.wifisentinel`. Change to
   `com.ismaelmartinez.wifisentinel` or similar if you own that domain.
2. **`minSdk`.** 29 vs 26 — the older bar lets more devices install but
   forces a branch for the pre-10 WiFi API. Leaning 29.
3. **Branding.** App icon, launcher label, dark-theme colours — copy from
   the dashboard's teal/dark palette or diverge for platform-native feel?
4. **Import command on the CLI side.** Worth landing before the Android
   app writes its first export, so we don't paint ourselves into a schema
   corner. Proposed signature:
   `wifisentinel import <path> [--source android]`.
5. **Rule subset for `LocalAnalyser`.** Which of the five personas' rules
   are honest to evaluate from phone-only data? Red-team and privacy lean
   feasible; network-engineer and compliance lean misleading.

## 11. Suggested next steps

If we go ahead:

1. Agree the package name and `minSdk`.
2. Land `wifisentinel import` on the CLI side with a relaxed schema variant
   flagged `meta.platform: "android"` and `meta.partial: true`.
3. Fill in the Android prototype's WiFi stage and ship it behind
   `./gradlew assembleDebug` so you can sideload and try it.
4. Add the host-discovery stage (NSD + TCP sweep) with unit tests that
   mock the socket layer.
5. Decide whether to grow this to a second phase (local `LocalAnalyser`
   with the honest subset of persona rules) or stop at "raw data export"
   and keep the analysis on the Mac side.
