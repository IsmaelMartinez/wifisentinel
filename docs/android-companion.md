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
| `wifi.security` | Matched `ScanResult.capabilities` for the current BSSID | Requires a fresh `startScan()` — we trigger and await the broadcast. The phone emits coarse labels ("Open", "WPA2", …) with no Personal/Enterprise distinction; the CLI import folds them into the canonical vocabulary (`src/collector/schema/security.ts`) so cross-source comparisons (rogue-AP weaker-security, `rf --compare`) work |
| `nearbyNetworks` (top-level) | `WifiManager.getScanResults()` | Implemented — deduped by BSSID (strongest sighting wins), connected AP excluded, capped at 25, strongest first (`WifiMapping.mapNearbyNetworks`). Throttled to 4 per 2 min; same permission gate. **Decoupled** from the connected-AP capture (`LocalScanResult.nearbyNetworks`, not nested under `wifi`), so a survey taken while disconnected — or with `WifiInfo` redacted, so `wifi` is null — still exports the RF neighbourhood whenever `getScanResults()` returned APs. Null means "not collected" — either the scan permission was absent, or the record predates the field (a pre-upgrade Room scan re-exported by a newer app version, which serialises the new field's default `null`). See §10 |
| `wifi.macRandomised` | — | **Not observable.** `WifiInfo.getMacAddress()` returns the sanitised `02:00:00:00:00:00` for all non-system callers; the real per-SSID randomisation flag lives in `WifiConfiguration.macRandomizationSetting` which requires a system permission. Omitted from the Android schema. |
| `network.ip`, `subnet`, `gateway.ip`, `dns.servers` | `DhcpInfo` / `LinkProperties` | Available without extra permissions |
| `network.gateway.mac` | ARP via `/proc/net/arp` | **Blocked** on modern Android; leave undefined |
| `network.hosts` | TCP connect sweep + `NsdManager` (mDNS) | Lightweight; no OS fingerprint, no nmap-grade detail |
| `connections.*`, `localServices` | — | **Not observable** from an unprivileged app; omit |
| `security.firewall`, `security.vpn` | `ConnectivityManager` link capabilities (`NET_CAPABILITY_*`) | Can detect an active VPN; no firewall introspection |
| `traffic.*` | — | **Not observable** without VpnService interception; explicit follow-up |
| `deauthDetection` | — | **Requires monitor mode**; not viable |
| `intrusionIndicators` | Partial — gateway change detection, duplicate-BSSID heuristics | Weak; useful as a trend signal only |
| `speed.latency.internetMs` | HTTP `HEAD` to a known host | An HTTPS round-trip (~100–400 ms healthy), not an ICMP ping (~15 ms) — the CLI import stamps `speed.latency.method: "https-rtt"` so reporters and personas threshold it accordingly |
| `speed.download.speedMbps` | HTTP `GET` of a sized blob | Implemented (`SpeedProbe`) — opt-in toggle, off by default to spare mobile data |

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
   broadcast (5 s timeout, fall back to cache) → `WifiInfo` via a
   `NetworkCallback` registered with `FLAG_INCLUDE_LOCATION_INFO` on API 31+
   (the synchronous `getNetworkCapabilities().transportInfo` snapshot is
   permanently location-redacted there — SSID/BSSID sanitised, `networkId`
   -1), falling back to the synchronous snapshot (fine on API 29/30) and
   then the deprecated `getConnectionInfo()` getter. **Unidentifiable AP:**
   when the API 31+ location-aware callback times out and we land on the
   redacted synchronous snapshot, both SSID and BSSID normalise to null.
   `captureWifi` early-returns null in that case rather than emit a
   signal-only connected-AP section — without an identity it can't be
   security-scored (no BSSID to match against the scan results), correlated
   across scans (the import folds a null BSSID to the `"unknown"` sentinel),
   or told apart from a nearby-list entry, so a signal-only section reads as
   a real observation the tool can't actually attribute. The RF neighbourhood
   is captured independently (below), so dropping it loses nothing the scan
   didn't already record.
3. **Nearby stage** — the fresh scan-result set is mapped into the top-level
   `nearbyNetworks` list independently of the connected-AP capture
   (`WifiMapping.mapNearbyNetworks` takes the nullable connected BSSID, which
   is simply null when `wifi` is), so a disconnected/redacted scan still
   surveys the RF environment.
4. **Network stage** — `DhcpInfo`, `LinkProperties`, VPN state.
5. **Host discovery** — `NsdManager` service-type sweep (configurable list:
   `_http._tcp`, `_ipp._tcp`, `_airplay._tcp`, `_homekit._tcp`, `_ssh._tcp`,
   `_printer._tcp`, `_googlecast._tcp`); TCP connect sweep to common ports
   (22, 80, 443, 53, 8080, 8443, 554) with a 300 ms timeout and a 32-way
   concurrency cap.
6. **Latency stage** — single `HEAD` to `https://www.cloudflare.com/cdn-cgi/trace`.
7. **Analyse stage** — rule-based local analyser.

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

Because the dashboard is not LAN-reachable, v1 sync is **manual, file-based**
(both halves are implemented):

- **Export.** The Scan and Detail screens write a `LocalScanResult` JSON
  file via `ActivityResultContracts.CreateDocument` — the user picks the
  destination (Downloads, Drive, …).
- **Import (CLI).** `wifisentinel import <file>` validates the JSON against
  a relaxed variant of `NetworkScanResult` (missing optional sections
  allowed, `meta.platform: "android"`), expands it with honest sentinels,
  recomputes the persona/standards analysis, and writes it into
  `~/.wifisentinel/scans/` so it shows up in history/trend/diff/devices and
  the dashboard. Trend consumers (`trend`, `rf --trend`, the dashboard
  Trends page) are source-aware: rows/points from partial imports are
  annotated, and summary/trend maths run over full CLI scans when a history
  mixes sources — the phone's weaker radio and 25-AP nearby cap would
  otherwise make the series oscillate with the source rather than the
  network. The `devices` tracker skips imported hosts entirely (their MAC is
  the `"unknown"` sentinel — the phone cannot read ARP — so they cannot be
  identified across scans).

End-to-end:

```bash
# 1. On the phone: Scan → Export as JSON → save wifisentinel-scan.json
# 2. Move the file to the CLI host (cloud drive, AirDrop, USB, …)
# 3. Import it:
wifisentinel import wifisentinel-scan.json
wifisentinel history        # the imported scan appears, flagged partial
```

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

The skeleton under `android/` has grown past the first spike. It ships:

- A buildable Gradle project (AGP 8.7, Kotlin 2.0, Room via KSP).
- Manifest with the permissions listed above.
- A single `MainActivity` hosting three Compose screens behind a tiny
  hand-rolled navigation state machine (no navigation-compose, no Hilt):
  - **Scan** — rationale dialog, "permission denied" state, rule-based
    analysis summary, a `CreateDocument` JSON export button, and two scan
    affordances: **Scan now** (full pipeline) and **Survey nearby**, a
    nearby-only RF survey that skips the connected-AP requirement (§10). A
    survey — or any scan whose connected AP couldn't be read — renders a "no
    associated network" note plus the RF list rather than a blank connected-AP
    card, and still exports via the same `CreateDocument` flow.
  - **History** — a newest-first list of stored scans (SSID, timestamp,
    overall risk), each row tappable. A nearby-only survey (no SSID) shows a
    "Nearby survey · N networks" title from the denormalised `nearbyCount`
    instead of a blank "unknown network".
  - **Detail** — re-views a stored scan and re-exports it via the same
    `CreateDocument` flow; the app bar is survey-aware too.
- On-device history via **Room** (`store/` package): a single `scans` table
  storing each completed `LocalScanResult` as a serialized
  `kotlinx.serialization` JSON blob keyed by `meta.scanId`, ordered by
  `timestamp` descending, with denormalised `ssid`/`overallRisk`/`nearbyCount`
  columns so the list renders without deserialising every blob. `nearbyCount`
  (nullable, added in schema v2 via `MIGRATION_1_2`) lets a nearby-only survey
  row show its RF density even though it has no SSID. `ScanStore` wraps the DAO,
  auto-persists every completed scan, and exposes the history as a reactive
  `Flow`. The table is excluded from auto-backup: `allowBackup=false` plus
  explicit `fullBackupContent`/`dataExtractionRules` that exclude
  `wifisentinel-scans.db` (§7).
- A `LocalScanner` that runs the full MVP pipeline:
  - **WiFi stage** — `startScan()` + broadcast-await so `security` is derived
    from fresh data rather than a stale cache. The connected-AP capture
    early-returns null when the AP is unidentifiable (API 31+ redacted
    fallback — see §4). The same scan-result set is mapped into the top-level
    `nearbyNetworks` list (deduped by BSSID, connected AP excluded, capped —
    `WifiMapping.mapNearbyNetworks`, JVM-tested), decoupled from the
    connected-AP capture so a disconnected/redacted scan still surveys the RF
    environment. A `surveyOnly` flag on `LocalScanner.scan()` drives **survey
    mode**: it skips the connected-AP capture (so `wifi` is null by
    construction) and the LAN/internet probes, returning just the RF
    neighbourhood.
  - **Network stage** — `DhcpInfo` / `LinkProperties` / VPN state.
  - **Host discovery** (`HostProbe`) — `NsdManager` mDNS sweep across the
    service-type list in §4, plus a bounded (32-way) TCP connect sweep of the
    local /24 on common ports, merged by IP.
  - **Latency probe** (`LatencyProbe`) — single HTTPS `HEAD` to Cloudflare's
    trace endpoint.
  - **Speed test** (`SpeedProbe`, opt-in) — bounded download throughput probe
    against Cloudflare's speed endpoint: fixed-size fetch (~25 MB) with a hard
    time cap, off by default and toggled on the Scan screen. The pure maths
    lives in `SpeedMapping` so it is JVM-unit-tested.
  - **Analyse stage** (`LocalAnalyser`, package `analyse`) — the honest subset
    of persona/standards rules (WiFi link security, VPN posture, cleartext LAN
    services, latency, and a 2.4 GHz channel-congestion nudge), pure and
    JVM-unit-tested.
- A `ChannelCongestion` helper (pure, framework-free, JVM-tested — same pattern
  as `WifiMapping`/`HostMerge`/`ScanPresentation`) that reads the RF
  neighbourhood a walk-around survey is actually for: it buckets
  `nearbyNetworks` by band + 802.11 channel, counts occupancy per channel, and —
  for the 2.4 GHz band, where 20 MHz channels overlap and 1/6/11 are the
  non-overlapping set — picks the least-congested of those channels (ties
  listed). The result/detail views render this below the nearby list for both a
  survey and a normal scan: per-channel occupancy plus a "least congested: ch N"
  line, hidden honestly when the list is null or empty. It also backs the
  analyser's congested-channel finding. The summary is a *derived* view —
  recomputed from `nearbyNetworks` on display and never stored or exported, so
  the JSON export contract with the CLI import is unchanged.
- A `LocalScanResult` data class that matches the schema subset in §3, now
  including the on-device `Analysis` model.
- JVM unit tests (`src/test/kotlin`, no emulator) covering the pure logic:
  - `LocalAnalyserTest` — the rule-based analyser, including the nearby-only
    survey path (an honest "survey" finding, no fabricated link warnings) and
    the 2.4 GHz congested-channel nudge (raised only for a connected 2.4 GHz AP
    with a clearly-emptier non-overlapping channel; skipped in survey mode).
  - `ChannelCongestionTest` — the pure bucketing and least-congested logic
    (`ChannelCongestion`): per-(band, channel) occupancy and ordering, the
    overlap-weighted 2.4 GHz pick across 1/6/11 (including ties and the
    no-2.4-GHz-data case), and the connected-AP move suggestion (margin gate,
    5 GHz skip, empty-list skip).
  - `ScanPresentationTest` — the framework-free survey/title logic
    (`ScanPresentation`) the Compose UI leans on: survey detection and the
    connected-SSID / nearby-survey / unknown-network title descriptor.
  - `WifiMappingTest` — the WiFi/network mapping (`WifiMapping`) extracted from
    `LocalScanner`: SSID/BSSID normalisation and redaction, security derivation
    from `ScanResult.capabilities`, frequency→channel/band, and the
    little-endian `DhcpInfo` IPv4 formatting.
  - `HostMergeTest` — `HostProbe`'s merge-by-IP (hostname/serviceType/port
    union, numeric-IP ordering) and subnet-derivation helpers (`HostMerge`).
  - `SpeedMappingTest` — the throughput maths (`SpeedMapping`) extracted from
    `SpeedProbe`: bytes+duration→Mbps, rounding, and empty-measurement cases.

  The mapping helpers were extracted into pure
  `WifiMapping`/`HostMerge`/`SpeedMapping` objects precisely so they can be
  tested on the JVM without faking `WifiManager` / `ConnectivityManager` or
  standing up an emulator.
- Instrumented tests (`src/androidTest/kotlin`, run on an emulator/device):
  - `MainActivitySmokeTest` — launches `MainActivity` via the Compose test
    rule's `ActivityScenario` and asserts the Scan screen renders.
  - `ScanDaoTest` — Room `ScanDao` insert/query/replace/clear against a real
    on-device SQLite database, plus a nearby-only survey row (null SSID with a
    `nearbyCount`) round-tripping through the denormalised projection.
  - `ScanEndToEndTest` — grants the scan permission, taps "Scan now", waits
    for the pipeline (`LocalScanner` → probes → `LocalAnalyser` →
    `ScanStore`) to finish, and asserts the result rendered and a row landed
    in scan history. The CI emulator has no real WiFi, so it asserts honest
    degradation (scan completes, analysis runs, record saved) rather than
    network specifics — `wifi` may legitimately be null there.

  CI runs these in a dedicated `android-instrumented` job on an API 35 x86_64
  emulator (reactivecircus/android-emulator-runner with AVD snapshot caching),
  separate from the `android` unit-test/APK job.

On the CLI side, `wifisentinel import <file>` (see `src/commands/import.ts` and
`src/collector/android-import.ts`) validates the export against a relaxed Zod
schema, expands it into a full `NetworkScanResult` with `meta.platform:
"android"` and `meta.partial: true`, and stores it so it appears in
`history` / `trend` / `diff` / `devices`. Security labels (connected AP and
nearby networks) are normalised into the canonical vocabulary at this
boundary — `src/collector/schema/security.ts` owns the taxonomy, and the
rogue-AP, `rf --compare`, standards, and persona consumers all compare
through it, so the phone's coarse "Open"/"WPA2" labels participate in the
same rules as the CLI's "WPA2 Personal"-style labels.

> **Build note.** The Gradle wrapper (8.11.1) is committed, so `./gradlew`
> works anywhere with a JDK 17+ and an Android SDK (`ANDROID_HOME`). Both CI
> jobs install the SDK with `android-actions/setup-android` — see
> `.github/workflows/ci.yml` and `android/README.md` for the commands.

## 10. Open questions

1. **Package name.** Default in the skeleton is
   `io.github.ismaelmartinez.wifisentinel`. Change to
   `com.ismaelmartinez.wifisentinel` or similar if you own that domain.
2. **`minSdk`.** 29 vs 26 — the older bar lets more devices install but
   forces a branch for the pre-10 WiFi API. Leaning 29.
3. **Branding.** App icon, launcher label, dark-theme colours — copy from
   the dashboard's teal/dark palette or diverge for platform-native feel?
4. ~~**Import command on the CLI side.**~~ Resolved — landed as
   `wifisentinel import <path> [--source android]` (§6).
5. **Rule subset for `LocalAnalyser`.** Which of the five personas' rules
   are honest to evaluate from phone-only data? Red-team and privacy lean
   feasible; network-engineer and compliance lean misleading. The honest set
   implemented so far: WiFi link security (open/WEP/WPA/WPA2/WPA3/OWE), VPN
   posture on an insecure link, cleartext LAN services from the TCP sweep,
   high internet latency, the nearby-only survey note, and — added with the
   channel-congestion view — a 2.4 GHz congested-channel nudge (INFO) when the
   connected AP shares a busy channel while a clearly-emptier non-overlapping
   channel exists. That last one is a light network-engineer rule that stays
   honest because it reads only phone-visible data (the connected channel and
   the `getScanResults()` neighbourhood), is skipped in survey mode (no
   associated AP to advise on) and off the 2.4 GHz band, and is framed as a
   suggestion the router's own channel picker may already outrank. All findings
   remain `partial = true`.
6. ~~**Disconnected-scan / survey mode.**~~ Resolved (data **and** UI).
   `nearbyNetworks` was lifted out of `LocalScanResult.Wifi` to a top-level
   field (`WifiMapping.mapNearbyNetworks` already took a nullable connected
   BSSID), so a scan taken while WiFi is disconnected — or with `WifiInfo`
   redacted, so `wifi` is null — still exports the RF neighbourhood whenever
   `getScanResults()` surfaced APs. The CLI import accepts the top-level list
   (preferring it over the legacy `wifi.nearbyNetworks` location, still read for
   back-compat) so a nearby-only partial scan round-trips into
   `history`/`trend`/`rf`/`devices`. **Survey mode** now drives this from the
   app: a `surveyOnly` flag on `LocalScanner.scan()` (skips the connected-AP
   capture and the LAN/internet probes), a **Survey nearby** button on the Scan
   screen, and survey-aware rendering — a "no associated network" state with the
   RF list in the result/detail views, a "Nearby survey · N networks" history
   title (from the denormalised `nearbyCount`), and an honest survey finding in
   `LocalAnalyser` instead of a "grant permission" failure. The pure decision
   logic lives in `ScanPresentation` (JVM-tested); the JSON export works for a
   survey unchanged.

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
