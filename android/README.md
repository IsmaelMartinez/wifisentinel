# WiFi Sentinel — Android companion (prototype)

> **Status:** investigation-stage spike. Not on the Play Store,
> not feature-complete, not an official release target. A sideloadable APK
> is attached to [GitHub releases](https://github.com/IsmaelMartinez/wifisentinel/releases)
> — see [Install on your phone](#install-on-your-phone-no-laptop-needed).
> [`docs/android-companion.md`](../docs/android-companion.md) has the design.

This directory contains a minimal Kotlin + Jetpack Compose skeleton for an
on-the-go WiFi analyser that runs entirely on the phone. It has no live
connection to the Mac CLI or the dashboard — sync is manual and file-based:
export a scan as JSON on the phone, then feed it to `wifisentinel import`
(see [Getting scans into the CLI](#getting-scans-into-the-cli)).

## What's here

```
android/
├── app/                          # the Android app module
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── kotlin/io/github/ismaelmartinez/wifisentinel/
│       │   ├── MainActivity.kt   # Compose entry point (Scan/History/Detail)
│       │   ├── analyse/          # LocalAnalyser (rule-based)
│       │   ├── scan/             # LocalScanner + probes + pure mapping helpers
│       │   ├── store/            # Room ScanStore (on-device history)
│       │   └── ui/theme/         # Compose theme
│       ├── res/values/           # strings + theme
│       └── res/xml/              # backup exclusion rules
│   ├── src/test/kotlin/          # JVM unit tests (no emulator)
│   └── src/androidTest/kotlin/   # instrumented tests (emulator/device)
├── build.gradle.kts              # root build file
├── settings.gradle.kts
├── gradle.properties
├── gradlew / gradlew.bat         # committed Gradle wrapper (8.11.1)
└── gradle/wrapper/
```

## What works (MVP)

- Requests `ACCESS_FINE_LOCATION` / `NEARBY_WIFI_DEVICES` at runtime.
- Reads the current WiFi connection via `WifiManager`.
- Captures nearby networks from the same `WifiManager` scan (deduped by
  BSSID, connected AP excluded, capped at 25, strongest first) — the count
  shows in the result view and the full list rides the JSON export so the
  CLI's channel-congestion analysis works on imported scans.
- Host discovery (NSD mDNS sweep + bounded TCP connect sweep, merged by IP).
- Latency probe (HTTPS `HEAD` timing). Note this is an HTTPS round-trip,
  not an ICMP ping — the CLI import stamps it `speed.latency.method:
  "https-rtt"` so reports threshold it against HTTPS-appropriate bands
  (~100–400 ms healthy) instead of ping bands.
- Opt-in speed test (download throughput) — off by default to spare mobile
  data; toggle it on the Scan screen. Bounded to a fixed-size Cloudflare
  fetch with a hard time cap; the result appears in the report, the Detail
  screen, and the JSON export.
- Rule-based local analyser (honest subset of the CLI's persona rules).
- Scan / History / Detail screens (single activity, hand-rolled navigation).
- On-device scan history via Room — every completed scan is auto-saved and
  listed newest-first; tap a row to re-view and re-export it.
- JSON export via `ActivityResultContracts.CreateDocument`.

## Install on your phone (no laptop needed)

Every [GitHub release](https://github.com/IsmaelMartinez/wifisentinel/releases)
carries a `wifisentinel-<tag>-android-debug.apk` asset (attached by
`.github/workflows/release.yml`). Release assets are direct downloads — no
GitHub login, no zip wrapper — so the whole flow works from the phone's
browser:

1. Open the [releases page](https://github.com/IsmaelMartinez/wifisentinel/releases)
   on the phone and download the `.apk` asset from the latest release.
2. Open the downloaded file. Android will ask you to allow installs from
   your browser ("install unknown apps") the first time — this is normal
   for any app outside the Play Store.
3. Done. Minimum Android version is 10 (API 29).

The APK is **debug-signed** (the prototype has no release signing key yet),
which is fine for sideloading. One consequence: when a release rotates to a
build signed with a different debug key, Android will refuse to install it
over the old one — uninstall the old app first. Exported scan JSON files
live outside app storage, so they survive; on-device scan history does not.

If you'd rather not sideload from releases, the CI workflow also uploads an
`app-debug-apk` artifact on every CI run — pushes to `main` and pull
requests alike (login required, arrives zipped, expires after 90 days) — or
build it yourself, below.

## Getting scans into the CLI

The phone→CLI flow is manual and file-based (no LAN server, no cloud sync —
see [`docs/android-companion.md` §6](../docs/android-companion.md#6-sync-story-no-lan)):

1. **On the phone:** run a scan, then tap **Export as JSON** (on the Scan
   screen right after a scan, or from any stored scan's Detail screen).
   Android's document picker asks where to save `wifisentinel-scan.json` —
   Drive, Downloads, anywhere the Storage Access Framework reaches.
2. **Move the file** to the machine that runs the CLI (AirDrop, cloud drive,
   USB, email to yourself — anything).
3. **On the CLI host:**

   ```bash
   wifisentinel import path/to/wifisentinel-scan.json
   # (or during development: npm run dev -- import path/to/wifisentinel-scan.json)
   ```

   The import validates the export against a relaxed schema
   (`src/collector/android-import.ts`), expands it into a full
   `NetworkScanResult` with `meta.platform: "android"` and
   `meta.partial: true`, runs the persona/standards analysis, and stores it
   in `~/.wifisentinel/scans/` alongside CLI scans — so it shows up in
   `history`, `trend`, `diff`, `devices`, and the dashboard.

What carries across: WiFi link details (SSID/BSSID/security/channel/band/
signal/txRate), nearby networks, IP/gateway/DNS, discovered hosts with open
ports, VPN state, the latency figure (stamped `https-rtt` so it isn't judged
against ICMP ping thresholds), and the opt-in download speed result.
Security labels are normalised into the CLI's canonical vocabulary on
import (`src/collector/schema/security.ts`), so the phone's coarse
"Open"/"WPA2" labels feed the same rogue-AP, `rf --compare`, and standards
rules as the macOS scanner's "WPA2 Personal"-style labels — an open evil
twin of your WPA2 network is flagged high-severity on imported scans too.
Everything the phone can't observe stays absent or carries a documented
sentinel — imported records are flagged partial rather than pretending to be
full audits.

## Testing

Two layers, mirroring what CI runs:

- **JVM unit tests** (`src/test/kotlin/`) — pure mapping/merge/analysis logic
  (`WifiMapping`, `HostMerge`, `SpeedMapping`, `LocalAnalyser`), no emulator:
  `./gradlew :app:testDebugUnitTest`.
- **Instrumented tests** (`src/androidTest/kotlin/`) — a Compose smoke test
  that launches `MainActivity` and asserts the Scan screen renders, a Room
  `ScanDao` test against a real on-device database, and an end-to-end scan
  test (`ScanEndToEndTest`) that grants the scan permission, taps "Scan now",
  waits for the pipeline to finish, and asserts the result rendered and a row
  landed in scan history:
  `./gradlew :app:connectedDebugAndroidTest` (needs an emulator or device;
  `./gradlew :app:assembleDebugAndroidTest` just compiles them).

CI runs both: the `android` job covers unit tests and uploads a debug APK
artifact; the separate `android-instrumented` job boots an API 35 x86_64
emulator (reactivecircus/android-emulator-runner, with AVD snapshot caching)
and runs the instrumented suite.

The end-to-end test exercises the device-dependent pipeline glue
(`LocalScanner` / `HostProbe` / `WifiManager` interplay) that the JVM tests
cannot reach. The CI emulator has no real WiFi, so it asserts the pipeline
degrades honestly (the scan completes, the analysis runs, the record is
saved) rather than asserting network specifics — `wifi` may legitimately be
null there.

## Build

The Gradle wrapper (8.11.1) is committed, so `./gradlew` works out of the box —
you only need a JDK (17+) and the Android SDK (`ANDROID_HOME` set, with
`platforms;android-35` and `build-tools;35.0.0` installed — Android Studio
sets this up for you, or use `sdkmanager` like the CI jobs do; see
`.github/workflows/ci.yml`). Without an SDK the module cannot compile, even
for the JVM unit tests.

```bash
cd android
./gradlew :app:testDebugUnitTest   # JVM unit tests
./gradlew assembleDebug            # produce app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug             # install on a connected device
```

Or open the `android/` directory in Android Studio (Ladybug 2024.2.1+ or
newer).

Minimum runtime: Android 10 (API 29). `compileSdk` and `targetSdk` are 35.

## Conventions

- Package: `io.github.ismaelmartinez.wifisentinel` (placeholder — see
  [Open questions](../docs/android-companion.md#10-open-questions)).
- UK English in user-facing strings (`analyse`, `colour`).
- No telemetry, no third-party analytics SDKs.
- All scan data stays in app-private storage.
