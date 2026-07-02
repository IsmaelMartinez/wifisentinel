# WiFi Sentinel — Android companion (prototype)

> **Status:** investigation-stage spike. Not installable from the Play Store,
> not feature-complete, not an official release target. See
> [`docs/android-companion.md`](../docs/android-companion.md) for the design.

This directory contains a minimal Kotlin + Jetpack Compose skeleton for an
on-the-go WiFi analyser that runs entirely on the phone. It does not talk
to the Mac CLI or the dashboard.

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
│   └── src/test/kotlin/          # JVM unit tests (no emulator)
├── build.gradle.kts              # root build file
├── settings.gradle.kts
└── gradle.properties
```

## What works (MVP)

- Requests `ACCESS_FINE_LOCATION` / `NEARBY_WIFI_DEVICES` at runtime.
- Reads the current WiFi connection via `WifiManager`.
- Host discovery (NSD mDNS sweep + bounded TCP connect sweep, merged by IP).
- Latency probe (HTTPS `HEAD` timing).
- Rule-based local analyser (honest subset of the CLI's persona rules).
- Scan / History / Detail screens (single activity, hand-rolled navigation).
- On-device scan history via Room — every completed scan is auto-saved and
  listed newest-first; tap a row to re-view and re-export it.
- JSON export via `ActivityResultContracts.CreateDocument`.

## What's stubbed / pending

- Speed test (download throughput) — off by default to spare mobile data.
- Emulator instrumentation smoke test.

## Building without an Android SDK

The Kotlin/Android module needs the Android SDK to compile. On a machine with
only Gradle + Java (e.g. some CI/sandbox environments) `./gradlew` cannot build
the app or run the JVM unit tests — use Android Studio or install the SDK
(`sdkmanager`, `ANDROID_HOME`) first.

## Build

Open the `android/` directory in Android Studio (Ladybug 2024.2.1+ or newer).
Android Studio will materialise the Gradle wrapper on first sync.

From the command line once the wrapper is in place:

```bash
cd android
./gradlew assembleDebug            # produce app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug             # install on a connected device
```

Minimum runtime: Android 10 (API 29). `compileSdk` and `targetSdk` are 35.

## Conventions

- Package: `io.github.ismaelmartinez.wifisentinel` (placeholder — see
  [Open questions](../docs/android-companion.md#10-open-questions)).
- UK English in user-facing strings (`analyse`, `colour`).
- No telemetry, no third-party analytics SDKs.
- All scan data stays in app-private storage.

## Status of the launcher icon

The skeleton references `@android:drawable/sym_def_app_icon` as a
placeholder. Swap it for a proper adaptive icon before any real release.
