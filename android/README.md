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
│       │   ├── MainActivity.kt   # Compose entry point
│       │   ├── scan/             # LocalScanner + data model
│       │   └── ui/theme/         # Compose theme
│       └── res/values/           # strings + theme
├── build.gradle.kts              # root build file
├── settings.gradle.kts
└── gradle.properties
```

## What works (MVP)

- Requests `ACCESS_FINE_LOCATION` / `NEARBY_WIFI_DEVICES` at runtime.
- Reads the current WiFi connection via `WifiManager`.
- Renders a single scan screen with a "Scan now" button.
- Prints the result as JSON.

## What's stubbed

- Host discovery (NSD + TCP connect sweep).
- Latency / speed probes.
- Local scan history (Room).
- JSON export via `ActivityResultContracts.CreateDocument`.
- Rule-based local analyser.

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
