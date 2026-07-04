package io.github.ismaelmartinez.wifisentinel.scan

import kotlin.math.round

/**
 * Pure mapping for the opt-in download speed test: turns raw byte/duration
 * counters from [SpeedProbe] into the schema's `speed.download` shape. Like
 * [WifiMapping] and [HostMerge], it is free of Android framework types so it
 * can be unit-tested on the JVM. See docs/android-companion.md §9.
 */
internal object SpeedMapping {

    /**
     * Throughput in megabits per second (SI: 1 Mbps = 10^6 bits/s, matching
     * the CLI's speed scanner), rounded to two decimal places. Null when the
     * probe measured nothing meaningful — zero bytes, or a duration too short
     * to divide by.
     */
    fun downloadMbps(bytesTransferred: Long, durationMs: Long): Double? {
        if (bytesTransferred <= 0 || durationMs <= 0) return null
        val mbps = (bytesTransferred * 8.0 / 1_000_000.0) / (durationMs / 1000.0)
        return round(mbps * 100) / 100
    }

    /**
     * Assemble the full `speed.download` record, or null if the measurement
     * was empty. Field names mirror the CLI's `speed.download` object
     * (`src/collector/schema/scan-result.ts`).
     */
    fun downloadResult(
        bytesTransferred: Long,
        durationMs: Long,
        testUrl: String,
    ): LocalScanResult.Speed.Download? =
        downloadMbps(bytesTransferred, durationMs)?.let { mbps ->
            LocalScanResult.Speed.Download(
                speedMbps = mbps,
                bytesTransferred = bytesTransferred,
                durationMs = durationMs,
                testUrl = testUrl,
            )
        }
}
